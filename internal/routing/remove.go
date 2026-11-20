package routing

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// Removing a worker address (fount launch-plan X4). A deleted worker's address
// leaves the live records, so it stops resolving, its keys sign nothing, RCPT
// answers 550, and it no longer counts toward MaxWorkers. What stays is a
// tombstone: the handle it was under, its last mail sequence, and when it went.
//
// The tombstone is what keeps the address safe. Only the same handle can name it
// again (POST /address checks the handle), and only after RemovedQuarantine, the
// mail retention: by then any mail still held for the old worker has expired, so
// a new worker on the address never sees it. Its sequence carries on from the old
// one, so its message, expiry and gap records never collide with the old
// worker's. A handle's own record is never removed: it holds the license's
// mailbox key and owners, and a released handle is never reissued (§4).

// RemovedQuarantine is how long a removed address stays out of use. It's the
// mail retention (design §6), so held mail has expired before the address can
// be named again.
const RemovedQuarantine = store.DefaultRetention

// MaxRemoved bounds the tombstones one handle keeps, since each is a record in
// the single routing object. Naming a removed address again reuses its
// tombstone, so only a brand-new address counts against it.
const MaxRemoved = 10 * MaxWorkers

// Removed is a removed address's tombstone.
type Removed struct {
	Root        []byte `json:"root"`     // the handle's record id
	Sequence    uint64 `json:"sequence"` // last mail sequence handed out
	RemovedAt   int64  `json:"removed_at"`
	Coordinated bool   `json:"coordinated,omitempty"` // it was enrolled, so the coordinator removed it
}

var (
	// ErrIsHandle means the address is a handle's own, which is never removed.
	ErrIsHandle = errors.New("routing: a handle's own address is not removed")
	// ErrRecentlyRemoved means the address was removed less than
	// RemovedQuarantine ago.
	ErrRecentlyRemoved = errors.New("routing: address was removed recently")
	// ErrRemovedLimit means the handle has MaxRemoved tombstones, so it can name
	// no brand-new address.
	ErrRemovedLimit = errors.New("routing: too many removed addresses")
)

// removed returns a tombstone. Caller holds s.mu.
func (s *Store) removed(id []byte) (*Removed, bool) {
	t, ok := s.data.Removed[hex.EncodeToString(id)]
	return t, ok
}

// removedUnder counts root's tombstones. Caller holds s.mu.
func (s *Store) removedUnder(root []byte) int {
	n := 0
	for _, t := range s.data.Removed {
		if hmac.Equal(t.Root, root) {
			n++
		}
	}
	return n
}

// RemoveAddress removes a worker address on the mailbox key's say: callerID is
// the Fount-Key-Id the request was verified under, which may be any address of
// the handle, or the removed address itself on a retry. The target must sit
// under the same handle, mustn't be the handle's own address, and mustn't be
// enrolled under a coordinator (ErrCoordinated: only the coordinator removes
// that). Removing an address already removed is nil, so a retry is safe.
func (s *Store) RemoveAddress(ctx context.Context, callerID, targetID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	root, ok := s.rootOfID(callerID)
	if !ok {
		return ErrNoMailbox
	}
	m, live := s.data.Mailboxes[hex.EncodeToString(targetID)]
	if !live {
		if t, ok := s.removed(targetID); ok && hmac.Equal(t.Root, root) {
			return nil
		}
		return ErrNoMailbox
	}
	if !hmac.Equal(m.root(), root) {
		return ErrNotHandle
	}
	if len(m.Root) == 0 {
		return ErrIsHandle
	}
	if m.Coordinated {
		return ErrCoordinated
	}
	return s.remove(ctx, m)
}

// RemoveCoordinated removes an enrolled worker address for the coordinator. An
// address the coordinator already removed is nil; one that isn't enrolled is
// ErrNotCoordinated.
func (s *Store) RemoveCoordinated(ctx context.Context, targetID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, live := s.data.Mailboxes[hex.EncodeToString(targetID)]
	if !live {
		if t, ok := s.removed(targetID); ok {
			if t.Coordinated {
				return nil
			}
			return ErrNotCoordinated
		}
		return ErrNoMailbox
	}
	if !m.Coordinated {
		return ErrNotCoordinated
	}
	if len(m.Root) == 0 {
		return ErrIsHandle
	}
	return s.remove(ctx, m)
}

// rootOfID is the handle record id for a live address or a tombstone. Caller
// holds s.mu.
func (s *Store) rootOfID(id []byte) ([]byte, bool) {
	if m, ok := s.data.Mailboxes[hex.EncodeToString(id)]; ok {
		return m.root(), true
	}
	if t, ok := s.removed(id); ok {
		return t.Root, true
	}
	return nil, false
}

// remove swaps a live worker record for its tombstone, with the notices about
// it, in one write. Caller holds s.mu.
func (s *Store) remove(ctx context.Context, m *Mailbox) error {
	key := hex.EncodeToString(m.MailboxID)
	root := s.data.Mailboxes[hex.EncodeToString(m.Root)]
	var prevRoot Mailbox
	if root != nil {
		prevRoot = *root
		kept := slices.DeleteFunc(slices.Clone(root.Notices), func(n Notice) bool { return hmac.Equal(n.Worker, m.MailboxID) })
		if len(kept) != len(root.Notices) {
			root.Notices = kept
			s.touch(root)
		}
	}
	if s.data.Removed == nil {
		s.data.Removed = map[string]*Removed{}
	}
	delete(s.data.Mailboxes, key)
	s.data.Removed[key] = &Removed{
		Root:        slices.Clone(m.Root),
		Sequence:    m.Sequence,
		RemovedAt:   s.now().Unix(),
		Coordinated: m.Coordinated,
	}
	if err := s.persist(ctx); err != nil {
		delete(s.data.Removed, key)
		s.data.Mailboxes[key] = m
		if root != nil {
			*root = prevRoot
		}
		return err
	}
	return nil
}

// reuse checks whether a new address may take id under root, and returns the
// sequence it starts from and whether it replaces a tombstone. Caller holds s.mu.
func (s *Store) reuse(id, root []byte) (seq uint64, tomb bool, err error) {
	if _, taken := s.data.Mailboxes[hex.EncodeToString(id)]; taken {
		return 0, false, ErrHandleTaken
	}
	t, ok := s.removed(id)
	if !ok {
		if s.removedUnder(root) >= MaxRemoved {
			return 0, false, ErrRemovedLimit
		}
		return 0, false, nil
	}
	if !hmac.Equal(t.Root, root) {
		return 0, false, ErrHandleTaken
	}
	if s.now().Before(time.Unix(t.RemovedAt, 0).Add(RemovedQuarantine)) {
		return 0, false, ErrRecentlyRemoved
	}
	return t.Sequence, true, nil
}

// RemovedOf returns a copy of an address's tombstone, for tests and audits.
func (s *Store) RemovedOf(mailboxID []byte) (Removed, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.removed(mailboxID)
	if !ok {
		return Removed{}, false
	}
	c := *t
	c.Root = slices.Clone(t.Root)
	return c, true
}

// removedMailboxKey resolves the mailbox key for a tombstone's id: the handle's
// current one, so a retried removal signed under the removed address's own id
// still verifies, and a mailbox key rotated since is the only one that does.
func (s *Store) removedMailboxKey(keyID string) (ed25519.PublicKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.data.Removed[keyID]
	if !ok {
		return nil, false
	}
	root, ok := s.data.Mailboxes[hex.EncodeToString(t.Root)]
	if !ok || len(root.MailboxKey) != ed25519.PublicKeySize {
		return nil, false
	}
	return slices.Clone(ed25519.PublicKey(root.MailboxKey)), true
}
