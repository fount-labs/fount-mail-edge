package routing

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// Owners from M3 (design §10, §14). The owner list is only what the licensee's
// device wrote, so before the edge mails an owner it proves the owner reads that
// address itself: each new owner gets one fixed "Reply to turn on email updates"
// mail whose reply address carries an edge token, and the edge records the proof
// when the reply arrives. A license can have more than one owner. Every proved
// owner hears about a new one, and a new owner gets nothing but the proof mail
// until OwnerWait ends, because the closed app does pairing and a bad build could
// pair an attacker.
//
// The state is the license's, so it lives on the handle's record: a new worker
// copies the first worker's owners, and copying one isn't a new owner. Each
// record's OwnerHashes still says who owns that worker.

const (
	ownerAddressInfo = "fount-mail-edge/v1/owner-addresses"
	ownerProofInfo   = "fount-mail-edge/v1/owner-proof"

	// OwnerWait is how long a new owner waits before the edge mails them anything
	// but the proof mail. **Proposed** (§10); the license's first owners don't wait,
	// because nobody could be told about them.
	OwnerWait = 72 * time.Hour

	// DefaultNewOwnersPerDay caps new owners per license per rolling day (§14
	// "daily caps on new owners"). **Proposed**; the M3 test sets the real value.
	DefaultNewOwnersPerDay = 5

	// MaxNotices bounds a license's queued owner mail. A full queue refuses owner
	// changes rather than drop a security notice. Until the send path drains it,
	// the daily cap keeps it from filling in under a month.
	MaxNotices = 256

	// ProofLocalPart is the reply address's local part, before "+<token>". It's a
	// reserved name (§4), so no handle can take it, and handles can't hold "+".
	ProofLocalPart = "fount"

	proofTokenBytes = 16 // 128 bits, as §10 asks of the pairing token
)

var proofEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrOwnerLimit means an owner change would pass the daily new-owner cap or fill
// the notice queue (429).
var ErrOwnerLimit = errors.New("routing: new-owner limit reached")

// Owner is one owner of a license, as the edge knows them.
type Owner struct {
	Hash     []byte `json:"hash"`   // the address MAC, as in OwnerHashes
	Sealed   []byte `json:"sealed"` // the address, sealed by sealOwner
	AddedAt  int64  `json:"added_at"`
	ActiveAt int64  `json:"active_at,omitempty"` // when OwnerWait ends; 0 for the license's first owners
	ProvedAt int64  `json:"proved_at,omitempty"` // when the edge saw the proof reply; 0 until then
}

func (o Owner) clone() Owner {
	o.Hash = slices.Clone(o.Hash)
	o.Sealed = slices.Clone(o.Sealed)
	return o
}

// NoticeKind is the kind of owner mail a Notice asks for.
type NoticeKind string

const (
	// NoticeOwnerProof is the one fixed mail to a new owner: "Reply to turn on
	// email updates", with the reply address from PendingNotice.ReplyTo.
	NoticeOwnerProof NoticeKind = "owner-proof"
	// NoticeNewOwner tells a proved owner that About was added.
	NoticeNewOwner NoticeKind = "new-owner"
	// NoticeOwnerRemoved tells a proved owner they were removed, so removing the
	// owners and then adding one can't happen unseen.
	NoticeOwnerRemoved NoticeKind = "owner-removed"
)

// Notice is one queued owner mail, held in routing data until the send path
// sends it. Each is one message to one owner.
type Notice struct {
	ID        string     `json:"id"`
	Kind      NoticeKind `json:"kind"`
	ToHash    []byte     `json:"to_hash"`
	To        []byte     `json:"to"`                   // sealed recipient address
	AboutHash []byte     `json:"about_hash,omitempty"` // NoticeNewOwner: the new owner
	About     []byte     `json:"about,omitempty"`      // sealed
	Worker    []byte     `json:"worker"`               // the record whose owner list changed
	CreatedAt int64      `json:"created_at"`
}

func (n Notice) clone() Notice {
	for _, b := range []*[]byte{&n.ToHash, &n.To, &n.AboutHash, &n.About, &n.Worker} {
		*b = slices.Clone(*b)
	}
	return n
}

// WithNewOwnerLimit sets the new owners a license can add per rolling day; n <= 0
// is no cap.
func WithNewOwnerLimit(n int) Option { return func(s *Store) { s.newOwnerLimit = n } }

// WithClock sets the store's clock for owner and pause times. Tests use it.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// sealOwner seals an owner address to its license and hash, so a sealed copy can't
// be moved to another record. This is §4's "encrypted owner addresses": anyone with
// the keyserver's ROUTING_DATA_KEY can read them.
func (s *Store) sealOwner(root, hash []byte, address string) ([]byte, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.ownerAEAD.Seal(nonce, nonce, []byte(normalize(address)), ownerAAD(root, hash)), nil
}

func (s *Store) openOwner(root, hash, sealed []byte) (string, error) {
	if len(sealed) < nonceLen {
		return "", errors.New("routing: sealed owner too short")
	}
	pt, err := s.ownerAEAD.Open(nil, sealed[:nonceLen], sealed[nonceLen:], ownerAAD(root, hash))
	if err != nil {
		return "", fmt.Errorf("routing: open owner: %w", err)
	}
	return string(pt), nil
}

func ownerAAD(root, hash []byte) []byte { return append(slices.Clone(root), hash...) }

func normalize(v string) string { return strings.ToLower(strings.TrimSpace(v)) }

// rootOf is the handle's record for m. Caller holds s.mu.
func (s *Store) rootOf(m *Mailbox) *Mailbox {
	if r, ok := s.data.Mailboxes[hex.EncodeToString(m.root())]; ok {
		return r
	}
	return m
}

// SetOwners writes the versioned owner list (design §8 PUT /routing). Each record
// keeps its owners as keyed hashes; the license's owner state on the handle's
// record keeps a sealed copy of each address, the proof, and the wait (§10). The
// version must not go backwards: the device re-asserts its current version on each
// sync, which overwrites a rolled-back object, and only a strictly greater version
// changes the list. Resending the stored version with the same list changes
// nothing, except on a license from before M3, whose owners it records. A lower
// version, or the stored version with a different list, is ErrStaleVersion.
//
// A new owner queues a proof mail to them, a new-owner notice to every proved
// owner, and an owner-removed notice to every proved owner taken off. Those wait
// in Notices for the send path. Once a license has had an owner, emptying the
// list and adding one is a new owner like any other.
func (s *Store) SetOwners(ctx context.Context, mailboxID []byte, version uint64, owners []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	if version < m.RoutingVersion {
		return ErrStaleVersion
	}
	hashes := make([][]byte, 0, len(owners))
	addrs := make(map[string]string, len(owners))
	for _, o := range owners {
		h := s.keyedHash(o)
		hashes = append(hashes, h)
		addrs[string(h)] = o
	}
	resend := version == m.RoutingVersion
	if resend && !slices.EqualFunc(hashes, m.OwnerHashes, hmac.Equal) {
		return ErrStaleVersion
	}
	root := s.rootOf(m)
	next, err := s.planOwners(root, m, hashes, addrs)
	if err != nil {
		return err
	}
	if resend && next == nil {
		return nil
	}
	records := []*Mailbox{m}
	if root != m {
		records = append(records, root)
	}
	return s.update(ctx, records, func(r *Mailbox) {
		if r == m {
			r.OwnerHashes, r.RoutingVersion = hashes, version
		}
		if r == root && next != nil {
			r.OwnersSeen, r.OwnerState, r.OwnerAdds, r.Notices = next.seen, next.state, next.adds, next.notices
		}
	})
}

type ownerPlan struct {
	seen    bool
	state   []Owner
	adds    []int64
	notices []Notice
}

// planOwners works out the license's owner state once m's owners are hashes. It
// returns nil when nothing would change. Caller holds s.mu.
func (s *Store) planOwners(root, m *Mailbox, hashes [][]byte, addrs map[string]string) (*ownerPlan, error) {
	now := s.now().Unix()
	present := map[string]bool{}
	for _, r := range s.family(m) {
		if r == m {
			continue
		}
		for _, h := range r.OwnerHashes {
			present[string(h)] = true
		}
	}
	for _, h := range hashes {
		present[string(h)] = true
	}

	changed := false
	// Before M3 a record had only OwnerHashes, so the first write after the
	// upgrade counts as the first owners too.
	first := !root.OwnersSeen
	var proved []Owner // owners who hear about this change
	p := &ownerPlan{}
	for _, o := range root.OwnerState {
		if o.ProvedAt > 0 && len(o.Sealed) > 0 {
			proved = append(proved, o)
		}
		if present[string(o.Hash)] {
			p.state = append(p.state, o.clone())
			continue
		}
		changed = true
		if o.ProvedAt > 0 && len(o.Sealed) > 0 {
			p.notices = append(p.notices, Notice{Kind: NoticeOwnerRemoved, ToHash: o.Hash, To: o.Sealed})
		}
	}
	for _, n := range root.Notices {
		// A proof mail to someone no longer an owner is moot. Other notices stay.
		if n.Kind == NoticeOwnerProof && !present[string(n.ToHash)] {
			changed = true
			continue
		}
		p.notices = append(p.notices, n.clone())
	}
	for _, t := range root.OwnerAdds {
		if now-t < int64(24*time.Hour/time.Second) {
			p.adds = append(p.adds, t)
		}
	}

	seen := map[string]bool{}
	for _, h := range hashes {
		if seen[string(h)] {
			continue
		}
		seen[string(h)] = true
		if slices.ContainsFunc(p.state, func(o Owner) bool { return hmac.Equal(o.Hash, h) }) {
			continue
		}
		changed = true
		sealed, err := s.sealOwner(root.MailboxID, h, addrs[string(h)])
		if err != nil {
			return nil, err
		}
		o := Owner{Hash: h, Sealed: sealed, AddedAt: now}
		if !first {
			o.ActiveAt = now + int64(OwnerWait/time.Second)
			p.adds = append(p.adds, now)
			for _, r := range proved {
				p.notices = append(p.notices, Notice{Kind: NoticeNewOwner, ToHash: r.Hash, To: r.Sealed, AboutHash: h, About: sealed})
			}
		}
		p.state = append(p.state, o)
		p.notices = append(p.notices, Notice{Kind: NoticeOwnerProof, ToHash: h, To: sealed})
	}
	if !changed {
		return nil, nil
	}
	if s.newOwnerLimit > 0 && len(p.adds) > s.newOwnerLimit || len(p.notices) > MaxNotices {
		return nil, ErrOwnerLimit
	}
	for i := range p.notices {
		n := &p.notices[i]
		if n.ID != "" {
			continue
		}
		id := make([]byte, 8)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		n.ID, n.Worker, n.CreatedAt = hex.EncodeToString(id), slices.Clone(m.MailboxID), now
	}
	p.seen = root.OwnersSeen || len(p.state) > 0
	return p, nil
}

// OwnerProven reports whether the edge may mail ownerHash on mailboxID's behalf:
// it's an owner of that worker, the edge has seen their proof reply, and their
// wait is over (§10, §14 "mail goes only to owners with the edge's own proof").
// It is send.ProofChecker.
func (s *Store) OwnerProven(mailboxID, ownerHash []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok || !slices.ContainsFunc(m.OwnerHashes, func(h []byte) bool { return hmac.Equal(h, ownerHash) }) {
		return false
	}
	for _, o := range s.rootOf(m).OwnerState {
		if hmac.Equal(o.Hash, ownerHash) {
			return o.ProvedAt > 0 && s.now().Unix() >= o.ActiveAt
		}
	}
	return false
}

// proofToken is the token in a new owner's reply address. It's derived, not
// stored, so the queued proof mail and the inbound check agree without keeping a
// secret in routing data, and re-adding an owner gives a new one.
func (s *Store) proofToken(root []byte, o Owner) string {
	mac := hmac.New(sha256.New, s.proofKey)
	mac.Write(root)
	mac.Write(o.Hash)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(o.AddedAt))
	mac.Write(t[:])
	return proofEncoding.EncodeToString(mac.Sum(nil)[:proofTokenBytes])
}

// proofTag returns the token of a "fount+<token>@…" recipient. Every such
// recipient is a proof reply, matched or not, so none reaches a mailbox. The
// domain is SMTP's to check.
func proofTag(recipient string) (string, bool) {
	local, _, ok := strings.Cut(normalize(recipient), "@")
	if !ok {
		return "", false
	}
	return strings.CutPrefix(local, ProofLocalPart+"+")
}

// findProof finds the owner a proof token belongs to. It checks every license's
// owners, which is fine at this scale and runs only for "fount+" recipients,
// whose misses SMTP rate limits like any other. Caller holds s.mu.
func (s *Store) findProof(tag string) (*Mailbox, int, bool) {
	for _, r := range s.data.Mailboxes {
		if len(r.Root) > 0 {
			continue
		}
		for i, o := range r.OwnerState {
			if hmac.Equal([]byte(s.proofToken(r.MailboxID, o)), []byte(tag)) {
				return r, i, true
			}
		}
	}
	return nil, 0, false
}

// proofStatus is RCPT's answer for a proof reply address. A token that's already
// been used still accepts, so a second reply doesn't bounce.
func (s *Store) proofStatus(tag string) smtp.RecipientStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.findProof(tag); ok {
		return smtp.RecipientAccepting
	}
	return smtp.RecipientUnknown
}

// Prove records that the owner behind a proof reply address reads it. It reports
// false if the token matches no owner.
func (s *Store) Prove(ctx context.Context, recipient string) (bool, error) {
	tag, ok := proofTag(recipient)
	if !ok {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return false, err
	}
	root, i, ok := s.findProof(tag)
	if !ok {
		return false, nil
	}
	if root.OwnerState[i].ProvedAt > 0 {
		return true, nil
	}
	now := s.now().Unix()
	err := s.update(ctx, []*Mailbox{root}, func(r *Mailbox) {
		state := slices.Clone(r.OwnerState)
		state[i].ProvedAt = now
		r.OwnerState = state
	})
	return err == nil, err
}

// ProofIntake wraps SMTP's store so a reply to a proof mail records the proof
// and is then dropped: it's an answer to the edge, not mail for the worker, and
// storing it would start a job. Everything else goes to next.
func (s *Store) ProofIntake(next smtp.Storer) smtp.Storer { return proofIntake{s, next} }

type proofIntake struct {
	s    *Store
	next smtp.Storer
}

func (p proofIntake) Put(ctx context.Context, env store.Envelope, raw []byte) (string, error) {
	if _, ok := proofTag(env.Recipient); !ok {
		return p.next.Put(ctx, env, raw)
	}
	switch ok, err := p.s.Prove(ctx, env.Recipient); {
	case err != nil:
		return "", err
	case !ok:
		return "", store.ErrNoRecipient
	}
	return "owner-proof", nil
}

// --- the notice queue's send seam -----------------------------------------

// PendingNotice is a queued notice, opened for sending.
type PendingNotice struct {
	ID      string
	Kind    NoticeKind
	To      string // the owner to mail
	About   string // NoticeNewOwner: the owner who was added
	ReplyTo string // NoticeOwnerProof: the reply address that proves the owner
	Worker  []byte // the record whose owner list changed
}

// NoticeMailer sends one owner notice. Nothing implements it yet: it waits on the
// send path (group F's send.Service) and the DKIM key (fount-mail-send-keys.md).
// Until then notices wait in routing data, so none is lost to a reboot.
type NoticeMailer interface {
	SendNotice(ctx context.Context, n PendingNotice) error
}

// PendingNotices lists every queued notice, oldest first per license. domain is
// the mail domain, such as "@fountbox.com", for proof reply addresses. A proof
// mail to an owner who has since proved is left out.
func (s *Store) PendingNotices(domain string) ([]PendingNotice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PendingNotice
	for _, r := range s.data.Mailboxes {
		if len(r.Root) > 0 {
			continue
		}
		for _, n := range r.Notices {
			p := PendingNotice{ID: n.ID, Kind: n.Kind, Worker: slices.Clone(n.Worker)}
			var err error
			if p.To, err = s.openOwner(r.MailboxID, n.ToHash, n.To); err != nil {
				return nil, err
			}
			if len(n.About) > 0 {
				if p.About, err = s.openOwner(r.MailboxID, n.AboutHash, n.About); err != nil {
					return nil, err
				}
			}
			if n.Kind == NoticeOwnerProof {
				i := slices.IndexFunc(r.OwnerState, func(o Owner) bool { return hmac.Equal(o.Hash, n.ToHash) })
				if i < 0 || r.OwnerState[i].ProvedAt > 0 {
					continue
				}
				p.ReplyTo = ProofLocalPart + "+" + s.proofToken(r.MailboxID, r.OwnerState[i]) + domain
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// NoticeSent removes a notice from the queue once it's sent.
func (s *Store) NoticeSent(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	for _, r := range s.data.Mailboxes {
		i := slices.IndexFunc(r.Notices, func(n Notice) bool { return n.ID == id })
		if i < 0 {
			continue
		}
		return s.update(ctx, []*Mailbox{r}, func(r *Mailbox) {
			r.Notices = slices.Delete(slices.Clone(r.Notices), i, i+1)
		})
	}
	return nil
}

// DrainNotices sends every queued notice through m and removes each one sent. It
// stops at the first failure, so the rest wait for the next pass. Nothing calls it
// until the send path exists.
func (s *Store) DrainNotices(ctx context.Context, m NoticeMailer, domain string) (int, error) {
	pending, err := s.PendingNotices(domain)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, n := range pending {
		if err := m.SendNotice(ctx, n); err != nil {
			return sent, err
		}
		if err := s.NoticeSent(ctx, n.ID); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

// --- pause ------------------------------------------------------------------

// SetPaused pauses or resumes a worker (design §8 POST /pause, §12). The caller
// has checked the passkey. Setting the state it already has changes nothing.
func (s *Store) SetPaused(ctx context.Context, mailboxID []byte, paused bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	if m.Paused == paused {
		return nil
	}
	now := s.now().Unix()
	return s.update(ctx, []*Mailbox{m}, func(m *Mailbox) { m.Paused, m.PausedAt = paused, now })
}

// Paused reports whether a worker is paused. An unknown worker isn't.
func (s *Store) Paused(mailboxID []byte) bool {
	m, ok := s.Snapshot(mailboxID)
	return ok && m.Paused
}
