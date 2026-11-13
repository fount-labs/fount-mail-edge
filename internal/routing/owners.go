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
// A connect reply (connect.go) is the other proof: the edge mailed the owner from
// the worker, and the device hands back that mail's Message-ID once they reply.
// An owner proved that way gets no proof mail; the wait and the notices stand.
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
	// changes rather than drop a security notice. While sending is off nothing
	// drains it, and the daily cap keeps it from filling in under a month.
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
//
// proofs are connect replies (connect.go) the device saw. Each must verify for
// this worker, be within ConnectLifetime, and name an owner in owners, or the
// whole write is ErrConnectProof and nothing changes. An owner a proof covers is
// proved now, so a new one gets no proof mail. Every other rule stands.
func (s *Store) SetOwners(ctx context.Context, mailboxID []byte, version uint64, owners []string, proofs ...ConnectProof) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	hashes := make([][]byte, 0, len(owners))
	addrs := make(map[string]string, len(owners))
	for _, o := range owners {
		h := s.keyedHash(o)
		hashes = append(hashes, h)
		addrs[string(h)] = o
	}
	connected, err := s.checkConnect(mailboxID, hashes, proofs)
	if err != nil {
		return err
	}
	if version < m.RoutingVersion {
		return ErrStaleVersion
	}
	resend := version == m.RoutingVersion
	if resend && !slices.EqualFunc(hashes, m.OwnerHashes, hmac.Equal) {
		return ErrStaleVersion
	}
	root := s.rootOf(m)
	next, err := s.planOwners(root, m, hashes, addrs, connected)
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

// planOwners works out the license's owner state once m's owners are hashes.
// connected are the owners a connect proof just proved. It returns nil when
// nothing would change. Caller holds s.mu.
func (s *Store) planOwners(root, m *Mailbox, hashes [][]byte, addrs map[string]string, connected map[string]bool) (*ownerPlan, error) {
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
			o = o.clone()
			if connected[string(o.Hash)] && o.ProvedAt == 0 {
				o.ProvedAt = now
				changed = true
			}
			p.state = append(p.state, o)
			continue
		}
		changed = true
		if o.ProvedAt > 0 && len(o.Sealed) > 0 {
			p.notices = append(p.notices, Notice{Kind: NoticeOwnerRemoved, ToHash: o.Hash, To: o.Sealed})
		}
	}
	for _, n := range root.Notices {
		// A proof mail to someone no longer an owner, or just proved by a connect
		// reply, is moot. Other notices stay.
		if n.Kind == NoticeOwnerProof && (!present[string(n.ToHash)] || connected[string(n.ToHash)]) {
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
		if connected[string(h)] {
			o.ProvedAt = now
		} else {
			p.notices = append(p.notices, Notice{Kind: NoticeOwnerProof, ToHash: h, To: sealed})
		}
		p.state = append(p.state, o)
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

// NoticeMailer sends one owner notice. internal/notice implements it on the send
// path, and cmd/edge runs it only when sending is on. Until then notices wait in
// routing data, so none is lost to a reboot or to sending being off.
type NoticeMailer interface {
	SendNotice(ctx context.Context, n PendingNotice) error
}

// ErrNoticeUndeliverable, wrapped in a NoticeMailer's error, means the notice
// can never be sent: the owner's domain refused it for good, or it kept failing
// past the mailer's give-up time. DrainNotices removes it. Any other error leaves
// it queued for a later pass.
var ErrNoticeUndeliverable = errors.New("routing: owner notice undeliverable")

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
			if moot(r, n) {
				continue
			}
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
				p.ReplyTo = ProofLocalPart + "+" + s.proofToken(r.MailboxID, r.OwnerState[i]) + domain
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// moot reports whether a queued notice no longer needs sending: a proof mail to
// someone who has proved, or who is no longer an owner. Caller holds s.mu.
func moot(root *Mailbox, n Notice) bool {
	if n.Kind != NoticeOwnerProof {
		return false
	}
	i := slices.IndexFunc(root.OwnerState, func(o Owner) bool { return hmac.Equal(o.Hash, n.ToHash) })
	return i < 0 || root.OwnerState[i].ProvedAt > 0
}

// NoticeSent removes a notice from the queue once it's sent.
func (s *Store) NoticeSent(ctx context.Context, id string) error {
	return s.removeNotices(ctx, func(_ *Mailbox, n Notice) bool { return n.ID == id })
}

// removeNotices drops every queued notice drop picks, in one write.
func (s *Store) removeNotices(ctx context.Context, drop func(*Mailbox, Notice) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	var records []*Mailbox
	for _, r := range s.data.Mailboxes {
		if slices.ContainsFunc(r.Notices, func(n Notice) bool { return drop(r, n) }) {
			records = append(records, r)
		}
	}
	if len(records) == 0 {
		return nil
	}
	return s.update(ctx, records, func(r *Mailbox) {
		r.Notices = slices.DeleteFunc(slices.Clone(r.Notices), func(n Notice) bool { return drop(r, n) })
	})
}

// DrainResult is what one DrainNotices pass did.
type DrainResult struct {
	Sent    int // sent and removed
	Dropped int // undeliverable and removed
	Waiting int // still queued for a later pass
}

// DrainNotices offers every queued notice to m once. A sent notice is removed, an
// undeliverable one (ErrNoticeUndeliverable) is removed, and any other failure
// leaves it queued, so one owner's broken domain never holds up another's
// notice. Moot proof mails are cleared first. The error is a storage failure or
// ctx ending; a notice whose removal failed is sent again on a later pass.
func (s *Store) DrainNotices(ctx context.Context, m NoticeMailer, domain string) (DrainResult, error) {
	var res DrainResult
	if err := s.removeNotices(ctx, moot); err != nil {
		return res, err
	}
	pending, err := s.PendingNotices(domain)
	if err != nil {
		return res, err
	}
	for i, n := range pending {
		if err := ctx.Err(); err != nil {
			res.Waiting += len(pending) - i
			return res, err
		}
		err := m.SendNotice(ctx, n)
		if err != nil && !errors.Is(err, ErrNoticeUndeliverable) {
			res.Waiting++
			continue
		}
		if rerr := s.NoticeSent(ctx, n.ID); rerr != nil {
			res.Waiting += len(pending) - i
			return res, rerr
		}
		if err != nil {
			res.Dropped++
		} else {
			res.Sent++
		}
	}
	return res, nil
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
