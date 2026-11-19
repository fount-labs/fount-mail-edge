package routing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"time"
)

// Coordinator is the newest Cloud coordinator generation the edge has seen
// (fount launch-plan decision 18): the generation number and that generation's
// request-signing key, both from a certificate the Cloud vault signed. It is
// kept in the routing object, so it survives a reboot and a newer edge can't
// fall back to an older generation. There is one at a time, for every mailbox
// enrolled under a coordinator.
type Coordinator struct {
	Generation uint64 `json:"generation"`
	Key        []byte `json:"key"` // Ed25519 public key
}

// The generation errors the Device API tells apart.
var (
	// ErrStaleGeneration means a newer coordinator generation has spoken.
	ErrStaleGeneration = errors.New("routing: stale coordinator generation")
	// ErrGenerationConflict means a certificate names a different key for the
	// current generation. One generation has one key.
	ErrGenerationConflict = errors.New("routing: generation already has another key")
	// ErrNotCoordinated means the mailbox isn't enrolled under a coordinator.
	ErrNotCoordinated = errors.New("routing: mailbox is not under a coordinator")
)

// CurrentCoordinator returns the newest generation and its key, or ok=false if
// no coordinator has enrolled.
func (s *Store) CurrentCoordinator() (gen uint64, key ed25519.PublicKey, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.data.Coordinator
	if c == nil {
		return 0, nil, false
	}
	return c.Generation, append(ed25519.PublicKey(nil), c.Key...), true
}

// Coordinated reports whether a mailbox is enrolled under a coordinator, so its
// per-mailbox operations must name the current generation.
func (s *Store) Coordinated(mailboxID []byte) bool {
	m, ok := s.Snapshot(mailboxID)
	return ok && m.Coordinated
}

// AdvanceCoordinator records a verified generation certificate. A lower
// generation is ErrStaleGeneration, the same generation with another key is
// ErrGenerationConflict, and the current one again changes nothing.
func (s *Store) AdvanceCoordinator(ctx context.Context, gen uint64, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	changed, err := s.checkGeneration(gen, key)
	if err != nil || !changed {
		return err
	}
	prev := s.data.Coordinator
	s.data.Coordinator = &Coordinator{Generation: gen, Key: bytes.Clone(key)}
	if err := s.persist(ctx); err != nil {
		s.data.Coordinator = prev
		return err
	}
	return nil
}

// EnrollCoordinator puts a mailbox under the coordinator generation gen, after
// AdvanceCoordinator's checks, in one write. ErrNoMailbox if it's absent.
func (s *Store) EnrollCoordinator(ctx context.Context, mailboxID []byte, gen uint64, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	changed, err := s.checkGeneration(gen, key)
	if err != nil {
		return err
	}
	if !changed && m.Coordinated {
		return nil
	}
	prevCoord, prevMb := s.data.Coordinator, *m
	s.data.Coordinator = &Coordinator{Generation: gen, Key: bytes.Clone(key)}
	m.Coordinated = true
	s.touch(m)
	if err := s.persist(ctx); err != nil {
		s.data.Coordinator, *m = prevCoord, prevMb
		return err
	}
	return nil
}

// checkGeneration reports whether gen/key moves the coordinator on. Caller holds
// s.mu.
func (s *Store) checkGeneration(gen uint64, key []byte) (bool, error) {
	c := s.data.Coordinator
	switch {
	case c == nil || gen > c.Generation:
		return true, nil
	case gen < c.Generation:
		return false, ErrStaleGeneration
	case !bytes.Equal(c.Key, key):
		return false, ErrGenerationConflict
	}
	return false, nil
}

// DefaultLapseHold is how long a mailbox paused for lapse keeps receiving mail
// past its entitlement's expiry (fount launch-plan decision 11: held for 30
// days, then it bounces).
const DefaultLapseHold = 30 * 24 * time.Hour

// WithLapseHold sets how long a lapsed mailbox holds mail past its entitlement's
// expiry. A value <= 0 is DefaultLapseHold.
func WithLapseHold(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.lapseHold = d
		}
	}
}

// SetLapsed pauses or resumes a mailbox for a lapsed payment. The coordinator
// sets it when the past_due grace ends. While it's set, SMTP holds the
// mailbox's mail instead of bouncing it, until the entitlement's expiry plus the
// hold, and the mailbox can't send. Its reads still work, so the account can
// export. ErrNoMailbox if the mailbox is absent.
func (s *Store) SetLapsed(ctx context.Context, mailboxID []byte, lapsed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	if m.Lapsed == lapsed {
		return nil
	}
	now := s.now().Unix()
	return s.update(ctx, []*Mailbox{m}, func(m *Mailbox) { m.Lapsed, m.LapsedAt = lapsed, now })
}

// Lapse reports whether a mailbox is paused for lapse, and until when (unix) it
// holds mail: 0 if its entitlement has no expiry.
func (s *Store) Lapse(mailboxID []byte) (lapsed bool, holdUntil int64) {
	m, ok := s.Snapshot(mailboxID)
	if !ok || !m.Lapsed {
		return false, 0
	}
	return true, s.holdUntil(&m)
}

// holdUntil is when a lapsed mailbox stops holding mail. It counts from the
// entitlement's expiry, not from when the lapse was set, so setting it again
// can't stretch the hold.
func (s *Store) holdUntil(m *Mailbox) int64 {
	if m.EntitlementExp == 0 {
		return 0
	}
	return m.EntitlementExp + int64(s.lapseHold/time.Second)
}

// ErrSameSigningKey means a rotation named the key the mailbox already has.
var ErrSameSigningKey = errors.New("routing: that is already the mailbox's signing key")

// RotateSigningKey replaces a coordinated mailbox's address signing key
// (decision 25: removing a team admin rotates it). The old key stops verifying
// at once, on every route that takes the address key, /send among them. Only the
// address key changes; the mailbox key, owner-change key and passkey stay.
// ErrNoMailbox if the mailbox is absent, ErrNotCoordinated if it isn't enrolled.
func (s *Store) RotateSigningKey(ctx context.Context, mailboxID []byte, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("routing: signing key must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	switch {
	case !ok:
		return ErrNoMailbox
	case !m.Coordinated:
		return ErrNotCoordinated
	case bytes.Equal(m.SigningKey, key):
		return ErrSameSigningKey
	}
	return s.update(ctx, []*Mailbox{m}, func(m *Mailbox) { m.SigningKey = bytes.Clone(key) })
}
