// Package routing is the edge's view of design §4's routing data: the single
// encrypted object edge/routing/current that says, for each mailbox, which
// X25519 key its mail is sealed to, which Ed25519 keys sign its Device API
// calls, and how far its per-mailbox sequence counter has advanced.
//
// It is the implementation behind three seams declared elsewhere:
//
//   - store.Directory   — resolve a recipient to its sealed-to public key and
//     allocate the next sequence number (used at RCPT and store time);
//   - deviceapi.KeyProvider — map a mailbox id to the registered public key for
//     a signer class, so the Device API can verify a call's signature;
//   - smtp.RecipientChecker — decide whether to accept mail for an address, so
//     RCPT has no catch-all and bounces a lapsed entitlement.
//
// # Identity model (M2)
//
// The design marks the Device API identity model "proposed, finalized in build
// step 1". M2 takes the documented simplification: one address per mailbox
// (§4 "one worker per address", §10 "one mailbox per license"), so the keyed
// hash of the address IS the mailbox id. A recipient therefore resolves by
// computing HMAC(ADDRESS_MAC_KEY, lowercase address) and looking that id up
// here, and the broker addresses every per-mailbox Device API call with
// Fount-Key-Id = hex(mailbox id). This is revisable: when a mailbox grows more
// than one address, the id and the per-address keyed hash separate and the
// lookup keys split, without changing the stored object's shape.
//
// # Storage
//
// The object is edge-internal — only the edge reads or writes it, and only
// decrypted with ROUTING_DATA_KEY; the broker never sees it. The plaintext is
// JSON (the edge owns both sides, so it stays evolvable); []byte fields marshal
// as base64. At rest it is magic || nonce || AES-256-GCM(json), the AEAD key
// derived from ROUTING_DATA_KEY by HKDF so the configured secret's length and
// encoding don't matter. The plaintext address never appears — only its keyed
// hash, as the map key and MailboxID — matching §4's "addresses stay on the
// device".
package routing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// ObjectKey is the single routing object (design §4 S3 layout).
const ObjectKey = "edge/routing/current"

const (
	magic    = "FMR1" // frames the at-rest object: magic || nonce || sealed(json)
	hkdfInfo = "fount-mail-edge/v1/routing-data"
	keyLen   = 32 // AES-256 and X25519/Ed25519 public keys are all 32 bytes
	nonceLen = 12 // AES-GCM standard nonce
)

// Data is the decrypted content of edge/routing/current.
type Data struct {
	Version   int                 `json:"version"`
	Mailboxes map[string]*Mailbox `json:"mailboxes"` // hex(mailbox id) -> record
}

// Mailbox is one mailbox's routing record (design §4 "On the server"). In M2 the
// keyed hash of the address is the mailbox id, so MailboxID doubles as the
// routing key and the id the message objects are stored under (§9).
type Mailbox struct {
	MailboxID      []byte `json:"mailbox_id"`       // = HMAC(ADDRESS_MAC_KEY, address), 32 bytes
	DecryptionKey  []byte `json:"decryption_key"`   // X25519 public key mail is sealed to
	SigningKey     []byte `json:"signing_key"`      // Ed25519; signs address-class API calls
	MailboxKey     []byte `json:"mailbox_key"`      // Ed25519; signs POST /address and the key chain
	OwnerChangeKey []byte `json:"owner_change_key"` // Ed25519; signs PUT /routing
	PasskeyKey     []byte `json:"passkey_key"`      // passkey public key; approves recovery (§5)
	LicenseHash    []byte `json:"license_hash"`     // keyed hash of the license (§4)
	EntitlementExp int64  `json:"entitlement_exp"`  // unix expiry of the last presented entitlement (§4)
	Sequence       uint64 `json:"sequence"`         // last per-mailbox sequence handed out (§9)

	OwnerHashes    [][]byte `json:"owner_hashes,omitempty"`    // keyed hashes of the owners (§4; encrypted owner addresses are M3)
	RoutingVersion uint64   `json:"routing_version,omitempty"` // device-held owner-list version; monotonic, the §4 rollback defense

	Root []byte `json:"root,omitempty"` // a worker address's handle record; empty on the handle itself

	// Paused stops the worker's jobs and sends, set by POST /pause with the passkey
	// (§12). Mail still arrives and can still be fetched. PausedAt is the last change.
	Paused   bool  `json:"paused,omitempty"`
	PausedAt int64 `json:"paused_at,omitempty"`

	// The license's owner state (M3, §10), kept on the handle's record only, because
	// an owner is the license's and a new worker copies its owners. See owners.go.
	OwnersSeen bool     `json:"owners_seen,omitempty"` // the license has had owners, so the next one isn't its first
	OwnerState []Owner  `json:"owner_state,omitempty"`
	OwnerAdds  []int64  `json:"owner_adds,omitempty"` // when each new owner of the last day was added, for the daily cap
	Notices    []Notice `json:"notices,omitempty"`    // owner mail waiting for the send path
}

// root is the id shared by a handle and its workers.
func (m *Mailbox) root() []byte {
	if len(m.Root) > 0 {
		return m.Root
	}
	return m.MailboxID
}

// Blobs is the object store routing needs: conditional writes, so two edges can't
// overwrite each other's changes. During a deploy two instances run at once.
type Blobs interface {
	store.Blobs
	// GetVersioned returns an object and the etag PutIfMatch needs to replace it.
	GetVersioned(ctx context.Context, key string) (data []byte, etag string, err error)
	// PutIfMatch writes only if the object still has etag, or, with an empty etag,
	// only if it doesn't exist. It returns the new etag or store.ErrConflict.
	PutIfMatch(ctx context.Context, key string, data []byte, etag string) (string, error)
}

// Store is the live routing data, loaded at construction and persisted back on
// every mutation. All access is serialized: the object is small (M2 scale) and the
// sequence counter must never hand the same number out twice. Each write is
// conditional on the object this store last saw. If another writer got there first,
// the write fails with store.ErrConflict, nothing changes, and the next write starts
// from a fresh load. The caller answers with a temporary failure.
type Store struct {
	blobs  Blobs
	macKey []byte
	aead   cipher.AEAD
	backup *backup

	ownerAEAD     cipher.AEAD // seals owner addresses (§4 "encrypted owner addresses")
	proofKey      []byte      // keys owner-proof tokens
	connectKey    []byte      // keys connect-mail Message-IDs (connect.go)
	newOwnerLimit int         // new owners per license per day; <= 0 is no cap
	now           func() time.Time

	mu    sync.Mutex
	data  *Data
	etag  string
	stale bool // the object changed under us; reload before the next write
}

// Option tunes a Store built by New.
type Option func(*Store)

// ErrNoObject means the routing object doesn't exist. It's fatal at boot: treating
// a lost object as empty would answer 550 for every address, free every handle,
// restart the sequences, and overwrite the object on the first write. A new
// deployment creates it once with Initialize.
var ErrNoObject = errors.New("routing: no routing object; initialize it with edgectl init for a new deployment, or restore a backup")

// ErrCorrupt means the routing object exists but won't decrypt or parse. Only a
// restore that replaces it can recover.
var ErrCorrupt = errors.New("routing: routing object unreadable")

// ErrObjectExists means Initialize found a routing object and left it alone.
var ErrObjectExists = errors.New("routing: routing object already exists")

// ErrRolledBack means the object in S3 is older than one this edge has already
// seen. A restore drains the edges first (docs/RESTORE.md), so a running edge can't
// trust it. Writes keep failing until a restart loads the object deliberately.
var ErrRolledBack = errors.New("routing: routing object went backwards")

// Initialize writes the empty routing object for a new deployment. It runs once,
// when the first edge boots and finds no object, and refuses to replace an object. Any read failure
// other than a clean miss also stops it, because that can't show the object is
// absent.
func Initialize(ctx context.Context, blobs Blobs, routingDataKey []byte) error {
	aead, err := newAEAD(routingDataKey)
	if err != nil {
		return err
	}
	s := &Store{blobs: blobs, aead: aead, data: &Data{Version: 1, Mailboxes: map[string]*Mailbox{}}}
	switch _, err := blobs.Get(ctx, ObjectKey); {
	case err == nil:
		return ErrObjectExists
	case !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("routing: check for an existing object: %w", err)
	}
	if err := s.persist(ctx); errors.Is(err, store.ErrConflict) {
		return ErrObjectExists
	} else if err != nil {
		return fmt.Errorf("routing: write: %w", err)
	}
	raw, err := blobs.Get(ctx, ObjectKey)
	if err != nil {
		return fmt.Errorf("routing: read back: %w", err)
	}
	_, err = s.decrypt(raw)
	return err
}

// New loads the routing object. A missing object is ErrNoObject, and a present
// object that won't decrypt or parse is also fatal, because serving mail against
// corrupt routing data would seal to the wrong keys.
func New(ctx context.Context, blobs Blobs, routingDataKey, addressMACKey []byte, opts ...Option) (*Store, error) {
	if len(addressMACKey) == 0 {
		return nil, errors.New("routing: empty ADDRESS_MAC_KEY")
	}
	aead, err := newAEAD(routingDataKey)
	if err != nil {
		return nil, err
	}
	ownerAEAD, err := deriveAEAD(routingDataKey, ownerAddressInfo)
	if err != nil {
		return nil, err
	}
	proofKey, err := deriveKey(addressMACKey, ownerProofInfo)
	if err != nil {
		return nil, err
	}
	connectKey, err := deriveKey(addressMACKey, ownerConnectInfo)
	if err != nil {
		return nil, err
	}
	s := &Store{blobs: blobs, macKey: addressMACKey, aead: aead, ownerAEAD: ownerAEAD, proofKey: proofKey,
		connectKey: connectKey, newOwnerLimit: DefaultNewOwnersPerDay, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func newAEAD(routingDataKey []byte) (cipher.AEAD, error) {
	if len(routingDataKey) == 0 {
		return nil, errors.New("routing: empty ROUTING_DATA_KEY")
	}
	return deriveAEAD(routingDataKey, hkdfInfo)
}

// deriveKey derives a 32-byte key for one purpose from a configured secret.
func deriveKey(secret []byte, info string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("routing: empty secret")
	}
	prk, err := hkdf.Extract(sha256.New, secret, nil)
	if err != nil {
		return nil, fmt.Errorf("routing: extract: %w", err)
	}
	key, err := hkdf.Expand(sha256.New, prk, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("routing: derive key: %w", err)
	}
	return key, nil
}

func deriveAEAD(secret []byte, info string) (cipher.AEAD, error) {
	key, err := deriveKey(secret, info)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) load(ctx context.Context) error {
	raw, etag, err := s.blobs.GetVersioned(ctx, ObjectKey)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoObject
	}
	if err != nil {
		return fmt.Errorf("routing: load: %w", err)
	}
	data, err := s.decrypt(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCorrupt, err)
	}
	if s.data != nil && data.Version < s.data.Version {
		return fmt.Errorf("%w: generation %d after %d", ErrRolledBack, data.Version, s.data.Version)
	}
	if data.Mailboxes == nil {
		data.Mailboxes = map[string]*Mailbox{}
	}
	s.data, s.etag = data, etag
	return nil
}

// refresh reloads the object if the last write lost a race. Every write path calls
// it first, under s.mu. A failed write can't reload for itself, because its caller
// still has to restore the records it changed.
func (s *Store) refresh(ctx context.Context) error {
	if !s.stale {
		return nil
	}
	if err := s.load(ctx); err != nil {
		log.Printf("routing: reload failed: %v", err)
		return err
	}
	s.stale = false
	return nil
}

func (s *Store) decrypt(raw []byte) (*Data, error) {
	if len(raw) < len(magic)+nonceLen {
		return nil, errors.New("routing: object too short")
	}
	if string(raw[:len(magic)]) != magic {
		return nil, errors.New("routing: bad object magic")
	}
	nonce := raw[len(magic) : len(magic)+nonceLen]
	ct := raw[len(magic)+nonceLen:]
	pt, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("routing: decrypt: %w", err)
	}
	var data Data
	if err := json.Unmarshal(pt, &data); err != nil {
		return nil, fmt.Errorf("routing: parse: %w", err)
	}
	return &data, nil
}

// persist seals and writes the current data, one generation on. Caller holds s.mu
// and restores its records on an error. A write that failed without an answer may
// still have landed. The next write then sees a conflict and reloads.
func (s *Store) persist(ctx context.Context) (err error) {
	s.data.Version++
	defer func() {
		if err != nil {
			s.data.Version--
		}
	}()
	pt, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := make([]byte, 0, len(magic)+nonceLen+len(pt)+s.aead.Overhead())
	out = append(out, magic...)
	out = append(out, nonce...)
	out = s.aead.Seal(out, nonce, pt, nil)
	etag, err := s.blobs.PutIfMatch(ctx, ObjectKey, out, s.etag)
	if errors.Is(err, store.ErrConflict) {
		s.stale = true
	}
	if err != nil {
		return err
	}
	s.etag = etag
	s.backup.write(ctx, out)
	return nil
}

// MailboxID is the keyed hash of a recipient address — the mailbox id in M2
// (§4). Exported so the write-path handlers and tests compute the same id.
func (s *Store) MailboxID(recipient string) []byte { return s.keyedHash(recipient) }

// keyedHash is the address MAC (§4): HMAC(ADDRESS_MAC_KEY, lowercase value). It
// backs both the mailbox id and the owner hashes, so the same address maps to
// the same value wherever it is referenced.
func (s *Store) keyedHash(v string) []byte {
	m := hmac.New(sha256.New, s.macKey)
	m.Write([]byte(strings.ToLower(strings.TrimSpace(v))))
	return m.Sum(nil)
}

// lookupRecipient finds the mailbox an inbound recipient is for. A
// "<local>+<tag>@domain" recipient is mail for "<local>@domain": the tag is a
// thread's reply token (app design §13), which the broker checks and the edge
// doesn't read. An empty tag claims no mailbox. Proof replies ("fount+…") are
// matched before this, by proofTag.
func (s *Store) lookupRecipient(recipient string) (Mailbox, bool) {
	base, tagged, ok := untagged(recipient)
	if !ok {
		return Mailbox{}, false
	}
	if !tagged {
		return s.lookup(hex.EncodeToString(s.MailboxID(recipient)))
	}
	return s.lookup(hex.EncodeToString(s.MailboxID(base)))
}

// untagged removes a "+tag" from the local part of an address: the tag is
// everything from the first "+", as in send's withoutTag, so an address the edge
// delivers to and one a worker may send From strip the same way. It reports
// false for an empty tag.
func untagged(addr string) (base string, tagged, ok bool) {
	local, domain, hasAt := strings.Cut(addr, "@")
	i := strings.IndexByte(local, '+')
	if !hasAt || i < 0 {
		return addr, false, true
	}
	if i == len(local)-1 {
		return "", true, false
	}
	return local[:i] + "@" + domain, true, true
}

// lookup returns a copy, because the live record changes under s.mu.
func (s *Store) lookup(mailboxIDHex string) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.data.Mailboxes[mailboxIDHex]
	if !ok {
		return Mailbox{}, false
	}
	return m.clone(), true
}

// Snapshot returns a copy of a mailbox's record for read-only inspection (the
// entitlement expiry the RCPT check will read, the owner hashes an owner-reply
// check will match against). Slice fields are copied so a caller can't mutate
// live routing data. Reports false if no mailbox has that id.
func (s *Store) Snapshot(mailboxID []byte) (Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return Mailbox{}, false
	}
	return m.clone(), true
}

// LicenseOf returns a copy of a mailbox's license hash, the key for per-license
// limits. Reports false if no mailbox has that id.
func (s *Store) LicenseOf(mailboxID []byte) ([]byte, bool) {
	m, ok := s.Snapshot(mailboxID)
	if !ok {
		return nil, false
	}
	return m.LicenseHash, true
}

// PasskeyOf returns a copy of a mailbox's registered passkey credential key
// (design §8 POST /recover verifies the WebAuthn assertion against it). Reports
// false if no mailbox has that id.
func (s *Store) PasskeyOf(mailboxID []byte) ([]byte, bool) {
	m, ok := s.Snapshot(mailboxID)
	if !ok {
		return nil, false
	}
	return m.PasskeyKey, true
}

func (m *Mailbox) clone() Mailbox {
	c := *m
	for dst, src := range map[*[]byte][]byte{
		&c.MailboxID: m.MailboxID, &c.DecryptionKey: m.DecryptionKey,
		&c.SigningKey: m.SigningKey, &c.MailboxKey: m.MailboxKey,
		&c.OwnerChangeKey: m.OwnerChangeKey, &c.PasskeyKey: m.PasskeyKey,
		&c.LicenseHash: m.LicenseHash, &c.Root: m.Root,
	} {
		*dst = append([]byte(nil), src...)
	}
	if m.OwnerHashes != nil {
		c.OwnerHashes = make([][]byte, len(m.OwnerHashes))
		for i, h := range m.OwnerHashes {
			c.OwnerHashes[i] = append([]byte(nil), h...)
		}
	}
	c.OwnerState = slices.Clone(m.OwnerState)
	for i := range c.OwnerState {
		c.OwnerState[i] = c.OwnerState[i].clone()
	}
	c.OwnerAdds = slices.Clone(m.OwnerAdds)
	c.Notices = slices.Clone(m.Notices)
	for i := range c.Notices {
		c.Notices[i] = c.Notices[i].clone()
	}
	return c
}

// --- store.Directory -------------------------------------------------------

// Resolve maps an envelope recipient to its sealed-to address record, or
// store.ErrNoRecipient when no mailbox claims it (no catch-all, §6).
// A tagged recipient resolves to the untagged address's mailbox; the envelope
// sealed with the message keeps the tag.
func (s *Store) Resolve(_ context.Context, recipient string) (store.Address, error) {
	m, ok := s.lookupRecipient(recipient)
	if !ok {
		return store.Address{}, store.ErrNoRecipient
	}
	if len(m.DecryptionKey) != keyLen {
		return store.Address{}, fmt.Errorf("routing: mailbox %x has no usable decryption key", m.MailboxID)
	}
	return store.Address{MailboxID: m.MailboxID, PublicKey: m.DecryptionKey}, nil
}

// NextSequence advances and persists the per-mailbox counter (§9). The write to
// S3 is synchronous so a reboot resumes at the right number; a rollback that
// reuses a number is what the broker's sequence-gap check is there to catch.
func (s *Store) NextSequence(ctx context.Context, mailboxID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return 0, err
	}
	key := hex.EncodeToString(mailboxID)
	m, ok := s.data.Mailboxes[key]
	if !ok {
		return 0, fmt.Errorf("routing: no mailbox %x for sequence", mailboxID)
	}
	m.Sequence++
	if err := s.persist(ctx); err != nil {
		m.Sequence-- // keep memory and S3 in step if the write failed
		return 0, err
	}
	return m.Sequence, nil
}

// --- deviceapi.KeyProvider -------------------------------------------------

func (s *Store) AddressKey(keyID string) (ed25519.PublicKey, bool) {
	return s.key(keyID, (*Mailbox).signingKey)
}
func (s *Store) MailboxKey(keyID string) (ed25519.PublicKey, bool) {
	return s.key(keyID, (*Mailbox).mailboxKey)
}
func (s *Store) OwnerChangeKey(keyID string) (ed25519.PublicKey, bool) {
	return s.key(keyID, (*Mailbox).ownerChangeKey)
}

func (m *Mailbox) signingKey() []byte     { return m.SigningKey }
func (m *Mailbox) mailboxKey() []byte     { return m.MailboxKey }
func (m *Mailbox) ownerChangeKey() []byte { return m.OwnerChangeKey }

func (s *Store) key(keyID string, pick func(*Mailbox) []byte) (ed25519.PublicKey, bool) {
	m, ok := s.lookup(keyID)
	if !ok {
		return nil, false
	}
	b := pick(&m)
	if len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(b), true
}

// --- smtp.RecipientChecker -------------------------------------------------

// Status reports whether the edge should accept mail for a recipient right now
// (smtp.RecipientChecker). It is RecipientUnknown when no mailbox claims the
// address (no catch-all, §6), RecipientExpired when a mailbox claims it but its
// entitlement has lapsed past the past_due grace (§4 "after past_due grace, the
// mailbox answers 550"), and RecipientAccepting otherwise. A zero EntitlementExp
// means no entitlement has been recorded — dev/smoke, or a record that predates
// enforcement — and is treated as accepting, never as expired; the app keeps
// EntitlementExp ahead of now while a license is current or in grace, so a
// lapsed value is the signal that even the grace is over. A "fount+<token>"
// reply to an owner-proof mail is accepting while its token matches an owner.
// Any other "<local>+<tag>" recipient answers as "<local>" does.
func (s *Store) Status(_ context.Context, recipient string) (smtp.RecipientStatus, error) {
	if tag, ok := proofTag(recipient); ok {
		return s.proofStatus(tag), nil
	}
	m, ok := s.lookupRecipient(recipient)
	if !ok {
		return smtp.RecipientUnknown, nil
	}
	if m.EntitlementExp > 0 && time.Now().Unix() >= m.EntitlementExp {
		return smtp.RecipientExpired, nil
	}
	return smtp.RecipientAccepting, nil
}

// --- write path (used by Device API write handlers and tests) --------------

// Upsert adds or replaces a mailbox record, keyed by its mailbox id, and
// persists. It is the seam the write-path handlers (POST /address, PUT /routing)
// and tests use to populate routing data; it does not itself enforce the signer
// rules those handlers apply. Mailbox creation goes through Create instead, so
// its uniqueness checks can't be bypassed.
func (s *Store) Upsert(ctx context.Context, m *Mailbox) error {
	if len(m.MailboxID) != keyLen {
		return fmt.Errorf("routing: mailbox id must be %d bytes", keyLen)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	return s.put(ctx, m)
}

// put stores a record and persists, rolling back memory on a write failure.
// Caller holds s.mu.
func (s *Store) put(ctx context.Context, m *Mailbox) error {
	key := hex.EncodeToString(m.MailboxID)
	prev := s.data.Mailboxes[key]
	s.data.Mailboxes[key] = m
	if err := s.persist(ctx); err != nil {
		if prev != nil {
			s.data.Mailboxes[key] = prev
		} else {
			delete(s.data.Mailboxes, key)
		}
		return err
	}
	return nil
}

// The write-path conflicts the Device API distinguishes. ErrHandleTaken and
// ErrLicenseTaken are the two creation conflicts (§4: a released handle is never
// reissued; one mailbox per license) and map to 409. ErrNoMailbox means the
// addressed mailbox does not exist (404). ErrStaleVersion means an owner-list
// write did not advance the version (409; a rolled-back object is corrected by
// re-asserting the current version, never an older one). ErrLicenseMismatch
// means a renewal's entitlement is for a different license than the one bound at
// creation (409), so a renewal can't move a mailbox between licenses.
// ErrNotHandle means a worker address names a handle other than the caller's, and
// ErrWorkerLimit means the handle has reached MaxWorkers (both 403). ErrKeyNotLogged
// means the write-once log refused a key, so nothing changed (500).
var (
	ErrHandleTaken     = errors.New("routing: handle already registered")
	ErrLicenseTaken    = errors.New("routing: license already has a mailbox")
	ErrNoMailbox       = errors.New("routing: no such mailbox")
	ErrStaleVersion    = errors.New("routing: routing version did not advance")
	ErrLicenseMismatch = errors.New("routing: entitlement license does not match mailbox")
	ErrNotHandle       = errors.New("routing: address is not under this handle")
	ErrWorkerLimit     = errors.New("routing: worker limit reached")
	ErrKeyNotLogged    = errors.New("routing: could not record key")
)

// MaxWorkers is the soft limit on workers under one handle (§4). A firm may run
// one worker per client, so it's far above any real firm's needs and exists only
// to stop abuse. Each worker adds a record to the single routing object.
const MaxWorkers = 500

// logConcurrency bounds the key log writes for one rotation, which happen while
// the store's lock is held.
const logConcurrency = 16

// LogKey records a mailbox key's hash in the write-once log (§9). The write paths
// call it under the store's lock, after their checks and before the record
// changes, so a refused request leaves no entry and no key goes live unlogged. A
// record write that fails afterwards leaves an entry for a key that never went
// live, which the log can't undo and an auditor can tolerate. Nil skips the log.
type LogKey func(ctx context.Context, mailboxID, keyHash []byte) error

func logKey(ctx context.Context, log LogKey, key []byte, ids ...[]byte) error {
	if log == nil {
		return nil
	}
	h := sha256.Sum256(key)
	errs := make([]error, len(ids))
	slots := make(chan struct{}, logConcurrency)
	var wg sync.WaitGroup
	for i, id := range ids {
		slots <- struct{}{}
		wg.Go(func() {
			defer func() { <-slots }()
			errs[i] = log(ctx, id, h[:])
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %v", ErrKeyNotLogged, err)
	}
	return nil
}

// family returns the records of m's handle and its workers. Caller holds s.mu.
func (s *Store) family(m *Mailbox) []*Mailbox {
	root := m.root()
	var out []*Mailbox
	for _, c := range s.data.Mailboxes {
		if hmac.Equal(c.root(), root) {
			out = append(out, c)
		}
	}
	return out
}

// update applies change to each record and persists, restoring them all on a
// write failure. change replaces fields and never mutates a slice in place. Caller
// holds s.mu.
func (s *Store) update(ctx context.Context, records []*Mailbox, change func(*Mailbox)) error {
	prev := make([]Mailbox, len(records))
	for i, m := range records {
		prev[i] = *m
		change(m)
	}
	if err := s.persist(ctx); err != nil {
		for i, m := range records {
			*m = prev[i]
		}
		return err
	}
	return nil
}

// NewMailbox is a mailbox to create: its handle address, the keyed license hash
// from the verified entitlement, and the device-asserted public keys (whose key
// chain the caller has already checked). Sequence starts at zero.
type NewMailbox struct {
	Address        string
	LicenseHash    []byte
	DecryptionKey  []byte
	SigningKey     []byte
	MailboxKey     []byte
	OwnerChangeKey []byte
	PasskeyKey     []byte
	EntitlementExp int64
	Log            LogKey
}

// Available reports whether a handle address is free to register.
func (s *Store) Available(_ context.Context, address string) (bool, error) {
	_, taken := s.lookup(hex.EncodeToString(s.MailboxID(address)))
	return !taken, nil
}

// Create registers a new mailbox and returns its id, refusing a handle that
// already exists or a license that already has a mailbox (§4). It is the only
// path that adds a mailbox, so those invariants hold regardless of what a
// handler does.
func (s *Store) Create(ctx context.Context, p NewMailbox) ([]byte, error) {
	id := s.MailboxID(p.Address)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	if _, taken := s.data.Mailboxes[hex.EncodeToString(id)]; taken {
		return nil, ErrHandleTaken
	}
	for _, m := range s.data.Mailboxes {
		if len(p.LicenseHash) > 0 && hmac.Equal(m.LicenseHash, p.LicenseHash) {
			return nil, ErrLicenseTaken
		}
	}
	if err := logKey(ctx, p.Log, p.MailboxKey, id); err != nil {
		return nil, err
	}
	if err := s.put(ctx, &Mailbox{
		MailboxID:      id,
		DecryptionKey:  p.DecryptionKey,
		SigningKey:     p.SigningKey,
		MailboxKey:     p.MailboxKey,
		OwnerChangeKey: p.OwnerChangeKey,
		PasskeyKey:     p.PasskeyKey,
		LicenseHash:    p.LicenseHash,
		EntitlementExp: p.EntitlementExp,
		Sequence:       0,
	}); err != nil {
		return nil, err
	}
	return id, nil
}

// NewAddress is an additional worker address to register under an existing
// mailbox (design §8 POST /address). In the M2 identity model each address is
// its own routing record, but a worker added this way belongs to the same
// licensee: it reuses the parent's mailbox key (§5 "one mailbox key per mailbox,
// signs each address's public key"), license hash, and entitlement expiry, and
// brings its own per-address decryption, signing, owner-change, and passkey
// keys. Authorization is the parent mailbox key's signature over the request and
// the key chain, checked by the handler before calling this.
type NewAddress struct {
	ParentMailboxID []byte
	Handle          string // the handle's full address, which Address sits under
	Address         string
	DecryptionKey   []byte
	SigningKey      []byte
	OwnerChangeKey  []byte
	PasskeyKey      []byte
	Log             LogKey
}

// AddAddress registers a worker address under an existing mailbox, inheriting
// its license (so it does not count as a second mailbox for that license) and
// returning the new address's mailbox id. It refuses an address under any handle
// but the caller's, before looking at whether that address is taken, and an address
// that is already registered (§4: a released handle is never reissued).
func (s *Store) AddAddress(ctx context.Context, p NewAddress) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	parent, ok := s.data.Mailboxes[hex.EncodeToString(p.ParentMailboxID)]
	if !ok {
		return nil, ErrNoMailbox
	}
	root := parent.root()
	if !hmac.Equal(s.keyedHash(p.Handle), root) {
		return nil, ErrNotHandle
	}
	id := s.keyedHash(p.Address)
	if _, taken := s.data.Mailboxes[hex.EncodeToString(id)]; taken {
		return nil, ErrHandleTaken
	}
	if len(s.family(parent)) > MaxWorkers { // the handle's own record is in there too
		return nil, ErrWorkerLimit
	}
	if err := logKey(ctx, p.Log, parent.MailboxKey, id); err != nil {
		return nil, err
	}
	if err := s.put(ctx, &Mailbox{
		MailboxID:      id,
		Root:           root,
		DecryptionKey:  p.DecryptionKey,
		SigningKey:     p.SigningKey,
		MailboxKey:     parent.MailboxKey,
		OwnerChangeKey: p.OwnerChangeKey,
		PasskeyKey:     p.PasskeyKey,
		LicenseHash:    parent.LicenseHash,
		EntitlementExp: parent.EntitlementExp,
		Sequence:       0,
	}); err != nil {
		return nil, err
	}
	return id, nil
}

// RotatedKeys is the new key set a recovery (or move) installs on an existing
// mailbox (design §5). The mailbox id, license, entitlement, sequence, and owner
// list are unchanged; only the device-held keys rotate, so the old signing key
// stops being accepted and new mail seals to the new decryption key.
type RotatedKeys struct {
	DecryptionKey  []byte
	SigningKey     []byte
	MailboxKey     []byte
	OwnerChangeKey []byte
	PasskeyKey     []byte
	Log            LogKey
}

// RotateKeys replaces an address's device-held keys and returns the SHA-256 of the
// new mailbox key. There is one mailbox key per mailbox (§5), so it changes on the
// handle and every worker, each with its own log entry. Otherwise the old key would
// still authorize POST /address through a sibling's id. The other keys are per
// address, and a worker on a healthy device keeps them. The authorization — a
// passkey assertion over an edge challenge and the new mailbox key's signature over
// the new key chain — is the handler's job, checked before calling this.
// ErrNoMailbox if the mailbox is absent.
func (s *Store) RotateKeys(ctx context.Context, mailboxID []byte, k RotatedKeys) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return nil, ErrNoMailbox
	}
	family := s.family(m)
	ids := make([][]byte, len(family))
	for i, f := range family {
		ids[i] = f.MailboxID
	}
	if err := logKey(ctx, k.Log, k.MailboxKey, ids...); err != nil {
		return nil, err
	}
	err := s.update(ctx, family, func(f *Mailbox) {
		f.MailboxKey = k.MailboxKey
		if f == m {
			f.DecryptionKey = k.DecryptionKey
			f.SigningKey = k.SigningKey
			f.OwnerChangeKey = k.OwnerChangeKey
			f.PasskeyKey = k.PasskeyKey
		}
	})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(k.MailboxKey)
	return h[:], nil
}

// RenewEntitlement updates the stored entitlement expiry on the handle and all its
// workers (design §8 POST /entitlement, §4 "renews it like a license check"), since
// they share a license. The renewal's license hash must match the one bound at
// creation, so a renewal can't move a mailbox to a different license; a mismatch is
// ErrLicenseMismatch.
func (s *Store) RenewEntitlement(ctx context.Context, mailboxID, licenseHash []byte, exp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(ctx); err != nil {
		return err
	}
	m, ok := s.data.Mailboxes[hex.EncodeToString(mailboxID)]
	if !ok {
		return ErrNoMailbox
	}
	if len(m.LicenseHash) > 0 && !hmac.Equal(m.LicenseHash, licenseHash) {
		return ErrLicenseMismatch
	}
	return s.update(ctx, s.family(m), func(f *Mailbox) { f.EntitlementExp = exp })
}
