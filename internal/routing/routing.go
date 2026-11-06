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
//   - smtp.RecipientChecker — report whether any mailbox claims an address, so
//     RCPT has no catch-all.
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
	"strings"
	"sync"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// objectKey is the single routing object (design §4 S3 layout).
const objectKey = "edge/routing/current"

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
}

// Store is the live routing data, loaded once at construction and persisted back
// on every mutation. All access is serialized: the object is small (M2 scale)
// and the sequence counter must never hand the same number out twice.
type Store struct {
	blobs  store.Blobs
	macKey []byte
	aead   cipher.AEAD

	mu   sync.Mutex
	data *Data
}

// New loads (or initializes) the routing object. A missing object is not an
// error — a fresh edge has no mailboxes yet — but a present object that won't
// decrypt or parse is fatal, because serving mail against corrupt routing data
// would seal to the wrong keys.
func New(ctx context.Context, blobs store.Blobs, routingDataKey, addressMACKey []byte) (*Store, error) {
	if len(addressMACKey) == 0 {
		return nil, errors.New("routing: empty ADDRESS_MAC_KEY")
	}
	aead, err := newAEAD(routingDataKey)
	if err != nil {
		return nil, err
	}
	s := &Store{blobs: blobs, macKey: addressMACKey, aead: aead}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func newAEAD(routingDataKey []byte) (cipher.AEAD, error) {
	if len(routingDataKey) == 0 {
		return nil, errors.New("routing: empty ROUTING_DATA_KEY")
	}
	prk, err := hkdf.Extract(sha256.New, routingDataKey, nil)
	if err != nil {
		return nil, fmt.Errorf("routing: extract: %w", err)
	}
	key, err := hkdf.Expand(sha256.New, prk, hkdfInfo, keyLen)
	if err != nil {
		return nil, fmt.Errorf("routing: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Store) load(ctx context.Context) error {
	raw, err := s.blobs.Get(ctx, objectKey)
	if errors.Is(err, store.ErrNotFound) {
		s.data = &Data{Version: 1, Mailboxes: map[string]*Mailbox{}}
		return nil
	}
	if err != nil {
		return fmt.Errorf("routing: load: %w", err)
	}
	data, err := s.decrypt(raw)
	if err != nil {
		return err
	}
	if data.Mailboxes == nil {
		data.Mailboxes = map[string]*Mailbox{}
	}
	s.data = data
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

// persist seals and writes the current data. Caller holds s.mu.
func (s *Store) persist(ctx context.Context) error {
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
	return s.blobs.Put(ctx, objectKey, out)
}

// MailboxID is the keyed hash of a recipient address — the mailbox id in M2
// (§4). Exported so the write-path handlers and tests compute the same id.
func (s *Store) MailboxID(recipient string) []byte {
	m := hmac.New(sha256.New, s.macKey)
	m.Write([]byte(strings.ToLower(strings.TrimSpace(recipient))))
	return m.Sum(nil)
}

func (s *Store) lookup(mailboxIDHex string) (*Mailbox, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.data.Mailboxes[mailboxIDHex]
	return m, ok
}

// --- store.Directory -------------------------------------------------------

// Resolve maps an envelope recipient to its sealed-to address record, or
// store.ErrNoRecipient when no mailbox claims it (no catch-all, §6).
func (s *Store) Resolve(_ context.Context, recipient string) (store.Address, error) {
	id := s.MailboxID(recipient)
	m, ok := s.lookup(hex.EncodeToString(id))
	if !ok {
		return store.Address{}, store.ErrNoRecipient
	}
	if len(m.DecryptionKey) != keyLen {
		return store.Address{}, fmt.Errorf("routing: mailbox %x has no usable decryption key", id)
	}
	return store.Address{MailboxID: m.MailboxID, PublicKey: m.DecryptionKey}, nil
}

// NextSequence advances and persists the per-mailbox counter (§9). The write to
// S3 is synchronous so a reboot resumes at the right number; a rollback that
// reuses a number is what the broker's sequence-gap check is there to catch.
func (s *Store) NextSequence(ctx context.Context, mailboxID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
func (s *Store) PasskeyKey(keyID string) (ed25519.PublicKey, bool) {
	return s.key(keyID, (*Mailbox).passkeyKey)
}

func (m *Mailbox) signingKey() []byte     { return m.SigningKey }
func (m *Mailbox) mailboxKey() []byte     { return m.MailboxKey }
func (m *Mailbox) ownerChangeKey() []byte { return m.OwnerChangeKey }
func (m *Mailbox) passkeyKey() []byte     { return m.PasskeyKey }

func (s *Store) key(keyID string, pick func(*Mailbox) []byte) (ed25519.PublicKey, bool) {
	m, ok := s.lookup(keyID)
	if !ok {
		return nil, false
	}
	b := pick(m)
	if len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(b), true
}

// --- smtp.RecipientChecker -------------------------------------------------

// Known reports whether a mailbox claims the recipient. RCPT uses it so there is
// no catch-all; a slow miss is the caller's concern, not this layer's.
func (s *Store) Known(_ context.Context, recipient string) (bool, error) {
	_, ok := s.lookup(hex.EncodeToString(s.MailboxID(recipient)))
	return ok, nil
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

// ErrHandleTaken and ErrLicenseTaken are the two creation conflicts (§4: a
// released handle is never reissued; one mailbox per license). The Device API
// maps both to 409.
var (
	ErrHandleTaken  = errors.New("routing: handle already registered")
	ErrLicenseTaken = errors.New("routing: license already has a mailbox")
)

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
	if _, taken := s.data.Mailboxes[hex.EncodeToString(id)]; taken {
		return nil, ErrHandleTaken
	}
	for _, m := range s.data.Mailboxes {
		if len(p.LicenseHash) > 0 && hmac.Equal(m.LicenseHash, p.LicenseHash) {
			return nil, ErrLicenseTaken
		}
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
