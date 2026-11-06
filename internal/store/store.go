// Package store holds inbound messages the way design §6 and §9 require: each
// raw message is HPKE-encrypted to the recipient address's public key, framed
// as the §9 object, signed with the per-boot mail-sign key, and written whole
// to S3 with the envelope recipient inside the encryption. No edge key can
// decrypt what it stores, and SMTP answers 250 only after the write confirms.
//
// The pieces the edge can't own from inside this package — resolving a
// recipient to its (mailbox-key-signed) address record and the durable blob
// store — are the Directory and Blobs seams, implemented by the routing layer
// over S3 and stubbed in memory for tests.
package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoRecipient means no mailbox has this address. SMTP turns it into a 550
// (unknown recipient, no catch-all — §6), so it must be distinguishable from a
// transient failure, which becomes a 452.
var ErrNoRecipient = errors.New("store: no such recipient")

// ErrNotFound means a requested object does not exist (a Blobs miss, or a
// GET/DELETE for an unknown message). The Device API maps it to 404.
var ErrNotFound = errors.New("store: not found")

type Store interface {
	// Put stores one raw message for one envelope recipient and returns its
	// edge id only once the write is durable. A non-nil error means SMTP must
	// NOT return 250. sender is the untrusted envelope sender, kept (inside the
	// ciphertext) for the broker and for per-sender quota accounting.
	Put(ctx context.Context, recipient, sender string, raw []byte) (id string, err error)
}

// Address is a resolved recipient. PublicKey has already been verified by the
// Directory as signed by the mailbox key; the store encrypts only to it.
type Address struct {
	MailboxID []byte // 32-byte keyed MAC of the address
	PublicKey []byte // 32-byte X25519 public key
}

// Directory resolves recipients and allocates per-mailbox sequence numbers. It
// is implemented over routing data in S3 (design §4); tests use an in-memory
// version.
type Directory interface {
	// Resolve maps an envelope recipient to its address record, or
	// ErrNoRecipient if no mailbox claims it. Used both at RCPT time and at
	// store time, so there is no catch-all.
	Resolve(ctx context.Context, recipient string) (Address, error)
	// NextSequence returns and persists the next per-mailbox counter (§9).
	NextSequence(ctx context.Context, mailboxID []byte) (uint64, error)
}

// Blobs is the durable object store (S3). Put returns only once the write is
// acknowledged, so Store.Put can honor "250 only after S3 confirms".
type Blobs interface {
	Put(ctx context.Context, key string, data []byte) error
	// Get returns an object's bytes, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns the full keys under prefix (one S3 prefix listing).
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete removes an object; deleting an absent object is not an error.
	Delete(ctx context.Context, key string) error
}

// Stored identifies one waiting message in GET /mail.
type Stored struct {
	ID   string `json:"id"`   // hex edge id
	Size int    `json:"size"` // bytes of the signed object
}

// MailReader is the Device API's read side (design §8 GET/DELETE /mail): the
// broker, having signed with an address key, lists, fetches, and confirms
// receipt of that mailbox's messages. realStore implements it; the discard
// store does not, so those routes stay 501 in dev.
type MailReader interface {
	List(ctx context.Context, mailboxID []byte) ([]Stored, error)
	Get(ctx context.Context, mailboxID []byte, edgeIDHex string) ([]byte, error)
	Delete(ctx context.Context, mailboxID []byte, edgeIDHex string) error
}

// Boot is a boot's published attestation record (design §4 edge/boots/<boot id>,
// §9). It carries the ed25519 public key this boot signed its messages with, so
// the broker can check a stored message's signature against the right boot even
// after that enclave is gone. In M2 it is the signing key and boot metadata; the
// full Tinfoil attestation document that vouches for the key is a later seam.
type Boot struct {
	BootID     string `json:"boot_id"`     // hex, 16 bytes
	SigningKey []byte `json:"signing_key"` // ed25519 public key (the per-boot mail-sign key)
	StartedAt  int64  `json:"started_at"`  // unix seconds
}

// BootStore writes this boot's attestation at startup and reads any boot's by id
// (design §8 GET /boots/:id). The object outlives the enclave, so a message
// signed by a retired boot stays verifiable. realStore implements it over S3;
// the discard store does not, so GET /boots stays 501 in dev.
type BootStore interface {
	WriteBoot(ctx context.Context) error
	ReadBoot(ctx context.Context, bootIDHex string) (Boot, error)
}

// KeyLog is the write-once mailbox-key log the broker audits (design §9): every
// mailbox key a mailbox has ever been given is appended here and never changed,
// so a key the host swapped in while a device was off is visible on the next
// sync. Appends are single objects that are never overwritten. The production
// target is a separate S3 bucket with Object Lock (compliance mode, write-once)
// on its own egress host; the in-bucket prefix realStore writes today is the M2
// stand-in, and moving it to that bucket is a documented infra seam. The discard
// store does not implement it, so POST /recover stays 501 in dev.
type KeyLog interface {
	AppendMailboxKeyHash(ctx context.Context, mailboxIDHex string, keyHash []byte, at int64) error
}

type realStore struct {
	dir    Directory
	blobs  Blobs
	sign   ed25519.PrivateKey
	bootID []byte
	now    func() time.Time
}

// New builds the real store. bootID is this boot's 16-byte identifier (it ends
// up in every object so the broker can check the signature against the right
// boot's attestation, §9).
func New(dir Directory, blobs Blobs, sign ed25519.PrivateKey, bootID []byte) Store {
	return &realStore{dir: dir, blobs: blobs, sign: sign, bootID: bootID, now: time.Now}
}

func (s *realStore) Put(ctx context.Context, recipient, sender string, raw []byte) (string, error) {
	addr, err := s.dir.Resolve(ctx, recipient)
	if err != nil {
		return "", err // ErrNoRecipient or transient; SMTP maps each distinctly
	}
	seq, err := s.dir.NextSequence(ctx, addr.MailboxID)
	if err != nil {
		return "", fmt.Errorf("sequence: %w", err)
	}
	edgeID := make([]byte, lenEdgeID)
	if _, err := rand.Read(edgeID); err != nil {
		return "", err
	}

	msg := &Message{
		EdgeID:     edgeID,
		MailboxID:  addr.MailboxID,
		PubKeyHash: pubKeyHash(addr.PublicKey),
		ReceivedAt: s.now().UTC(),
		Sequence:   seq,
		BootID:     s.bootID,
	}
	if err := msg.seal(addr.PublicKey, sender, recipient, raw); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}

	// edge/mail/<mailbox id>/<edge id> (design §4 S3 layout).
	key := mailObjectKey(addr.MailboxID, hex.EncodeToString(edgeID))
	if err := s.blobs.Put(ctx, key, msg.MarshalSigned(s.sign)); err != nil {
		return "", fmt.Errorf("blob put: %w", err)
	}
	return hex.EncodeToString(edgeID), nil
}

func mailboxPrefix(mailboxID []byte) string {
	return "edge/mail/" + hex.EncodeToString(mailboxID) + "/"
}

func mailObjectKey(mailboxID []byte, edgeIDHex string) string {
	return mailboxPrefix(mailboxID) + edgeIDHex
}

// validEdgeID rejects anything that isn't a 32-hex-char edge id, so a crafted
// id can't widen the key beyond this mailbox's prefix.
func validEdgeID(edgeIDHex string) bool {
	if len(edgeIDHex) != lenEdgeID*2 {
		return false
	}
	_, err := hex.DecodeString(edgeIDHex)
	return err == nil
}

func (s *realStore) List(ctx context.Context, mailboxID []byte) ([]Stored, error) {
	prefix := mailboxPrefix(mailboxID)
	keys, err := s.blobs.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Stored, 0, len(keys))
	for _, k := range keys {
		id := strings.TrimPrefix(k, prefix)
		if !validEdgeID(id) {
			continue // ignore anything that isn't a message object
		}
		out = append(out, Stored{ID: id})
	}
	return out, nil
}

func (s *realStore) Get(ctx context.Context, mailboxID []byte, edgeIDHex string) ([]byte, error) {
	if !validEdgeID(edgeIDHex) {
		return nil, ErrNotFound
	}
	return s.blobs.Get(ctx, mailObjectKey(mailboxID, edgeIDHex))
}

func (s *realStore) Delete(ctx context.Context, mailboxID []byte, edgeIDHex string) error {
	if !validEdgeID(edgeIDHex) {
		return ErrNotFound
	}
	return s.blobs.Delete(ctx, mailObjectKey(mailboxID, edgeIDHex))
}

func bootObjectKey(bootIDHex string) string { return "edge/boots/" + bootIDHex }

// validBootID rejects anything that isn't a 32-hex-char boot id, so a crafted id
// can't widen the key beyond the boots prefix.
func validBootID(bootIDHex string) bool {
	if len(bootIDHex) != lenBootID*2 {
		return false
	}
	_, err := hex.DecodeString(bootIDHex)
	return err == nil
}

// WriteBoot publishes this boot's attestation record (§9). It is idempotent: the
// same boot writes the same object, and a boot id never collides across boots.
func (s *realStore) WriteBoot(ctx context.Context) error {
	b := Boot{
		BootID:     hex.EncodeToString(s.bootID),
		SigningKey: s.sign.Public().(ed25519.PublicKey),
		StartedAt:  s.now().UTC().Unix(),
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.blobs.Put(ctx, bootObjectKey(b.BootID), raw)
}

func (s *realStore) ReadBoot(ctx context.Context, bootIDHex string) (Boot, error) {
	if !validBootID(bootIDHex) {
		return Boot{}, ErrNotFound
	}
	raw, err := s.blobs.Get(ctx, bootObjectKey(bootIDHex))
	if err != nil {
		return Boot{}, err // ErrNotFound or transient
	}
	var b Boot
	if err := json.Unmarshal(raw, &b); err != nil {
		return Boot{}, fmt.Errorf("store: parse boot object: %w", err)
	}
	return b, nil
}

func keyLogPrefix(mailboxIDHex string) string { return "edge/keylog/" + mailboxIDHex + "/" }

// AppendMailboxKeyHash records one mailbox-key hash in the write-once log. Each
// append is a distinct object (timestamp plus random suffix in the key) so an
// entry is never overwritten; the broker lists the prefix to read a mailbox's
// whole key history. The caller passes a validated hex mailbox id, so the object
// key can't widen beyond the keylog prefix.
func (s *realStore) AppendMailboxKeyHash(ctx context.Context, mailboxIDHex string, keyHash []byte, at int64) error {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	key := fmt.Sprintf("%s%d-%s", keyLogPrefix(mailboxIDHex), at, hex.EncodeToString(suffix))
	return s.blobs.Put(ctx, key, keyHash)
}

type discard struct{}

// NewDiscard stores nothing and always succeeds. Smoke-testing only; never a
// release path.
func NewDiscard() Store { return discard{} }

func (discard) Put(context.Context, string, string, []byte) (string, error) {
	return "discarded", nil
}
