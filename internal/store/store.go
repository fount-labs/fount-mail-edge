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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
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

// ErrConflict means an object changed since it was read, so a conditional write
// didn't happen. The caller retries against fresh data; SMTP answers 451.
var ErrConflict = errors.New("store: object changed")

// ErrMailboxFull means the mailbox is at its storage cap (design §6: "up to
// about 2 GB per mailbox. When full, it answers 452"). SMTP turns a Put error
// into a 452, so the sender retries until the owner fetches and frees space.
var ErrMailboxFull = errors.New("store: mailbox full")

// DefaultMaxMailboxBytes is the per-mailbox storage cap when New is given no
// WithMaxMailboxBytes option: about 2 GB of unfetched mail (§6).
const DefaultMaxMailboxBytes int64 = 2 << 30

// DefaultRetention is how long unfetched mail is held before the sweep expires
// it (design §6: "Holds unfetched mail for 30 days"). Override with
// WithRetention.
const DefaultRetention = 30 * 24 * time.Hour

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

// Object is one entry in a Blobs listing: an object's full key, its size in
// bytes, and when it was last written. Size lets the store report GET /mail
// sizes and sum a mailbox's usage for the storage quota; Modified (S3's
// LastModified, set once at receipt since objects are never rewritten) lets the
// retention sweep decide a message's age without fetching it. Both come from
// the listing, so neither needs a per-object fetch.
type Object struct {
	Key      string
	Size     int64
	Modified time.Time // zero if the backend didn't report it
}

// Blobs is the durable object store (S3). Put returns only once the write is
// acknowledged, so Store.Put can honor "250 only after S3 confirms".
type Blobs interface {
	Put(ctx context.Context, key string, data []byte) error
	// Get returns an object's bytes, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// List returns the objects under prefix with their sizes, following S3
	// continuation tokens so the result spans every page.
	List(ctx context.Context, prefix string) ([]Object, error)
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

// Boot log layout (design §4). These keys live in the separate Object Lock bucket
// when New gets WithLogBlobs. The edge can only write there, so GET /boots keeps
// reading the copy under edge/boots.
func bootLogKey(bootIDHex string) string { return "boots/" + bootIDHex }

func keyLogKey(mailboxIDHex string, keyHash []byte) string {
	return "mailboxes/" + mailboxIDHex + "/" + hex.EncodeToString(keyHash)
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

// Sweeper expires unfetched mail past the retention window (design §6). The edge
// runs it periodically. realStore implements it; the discard store does not, so
// dev has no sweep.
type Sweeper interface {
	// Sweep deletes every message older than the retention window as of now,
	// writing a signed expiry record for each before it deletes the message.
	Sweep(ctx context.Context, now time.Time) (SweepResult, error)
}

// SweepResult counts one sweep. Skipped messages are past the window but couldn't
// be verified, so they stay until the bucket's lifecycle rule removes them, and a
// nonzero count needs a look.
type SweepResult struct {
	Expired, Skipped int
}

// GapReader returns the signed records for sequence numbers that have no message,
// so the broker can tell them from withheld mail (§8). realStore implements it; the
// discard store does not, so GET /gaps stays 501 in dev.
type GapReader interface {
	// Gaps returns up to MaxGaps records above sequence after, lowest first.
	Gaps(ctx context.Context, mailboxID []byte, after uint64) ([][]byte, error)
}

// MaxGaps bounds one GET /gaps. The broker pages by the last sequence it saw.
const MaxGaps = 256

// storeBudget bounds finishing a message once its sequence is spent, on a context
// of its own. S3 calls take at most 30 seconds, and there are at most two.
const storeBudget = 60 * time.Second

type realStore struct {
	dir        Directory
	blobs      Blobs
	logBlobs   Blobs // boot and key logs; see WithLogBlobs
	sign       ed25519.PrivateKey
	bootID     []byte
	now        func() time.Time
	maxMailbox int64         // per-mailbox storage cap; <=0 is unlimited
	retention  time.Duration // unfetched-mail hold; <=0 disables the sweep
}

// Option tunes a realStore built by New.
type Option func(*realStore)

// WithMaxMailboxBytes sets the per-mailbox storage cap (§6). A value <= 0 means
// unlimited. Without it New uses DefaultMaxMailboxBytes.
func WithMaxMailboxBytes(n int64) Option { return func(s *realStore) { s.maxMailbox = n } }

// WithRetention sets how long unfetched mail is held before Sweep expires it
// (§6). A value <= 0 disables the sweep. Without it New uses DefaultRetention.
func WithRetention(d time.Duration) Option { return func(s *realStore) { s.retention = d } }

// WithLogBlobs sends the boot log and mailbox-key log to their own bucket (§4).
// Object Lock needs versioning, which the mail bucket must not have. Without it
// the logs go to the mail bucket, where the edge's credentials refuse these keys,
// so a production edge missing this option fails closed.
func WithLogBlobs(b Blobs) Option { return func(s *realStore) { s.logBlobs = b } }

// New builds the real store. bootID is this boot's 16-byte identifier (it ends
// up in every object so the broker can check the signature against the right
// boot's attestation, §9).
func New(dir Directory, blobs Blobs, sign ed25519.PrivateKey, bootID []byte, opts ...Option) Store {
	s := &realStore{dir: dir, blobs: blobs, logBlobs: blobs, sign: sign, bootID: bootID, now: time.Now, maxMailbox: DefaultMaxMailboxBytes, retention: DefaultRetention}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *realStore) Put(ctx context.Context, recipient, sender string, raw []byte) (string, error) {
	addr, err := s.dir.Resolve(ctx, recipient)
	if err != nil {
		return "", err // ErrNoRecipient or transient; SMTP maps each distinctly
	}

	// Enforce the per-mailbox storage cap (§6) before allocating a sequence
	// number: a message rejected for a full mailbox must leave no gap in the
	// per-mailbox counter (a gap is how the device spots withheld mail, §8). The
	// stored object's size is a closed form of the envelope and body lengths, so
	// the check needs no sealing.
	if s.maxMailbox > 0 {
		used, err := s.usage(ctx, addr.MailboxID)
		if err != nil {
			return "", fmt.Errorf("mailbox usage: %w", err)
		}
		if used+storedSize(sender, recipient, len(raw)) > s.maxMailbox {
			return "", ErrMailboxFull
		}
	}

	edgeID := make([]byte, lenEdgeID)
	if _, err := rand.Read(edgeID); err != nil {
		return "", err
	}

	// A sequence with no message looks like withheld mail (§8). So from here a
	// session ending can't stop the write, and a failed write leaves a signed void
	// record. A crash can still leave a gap, and that's what the broker's check is for.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeBudget)
	defer cancel()
	seq, err := s.dir.NextSequence(ctx, addr.MailboxID)
	if err != nil {
		return "", fmt.Errorf("sequence: %w", err)
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
		return "", s.void(ctx, msg, fmt.Errorf("seal: %w", err))
	}

	// edge/mail/<mailbox id>/<edge id> (design §4 S3 layout).
	key := mailObjectKey(addr.MailboxID, hex.EncodeToString(edgeID))
	if err := s.blobs.Put(ctx, key, msg.MarshalSigned(s.sign)); err != nil {
		return "", s.void(ctx, msg, fmt.Errorf("blob put: %w", err))
	}
	return hex.EncodeToString(edgeID), nil
}

// void records that msg's sequence will never hold a message, and returns cause
// along with any failure to say so. The sender got a temporary failure and will
// retry, under a new sequence.
func (s *realStore) void(ctx context.Context, msg *Message, cause error) error {
	boot := hex.EncodeToString(s.bootID)
	return errors.Join(cause, s.writeRecord(ctx, ExpiryRecord{
		MailboxID:   hex.EncodeToString(msg.MailboxID),
		EdgeID:      hex.EncodeToString(msg.EdgeID),
		Sequence:    msg.Sequence,
		ReceivedAt:  msg.ReceivedAt.UnixMilli(),
		ExpiredAt:   s.now().UTC().Unix(),
		BootID:      boot,
		MessageBoot: boot,
		Reason:      ReasonVoid,
	}))
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
	objs, err := s.blobs.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]Stored, 0, len(objs))
	for _, o := range objs {
		id := strings.TrimPrefix(o.Key, prefix)
		if !validEdgeID(id) {
			continue // ignore anything that isn't a message object
		}
		out = append(out, Stored{ID: id, Size: int(o.Size)})
	}
	return out, nil
}

// usage sums the bytes a mailbox currently holds, from the object sizes in a
// prefix listing. Keys that aren't message objects (none today under this
// prefix) still count toward the cap, which is the safe direction.
func (s *realStore) usage(ctx context.Context, mailboxID []byte) (int64, error) {
	objs, err := s.blobs.List(ctx, mailboxPrefix(mailboxID))
	if err != nil {
		return 0, err
	}
	var total int64
	for _, o := range objs {
		total += o.Size
	}
	return total, nil
}

// storedSize is the exact byte length MarshalSigned produces for a message with
// these envelope and body lengths. Every field other than enc/ct/plaintext is
// fixed-width (§9), the HPKE encapsulated key is a 32-byte X25519 point, and the
// AEAD adds a 16-byte tag — so the on-disk size is known before sealing. A unit
// test pins this against a real MarshalSigned so a suite change can't drift it.
func storedSize(sender, recipient string, rawLen int) int64 {
	const encLen = 32 // X25519 encapsulated key
	const aeadTag = 16
	plaintext := 2 + len(sender) + 2 + len(recipient) + rawLen
	ct := plaintext + aeadTag
	// headerLen + encLen-prefix(2) + enc + ctLen-prefix(4) + ct + signature.
	return int64(headerLen + 2 + encLen + 4 + ct + ed25519.SignatureSize)
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

// WriteBoot publishes this boot's attestation record to the mail bucket, which
// GET /boots reads, and to the boot log, which detects hidden boots (§16). It tries
// both even if one fails. It is idempotent: the
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
	return errors.Join(
		s.blobs.Put(ctx, bootObjectKey(b.BootID), raw),
		s.logBlobs.Put(ctx, bootLogKey(b.BootID), raw),
	)
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

// AppendMailboxKeyHash records one mailbox-key hash in the write-once log. Each key
// is its own object under the mailbox, and Object Lock keeps every version, so an
// entry can't be replaced. The caller passes a validated hex mailbox id, so the
// object key can't widen beyond the mailbox's prefix.
func (s *realStore) AppendMailboxKeyHash(ctx context.Context, mailboxIDHex string, keyHash []byte, at int64) error {
	raw, err := json.Marshal(struct {
		KeyHash string `json:"key_hash"`
		At      int64  `json:"at"`
	}{hex.EncodeToString(keyHash), at})
	if err != nil {
		return err
	}
	return s.logBlobs.Put(ctx, keyLogKey(mailboxIDHex, keyHash), raw)
}

// --- Retention sweep (design §6) -------------------------------------------

// ExpiryRecord accounts for a sequence number with no message. ReasonExpired means
// the sweep deleted an unfetched message: the sender already got a 250 and the edge
// can't read who they were, so this is what the app can report to the owner.
// ReasonVoid means the sequence was spent but the message was never stored, and the
// sender was told to retry. Either way, what would otherwise look like withheld mail
// (a gap in the counter, §8) is accountable. Signed by the boot's mail-sign key, so
// the broker trusts it against that boot's attestation (§9).
type ExpiryRecord struct {
	MailboxID  string `json:"mailbox_id"`  // hex
	EdgeID     string `json:"edge_id"`     // hex
	Sequence   uint64 `json:"sequence"`    // the per-mailbox number with no message
	ReceivedAt int64  `json:"received_at"` // unix ms, from the message header
	ExpiredAt  int64  `json:"expired_at"`  // unix seconds, when this was written
	BootID     string `json:"boot_id"`     // hex boot that wrote this (whose key signs)

	// MessageBoot is the boot that signed the message. The sweep finds that boot's
	// key in S3, which the host could plant, so the broker must check this boot
	// against the boot log before trusting an expiry.
	MessageBoot string `json:"message_boot"`
	Reason      string `json:"reason"` // ReasonExpired or ReasonVoid
}

const (
	ReasonExpired = "expired"
	ReasonVoid    = "void"
)

func expiryPrefix(mailboxIDHex string) string { return "edge/expiry/" + mailboxIDHex + "/" }

func expiryKey(mailboxIDHex string, seq uint64) string {
	return expiryPrefix(mailboxIDHex) + strconv.FormatUint(seq, 10)
}

// Gaps implements GapReader.
func (s *realStore) Gaps(ctx context.Context, mailboxID []byte, after uint64) ([][]byte, error) {
	prefix := expiryPrefix(hex.EncodeToString(mailboxID))
	objs, err := s.blobs.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var seqs []uint64
	for _, o := range objs {
		seq, err := strconv.ParseUint(strings.TrimPrefix(o.Key, prefix), 10, 64)
		if err == nil && seq > after {
			seqs = append(seqs, seq)
		}
	}
	slices.Sort(seqs)
	if len(seqs) > MaxGaps {
		seqs = seqs[:MaxGaps]
	}
	out := make([][]byte, 0, len(seqs))
	for _, seq := range seqs {
		raw, err := s.blobs.Get(ctx, prefix+strconv.FormatUint(seq, 10))
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// Sweep expires mail past the retention window. For each too-old object it verifies
// the message against the boot that signed it, writes the signed expiry record
// FIRST, then deletes the message — so a message is never deleted without an expiry
// record (which would reopen the false-withheld-mail gap). A message that doesn't
// verify is skipped and counted. It is idempotent: the expiry record key is the
// mailbox id + sequence, so a retried sweep rewrites the same record and retries the
// delete.
func (s *realStore) Sweep(ctx context.Context, now time.Time) (SweepResult, error) {
	var res SweepResult
	if s.retention <= 0 {
		return res, nil
	}
	objs, err := s.blobs.List(ctx, "edge/mail/")
	if err != nil {
		return res, err
	}
	cutoff := now.Add(-s.retention)
	signers := map[string]ed25519.PublicKey{
		hex.EncodeToString(s.bootID): s.sign.Public().(ed25519.PublicKey),
	}
	for _, o := range objs {
		// Never delete a message we can't date: a zero Modified (backend didn't
		// report it) or one still inside the window is left alone.
		if o.Modified.IsZero() || !o.Modified.Before(cutoff) {
			continue
		}
		raw, err := s.blobs.Get(ctx, o.Key)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // already gone
			}
			return res, err
		}
		signPub, err := s.signerOf(ctx, raw, signers)
		if err != nil {
			return res, err
		}
		if signPub == nil {
			res.Skipped++
			continue
		}
		p, err := Parse(raw, signPub)
		if err != nil || o.Key != mailObjectKey(p.MailboxID, hex.EncodeToString(p.EdgeID)) {
			res.Skipped++ // not what it claims to be, so it can't speak for a sequence
			continue
		}
		if err := s.writeExpiry(ctx, p, now); err != nil {
			return res, err
		}
		if err := s.blobs.Delete(ctx, o.Key); err != nil {
			return res, err
		}
		res.Expired++
	}
	return res, nil
}

// signerOf returns the signing key of the boot a stored message names, remembering
// it in signers for the rest of the sweep. It's nil if that boot has no usable
// record, which only a failed read tells apart from a real problem.
func (s *realStore) signerOf(ctx context.Context, raw []byte, signers map[string]ed25519.PublicKey) (ed25519.PublicKey, error) {
	id, ok := bootIDOf(raw)
	if !ok {
		return nil, nil
	}
	key := hex.EncodeToString(id)
	if pub, ok := signers[key]; ok {
		return pub, nil
	}
	b, err := s.ReadBoot(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
		signers[key] = nil
	case err != nil:
		return nil, err
	case len(b.SigningKey) != ed25519.PublicKeySize:
		signers[key] = nil
	default:
		signers[key] = b.SigningKey
	}
	return signers[key], nil
}

// writeExpiry stores the signed expiry record for one expired message.
func (s *realStore) writeExpiry(ctx context.Context, p *Parsed, now time.Time) error {
	return s.writeRecord(ctx, ExpiryRecord{
		MailboxID:   hex.EncodeToString(p.MailboxID),
		EdgeID:      hex.EncodeToString(p.EdgeID),
		Sequence:    p.Sequence,
		ReceivedAt:  p.ReceivedAt.UnixMilli(),
		ExpiredAt:   now.UTC().Unix(),
		BootID:      hex.EncodeToString(s.bootID),
		MessageBoot: hex.EncodeToString(p.BootID),
		Reason:      ReasonExpired,
	})
}

func (s *realStore) writeRecord(ctx context.Context, rec ExpiryRecord) error {
	body, err := marshalExpiry(rec, s.sign)
	if err != nil {
		return err
	}
	return s.blobs.Put(ctx, expiryKey(rec.MailboxID, rec.Sequence), body)
}

// marshalExpiry encodes a record as b64url(json).b64url(sig), the same compact
// signed-token shape internal/entitlement uses, so the broker verifies it the
// same way.
func marshalExpiry(rec ExpiryRecord, sign ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(sign, payload)
	enc := base64.RawURLEncoding
	return []byte(enc.EncodeToString(payload) + "." + enc.EncodeToString(sig)), nil
}

// ParseExpiryRecord decodes and verifies an expiry record against signPub. It is
// the broker's reference (and backs the sweep tests); the edge never reads one
// back.
func ParseExpiryRecord(b []byte, signPub ed25519.PublicKey) (ExpiryRecord, error) {
	parts := strings.Split(string(b), ".")
	if len(parts) != 2 {
		return ExpiryRecord{}, errors.New("store: malformed expiry record")
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[0])
	if err != nil {
		return ExpiryRecord{}, fmt.Errorf("store: expiry payload: %w", err)
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil {
		return ExpiryRecord{}, fmt.Errorf("store: expiry sig: %w", err)
	}
	if !ed25519.Verify(signPub, payload, sig) {
		return ExpiryRecord{}, errors.New("store: expiry signature does not verify")
	}
	var rec ExpiryRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return ExpiryRecord{}, fmt.Errorf("store: expiry json: %w", err)
	}
	return rec, nil
}

type discard struct{}

// NewDiscard stores nothing and always succeeds. Smoke-testing only; never a
// release path.
func NewDiscard() Store { return discard{} }

func (discard) Put(context.Context, string, string, []byte) (string, error) {
	return "discarded", nil
}
