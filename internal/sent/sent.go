// Package sent keeps each worker's send records durably in S3 (fount
// launch-plan decision 14), so "was this Message-ID sent?" has the same answer
// after an edge reboot, and a coordinator restored from an older backup can't
// send a reply twice.
//
// One object per worker and Message-ID, at
//
//	edge/sent/<hex mailbox id>/<hex HMAC(name key, mailbox id || 0 || Message-ID)>
//
// sealed with AES-256-GCM under a key derived from ROUTING_DATA_KEY, with the
// object key as associated data, so S3 sees neither the Message-ID nor the
// recipients, and can't move a record to another name. Both keys come from the
// vault's keyset, so every edge release reads every other's records.
//
// Records are kept for the retention the release sets (SENT_RETENTION_DAYS)
// from their last write, which must be at least as long as a coordinator restore
// can reach back. The edge's daily sweep deletes older ones.
package sent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// DefaultRetention is how long a send record is kept after its last write when
// the release doesn't say. It must cover how far back a coordinator restore can
// reach: the coordinator's backup bucket must expire noncurrent versions sooner.
const DefaultRetention = 90 * 24 * time.Hour

// Prefix is where the records live in the mail bucket.
const Prefix = "edge/sent/"

const (
	sealInfo = "fount-mail-edge/v1/sent-records"
	nameInfo = "fount-mail-edge/v1/sent-names"
	magic    = "FMS1"
	nonceLen = 12
)

// Store implements send.SentRecords over S3.
type Store struct {
	blobs     store.Blobs
	aead      cipher.AEAD
	nameKey   []byte
	retention time.Duration
}

var _ send.SentRecords = (*Store)(nil)

// New builds the store. secret is ROUTING_DATA_KEY; retention <= 0 is
// DefaultRetention.
func New(blobs store.Blobs, secret []byte, retention time.Duration) (*Store, error) {
	if len(secret) == 0 {
		return nil, errors.New("sent: empty secret")
	}
	sealKey, err := derive(secret, sealInfo)
	if err != nil {
		return nil, err
	}
	nameKey, err := derive(secret, nameInfo)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sealKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if retention <= 0 {
		retention = DefaultRetention
	}
	return &Store{blobs: blobs, aead: aead, nameKey: nameKey, retention: retention}, nil
}

func derive(secret []byte, info string) ([]byte, error) {
	prk, err := hkdf.Extract(sha256.New, secret, nil)
	if err != nil {
		return nil, err
	}
	return hkdf.Expand(sha256.New, prk, info, 32)
}

// Retention is how long a record is kept after its last write.
func (s *Store) Retention() time.Duration { return s.retention }

func (s *Store) objectKey(mailboxID []byte, messageID string) string {
	m := hmac.New(sha256.New, s.nameKey)
	m.Write(mailboxID)
	m.Write([]byte{0})
	m.Write([]byte(send.NormalizeMessageID(messageID)))
	return Prefix + hex.EncodeToString(mailboxID) + "/" + hex.EncodeToString(m.Sum(nil))
}

// Load returns the record for messageID from mailboxID, or nil if there is none.
func (s *Store) Load(ctx context.Context, mailboxID []byte, messageID string) (*send.SentRecord, error) {
	key := s.objectKey(mailboxID, messageID)
	raw, err := s.blobs.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) < len(magic)+nonceLen || string(raw[:len(magic)]) != magic {
		return nil, errors.New("sent: malformed record")
	}
	nonce := raw[len(magic) : len(magic)+nonceLen]
	pt, err := s.aead.Open(nil, nonce, raw[len(magic)+nonceLen:], []byte(key))
	if err != nil {
		return nil, fmt.Errorf("sent: open record: %w", err)
	}
	var r send.SentRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return nil, fmt.Errorf("sent: parse record: %w", err)
	}
	if send.NormalizeMessageID(r.MessageID) != send.NormalizeMessageID(messageID) || len(r.Outcomes) != len(r.Recipients) {
		return nil, errors.New("sent: record doesn't match its name")
	}
	return &r, nil
}

// Save writes the record, replacing any earlier one for its Message-ID.
func (s *Store) Save(ctx context.Context, mailboxID []byte, r *send.SentRecord) error {
	key := s.objectKey(mailboxID, r.MessageID)
	pt, err := json.Marshal(r)
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
	out = s.aead.Seal(out, nonce, pt, []byte(key))
	return s.blobs.Put(ctx, key, out)
}

// Delete removes the record for messageID, which is only right when nothing was
// sent under it.
func (s *Store) Delete(ctx context.Context, mailboxID []byte, messageID string) error {
	return s.blobs.Delete(ctx, s.objectKey(mailboxID, messageID))
}

// Sweep deletes records whose last write is older than the retention. A record
// S3 can't date is kept.
func (s *Store) Sweep(ctx context.Context, now time.Time) (int, error) {
	objs, err := s.blobs.List(ctx, Prefix)
	if err != nil {
		return 0, err
	}
	cutoff := now.Add(-s.retention)
	n := 0
	for _, o := range objs {
		if o.Modified.IsZero() || !o.Modified.Before(cutoff) || !strings.HasPrefix(o.Key, Prefix) {
			continue
		}
		if err := s.blobs.Delete(ctx, o.Key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
