package routing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// backupKey is the one object in the versioned backup bucket (design §4). S3 keeps
// each change as a version, so a restore can pick any point in time.
const backupKey = "routing/current"

const (
	backupMagic = "FMB1" // frames a backup: magic || boot id || signature || routing object
	bootIDLen   = 16
)

// backup writes a signed copy of each routing change. Losing edge/routing/current
// stops all mail, and the object it copies is already encrypted, so the backup
// bucket holds nothing readable and no mail. It's signed by the boot's mail-sign
// key, so a restore can reject a copy the edge never wrote.
type backup struct {
	blobs  store.Blobs
	sign   ed25519.PrivateKey
	bootID []byte
}

// WithBackup copies every routing change to blobs, signed by sign. bootID names
// the boot whose attested key to verify the signature against.
func WithBackup(blobs store.Blobs, sign ed25519.PrivateKey, bootID []byte) Option {
	return func(s *Store) { s.backup = &backup{blobs: blobs, sign: sign, bootID: bootID} }
}

// write copies object to the backup bucket. A failure is loud but not returned:
// the change is already durable in the primary, and failing it would refuse mail
// over a problem with the copy.
func (b *backup) write(ctx context.Context, object []byte) {
	if b == nil {
		return
	}
	framed := make([]byte, 0, len(backupMagic)+bootIDLen+ed25519.SignatureSize+len(object))
	framed = append(framed, backupMagic...)
	framed = append(framed, b.bootID...)
	framed = append(framed, ed25519.Sign(b.sign, signedBackup(b.bootID, object))...)
	framed = append(framed, object...)
	if err := b.blobs.Put(ctx, backupKey, framed); err != nil {
		log.Printf("routing: WARNING backup not written: %v", err)
	}
}

func signedBackup(bootID, object []byte) []byte {
	msg := make([]byte, 0, len(backupMagic)+len(bootID)+len(object))
	msg = append(msg, backupMagic...)
	msg = append(msg, bootID...)
	return append(msg, object...)
}

// BackupBootID returns which boot signed a backup, so a restore can look up that
// boot's signing key.
func BackupBootID(framed []byte) ([]byte, error) {
	if len(framed) < len(backupMagic)+bootIDLen+ed25519.SignatureSize || string(framed[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("routing: not a backup")
	}
	return framed[len(backupMagic) : len(backupMagic)+bootIDLen], nil
}

// OpenBackup verifies a backup against the signing boot's public key and returns
// the routing object to restore. Only a restore uses it.
func OpenBackup(framed []byte, signPub ed25519.PublicKey) ([]byte, error) {
	bootID, err := BackupBootID(framed)
	if err != nil {
		return nil, err
	}
	sigAt := len(backupMagic) + bootIDLen
	sig, object := framed[sigAt:sigAt+ed25519.SignatureSize], framed[sigAt+ed25519.SignatureSize:]
	if !ed25519.Verify(signPub, signedBackup(bootID, object), sig) {
		return nil, errors.New("routing: backup signature invalid")
	}
	return object, nil
}

// Summary describes a routing object, for an operator to check before restoring it.
type Summary struct {
	Generation int
	Mailboxes  int
	Sequences  uint64 // the sum of every mailbox's counter, to compare two objects
}

// Restore holds what the edge needs to install a backup.
type Restore struct {
	Object         []byte // from OpenBackup
	RoutingDataKey []byte
	// SkipSequences moves every counter forward. An older backup can hold counters
	// below numbers already issued, and reusing one is worse than a gap, so a restore
	// from anything but the newest copy must skip past them.
	SkipSequences uint64
	// Replace allows overwriting an existing object.
	Replace bool
}

// Inspect decrypts the object and reports what it holds, writing nothing.
func (r Restore) Inspect() (Summary, error) {
	s, err := r.open()
	if err != nil {
		return Summary{}, err
	}
	return s.summary(), nil
}

func (r Restore) open() (*Store, error) {
	aead, err := newAEAD(r.RoutingDataKey)
	if err != nil {
		return nil, err
	}
	s := &Store{aead: aead}
	if s.data, err = s.decrypt(r.Object); err != nil {
		return nil, err
	}
	if s.data.Mailboxes == nil {
		s.data.Mailboxes = map[string]*Mailbox{}
	}
	return s, nil
}

func (s *Store) summary() Summary {
	sum := Summary{Generation: s.data.Version, Mailboxes: len(s.data.Mailboxes)}
	for _, m := range s.data.Mailboxes {
		sum.Sequences += m.Sequence
	}
	return sum
}

// Apply writes the backup as the live object, conditional on what's there now, and
// reads it back. The edge stops serving first (docs/RESTORE.md). The generation
// stays near the backup's, so an edge left running refuses the object, rather than
// carrying on with what it holds in memory.
func (r Restore) Apply(ctx context.Context, blobs Blobs) (Summary, error) {
	s, err := r.open()
	if err != nil {
		return Summary{}, err
	}
	s.blobs = blobs
	switch _, etag, err := blobs.GetVersioned(ctx, ObjectKey); {
	case err == nil && !r.Replace:
		return Summary{}, ErrObjectExists
	case err == nil:
		s.etag = etag
	case !errors.Is(err, store.ErrNotFound):
		return Summary{}, fmt.Errorf("routing: check for an existing object: %w", err)
	}
	for _, m := range s.data.Mailboxes {
		m.Sequence += r.SkipSequences
	}
	if err := s.persist(ctx); err != nil {
		return Summary{}, fmt.Errorf("routing: write: %w", err)
	}
	raw, err := blobs.Get(ctx, ObjectKey)
	if err != nil {
		return Summary{}, fmt.Errorf("routing: read back: %w", err)
	}
	if _, err := s.decrypt(raw); err != nil {
		return Summary{}, fmt.Errorf("routing: read back: %w", err)
	}
	return s.summary(), nil
}
