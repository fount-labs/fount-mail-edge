package routing

import (
	"context"
	"crypto/ed25519"
	"errors"
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
// the routing object to restore. It's for the restore drill, not the running edge.
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
