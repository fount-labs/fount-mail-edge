package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// NonceSize matches Tinfoil's attestation nonce.
const NonceSize = 32

// Purpose separates the boxes, so one made for a share can't be opened as a keyset.
type Purpose string

const (
	PurposeKeyset Purpose = "keyset"
	PurposeShare  Purpose = "share"
	PurposeImport Purpose = "import"
	// PurposeSendKeyset is the send keyset's own box, sealed to the requester's
	// send-transfer key, so a box for the keyset can't be opened as one for it.
	PurposeSendKeyset Purpose = "send-keyset"
)

// Nonces bind a box to one exchange. Issued is the one-use nonce from the begin
// call, and Answer is the caller's own.
type Nonces struct {
	Issued []byte
	Answer []byte
}

// Seal encrypts to the recipient. When both keys are attested, the static X25519
// agreement authenticates both sides: only the recipient can open the box, and
// only the sender could have made it.
func Seal(p Purpose, sender *ecdh.PrivateKey, recipient *ecdh.PublicKey, n Nonces, plaintext []byte) ([]byte, error) {
	gcm, err := boxCipher(p, sender, recipient, sender.PublicKey(), recipient, n)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open is Seal's inverse, run by the recipient.
func Open(p Purpose, recipient *ecdh.PrivateKey, sender *ecdh.PublicKey, n Nonces, box []byte) ([]byte, error) {
	gcm, err := boxCipher(p, recipient, sender, sender, recipient.PublicKey(), n)
	if err != nil {
		return nil, err
	}
	if len(box) < gcm.NonceSize() {
		return nil, errors.New("sealed box is too short")
	}
	plaintext, err := gcm.Open(nil, box[:gcm.NonceSize()], box[gcm.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("sealed box doesn't open: wrong key, wrong exchange, or altered")
	}
	return plaintext, nil
}

func boxCipher(p Purpose, mine *ecdh.PrivateKey, peer, sender, recipient *ecdh.PublicKey, n Nonces) (cipher.AEAD, error) {
	if len(n.Issued) != NonceSize || len(n.Answer) != NonceSize {
		return nil, fmt.Errorf("nonces must be %d bytes", NonceSize)
	}
	switch p {
	case PurposeKeyset, PurposeShare, PurposeImport, PurposeSendKeyset:
	default:
		return nil, fmt.Errorf("unknown purpose %q", p)
	}
	shared, err := mine.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}
	// Every field after the purpose has a fixed length, so this can't be ambiguous.
	info := []byte("fount-mail-vault/v1/" + string(p) + "\x00")
	info = append(info, sender.Bytes()...)
	info = append(info, recipient.Bytes()...)
	info = append(info, n.Issued...)
	info = append(info, n.Answer...)
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
