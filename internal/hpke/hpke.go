// Package hpke implements the sender (seal) side of HPKE base mode
// (RFC 9180) using only the standard library, for the one suite the mail edge
// uses to encrypt each stored message to an address's public key:
//
//	DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
//
// The edge only ever encrypts, so only Seal is exported. The key schedule,
// Encap/Decap, deterministic key derivation, and an Open are kept unexported
// in this package so the known-answer test (hpke_test.go) can reproduce
// RFC 9180 Appendix A.1 byte for byte. That vector is the reason a hand-rolled
// construction is acceptable here: it is checked against the RFC's own answer,
// and the suite was chosen (AES-128-GCM) precisely because the RFC publishes a
// vector for it.
package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	kemID  = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	kdfID  = 0x0001 // HKDF-SHA256
	aeadID = 0x0001 // AES-128-GCM

	nSecret = 32 // DHKEM shared secret length
	nSk     = 32 // X25519 scalar length
	nK      = 16 // AES-128-GCM key length
	nN      = 12 // AEAD nonce length

	modeBase = 0x00
)

func i2osp2(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func buildSuiteID(prefix string, ids ...int) []byte {
	b := make([]byte, 0, len(prefix)+2*len(ids))
	b = append(b, prefix...)
	for _, id := range ids {
		b = append(b, i2osp2(id)...)
	}
	return b
}

var (
	kemSuiteID  = buildSuiteID("KEM", kemID)
	hpkeSuiteID = buildSuiteID("HPKE", kemID, kdfID, aeadID)
)

// SuiteID is the RFC 9180 suite identifier — kem_id, kdf_id, aead_id as three
// big-endian uint16s — recorded in each stored object's "suite id" field so a
// later suite (forward secrecy, a post-quantum hybrid) is distinguishable on
// read. See design §9.
func SuiteID() []byte {
	return buildSuiteID("", kemID, kdfID, aeadID)
}

func labeledExtract(suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, "HPKE-v1"...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(sha256.New, labeledIKM, salt)
}

func labeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = append(labeledInfo, i2osp2(length)...)
	labeledInfo = append(labeledInfo, "HPKE-v1"...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
}

func extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePrk, err := labeledExtract(kemSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return labeledExpand(kemSuiteID, eaePrk, "shared_secret", kemContext, nSecret)
}

func encap(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey) (sharedSecret, enc []byte, err error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(enc)+len(pkR.Bytes()))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR.Bytes()...)
	ss, err := extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return ss, enc, nil
}

func decap(enc []byte, skR *ecdh.PrivateKey) ([]byte, error) {
	pkE, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, err
	}
	kemContext := make([]byte, 0, len(enc)+len(skR.PublicKey().Bytes()))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, skR.PublicKey().Bytes()...)
	return extractAndExpand(dh, kemContext)
}

// keySchedule is base mode only (no PSK), which is all the edge uses.
func keySchedule(sharedSecret, info []byte) (key, baseNonce []byte, err error) {
	pskIDHash, err := labeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := labeledExtract(hpkeSuiteID, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	ksContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksContext = append(ksContext, modeBase)
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret, err := labeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	key, err = labeledExpand(hpkeSuiteID, secret, "key", ksContext, nK)
	if err != nil {
		return nil, nil, err
	}
	baseNonce, err = labeledExpand(hpkeSuiteID, secret, "base_nonce", ksContext, nN)
	if err != nil {
		return nil, nil, err
	}
	return key, baseNonce, nil
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealWith performs a single-shot base-mode seal with a caller-supplied
// ephemeral key. Sequence number is 0, so the AEAD nonce is the base nonce.
func sealWith(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	sharedSecret, enc, err := encap(skE, pkR)
	if err != nil {
		return nil, nil, err
	}
	key, baseNonce, err := keySchedule(sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	a, err := aead(key)
	if err != nil {
		return nil, nil, err
	}
	return enc, a.Seal(nil, baseNonce, pt, aad), nil
}

// Open decrypts a base-mode ciphertext with the recipient's X25519 private key
// (32 raw bytes). It is the inverse of Seal and the reference for what a
// consumer (the broker) must do. The edge itself holds no decryption key and
// never calls this on the boot path; it exists for consumers and round-trip
// tests.
func Open(recipientPriv, enc, info, aad, ct []byte) ([]byte, error) {
	skR, err := ecdh.X25519().NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, fmt.Errorf("hpke: bad recipient private key: %w", err)
	}
	return open(skR, enc, info, aad, ct)
}

// open is the matching single-shot base-mode open shared by Open and tests.
func open(skR *ecdh.PrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	sharedSecret, err := decap(enc, skR)
	if err != nil {
		return nil, err
	}
	key, baseNonce, err := keySchedule(sharedSecret, info)
	if err != nil {
		return nil, err
	}
	a, err := aead(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, baseNonce, ct, aad)
}

// deriveKeyPair is RFC 9180 DeriveKeyPair for X25519, used by the known-answer
// test to reproduce the fixed keys in Appendix A.1.
func deriveKeyPair(ikm []byte) (*ecdh.PrivateKey, error) {
	dkpPrk, err := labeledExtract(kemSuiteID, nil, "dkp_prk", ikm)
	if err != nil {
		return nil, err
	}
	sk, err := labeledExpand(kemSuiteID, dkpPrk, "sk", nil, nSk)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(sk)
}

// Seal encrypts pt to the recipient's X25519 public key (32 raw bytes) under
// HPKE base mode, binding aad and info, with a fresh ephemeral key each call.
// It returns the encapsulated key (enc, 32 bytes) and the ciphertext (pt plus
// a 16-byte AEAD tag).
func Seal(recipientPub, info, aad, pt []byte) (enc, ct []byte, err error) {
	pkR, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: bad recipient public key: %w", err)
	}
	skE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sealWith(skE, pkR, info, aad, pt)
}
