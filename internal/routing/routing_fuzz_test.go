package routing

import (
	"crypto/rand"
	"testing"
)

// FuzzDecrypt feeds arbitrary at-rest bytes to the routing-object decoder. The
// object is sealed under a key the fuzzer does not hold, so no forged blob can
// reach the JSON stage; the property is that the framing (magic, nonce split,
// ciphertext slice) never panics on short, truncated, or adversarial input — a
// corrupted S3 object must fail cleanly, not crash the enclave.
func FuzzDecrypt(f *testing.F) {
	aead, err := newAEAD([]byte("fuzz-routing-data-key"))
	if err != nil {
		f.Fatalf("newAEAD: %v", err)
	}
	s := &Store{aead: aead}

	// A validly-sealed empty routing object, so the corpus mutates around the
	// one input that reaches json.Unmarshal.
	nonce := make([]byte, nonceLen)
	_, _ = rand.Read(nonce)
	sealed := append([]byte(magic), nonce...)
	sealed = aead.Seal(sealed, nonce, []byte(`{"version":1,"mailboxes":{}}`), nil)
	f.Add(sealed)
	f.Add([]byte{})
	f.Add([]byte(magic))
	f.Add(append([]byte(magic), nonce...))
	f.Add([]byte("FMR1short"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = s.decrypt(raw)
	})
}
