package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzParse feeds arbitrary bytes to the §9 stored-object decoder under a fixed
// verify key. The attacker-controlled lengths (encLen/ctLen) drive the slicing,
// so the property that matters is that no input panics or slices out of bounds,
// and that anything Parse accepts both verifies against the key and has
// well-formed fixed-width fields (the broker relies on this shape).
func FuzzParse(f *testing.F) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}
	f.Add([]byte(magic))
	f.Add([]byte{})
	f.Add(make([]byte, headerLen+2))
	f.Add(append([]byte(magic), make([]byte, headerLen)...))

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b, pub)
		if err != nil {
			return
		}
		// A signature forged under a key the fuzzer doesn't hold is infeasible,
		// so reaching here should be unreachable; if it ever is, the fields must
		// still be the fixed widths the broker decodes blindly.
		if len(p.EdgeID) != lenEdgeID || len(p.MailboxID) != lenMailboxID ||
			len(p.PubKeyHash) != lenPubKeyHash || len(p.BootID) != lenBootID {
			t.Fatalf("accepted object with malformed field widths")
		}
	})
}
