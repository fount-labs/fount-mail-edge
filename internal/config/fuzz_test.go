package config

import (
	"bytes"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// A vault's payload is sealed to the edge's public transfer key, which anyone can
// seal to, so a fake vault reaches ParseSendKeyset with bytes of its choosing
// before the commitment check. It must refuse them without panicking, and accept
// only the one encoding of a keyset.
func FuzzSendKeyset(f *testing.F) {
	sk, err := wire.GenerateSend()
	if err != nil {
		f.Fatal(err)
	}
	good := sk.MarshalBinary()
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 0xff, 0xff})
	f.Add(append(append([]byte(nil), good...), 0))
	f.Add(good[:len(good)/2])
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := wire.ParseSendKeyset(b)
		if err != nil {
			return
		}
		if !bytes.Equal(k.MarshalBinary(), b) {
			t.Fatal("two encodings parse to one send keyset")
		}
		if _, err := sendKeys(k); err != nil {
			t.Fatalf("parsed but doesn't install: %v", err)
		}
	})
}
