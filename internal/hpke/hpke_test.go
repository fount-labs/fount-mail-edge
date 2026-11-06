package hpke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 9180 Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM,
// base mode. If any of these assertions fail, the construction is wrong — this
// is the whole justification for a stdlib hand-roll.
const (
	vInfo         = "4f6465206f6e2061204772656369616e2055726e"
	vIKME         = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"
	vPKEm         = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	vIKMR         = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"
	vPKRm         = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
	vEnc          = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	vSharedSecret = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
	vKey          = "4531685d41d65f03dc48f6b8302c05b0"
	vBaseNonce    = "56d890e5accaaf011cff4b7d"
	vAAD          = "436f756e742d30"
	vPT           = "4265617574792069732074727574682c20747275746820626561757479"
	vCT           = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestRFC9180A1(t *testing.T) {
	info := mustHex(t, vInfo)
	aad := mustHex(t, vAAD)
	pt := mustHex(t, vPT)

	skE, err := deriveKeyPair(mustHex(t, vIKME))
	if err != nil {
		t.Fatalf("deriveKeyPair(ikmE): %v", err)
	}
	if got := hex.EncodeToString(skE.PublicKey().Bytes()); got != vPKEm {
		t.Fatalf("pkEm = %s, want %s", got, vPKEm)
	}

	skR, err := deriveKeyPair(mustHex(t, vIKMR))
	if err != nil {
		t.Fatalf("deriveKeyPair(ikmR): %v", err)
	}
	if got := hex.EncodeToString(skR.PublicKey().Bytes()); got != vPKRm {
		t.Fatalf("pkRm = %s, want %s", got, vPKRm)
	}

	sharedSecret, enc, err := encap(skE, skR.PublicKey())
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if got := hex.EncodeToString(enc); got != vEnc {
		t.Fatalf("enc = %s, want %s", got, vEnc)
	}
	if got := hex.EncodeToString(sharedSecret); got != vSharedSecret {
		t.Fatalf("shared_secret = %s, want %s", got, vSharedSecret)
	}

	key, baseNonce, err := keySchedule(sharedSecret, info)
	if err != nil {
		t.Fatalf("keySchedule: %v", err)
	}
	if got := hex.EncodeToString(key); got != vKey {
		t.Fatalf("key = %s, want %s", got, vKey)
	}
	if got := hex.EncodeToString(baseNonce); got != vBaseNonce {
		t.Fatalf("base_nonce = %s, want %s", got, vBaseNonce)
	}

	gotEnc, ct, err := sealWith(skE, skR.PublicKey(), info, aad, pt)
	if err != nil {
		t.Fatalf("sealWith: %v", err)
	}
	if got := hex.EncodeToString(gotEnc); got != vEnc {
		t.Fatalf("seal enc = %s, want %s", got, vEnc)
	}
	if got := hex.EncodeToString(ct); got != vCT {
		t.Fatalf("ct = %s, want %s", got, vCT)
	}

	back, err := open(skR, gotEnc, info, aad, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatalf("open = %x, want %x", back, pt)
	}
}

// Seal uses a fresh ephemeral key each call, so two seals of the same message
// differ, and each still opens to the original.
func TestSealRoundTripRandom(t *testing.T) {
	skR, err := deriveKeyPair(mustHex(t, vIKMR))
	if err != nil {
		t.Fatal(err)
	}
	pub := skR.PublicKey().Bytes()
	info := []byte("fount-mail-edge/v1")
	aad := []byte("mailbox-binding")
	pt := []byte("the raw inbound message, stored whole")

	enc1, ct1, err := Seal(pub, info, aad, pt)
	if err != nil {
		t.Fatalf("Seal 1: %v", err)
	}
	enc2, ct2, err := Seal(pub, info, aad, pt)
	if err != nil {
		t.Fatalf("Seal 2: %v", err)
	}
	if bytes.Equal(enc1, enc2) || bytes.Equal(ct1, ct2) {
		t.Fatal("two seals of the same message must differ (fresh ephemeral key)")
	}
	for i, tc := range [][2][]byte{{enc1, ct1}, {enc2, ct2}} {
		back, err := open(skR, tc[0], info, aad, tc[1])
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("open %d = %q, want %q", i, back, pt)
		}
	}
}

// Wrong aad (the stored object's binding) must fail to open.
func TestOpenRejectsWrongAAD(t *testing.T) {
	skR, err := deriveKeyPair(mustHex(t, vIKMR))
	if err != nil {
		t.Fatal(err)
	}
	enc, ct, err := Seal(skR.PublicKey().Bytes(), []byte("info"), []byte("aad-A"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open(skR, enc, []byte("info"), []byte("aad-B"), ct); err == nil {
		t.Fatal("open must fail when aad differs")
	}
}

func TestSuiteID(t *testing.T) {
	if got := hex.EncodeToString(SuiteID()); got != "002000010001" {
		t.Fatalf("SuiteID = %s, want 002000010001", got)
	}
}

func TestSealRejectsBadKey(t *testing.T) {
	short := make([]byte, 31)
	rand.Read(short)
	if _, _, err := Seal(short, nil, nil, []byte("x")); err == nil {
		t.Fatal("Seal must reject a non-32-byte recipient key")
	}
}
