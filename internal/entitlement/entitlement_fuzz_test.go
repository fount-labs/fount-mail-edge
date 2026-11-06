package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary tokens to the entitlement verifier under a fixed
// key the fuzzer does not control. It must never panic, and — the load-bearing
// property (§4, §8) — it must only return claims the edge is allowed to trust:
// a correct version, a 32-byte device key to bind the request to, a non-empty
// license hash, and a token that has not expired past the skew.
func FuzzVerify(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)
	skew := 5 * time.Minute

	// A validly-signed token so the corpus mutates around a real one, plus a
	// token signed by a different key (must never verify).
	good, err := Sign(Claims{
		Version:     Version,
		LicenseHash: []byte("lic-hash"),
		DeviceKey:   pub, // any 32 bytes; only the signing key matters for Verify
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(time.Hour).Unix(),
	}, priv)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	f.Add(good)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := Sign(Claims{Version: Version, LicenseHash: []byte("x"), DeviceKey: pub, ExpiresAt: now.Add(time.Hour).Unix()}, otherPriv)
	f.Add(forged)
	f.Add("")
	f.Add(".")
	f.Add("notbase64.notbase64")

	f.Fuzz(func(t *testing.T, token string) {
		c, err := Verify(token, pub, now, skew)
		if err != nil {
			if c != nil {
				t.Fatalf("error returned with non-nil claims: %v", err)
			}
			return
		}
		if c.Version != Version {
			t.Fatalf("accepted version %d", c.Version)
		}
		if len(c.DeviceKey) != ed25519.PublicKeySize {
			t.Fatalf("accepted device key of %d bytes", len(c.DeviceKey))
		}
		if len(c.LicenseHash) == 0 {
			t.Fatalf("accepted empty license hash")
		}
		if now.Unix() > c.ExpiresAt+int64(skew.Seconds()) {
			t.Fatalf("accepted expired token: now=%d exp=%d", now.Unix(), c.ExpiresAt)
		}
	})
}
