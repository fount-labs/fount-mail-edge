package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

const testRPID = "mail.fount.sh"

// credential is a test P-256 passkey: the private key plus its 65-byte SEC1
// public key as the edge would have stored it at registration.
type credential struct {
	priv   *ecdsa.PrivateKey
	sec1   []byte
	origin string
}

func newCredential(tb testing.TB) credential {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	sec1 := append([]byte{0x04},
		append(priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32))...)...)
	return credential{priv: priv, sec1: sec1, origin: "https://" + testRPID}
}

// assert builds a valid assertion over challenge, the way a platform
// authenticator would: flags user-present+verified, rpIdHash = SHA256(rpID),
// signature over SHA256(authData || SHA256(clientDataJSON)).
func (c credential) assert(tb testing.TB, challenge []byte, flags byte) Assertion {
	tb.Helper()
	return c.assertType(tb, "webauthn.get", challenge, flags)
}

func (c credential) assertType(tb testing.TB, typ string, challenge []byte, flags byte) Assertion {
	tb.Helper()
	cdj := []byte(fmt.Sprintf(
		`{"type":"%s","challenge":"%s","origin":"%s","crossOrigin":false}`,
		typ, base64.RawURLEncoding.EncodeToString(challenge), c.origin))
	rpHash := sha256.Sum256([]byte(testRPID))
	authData := append(rpHash[:], flags, 0, 0, 0, 1)

	clientHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, digest[:])
	if err != nil {
		tb.Fatal(err)
	}
	return Assertion{AuthenticatorData: authData, ClientDataJSON: cdj, Signature: sig}
}

func TestVerifyRoundTrip(t *testing.T) {
	c := newCredential(t)
	ch := make([]byte, 32)
	rand.Read(ch)
	a := c.assert(t, ch, flagUserPresent|flagUserVerified)
	if err := Verify(c.sec1, a, ch, testRPID, c.origin); err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	// Origin check is optional: an empty expected origin still verifies.
	if err := Verify(c.sec1, a, ch, testRPID, ""); err != nil {
		t.Fatalf("valid assertion rejected with no origin check: %v", err)
	}
}

func TestVerifyRejections(t *testing.T) {
	c := newCredential(t)
	ch := make([]byte, 32)
	rand.Read(ch)

	tests := []struct {
		name string
		mut  func(*Assertion, *[]byte, *string, *string) // assertion, challenge, rpID, origin
		want error
	}{
		{"wrong challenge", func(_ *Assertion, chg *[]byte, _, _ *string) {
			*chg = make([]byte, 32)
			(*chg)[0] = 0xff
		}, ErrChallenge},
		{"wrong rp id", func(_ *Assertion, _ *[]byte, rp, _ *string) { *rp = "evil.example" }, ErrRPIDMismatch},
		{"wrong origin", func(_ *Assertion, _ *[]byte, _, o *string) { *o = "https://evil.example" }, ErrOrigin},
		{"no user-verified flag", func(a *Assertion, _ *[]byte, _, _ *string) {
			a.AuthenticatorData[32] = flagUserPresent // UP set, UV cleared
		}, ErrUserPresence},
		{"tampered signature", func(a *Assertion, _ *[]byte, _, _ *string) {
			a.Signature[len(a.Signature)-1] ^= 0x01
		}, ErrSignature},
		{"tampered client data", func(a *Assertion, _ *[]byte, _, _ *string) {
			a.ClientDataJSON = append(a.ClientDataJSON[:len(a.ClientDataJSON)-1], ' ', '}')
		}, ErrSignature},
		{"truncated auth data", func(a *Assertion, _ *[]byte, _, _ *string) {
			a.AuthenticatorData = a.AuthenticatorData[:10]
		}, ErrBadAuthData},
		{"garbage client data", func(a *Assertion, _ *[]byte, _, _ *string) {
			a.ClientDataJSON = []byte("not json")
		}, ErrBadClientData}, // rejected at the JSON parse, before the signature check
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := c.assert(t, ch, flagUserPresent|flagUserVerified)
			chg := append([]byte{}, ch...)
			rp, origin := testRPID, c.origin
			tc.mut(&a, &chg, &rp, &origin)
			if err := Verify(c.sec1, a, chg, rp, origin); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A registration ceremony's signature must not pass as a login. The real signature
// here covers the wrong type, so this reaches the type check.
func TestVerifyRejectsARegistration(t *testing.T) {
	c := newCredential(t)
	ch := make([]byte, 32)
	rand.Read(ch)
	a := c.assertType(t, "webauthn.create", ch, flagUserPresent|flagUserVerified)
	if err := Verify(c.sec1, a, ch, testRPID, c.origin); !errors.Is(err, ErrWrongType) {
		t.Fatalf("got %v, want %v", err, ErrWrongType)
	}
}

func TestVerifyWrongKey(t *testing.T) {
	c := newCredential(t)
	other := newCredential(t)
	ch := make([]byte, 32)
	rand.Read(ch)
	a := c.assert(t, ch, flagUserPresent|flagUserVerified)
	if err := Verify(other.sec1, a, ch, testRPID, c.origin); !errors.Is(err, ErrSignature) {
		t.Fatalf("assertion verified against the wrong key: %v", err)
	}
}

func TestParseP256Rejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", make([]byte, 64)},
		{"wrong prefix", append([]byte{0x02}, make([]byte, 64)...)},
		{"off curve", append([]byte{0x04}, make([]byte, 64)...)}, // X=Y=0 is not on P-256
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseP256(tc.in); !errors.Is(err, ErrBadKey) {
				t.Fatalf("got %v, want ErrBadKey", err)
			}
		})
	}
}

// FuzzVerify is the Tier-1 fuzz target for this parser: Verify must never panic
// on any assertion bytes, and must reject them. A real assertion is signed, so
// random fuzz input can only ever fail to verify, never pass.
func FuzzVerify(f *testing.F) {
	c := newCredential(f)
	ch := make([]byte, 32)
	rand.Read(ch)
	// Seed only with malformed shapes. A valid assertion is deliberately not
	// seeded: the fuzzer cannot forge an ECDSA signature, so Verify returning
	// nil would mean a genuine forgery — exactly what this asserts can't happen.
	rpHash := sha256.Sum256([]byte(testRPID))
	f.Add([]byte("short"), []byte(`{"type":"webauthn.get"}`), []byte{})
	f.Add(append(rpHash[:], 0x05, 0, 0, 0, 1), []byte(`{"type":"webauthn.get","challenge":"AAAA"}`), make([]byte, 70))

	f.Fuzz(func(t *testing.T, authData, cdj, sig []byte) {
		// Must not panic; and no fuzzed input may verify.
		if err := Verify(c.sec1, Assertion{authData, cdj, sig}, ch, testRPID, c.origin); err == nil {
			t.Fatalf("fuzz input unexpectedly verified")
		}
	})
}
