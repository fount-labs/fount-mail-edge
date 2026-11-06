package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sampleClaims(t *testing.T) (Claims, ed25519.PublicKey) {
	t.Helper()
	devPub, _ := mustKey(t)
	return Claims{
		LicenseHash: []byte("license-keyed-hash"),
		DeviceKey:   devPub,
		IssuedAt:    time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:   time.Now().Add(time.Hour).Unix(),
	}, devPub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	verifyPub, signPriv := mustKey(t)
	claims, devPub := sampleClaims(t)

	tok, err := Sign(claims, signPriv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(tok, verifyPub, time.Now(), time.Minute)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got.DeviceKey) != string(devPub) {
		t.Fatal("device key mismatch")
	}
	if string(got.LicenseHash) != "license-keyed-hash" {
		t.Fatal("license hash mismatch")
	}
	if got.Version != Version {
		t.Fatalf("version = %d", got.Version)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, signPriv := mustKey(t)
	otherPub, _ := mustKey(t)
	claims, _ := sampleClaims(t)
	tok, _ := Sign(claims, signPriv)

	if _, err := Verify(tok, otherPub, time.Now(), time.Minute); err != ErrSignature {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	verifyPub, signPriv := mustKey(t)
	claims, _ := sampleClaims(t)
	tok, _ := Sign(claims, signPriv)

	// Flip a byte in the payload segment.
	b := []byte(tok)
	b[0] ^= 0x01
	if _, err := Verify(string(b), verifyPub, time.Now(), time.Minute); err == nil {
		t.Fatal("tampered token must not verify")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	verifyPub, signPriv := mustKey(t)
	claims, _ := sampleClaims(t)
	claims.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	tok, _ := Sign(claims, signPriv)

	if _, err := Verify(tok, verifyPub, time.Now(), time.Minute); err != ErrExpired {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	// Within skew it is still accepted.
	claims.ExpiresAt = time.Now().Add(-30 * time.Second).Unix()
	tok, _ = Sign(claims, signPriv)
	if _, err := Verify(tok, verifyPub, time.Now(), time.Minute); err != nil {
		t.Fatalf("within skew should pass: %v", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	verifyPub, _ := mustKey(t)
	for _, tok := range []string{"", "nodot", "only.", ".only", "!!.??"} {
		if _, err := Verify(tok, verifyPub, time.Now(), time.Minute); err == nil {
			t.Fatalf("token %q should be rejected", tok)
		}
	}
}

func TestVerifyRejectsBadVersion(t *testing.T) {
	verifyPub, signPriv := mustKey(t)
	claims, _ := sampleClaims(t)
	claims.Version = 2
	tok, _ := Sign(claims, signPriv)
	if _, err := Verify(tok, verifyPub, time.Now(), time.Minute); err != ErrVersion {
		t.Fatalf("err = %v, want ErrVersion", err)
	}
}
