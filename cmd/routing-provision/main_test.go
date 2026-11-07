package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func keysJSON(t *testing.T, change func(*publicKeys)) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	k := publicKeys{
		DecryptionKey: key(1), SigningKey: key(2), MailboxKey: key(3), OwnerChangeKey: key(4),
		PasskeyKey: append([]byte{0x04}, append(priv.X.FillBytes(make([]byte, 32)), priv.Y.FillBytes(make([]byte, 32))...)...),
	}
	if change != nil {
		change(&k)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNewMailbox(t *testing.T) {
	m, err := newMailbox("abuse", "fountbox.com", keysJSON(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if m.Address != "abuse@fountbox.com" || m.EntitlementExp != 0 || len(m.LicenseHash) != 0 {
		t.Fatalf("mailbox = %+v", m)
	}
}

func TestOnlyRoleAddresses(t *testing.T) {
	for _, role := range []string{"", "admin", "support", "worker", "abuse@fountbox.com"} {
		if _, err := newMailbox(role, "@fountbox.com", keysJSON(t, nil)); err == nil {
			t.Errorf("role %q accepted", role)
		}
	}
}

func TestRefusesBadKeys(t *testing.T) {
	for name, change := range map[string]func(*publicKeys){
		"decryption": func(k *publicKeys) { k.DecryptionKey = nil },
		"signing":    func(k *publicKeys) { k.SigningKey = []byte{1} },
		"mailbox":    func(k *publicKeys) { k.MailboxKey = nil },
		"owner":      func(k *publicKeys) { k.OwnerChangeKey = nil },
		"passkey":    func(k *publicKeys) { k.PasskeyKey = []byte{4} },
	} {
		if _, err := newMailbox("abuse", "@fountbox.com", keysJSON(t, change)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
