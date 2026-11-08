package operator

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoleKeysPairUp(t *testing.T) {
	priv, pub, err := GenerateRoleKeys("abuse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewMailbox("abuse", "fountbox.com", pub); err != nil {
		t.Fatalf("provision would refuse the public keys: %v", err)
	}
	dec, err := ecdh.X25519().NewPrivateKey(priv.DecryptionKey)
	if err != nil || string(dec.PublicKey().Bytes()) != string(pub.DecryptionKey) {
		t.Fatal("decryption key doesn't match")
	}
	for name, pair := range map[string][2][]byte{
		"signing": {priv.SigningKey, pub.SigningKey},
		"mailbox": {priv.MailboxKey, pub.MailboxKey},
		"owner":   {priv.OwnerChangeKey, pub.OwnerChangeKey},
	} {
		got := ed25519.NewKeyFromSeed(pair[0]).Public().(ed25519.PublicKey)
		if string(got) != string(pair[1]) {
			t.Errorf("%s key doesn't match", name)
		}
	}
	pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), priv.PasskeyKey)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := pk.PublicKey.Bytes(); string(b) != string(pub.PasskeyKey) {
		t.Fatal("passkey key doesn't match")
	}
	if priv2, _, _ := GenerateRoleKeys("abuse"); string(priv2.SigningKey) == string(priv.SigningKey) {
		t.Fatal("two runs made the same key")
	}
}

func TestRoleKeysOnlyForRoles(t *testing.T) {
	if _, _, err := GenerateRoleKeys("admin"); err == nil {
		t.Fatal("made keys for a non-role address")
	}
}

func TestWriteRoleKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	privPath, pubPath, err := WriteRoleKeys(dir, "postmaster")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode %v, want 0600", info.Mode().Perm())
	}
	raw, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	var pub PublicKeys
	if err := json.Unmarshal(raw, &pub); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMailbox("postmaster", "fountbox.com", pub); err != nil {
		t.Fatalf("provision would refuse the written public keys: %v", err)
	}
	var p ProvisionPayload
	p.Role = "postmaster"
	if err := json.Unmarshal(raw, &p.Keys); err != nil || string(p.Keys.MailboxKey) != string(pub.MailboxKey) {
		t.Fatal("edgectl provision can't read the public file")
	}
	if _, _, err := WriteRoleKeys(dir, "postmaster"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrote existing keys: %v", err)
	}
}

func TestWriteRoleKeysRefusesARepo(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := WriteRoleKeys(filepath.Join(repo, "secrets", "abuse"), "abuse")
	if err == nil || !strings.Contains(err.Error(), "inside the git repo") {
		t.Fatalf("wrote keys inside a repo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "secrets")); !os.IsNotExist(err) {
		t.Fatal("created a directory inside the repo")
	}
}
