package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKey(t *testing.T, dir, id string, key any) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id, "private_key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keyDir(t *testing.T, ids ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, id := range ids {
		switch id {
		case "mail-tls":
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			writeKey(t, dir, id, k)
		case "mail-sign":
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			writeKey(t, dir, id, k)
		default:
			k, _ := ecdh.X25519().GenerateKey(rand.Reader)
			writeKey(t, dir, id, k)
		}
	}
	return dir
}

func TestSplitLoadsTakeOnlyTheirKeys(t *testing.T) {
	front, err := LoadFront(keyDir(t, "mail-tls"))
	if err != nil || front.TLS == nil || front.Sign != nil || front.Transfer != nil {
		t.Fatalf("front: %+v, %v", front, err)
	}
	core, err := LoadCore(keyDir(t, "mail-sign", "transfer"))
	if err != nil || core.TLS != nil || core.Sign == nil || core.Transfer == nil {
		t.Fatalf("core: %+v, %v", core, err)
	}
	snd, err := LoadSend(keyDir(t, "send-transfer"))
	if err != nil || snd.SendTransfer == nil || snd.TLS != nil || snd.Sign != nil || snd.Transfer != nil {
		t.Fatalf("send: %+v, %v", snd, err)
	}
	if _, err := LoadSend(keyDir(t)); err == nil {
		t.Fatal("mail-send booted with no send-transfer key")
	}
}

// A config that grants a container another's key must not boot.
func TestSplitLoadsRefuseAnotherContainersKey(t *testing.T) {
	for name, c := range map[string]struct {
		load func(string) (*Keys, error)
		ids  []string
		bad  string
	}{
		"front with transfer":      {LoadFront, []string{"mail-tls", "transfer"}, "transfer"},
		"front with mail-sign":     {LoadFront, []string{"mail-tls", "mail-sign"}, "mail-sign"},
		"front with send-transfer": {LoadFront, []string{"mail-tls", "send-transfer"}, "send-transfer"},
		"core with mail-tls":       {LoadCore, []string{"mail-sign", "transfer", "mail-tls"}, "mail-tls"},
		"core with send-transfer":  {LoadCore, []string{"mail-sign", "transfer", "send-transfer"}, "send-transfer"},
		"send with transfer":       {LoadSend, []string{"send-transfer", "transfer"}, "transfer"},
		"send with mail-sign":      {LoadSend, []string{"send-transfer", "mail-sign"}, "mail-sign"},
		"send with mail-tls":       {LoadSend, []string{"send-transfer", "mail-tls"}, "mail-tls"},
	} {
		if _, err := c.load(keyDir(t, c.ids...)); err == nil || !strings.Contains(err.Error(), c.bad) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
