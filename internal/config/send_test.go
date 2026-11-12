package config

import (
	"os"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"
)

func setSend(t *testing.T) {
	t.Helper()
	for _, k := range append(append(append([]string{"EDGE_DEV", "VAULT_HOSTS"}, SendForbidden...), SendSettings...), SecretNames...) {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("VAULT_HOSTS", "vault-a.example,vault-b.example")
}

func TestLoadSend(t *testing.T) {
	setSend(t)
	c, err := LoadSend()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.VaultHosts) != 2 || c.SendKeysetCommitment != "" || c.SendEnabled || c.Secrets.Send != nil {
		t.Fatalf("%+v", c)
	}
	os.Unsetenv("VAULT_HOSTS")
	if _, err := LoadSend(); err != nil {
		t.Fatalf("no commitment and no vaults: %v", err)
	}
	t.Setenv("SEND_KEYSET_COMMITMENT", strings.Repeat("ab", 32))
	if _, err := LoadSend(); err == nil {
		t.Fatal("a send commitment with no vault to pull it from")
	}
}

// mail-send keeps every gate Load has: SEND_ENABLED needs all the send settings.
func TestLoadSendKeepsTheSendGates(t *testing.T) {
	full := map[string]string{
		"SEND_ENABLED":           "1",
		"SEND_KEYSET_COMMITMENT": strings.Repeat("ab", 32),
		"SEND_RELAY_ADDR":        "out.fountbox.com:443",
		"SEND_RELAY_PINS":        strings.Repeat("cd", 32),
		"DKIM_SELECTOR":          "f1",
	}
	setSend(t)
	for k, v := range full {
		t.Setenv(k, v)
	}
	c, err := LoadSend()
	if err != nil || !c.SendEnabled || c.SendRelayAddr != "out.fountbox.com:443" {
		t.Fatalf("%+v %v", c, err)
	}
	for k := range full {
		if k == "SEND_ENABLED" {
			continue
		}
		t.Run(k, func(t *testing.T) {
			setSend(t)
			for k2, v := range full {
				if k2 != k {
					t.Setenv(k2, v)
				}
			}
			if _, err := LoadSend(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("SEND_ENABLED without %s: %v", k, err)
			}
		})
	}
}

func TestLoadSendRefusesOtherContainersSettings(t *testing.T) {
	for _, k := range append(append([]string{}, SendForbidden...), SecretNames...) {
		t.Run(k, func(t *testing.T) {
			setSend(t)
			t.Setenv(k, "")
			if _, err := LoadSend(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("LoadSend with %s: %v", k, err)
			}
		})
	}
}

// In a split edge the send settings live on mail-send alone: core refuses them,
// and only core may name mail-send.
func TestSendSettingsStayOffCore(t *testing.T) {
	for _, k := range SendSettings {
		t.Run(k, func(t *testing.T) {
			setSecrets(t)
			t.Setenv("EDGE_DEV", "")
			t.Setenv(k, "")
			if _, err := LoadCore(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("LoadCore with %s: %v", k, err)
			}
		})
	}
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("SEND_LINK", "mail-send:7026")
	c, err := LoadCore()
	if err != nil || c.SendLink != "mail-send:7026" {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SEND_LINK") {
		t.Fatalf("the one-container edge with SEND_LINK: %v", err)
	}
	t.Setenv("SEND_LINK", "mail-send")
	if _, err := LoadCore(); err == nil {
		t.Fatal("SEND_LINK with no port")
	}
}

func TestInstallSendKeysetChecksTheCommitment(t *testing.T) {
	sk, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	if err := c.InstallSendKeyset(sk); err == nil {
		t.Fatal("installed with no commitment")
	}
	c.SendKeysetCommitment = strings.Repeat("ab", 32)
	if err := c.InstallSendKeyset(sk); err == nil {
		t.Fatal("installed another keyset")
	}
	c.SendKeysetCommitment = sk.Commitment()
	if err := c.InstallSendKeyset(sk); err != nil || c.Secrets.Send == nil || c.Secrets.Send.Commitment != sk.Commitment() {
		t.Fatalf("%v", err)
	}
}
