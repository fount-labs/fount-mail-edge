package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// setSecrets sets a release's measured config. The name is historical: a release
// no longer has secrets in its environment.
func setSecrets(t *testing.T) {
	t.Helper()
	for _, k := range SecretNames {
		os.Unsetenv(k)
	}
	t.Setenv("VAULT_HOSTS", "vault-a.example,vault-b.example")
	t.Setenv("KEYSET_COMMITMENT", strings.Repeat("ab", 32))
	t.Setenv("ENTITLEMENT_VERIFY_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)))
	t.Setenv("OPERATOR_KEY", strings.Repeat("cd", 32))
	t.Setenv("ACME_DIRECTORY", acmeProduction)
	t.Setenv("EGRESS_FORWARDER", "forwarder")
	t.Setenv("EGRESS_ROUTES", "9001=mail.s3.us-east-1.amazonaws.com,9002=log.s3.us-east-1.amazonaws.com")
	t.Setenv("S3_BUCKET", "mail")
	t.Setenv("S3_BOOT_LOG_BUCKET", "log")
	t.Setenv("S3_REGION", "us-east-1")
	for _, k := range append([]string{"SEND_LINK"}, SendSettings...) {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestReleaseRefusesAnEgressGap(t *testing.T) {
	cases := map[string]struct{ key, value, want string }{
		"no forwarder":      {"EGRESS_FORWARDER", "", "EGRESS_FORWARDER"},
		"no routes":         {"EGRESS_ROUTES", "", "EGRESS_ROUTES"},
		"bad routes":        {"EGRESS_ROUTES", "9001", "EGRESS_ROUTES"},
		"unrouted bucket":   {"S3_BUCKET", "other", "no route to other.s3"},
		"unrouted log":      {"S3_BOOT_LOG_BUCKET", "other", "no route to other.s3"},
		"unrouted endpoint": {"S3_ENDPOINT", "https://other.example", "no route to other.example"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			setSecrets(t)
			t.Setenv("EDGE_DEV", "")
			t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
			t.Setenv(c.key, c.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load() err = %v", err)
			}
		})
	}
}

func TestVisibleSecret(t *testing.T) {
	for _, k := range SecretNames {
		os.Unsetenv(k)
	}
	if got := VisibleSecret(); got != "" {
		t.Fatalf("VisibleSecret() = %q", got)
	}
	for _, k := range SecretNames {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "")
			if got := VisibleSecret(); got != k {
				t.Fatalf("VisibleSecret() = %q", got)
			}
		})
	}
}

// The release config is what's measured, so hold it to the egress design. The
// format is plain enough to read without a YAML parser, which keeps go.mod empty.
func TestReleaseConfigEgress(t *testing.T) {
	data, err := os.ReadFile("../../tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	nets, rest, ok := strings.Cut(text[strings.Index(text, "\nnetworks:"):], "\ncontainers:")
	if !ok {
		t.Fatal("no containers section")
	}
	_, forwarder, ok := strings.Cut(rest, "- name: forwarder")
	if !ok {
		t.Fatal("no forwarder container")
	}
	_, edge, ok := strings.Cut(rest, "- name: mail-core")
	if !ok {
		t.Fatal("no mail-core container")
	}
	edge, _, _ = strings.Cut(edge, "\n  - name: ")
	field := func(block, key string) string {
		_, v, ok := strings.Cut(block, key)
		if !ok {
			t.Fatalf("no %s", key)
		}
		v, _, _ = strings.Cut(v, "\n")
		v, _, _ = strings.Cut(v, " #")
		return strings.Trim(strings.TrimSpace(v), `"`)
	}

	if strings.Contains(nets, "amazonaws.com") {
		t.Error("a bucket is back on the allowlist, which S3 doesn't work through")
	}
	if got := field(edge, "networks: "); got != "[edge, internal, frontlink, sendnet]" {
		t.Errorf("mail-core networks = %s", got)
	}
	if got := field(forwarder, "networks: "); got != "[internal, storage]" {
		t.Errorf("forwarder networks = %s", got)
	}
	if !strings.Contains(nets, "storage:\n    egress: open") {
		t.Error("storage isn't the open network")
	}
	for _, k := range []string{"secrets:", "keys:", "ports:", "cvm_admin"} {
		if strings.Contains(forwarder, k) {
			t.Errorf("forwarder has %s", k)
		}
	}
	if a, b := field(edge, "image: "), field(forwarder, "image: "); a != b {
		t.Errorf("images differ: %s, %s", a, b)
	}
	if got := field(edge, "EGRESS_FORWARDER: "); got != "forwarder" {
		t.Errorf("EGRESS_FORWARDER = %s", got)
	}
	routes := field(edge, "EGRESS_ROUTES: ")
	if got := field(forwarder, "EGRESS_ROUTES: "); got != routes {
		t.Errorf("the containers' routes differ:\n%s\n%s", routes, got)
	}
	region := field(edge, "S3_REGION: ")
	for _, k := range []string{"S3_BUCKET: ", "S3_BOOT_LOG_BUCKET: ", "S3_BACKUP_BUCKET: "} {
		if host := field(edge, k) + ".s3." + region + ".amazonaws.com"; !strings.Contains(routes, "="+host) {
			t.Errorf("no route to %s", host)
		}
	}
	// Keys come from the vault, so nothing may come from a keyserver or Tinfoil.
	for _, k := range []string{"keyserver-url", "secrets:"} {
		if strings.Contains(text, k) {
			t.Errorf("the config still has %s", k)
		}
	}
	if !strings.Contains(edge, "attestation: true") {
		t.Error("mail-core has no attestation socket, so it can't pull its keys")
	}
	if got := field(edge, "keys: "); !strings.Contains(got, "transfer") {
		t.Errorf("mail-core keys = %s, missing transfer", got)
	}
	if _, after, ok := strings.Cut(text, "- id: transfer"); !ok || !strings.HasPrefix(strings.SplitN(after, "\n", 3)[1], "    key: x25519") {
		t.Error("no x25519 transfer key")
	}
	_, edgeNet, _ := strings.Cut(nets, "\n  edge:")
	edgeNet, _, _ = strings.Cut(edgeNet, "\n  internal:")
	for _, host := range strings.Split(field(edge, "VAULT_HOSTS: "), ",") {
		if !strings.Contains(edgeNet, "- "+host) {
			t.Errorf("vault %s isn't on the edge allowlist", host)
		}
	}
}

// A staging certificate boots fine and every sender then refuses it.
func TestReleaseRefusesStagingACME(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	for name, v := range map[string]string{"unset": "", "explicit": acmeStaging} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ACME_DIRECTORY", v)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ACME_DIRECTORY") {
				t.Fatalf("Load() err = %v", err)
			}
		})
	}
}

func TestDevMayUseStagingACME(t *testing.T) {
	t.Setenv("EDGE_DEV", "1")
	t.Setenv("ACME_DIRECTORY", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.ACMEDirectory != acmeStaging {
		t.Fatalf("ACMEDirectory = %q", c.ACMEDirectory)
	}
}

// The measured config is what a release boots with, and Load refuses staging.
func TestReleaseConfigNamesProductionACME(t *testing.T) {
	raw, err := os.ReadFile("../../tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `ACME_DIRECTORY: "`+acmeProduction+`"`) {
		t.Fatalf("tinfoil-config.yml must set ACME_DIRECTORY to %s", acmeProduction)
	}
}

// KMS returns a DER key; loading it raw would reject every entitlement at runtime.
func TestReleaseRefusesWrongLengthVerifyKey(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	t.Setenv("ENTITLEMENT_VERIFY_KEY", base64.StdEncoding.EncodeToString(make([]byte, 44)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "ENTITLEMENT_VERIFY_KEY") {
		t.Fatalf("Load() err = %v", err)
	}
}

// A release can't boot with its tunnelled ports open to any tk_ key.
func TestReleaseRefusesMissingGatewayPins(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	for name, v := range map[string]string{"unset": "", "placeholder": "PLACEHOLDER"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("GATEWAY_CLIENT_PINS", v)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "GATEWAY_CLIENT_PINS") {
				t.Fatalf("Load() err = %v", err)
			}
		})
	}
}

func TestPinsLoad(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32)+","+strings.Repeat("cd", 32))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GatewayPins) != 2 {
		t.Fatalf("pins = %d", len(c.GatewayPins))
	}
}

func TestDevBootsWithoutPins(t *testing.T) {
	t.Setenv("EDGE_DEV", "1")
	t.Setenv("GATEWAY_CLIENT_PINS", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GatewayPins) != 0 {
		t.Fatalf("pins = %d", len(c.GatewayPins))
	}
}

func TestMailHostnames(t *testing.T) {
	t.Setenv("EDGE_DEV", "1")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.MailHostnames, ","); got != "mx1.fountbox.com,mx2.fountbox.com" {
		t.Fatalf("default hostnames = %q", got)
	}
	t.Setenv("MAIL_HOSTNAMES", " a.test , b.test,")
	if c, err = Load(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.MailHostnames, ","); got != "a.test,b.test" {
		t.Fatalf("hostnames = %q", got)
	}
	t.Setenv("MAIL_HOSTNAMES", " , ")
	if _, err := Load(); err == nil {
		t.Fatal("empty hostnames accepted")
	}
}

func TestReleaseNeedsAVaultAndCommitment(t *testing.T) {
	cases := map[string]struct{ key, value, want string }{
		"no vaults":         {"VAULT_HOSTS", "", "VAULT_HOSTS"},
		"vault url":         {"VAULT_HOSTS", "https://vault-a.example", "bare hostname"},
		"no commitment":     {"KEYSET_COMMITMENT", "", "KEYSET_COMMITMENT"},
		"bad commitment":    {"KEYSET_COMMITMENT", strings.Repeat("AB", 32), "KEYSET_COMMITMENT"},
		"no entitlement":    {"ENTITLEMENT_VERIFY_KEY", "", "ENTITLEMENT_VERIFY_KEY"},
		"no operator":       {"OPERATOR_KEY", "", "OPERATOR_KEY"},
		"short operator":    {"OPERATOR_KEY", strings.Repeat("cd", 31), "OPERATOR_KEY"},
		"base64 operator":   {"OPERATOR_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)), "OPERATOR_KEY"},
		"placeholder vault": {"VAULT_HOSTS", "PLACEHOLDER vault", "bare hostname"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			setSecrets(t)
			t.Setenv("EDGE_DEV", "")
			t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
			t.Setenv(c.key, c.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load() err = %v", err)
			}
		})
	}
}

func TestReleaseHoldsNoSecretsUntilTheVault(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Secrets.AddressMACKey != nil || c.Secrets.S3SecretAccessKey != "" {
		t.Fatal("a release loaded secrets before the vault")
	}
	k, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k}); err == nil || !strings.Contains(err.Error(), "S3 credentials") {
		t.Fatalf("installed keys with no S3 credentials: %v", err)
	}
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k, S3: &wire.S3Credentials{AccessKeyID: "A", SecretAccessKey: "B"}}); err != nil {
		t.Fatal(err)
	}
	if string(c.Secrets.AddressMACKey) != string(k.AddressMACKey[:]) || !strings.Contains(string(c.Secrets.ACMEAccountKeyPEM), "PRIVATE KEY") {
		t.Fatal("installed the wrong keys")
	}
}

func TestReleaseSendGates(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	c, err := Load()
	if err != nil || c.SendEnabled || c.SendKeysetCommitment != "" {
		t.Fatalf("unset: %+v %v", c, err)
	}
	for _, v := range []string{"true", "0"} {
		t.Setenv("SEND_ENABLED", v)
		if _, err := Load(); err == nil {
			t.Errorf("SEND_ENABLED=%q booted a release", v)
		}
	}
	t.Setenv("SEND_ENABLED", "")

	// The commitment alone takes the send keyset and leaves sending off.
	t.Setenv("SEND_KEYSET_COMMITMENT", strings.Repeat("ef", 32))
	if c, err := Load(); err != nil || c.SendEnabled || c.SendKeysetCommitment != strings.Repeat("ef", 32) {
		t.Fatalf("commitment only: %v", err)
	}
	t.Setenv("SEND_KEYSET_COMMITMENT", "EF")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SEND_KEYSET_COMMITMENT") {
		t.Fatalf("bad commitment: %v", err)
	}

	full := map[string]string{
		"SEND_ENABLED":           "1",
		"SEND_KEYSET_COMMITMENT": strings.Repeat("ef", 32),
		"SEND_RELAY_ADDR":        "gateway-a.example:8444",
		"SEND_RELAY_PINS":        strings.Repeat("12", 32),
		"DKIM_SELECTOR":          "f1",
	}
	for k, v := range full {
		t.Setenv(k, v)
	}
	if c, err := Load(); err != nil || !c.SendEnabled || len(c.SendRelayPins) != 1 || c.DKIMSelector != "f1" {
		t.Fatalf("every send setting: %v", err)
	}
	for _, missing := range []string{"SEND_KEYSET_COMMITMENT", "SEND_RELAY_ADDR", "SEND_RELAY_PINS", "DKIM_SELECTOR"} {
		t.Run("enabled without "+missing, func(t *testing.T) {
			t.Setenv(missing, "")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("booted, or the error doesn't name %s: %v", missing, err)
			}
		})
	}
	for k, bad := range map[string]string{"SEND_RELAY_ADDR": "gateway-a.example", "SEND_RELAY_PINS": "zz", "DKIM_SELECTOR": "f1._domainkey"} {
		t.Run("bad "+k, func(t *testing.T) {
			t.Setenv(k, bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("%s=%q: %v", k, bad, err)
			}
		})
	}
}

func TestDevMaySetSendEnabledAlone(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "1")
	t.Setenv("SEND_ENABLED", "1")
	if c, err := Load(); err != nil || !c.SendEnabled {
		t.Fatalf("dev: %v", err)
	}
}

func TestInstallSendKeyset(t *testing.T) {
	k, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	s3 := &wire.S3Credentials{AccessKeyID: "A", SecretAccessKey: "B"}

	c := &Config{SendKeysetCommitment: sk.Commitment()}
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k, S3: s3, SendKeyset: sk}); err != nil {
		t.Fatal(err)
	}
	got := c.Secrets.Send
	want, _ := sk.DKIMRSA()
	relay, _ := sk.RelayClient()
	if got == nil || got.Commitment != sk.Commitment() || !got.DKIMRSA.Equal(want) || !got.RelayClient.Equal(relay) {
		t.Fatal("installed the wrong send keys")
	}

	// A vault with no send keyset installs the rest, and a later one replaces it.
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k, S3: s3}); err != nil || c.Secrets.Send != nil {
		t.Fatalf("no send keyset: %v", err)
	}

	// Never installed without a commitment to check it against.
	c = &Config{}
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k, S3: s3, SendKeyset: sk}); err != nil || c.Secrets.Send != nil {
		t.Fatalf("installed an uncommitted send keyset: %v", err)
	}

	c = &Config{SendKeysetCommitment: strings.Repeat("ef", 32)}
	if err := c.InstallVaultKeys(&wire.PullResult{Keyset: k, S3: s3, SendKeyset: sk}); err == nil {
		t.Fatal("installed a send keyset that doesn't match the commitment")
	}
}

func TestReleaseConfigLeavesSendingOff(t *testing.T) {
	raw, err := os.ReadFile("../../tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SEND_ENABLED") {
		t.Fatal("tinfoil-config.yml must not set SEND_ENABLED until sending is proven")
	}
}
