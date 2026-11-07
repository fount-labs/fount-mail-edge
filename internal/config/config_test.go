package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func setSecrets(t *testing.T) {
	t.Helper()
	for _, k := range SecretNames {
		t.Setenv(k, "x")
	}
	t.Setenv("ENTITLEMENT_VERIFY_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)))
	t.Setenv("ACME_DIRECTORY", acmeProduction)
	t.Setenv("EGRESS_FORWARDER", "forwarder")
	t.Setenv("EGRESS_ROUTES", "9001=mail.s3.us-east-1.amazonaws.com,9002=log.s3.us-east-1.amazonaws.com")
	t.Setenv("S3_BUCKET", "mail")
	t.Setenv("S3_BOOT_LOG_BUCKET", "log")
	t.Setenv("S3_REGION", "us-east-1")
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
	edge, forwarder, ok := strings.Cut(rest, "- name: forwarder")
	if !ok {
		t.Fatal("no forwarder container")
	}
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
	if got := field(edge, "networks: "); got != "[edge, internal]" {
		t.Errorf("edge networks = %s", got)
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
	_, secrets, _ := strings.Cut(edge, "secrets:")
	for _, name := range SecretNames {
		if !strings.Contains(secrets, "- "+name) {
			t.Errorf("%s isn't declared", name)
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
