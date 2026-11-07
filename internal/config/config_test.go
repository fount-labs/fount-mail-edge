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
	for _, k := range []string{"ACME_ACCOUNT_KEY", "ADDRESS_MAC_KEY", "ROUTING_DATA_KEY", "ENTITLEMENT_VERIFY_KEY", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"} {
		t.Setenv(k, "x")
	}
	t.Setenv("ENTITLEMENT_VERIFY_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)))
	t.Setenv("ACME_DIRECTORY", acmeProduction)
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
