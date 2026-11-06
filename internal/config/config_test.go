package config

import (
	"strings"
	"testing"
)

func setSecrets(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ACME_ACCOUNT_KEY", "ADDRESS_MAC_KEY", "ROUTING_DATA_KEY", "ENTITLEMENT_VERIFY_KEY", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"} {
		t.Setenv(k, "x")
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
