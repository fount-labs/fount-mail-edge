package config

import (
	"os"
	"strings"
	"testing"
)

func setFront(t *testing.T) {
	t.Helper()
	for _, k := range append(append([]string{"EDGE_DEV"}, FrontForbidden...), SecretNames...) {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("GATEWAY_CLIENT_PINS", strings.Repeat("ab", 32))
	t.Setenv("CORE_LINK", "mail-core:7025")
	t.Setenv("CORE_API", "mail-core:8080")
}

func TestLoadFront(t *testing.T) {
	setFront(t)
	f, err := LoadFront()
	if err != nil {
		t.Fatal(err)
	}
	if f.CoreLink != "mail-core:7025" || f.CoreAPI != "mail-core:8080" || len(f.GatewayPins) != 1 || f.SMTPAddr != ":2525" {
		t.Fatalf("%+v", f)
	}
}

// mail-front must refuse any setting that belongs to core or to sending, even
// an empty one, so a config can't quietly widen what front holds.
func TestLoadFrontRefusesCoreAndSendSettings(t *testing.T) {
	for _, k := range append(append([]string{}, FrontForbidden...), SecretNames...) {
		t.Run(k, func(t *testing.T) {
			setFront(t)
			t.Setenv(k, "")
			if _, err := LoadFront(); err == nil || !strings.Contains(err.Error(), k) {
				t.Fatalf("LoadFront with %s: %v", k, err)
			}
		})
	}
	for _, k := range SendSettings {
		found := false
		for _, f := range FrontForbidden {
			found = found || f == k
		}
		if !found {
			t.Errorf("%s isn't forbidden on front", k)
		}
	}
}

func TestLoadFrontNeedsCoreAndPins(t *testing.T) {
	for _, k := range []string{"CORE_LINK", "CORE_API", "GATEWAY_CLIENT_PINS"} {
		t.Run(k, func(t *testing.T) {
			setFront(t)
			os.Unsetenv(k)
			if _, err := LoadFront(); err == nil {
				t.Fatalf("LoadFront without %s", k)
			}
		})
	}
}

// mail-core terminates no tunnel, so it needs no gateway pins; the one-container
// edge still does.
func TestLoadCoreNeedsNoGatewayPins(t *testing.T) {
	setSecrets(t)
	t.Setenv("EDGE_DEV", "")
	t.Setenv("GATEWAY_CLIENT_PINS", "")
	if _, err := LoadCore(); err != nil {
		t.Fatalf("LoadCore: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load booted with no gateway pins")
	}
}
