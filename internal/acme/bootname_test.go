package acme

import (
	"slices"
	"testing"
)

func TestWithBootName(t *testing.T) {
	hosts := []string{"mx1.example", "mx2.example"}
	if got := WithBootName(hosts, ""); !slices.Equal(got, hosts) {
		t.Fatalf("no boot domain: %v", got)
	}
	a, b := WithBootName(hosts, "boot.example"), WithBootName(hosts, "boot.example")
	if len(a) != 3 || !slices.Equal(a[:2], hosts) {
		t.Fatalf("with boot domain: %v", a)
	}
	if !IsBootName(a[2], "boot.example") {
		t.Fatalf("%q isn't a boot name", a[2])
	}
	if a[2] == b[2] {
		t.Fatalf("two boots got the same name %q", a[2])
	}
	if len(hosts) != 2 {
		t.Fatal("WithBootName changed its input")
	}
}

func TestIsBootName(t *testing.T) {
	good := "abcdefghijklmnopqrstuvwxyz.boot.example"
	if !IsBootName(good, "boot.example") {
		t.Fatalf("%q refused", good)
	}
	for _, name := range []string{
		"abcdefghijklmnopqrstuvwxy.boot.example",    // too short
		"abcdefghijklmnopqrstuvwxyz2.boot.example",  // too long
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ.boot.example",   // upper case
		"abcdefghijklmnopqrstuvwxy1.boot.example",   // not base32
		"abcdefghijklmnopqrstuvwxyz.other.example",  // another domain
		"a.abcdefghijklmnopqrstuvwxyz.boot.example", // two labels deep
		"boot.example",
		"",
	} {
		if IsBootName(name, "boot.example") {
			t.Errorf("%q accepted", name)
		}
	}
	if IsBootName(good, "") {
		t.Error("accepted with no boot domain")
	}
}
