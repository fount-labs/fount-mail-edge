package sendercheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The test binary doubles as the child, the way the edge binary does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == Subcommand {
		if err := Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type zone struct {
	mu    sync.Mutex
	v     vector
	asked []string
}

func (z *zone) TXT(_ context.Context, name string) ([]string, error) {
	z.mu.Lock()
	z.asked = append(z.asked, name)
	z.mu.Unlock()
	r, err := z.v.lookup(name)
	if err == errNoRecord {
		return nil, ErrNoRecord
	}
	return r, err
}

func selfCommand(t *testing.T) func(context.Context) *exec.Cmd {
	cmd, err := SelfCommand()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return m
}

func TestProcessRunsTheChild(t *testing.T) {
	v := vectors(t)["ed25519 relaxed"]
	z := &zone{v: v}
	p := &Process{Command: selfCommand(t), DNS: func() Resolver { return z }}
	out := p.Check(context.Background(), []byte(v.Raw), recipient, received)
	var got Verdict
	if err := decodeStrict(out, &got); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	sum := sha256.Sum256([]byte(v.Raw))
	if !got.Aligned || !got.RecipientSigned || got.CheckedBy != "edge" || got.V != 1 || got.RawSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("%s", out)
	}
	if got.DateSkewSeconds == nil || *got.DateSkewSeconds != -30 {
		t.Fatalf("skew %s", out)
	}
	if !slices.Equal(z.asked, []string{"s1._domainkey.example.com"}) {
		t.Fatalf("asked %v", z.asked)
	}
}

func TestProcessWithoutDNS(t *testing.T) {
	v := vectors(t)["ed25519 relaxed"]
	out := (&Process{Command: selfCommand(t)}).Check(context.Background(), []byte(v.Raw), recipient, received)
	var got Verdict
	if err := decodeStrict(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.Aligned || got.DKIM[0].Result != "temperror" {
		t.Fatalf("%s", out)
	}
}

// A name that isn't a DKIM key name is never asked.
func TestProcessAsksOnlyKeyNames(t *testing.T) {
	v := vectors(t)["ed25519 relaxed"]
	v.Raw = strings.Replace(v.Raw, "d=example.com", "d=exa!mple.com", 1)
	z := &zone{v: v}
	out := (&Process{Command: selfCommand(t), DNS: func() Resolver { return z }}).Check(context.Background(), []byte(v.Raw), recipient, received)
	if len(z.asked) != 0 {
		t.Fatalf("asked %v", z.asked)
	}
	var got Verdict
	if err := decodeStrict(out, &got); err != nil || got.DKIM[0].Result != "permerror" {
		t.Fatalf("%s %v", out, err)
	}
	for name, ok := range map[string]bool{
		"s1._domainkey.example.com":     true,
		"a.b._domainkey.mail.example.c": true,
		"example.com":                   false,
		"_domainkey.example.com":        false,
		"s1._domainkey.":                false,
		"s1._domainkey.exa mple.com":    false,
		"s1._domainkey.-x.com":          false,
	} {
		if ValidKeyName(name) != ok {
			t.Errorf("%q: want %v", name, ok)
		}
	}
}

func TestProcessFailsClosed(t *testing.T) {
	ctx := context.Background()
	raw := []byte(vectors(t)["ed25519 relaxed"].Raw)
	for name, cmd := range map[string]func(context.Context) *exec.Cmd{
		"crash": func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "echo boom >&2; exit 3")
		},
		"garbage": func(ctx context.Context) *exec.Cmd {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "cat >/dev/null & printf 'not a frame'")
		},
		"missing": func(ctx context.Context) *exec.Cmd { return exec.CommandContext(ctx, "/nonexistent/edge") },
	} {
		m := decode(t, (&Process{Command: cmd}).Check(ctx, raw, recipient, received))
		if len(m) != 3 || m["error"] != "the edge couldn't check the sender" || m["checked_by"] != "edge" {
			t.Errorf("%s: %v", name, m)
		}
	}
	m := decode(t, (&Process{Command: selfCommand(t)}).Check(ctx, []byte("no header end"), recipient, received))
	if len(m) != 3 || m["error"] != "the message header couldn't be read" {
		t.Errorf("unreadable: %v", m)
	}
}

// A child that lies about its verdict's shape isn't believed.
func TestFinishIsStrict(t *testing.T) {
	for _, b := range []string{`{"spf":{}}`, `{"from":{"address":"a","extra":1}}`, `not json`} {
		if _, err := finish([]byte(b), nil); err == nil {
			t.Errorf("%s accepted", b)
		}
	}
	out, err := finish([]byte(`{"v":7,"checked_by":"child","raw_sha256":"bogus","dkim":null}`), []byte("raw"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("raw"))
	m := decode(t, out)
	if m["v"] != float64(1) || m["checked_by"] != "edge" || m["raw_sha256"] != hex.EncodeToString(sum[:]) || m["dkim"] == nil {
		t.Fatalf("%s", out)
	}
}
