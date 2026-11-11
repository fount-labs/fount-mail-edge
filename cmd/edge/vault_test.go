package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/fount-labs/fount-mail-vault/wire"
)

func TestPullRound(t *testing.T) {
	keyset, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	sendKeyset, err := wire.GenerateSend()
	if err != nil {
		t.Fatal(err)
	}
	full := &wire.PullResult{Keyset: keyset, SendKeyset: sendKeyset}
	bare := &wire.PullResult{Keyset: keyset}
	down := errors.New("vault down")
	type answer struct {
		got *wire.PullResult
		err error
	}
	cases := map[string]struct {
		vaults    map[string]answer
		wantSend  bool
		ok        bool
		asked     []string
		installed []string
		send      bool // the last install had a send keyset
	}{
		"no send commitment, first vault": {
			vaults: map[string]answer{"a": {got: bare}, "b": {got: bare}},
			ok:     true, asked: []string{"a"}, installed: []string{"a"},
		},
		"first vault has both": {
			vaults:   map[string]answer{"a": {got: full}, "b": {got: full}},
			wantSend: true, ok: true, asked: []string{"a"}, installed: []string{"a"}, send: true,
		},
		"second vault has the send keyset": {
			vaults:   map[string]answer{"a": {got: bare}, "b": {got: full}},
			wantSend: true, ok: true, asked: []string{"a", "b"}, installed: []string{"a", "b"}, send: true,
		},
		"no vault has it: boot with the keyset, sending off": {
			vaults:   map[string]answer{"a": {got: bare}, "b": {got: bare}},
			wantSend: true, ok: true, asked: []string{"a", "b"}, installed: []string{"a"},
		},
		"first vault down, second has no send keyset": {
			vaults:   map[string]answer{"a": {err: down}, "b": {got: bare}},
			wantSend: true, ok: true, asked: []string{"a", "b"}, installed: []string{"b"},
		},
		"every vault down": {
			vaults:   map[string]answer{"a": {err: down}, "b": {err: down}},
			wantSend: true, asked: []string{"a", "b"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var asked, installed []string
			var last *wire.PullResult
			pull := func(_ context.Context, host string) (*wire.PullResult, error) {
				asked = append(asked, host)
				a := c.vaults[host]
				return a.got, a.err
			}
			install := func(r *wire.PullResult) error {
				installed = append(installed, asked[len(asked)-1])
				last = r
				return nil
			}
			ok := pullRound(context.Background(), []string{"a", "b"}, pull, install, c.wantSend)
			if ok != c.ok || !slices.Equal(asked, c.asked) || !slices.Equal(installed, c.installed) {
				t.Fatalf("ok=%v asked=%v installed=%v, want %v %v %v", ok, asked, installed, c.ok, c.asked, c.installed)
			}
			if ok && (last.SendKeyset != nil) != c.send {
				t.Fatalf("installed a send keyset: %v, want %v", last.SendKeyset != nil, c.send)
			}
		})
	}
}

// A vault whose keys don't install (no S3 credentials) is skipped like one that's down.
func TestPullRoundSkipsAVaultThatFailsToInstall(t *testing.T) {
	keyset, err := wire.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	pull := func(_ context.Context, host string) (*wire.PullResult, error) {
		asked = append(asked, host)
		return &wire.PullResult{Keyset: keyset}, nil
	}
	install := func(*wire.PullResult) error {
		if asked[len(asked)-1] == "a" {
			return errors.New("no S3 credentials")
		}
		return nil
	}
	if !pullRound(context.Background(), []string{"a", "b"}, pull, install, false) || !slices.Equal(asked, []string{"a", "b"}) {
		t.Fatalf("asked %v", asked)
	}
}
