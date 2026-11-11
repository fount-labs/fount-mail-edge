package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const (
	vaultRetryFirst = 5 * time.Second
	vaultRetryMax   = 2 * time.Minute
)

// pullKeys waits for a vault, trying each in turn. The edge doesn't verify the
// vault: the vault only seals to an attested edge release, and wire.PullKeysets
// refuses any keyset or send keyset but the committed ones, so a fake vault gets
// nothing and gives nothing.
func pullKeys(ctx context.Context, cfg *config.Config, k *keys.Keys) error {
	client := &http.Client{Timeout: 90 * time.Second}
	attester := wire.NewSocketAttester(wire.AttestationSocket)
	want := wire.Commitments{Keyset: cfg.KeysetCommitment, Send: cfg.SendKeysetCommitment}
	pull := func(ctx context.Context, host string) (*wire.PullResult, error) {
		return wire.PullKeysets(ctx, client, "https://"+host, k.Transfer, attester, nil, want)
	}
	wait := vaultRetryFirst
	for {
		if pullRound(ctx, cfg.VaultHosts, pull, cfg.InstallVaultKeys, want.Send != "") {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped while waiting for a vault: %w", ctx.Err())
		case <-time.After(wait):
		}
		wait = min(wait*2, vaultRetryMax)
	}
}

type pullFunc func(ctx context.Context, host string) (*wire.PullResult, error)

// pullRound asks each vault once and reports whether keys are installed. When
// the release wants a send keyset, a vault without one doesn't end the round:
// its keyset installs, and the next vault is asked for both. If none has the
// send keyset, the edge boots with what it has and sending stays off, because
// receiving mail mustn't wait on a key that only sending needs.
func pullRound(ctx context.Context, hosts []string, pull pullFunc, install func(*wire.PullResult) error, wantSend bool) bool {
	installed := ""
	for _, host := range hosts {
		got, err := pull(ctx, host)
		if err == nil && wantSend && got.SendKeyset == nil && installed != "" {
			log.Printf("edge: %s has no send keyset either", host)
			continue
		}
		if err == nil {
			err = install(got)
		}
		if err != nil {
			log.Printf("edge: keys from %s: %v", host, err)
			continue
		}
		log.Printf("edge: keyset %s from %s in %s", got.Keyset.Commitment(), host, got.Elapsed.Round(time.Millisecond))
		if got.SendKeyset != nil {
			log.Printf("edge: send keyset %s from %s", got.SendKeyset.Commitment(), host)
			return true
		}
		if !wantSend {
			return true
		}
		log.Printf("edge: %s has no send keyset", host)
		installed = host
	}
	if installed != "" {
		log.Printf("edge: no vault has the send keyset, so sending stays off until a restart finds one")
	}
	return installed != ""
}
