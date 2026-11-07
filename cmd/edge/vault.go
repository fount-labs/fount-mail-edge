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
// vault: the vault only seals to an attested edge release, and wire.Pull refuses
// any keyset but the committed one, so a fake vault gets nothing and gives nothing.
func pullKeys(ctx context.Context, cfg *config.Config, k *keys.Keys) error {
	client := &http.Client{Timeout: 90 * time.Second}
	attester := wire.NewSocketAttester(wire.AttestationSocket)
	wait := vaultRetryFirst
	for {
		for _, host := range cfg.VaultHosts {
			got, err := wire.Pull(ctx, client, "https://"+host, k.Transfer, attester, nil, cfg.KeysetCommitment)
			if err == nil {
				err = cfg.InstallVaultKeys(got)
			}
			if err == nil {
				log.Printf("edge: keyset %s from %s in %s", got.Keyset.Commitment(), host, got.Elapsed.Round(time.Millisecond))
				return nil
			}
			log.Printf("edge: keys from %s: %v", host, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped while waiting for a vault: %w", ctx.Err())
		case <-time.After(wait):
		}
		wait = min(wait*2, vaultRetryMax)
	}
}
