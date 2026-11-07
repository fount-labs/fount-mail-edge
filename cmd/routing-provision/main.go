// Command routing-provision adds a Fount-owned mailbox for a role address that must
// exist: abuse@ and postmaster@ (§4). The Device API refuses those names, so nobody
// can register them. It runs from an operator's machine, once per address, before
// the first release. An edge that's already running won't see the new mailbox until
// it next writes routing data, so stop it or expect a short delay.
//
// -keys names a JSON file of public keys, base64 encoded, with the field names of
// POST /mailbox. They come from the device that reads this mailbox, which holds the
// private halves. This command never sees those.
//
// It reads the same values the edge does: ROUTING_DATA_KEY, ADDRESS_MAC_KEY,
// S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY come from the keyserver's secrets, and
// S3_BUCKET, S3_BOOT_LOG_BUCKET, S3_REGION, and MAIL_DOMAIN from tinfoil-config.yml.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/s3"
	"github.com/fount-labs/fount-mail-edge/internal/store"
	"github.com/fount-labs/fount-mail-edge/internal/webauthn"
)

// roles are the addresses this command may create. It's deliberately no wider: the
// reserved list exists to keep every other name unregistered.
var roles = map[string]bool{"abuse": true, "postmaster": true}

type publicKeys struct {
	DecryptionKey  []byte `json:"decryption_key"`
	SigningKey     []byte `json:"signing_key"`
	MailboxKey     []byte `json:"mailbox_key"`
	OwnerChangeKey []byte `json:"owner_change_key"`
	PasskeyKey     []byte `json:"passkey_key"`
}

func main() {
	role := flag.String("role", "", "abuse or postmaster")
	keys := flag.String("keys", "", "JSON file of the mailbox's public keys")
	flag.Parse()
	if err := run(*role, *keys); err != nil {
		log.Fatalf("routing-provision: %v", err)
	}
}

func run(role, keysPath string) error {
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		return err
	}
	domain := os.Getenv("MAIL_DOMAIN")
	if domain == "" {
		return errors.New("MAIL_DOMAIN is required")
	}
	m, err := newMailbox(role, domain, raw)
	if err != nil {
		return err
	}
	routingKey, err := config.RequireKey("ROUTING_DATA_KEY")
	if err != nil {
		return err
	}
	macKey, err := config.RequireKey("ADDRESS_MAC_KEY")
	if err != nil {
		return err
	}
	bucket, logBucket := os.Getenv("S3_BUCKET"), os.Getenv("S3_BOOT_LOG_BUCKET")
	if bucket == "" || logBucket == "" {
		return errors.New("S3_BUCKET and S3_BOOT_LOG_BUCKET are required")
	}
	blobs, err := client(bucket)
	if err != nil {
		return err
	}
	logBlobs, err := client(logBucket)
	if err != nil {
		return err
	}
	keylog := store.New(nil, blobs, nil, nil, store.WithLogBlobs(logBlobs)).(store.KeyLog)
	m.Log = func(ctx context.Context, id, keyHash []byte) error {
		return keylog.AppendMailboxKeyHash(ctx, hex.EncodeToString(id), keyHash, time.Now().Unix())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rt, err := routing.New(ctx, blobs, routingKey, macKey)
	if err != nil {
		return err
	}
	id, err := rt.Create(ctx, m)
	if err != nil {
		return err
	}
	fmt.Printf("%s: mailbox %x\n", m.Address, id)
	return nil
}

func client(bucket string) (*s3.Client, error) {
	region := os.Getenv("S3_REGION")
	return s3.New(s3.Config{
		Endpoint:        "https://" + bucket + ".s3." + region + ".amazonaws.com",
		Region:          region,
		AccessKeyID:     os.Getenv("S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("S3_SECRET_ACCESS_KEY"),
	})
}

// newMailbox builds the record. It has no license and no entitlement expiry, so it
// doesn't count against anyone's license and never lapses.
func newMailbox(role, domain string, keysJSON []byte) (routing.NewMailbox, error) {
	if !roles[role] {
		return routing.NewMailbox{}, fmt.Errorf("role %q: want abuse or postmaster", role)
	}
	if !strings.HasPrefix(domain, "@") {
		domain = "@" + domain
	}
	var k publicKeys
	if err := json.Unmarshal(keysJSON, &k); err != nil {
		return routing.NewMailbox{}, fmt.Errorf("keys: %w", err)
	}
	for _, key := range [][]byte{k.DecryptionKey, k.SigningKey, k.MailboxKey, k.OwnerChangeKey} {
		if len(key) != 32 {
			return routing.NewMailbox{}, errors.New("keys must be 32 bytes")
		}
	}
	if !webauthn.ValidCredentialKey(k.PasskeyKey) {
		return routing.NewMailbox{}, errors.New("passkey key must be a P-256 point")
	}
	return routing.NewMailbox{
		Address:        role + domain,
		DecryptionKey:  k.DecryptionKey,
		SigningKey:     k.SigningKey,
		MailboxKey:     k.MailboxKey,
		OwnerChangeKey: k.OwnerChangeKey,
		PasskeyKey:     k.PasskeyKey,
	}, nil
}
