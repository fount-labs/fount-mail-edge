// Command routing-restore installs a routing backup as the live routing object. It
// runs from an operator's machine, with every edge stopped; docs/RESTORE.md is the
// full procedure. Without -write it only verifies the backup and reports what it
// holds.
//
// It reads the same values the edge does: ROUTING_DATA_KEY, S3_ACCESS_KEY_ID, and
// S3_SECRET_ACCESS_KEY come from the keyserver's secrets, and S3_BUCKET and
// S3_REGION from tinfoil-config.yml.
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
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/s3"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type options struct {
	backup, bootRecord string
	skip               uint64
	write, replace     bool
}

func main() {
	var o options
	flag.StringVar(&o.backup, "backup", "", "a backup object downloaded from the routing backup bucket")
	flag.StringVar(&o.bootRecord, "boot-record", "", "the signing boot's record, if edge/boots no longer has it")
	flag.Uint64Var(&o.skip, "skip-sequences", 0, "move every sequence counter forward by this much")
	flag.BoolVar(&o.write, "write", false, "install the backup; without this, only verify it")
	flag.BoolVar(&o.replace, "replace", false, "allow replacing an existing routing object")
	flag.Parse()
	if err := run(o); err != nil {
		log.Fatalf("routing-restore: %v", err)
	}
}

func run(o options) error {
	if o.backup == "" {
		return errors.New("-backup is required")
	}
	key, err := config.RequireKey("ROUTING_DATA_KEY")
	if err != nil {
		return err
	}
	bucket, region := os.Getenv("S3_BUCKET"), os.Getenv("S3_REGION")
	if bucket == "" || region == "" {
		return errors.New("S3_BUCKET and S3_REGION are required")
	}
	blobs, err := s3.New(s3.Config{
		Endpoint:        "https://" + bucket + ".s3." + region + ".amazonaws.com",
		Region:          region,
		AccessKeyID:     os.Getenv("S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("S3_SECRET_ACCESS_KEY"),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	framed, err := os.ReadFile(o.backup)
	if err != nil {
		return err
	}
	bootID, err := routing.BackupBootID(framed)
	if err != nil {
		return err
	}
	record, err := bootRecord(ctx, blobs, o.bootRecord, hex.EncodeToString(bootID))
	if err != nil {
		return err
	}
	object, err := routing.OpenBackup(framed, record.SigningKey)
	if err != nil {
		return err
	}
	r := routing.Restore{Object: object, RoutingDataKey: key, SkipSequences: o.skip, Replace: o.replace}
	sum, err := r.Inspect()
	if err != nil {
		return err
	}
	fmt.Printf("backup signed by boot %x: generation %d, %d mailboxes, sequence total %d\n",
		bootID, sum.Generation, sum.Mailboxes, sum.Sequences)
	if !o.write {
		fmt.Println("verified; nothing written")
		return nil
	}
	sum, err = r.Apply(ctx, blobs)
	if err != nil {
		return err
	}
	fmt.Printf("restored: generation %d, sequence total %d\n", sum.Generation, sum.Sequences)
	return nil
}

// bootRecord finds the key that signed the backup: from a file when the operator
// has fetched the boot log's copy, and otherwise from the mail bucket.
func bootRecord(ctx context.Context, blobs store.Blobs, path, bootID string) (store.Boot, error) {
	var (
		raw []byte
		err error
	)
	if path != "" {
		raw, err = os.ReadFile(path)
	} else {
		raw, err = blobs.Get(ctx, "edge/boots/"+bootID)
	}
	if err != nil {
		return store.Boot{}, fmt.Errorf("boot record %s: %w", bootID, err)
	}
	var b store.Boot
	if err := json.Unmarshal(raw, &b); err != nil {
		return store.Boot{}, fmt.Errorf("boot record %s: %w", bootID, err)
	}
	if b.BootID != bootID {
		return store.Boot{}, fmt.Errorf("boot record is for %s, want %s", b.BootID, bootID)
	}
	return b, nil
}
