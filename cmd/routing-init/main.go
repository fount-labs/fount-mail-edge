// Command routing-init writes the empty routing object for a new deployment. It
// runs once, from an operator's machine, before the first release. The edge
// refuses to boot without the object, so that a lost one can't be mistaken for a
// new deployment, and this never replaces an object that exists.
//
// It reads the same values the edge does: ROUTING_DATA_KEY, S3_ACCESS_KEY_ID, and
// S3_SECRET_ACCESS_KEY come from the keyserver's secrets, and S3_BUCKET and
// S3_REGION from tinfoil-config.yml. With -check it only reports what the edge's
// credentials see, and writes nothing.
package main

import (
	"context"
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

func main() {
	check := flag.Bool("check", false, "report what the credentials see, and write nothing")
	flag.Parse()
	if err := run(*check); err != nil {
		log.Fatalf("routing-init: %v", err)
	}
}

func run(check bool) error {
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

	if check {
		return report(ctx, blobs)
	}
	switch err := routing.Initialize(ctx, blobs, key); {
	case errors.Is(err, routing.ErrObjectExists):
		fmt.Println("routing object already exists; left it alone")
		return nil
	case err != nil:
		return err
	}
	fmt.Println("routing object written and read back")
	return nil
}

// report shows how S3 answers the edge's credentials. A missing object has to be
// a clean miss, because anything else is an error at boot.
func report(ctx context.Context, blobs *s3.Client) error {
	objs, err := blobs.List(ctx, "edge/")
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	fmt.Printf("list edge/: %d objects\n", len(objs))
	switch _, err := blobs.Get(ctx, routing.ObjectKey); {
	case err == nil:
		fmt.Println("routing object: present")
	case errors.Is(err, store.ErrNotFound):
		fmt.Println("routing object: absent (clean 404)")
	default:
		return fmt.Errorf("get: %w", err)
	}
	return nil
}
