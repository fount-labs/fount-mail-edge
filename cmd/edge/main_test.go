package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

func TestHealthcheckFollowsHealthRoute(t *testing.T) {
	srv := httptest.NewServer(health(certs.NewManager()))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := healthcheck(addr); err != nil {
		t.Fatalf("a healthy edge failed its check: %v", err)
	}
}

func TestHealthcheckFailsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if err := healthcheck(strings.TrimPrefix(srv.URL, "http://")); err == nil {
		t.Fatal("a 404 must fail the check")
	}
}

func TestHealthcheckFailsWhenNothingListens(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()
	if err := healthcheck(addr); err == nil {
		t.Fatal("a dead listener must fail the check")
	}
}

func TestDeviceAPIServerBoundsRequests(t *testing.T) {
	s := deviceAPIServer(":0", http.NotFoundHandler(), nil)
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 {
		t.Fatalf("a request could stall forever: %+v", s)
	}
	if s.MaxHeaderBytes == 0 || s.MaxHeaderBytes > 64<<10 {
		t.Fatalf("MaxHeaderBytes = %d", s.MaxHeaderBytes)
	}
}

func TestForwarderRefusesToRunWithASecret(t *testing.T) {
	t.Setenv("EGRESS_ROUTES", "9001=bucket.example")
	t.Setenv("S3_SECRET_ACCESS_KEY", "x")
	err := forward()
	if err == nil || !strings.Contains(err.Error(), "S3_SECRET_ACCESS_KEY") {
		t.Fatalf("forward() err = %v", err)
	}
}

func TestForwarderNeedsRoutes(t *testing.T) {
	t.Setenv("EGRESS_ROUTES", "")
	if err := forward(); err == nil || !strings.Contains(err.Error(), "EGRESS_ROUTES") {
		t.Fatalf("forward() err = %v", err)
	}
}

type flakyBoots struct {
	store.BootStore
	failures, calls int
}

func (b *flakyBoots) WriteBoot(context.Context) error {
	b.calls++
	if b.calls <= b.failures {
		return errors.New("s3 down")
	}
	return nil
}

func TestPublishBootRetries(t *testing.T) {
	b := &flakyBoots{failures: 2}
	if err := publishBoot(context.Background(), b, []time.Duration{0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if b.calls != 3 {
		t.Fatalf("calls = %d", b.calls)
	}
}

func TestPublishBootGivesUpLoudly(t *testing.T) {
	b := &flakyBoots{failures: 99}
	if err := publishBoot(context.Background(), b, []time.Duration{0, 0}); err == nil {
		t.Fatal("publishBoot hid a boot with no record")
	}
	if b.calls != 3 {
		t.Fatalf("calls = %d", b.calls)
	}
}
