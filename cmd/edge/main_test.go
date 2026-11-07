package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/certs"
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
