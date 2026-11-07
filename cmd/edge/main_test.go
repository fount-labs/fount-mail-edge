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
