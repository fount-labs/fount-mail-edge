package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
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

func testKeys(t *testing.T) *keys.Keys {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, key any) {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(filepath.Join(path, "private_key.pem"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write("mail-tls", tlsKey)
	write("mail-sign", sign)
	k, err := keys.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A tunnel without a pinned client key can't reach SMTP, or anyone with a tk_ key
// could write a PROXY header naming a fake sender.
func TestTunnelRefusesAPlainConnection(t *testing.T) {
	cfg := &config.Config{GatewayPins: []gatewaytls.Pin{{1}}}
	ln, err := tunnelListener(cfg, testKeys(t), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 64))
		got <- err
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("PROXY TCP4 198.51.100.7 203.0.113.1 40000 25\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err == nil {
		t.Fatal("the edge read plaintext from a tunnel with no client key")
	}
}
