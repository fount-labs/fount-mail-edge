package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

type fakeCache struct {
	cert   *tls.Certificate
	stored *tls.Certificate
}

func (f *fakeCache) Load(string) (*tls.Certificate, bool) {
	return f.cert, f.cert != nil
}
func (f *fakeCache) Store(_ string, c *tls.Certificate) error {
	f.stored = c
	return nil
}

func TestRunLoopCacheHitSkipsIssuance(t *testing.T) {
	cached := &tls.Certificate{}
	cache := &fakeCache{cert: cached}
	m := NewManager()
	issued := false

	// reachable never fires; a cache hit must return before touching it.
	RunLoop(context.Background(), m, cache, make(chan struct{}), "host", func(context.Context, string) (*tls.Certificate, error) {
		issued = true
		return nil, nil
	})

	if issued {
		t.Fatal("issuance ran despite a cache hit")
	}
	if cur, ok := m.Current(); !ok || cur != cached {
		t.Fatal("cached cert was not installed")
	}
}

func TestRunLoopRetriesThenInstallsAndCaches(t *testing.T) {
	readyWait, retryBackoff = time.Millisecond, time.Millisecond
	defer func() { readyWait, retryBackoff = 15*time.Second, 3*time.Minute }()

	m := NewManager()
	cache := &fakeCache{}
	reachable := make(chan struct{})
	close(reachable)

	cert := &tls.Certificate{}
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	RunLoop(ctx, m, cache, reachable, "host", func(context.Context, string) (*tls.Certificate, error) {
		calls++
		if calls < 2 {
			return nil, errors.New("transient")
		}
		return cert, nil
	})

	if calls != 2 {
		t.Fatalf("want 2 issuance attempts (1 fail, 1 success), got %d", calls)
	}
	if cur, ok := m.Current(); !ok || cur != cert {
		t.Fatal("issued cert was not installed")
	}
	if cache.stored != cert {
		t.Fatal("issued cert was not cached")
	}
}
