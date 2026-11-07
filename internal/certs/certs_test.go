package certs

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCache struct {
	mu     sync.Mutex
	cert   *tls.Certificate
	stored *tls.Certificate
	fails  int // Load errors this many times first
	loads  int
}

func (f *fakeCache) Load(string) (*tls.Certificate, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.loads <= f.fails {
		return nil, false, errors.New("s3 unavailable")
	}
	return f.cert, f.cert != nil, nil
}

func (f *fakeCache) Store(_ string, c *tls.Certificate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = c
	return nil
}

func (f *fakeCache) storedCert() *tls.Certificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stored
}

// certFor returns a certificate valid from notBefore to notAfter.
func certFor(t *testing.T, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "host"}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func fresh(t *testing.T) *tls.Certificate {
	t.Helper()
	return certFor(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
}

func fastTimers(t *testing.T) {
	t.Helper()
	r, b, m, c, g := readyWait, retryBackoff, maxBackoff, cacheRetry, renewGap
	readyWait, retryBackoff, maxBackoff, cacheRetry, renewGap = time.Millisecond, time.Millisecond, 8*time.Millisecond, time.Millisecond, time.Millisecond
	t.Cleanup(func() { readyWait, retryBackoff, maxBackoff, cacheRetry, renewGap = r, b, m, c, g })
}

func closed() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// run drives RunLoop until the test calls stop, and fails if it doesn't end.
func run(t *testing.T, m *Manager, cache Cache, reachable <-chan struct{}, issue IssueFunc) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunLoop(ctx, m, cache, reachable, "host", issue)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("RunLoop didn't stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 500 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestRunLoopCacheHitSkipsIssuance(t *testing.T) {
	cached := fresh(t)
	m := NewManager()
	var issued atomic.Bool

	// reachable never fires; a cache hit must not wait for it.
	run(t, m, &fakeCache{cert: cached}, make(chan struct{}), func(context.Context, string) (*tls.Certificate, error) {
		issued.Store(true)
		return nil, errors.New("unused")
	})
	waitFor(t, "the cached cert", func() bool { cur, ok := m.Current(); return ok && cur == cached })
	if issued.Load() {
		t.Fatal("issuance ran despite a good cached certificate")
	}
}

func TestRunLoopRetriesThenInstallsAndCaches(t *testing.T) {
	fastTimers(t)
	m := NewManager()
	cache := &fakeCache{}
	cert := fresh(t)
	var calls atomic.Int32
	run(t, m, cache, closed(), func(context.Context, string) (*tls.Certificate, error) {
		if calls.Add(1) < 2 {
			return nil, errors.New("transient")
		}
		return cert, nil
	})
	waitFor(t, "the issued cert", func() bool { cur, ok := m.Current(); return ok && cur == cert && cache.storedCert() == cert })
	if calls.Load() != 2 {
		t.Fatalf("want 2 issuance attempts (1 fail, 1 success), got %d", calls.Load())
	}
}

// A failed read of the cache must not spend one of the 5 certificates a week.
func TestCacheErrorIsNotAMiss(t *testing.T) {
	fastTimers(t)
	cached := fresh(t)
	m := NewManager()
	run(t, m, &fakeCache{cert: cached, fails: 3}, closed(), func(context.Context, string) (*tls.Certificate, error) {
		t.Error("issued a certificate because S3 had a bad moment")
		return nil, errors.New("unused")
	})
	waitFor(t, "the cached cert", func() bool { cur, ok := m.Current(); return ok && cur == cached })
}

func TestExpiredCachedCertificateIsReissued(t *testing.T) {
	fastTimers(t)
	m := NewManager()
	cert := fresh(t)
	old := certFor(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	run(t, m, &fakeCache{cert: old}, closed(), func(context.Context, string) (*tls.Certificate, error) { return cert, nil })
	waitFor(t, "the new cert", func() bool { cur, ok := m.Current(); return ok && cur == cert })
}

func TestRenewsAtTwoThirdsOfLifetime(t *testing.T) {
	fastTimers(t)
	now := time.Now()
	// 9 days long: two-thirds is 6 days in. Past that it renews at once.
	due := certFor(t, now.Add(-7*24*time.Hour), now.Add(2*24*time.Hour))
	notDue := certFor(t, now.Add(-5*24*time.Hour), now.Add(4*24*time.Hour))

	m := NewManager()
	var calls atomic.Int32
	next := fresh(t)
	run(t, m, &fakeCache{cert: notDue}, closed(), func(context.Context, string) (*tls.Certificate, error) {
		calls.Add(1)
		return next, nil
	})
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("renewed a certificate before two-thirds of its life")
	}

	m = NewManager()
	cache := &fakeCache{cert: due}
	run(t, m, cache, closed(), func(context.Context, string) (*tls.Certificate, error) {
		calls.Add(1)
		return next, nil
	})
	waitFor(t, "the renewal", func() bool { cur, ok := m.Current(); return ok && cur == next && cache.storedCert() == next })
}

// An expired cached certificate is a miss, so issuance still waits for the gateway.
// Going early would fail validation and spend the hourly allowance.
func TestExpiredCachedCertificateWaitsForTheGateway(t *testing.T) {
	fastTimers(t)
	old := certFor(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	var calls atomic.Int32
	run(t, NewManager(), &fakeCache{cert: old}, make(chan struct{}), func(context.Context, string) (*tls.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("gateway isn't there")
	})
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("issued before the gateway was reachable")
	}
}

// The loop carries on after a success, so the next certificate renews too.
func TestKeepsRenewing(t *testing.T) {
	fastTimers(t)
	now := time.Now()
	due := certFor(t, now.Add(-7*24*time.Hour), now.Add(2*24*time.Hour))
	next := fresh(t)
	m := NewManager()
	var calls atomic.Int32
	run(t, m, nil, closed(), func(context.Context, string) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			return due, nil
		}
		return next, nil
	})
	waitFor(t, "the second certificate", func() bool { cur, ok := m.Current(); return ok && cur == next })
}

// A renewal that keeps failing leaves the old certificate serving.
func TestFailedRenewalKeepsServing(t *testing.T) {
	fastTimers(t)
	now := time.Now()
	due := certFor(t, now.Add(-7*24*time.Hour), now.Add(2*24*time.Hour))
	m := NewManager()
	var calls atomic.Int32
	run(t, m, &fakeCache{cert: due}, closed(), func(context.Context, string) (*tls.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("gateway down")
	})
	waitFor(t, "three tries", func() bool { return calls.Load() >= 3 })
	if cur, ok := m.Current(); !ok || cur != due {
		t.Fatal("a failed renewal took down a good certificate")
	}
}

// A CA handing out certificates already due for renewal can't drive a tight loop.
func TestRenewalCantSpin(t *testing.T) {
	fastTimers(t)
	renewGap = 10 * time.Second
	now := time.Now()
	due := certFor(t, now.Add(-7*24*time.Hour), now.Add(2*24*time.Hour))
	var calls atomic.Int32
	stop := run(t, NewManager(), nil, closed(), func(context.Context, string) (*tls.Certificate, error) {
		calls.Add(1)
		return due, nil
	})
	time.Sleep(50 * time.Millisecond)
	stop()
	if calls.Load() != 1 {
		t.Fatalf("%d issuances", calls.Load())
	}
}

func TestCurrentStopsBeforeExpiry(t *testing.T) {
	m := NewManager()
	if _, ok := m.Current(); ok {
		t.Fatal("no certificate reported as servable")
	}
	m.Set(certFor(t, time.Now().Add(-time.Hour), time.Now().Add(expiryMargin+time.Minute)))
	if _, ok := m.Current(); !ok {
		t.Fatal("a certificate with time left wasn't served")
	}
	m.Set(certFor(t, time.Now().Add(-time.Hour), time.Now().Add(expiryMargin-time.Minute)))
	if _, ok := m.Current(); ok {
		t.Fatal("served a certificate about to expire")
	}
	m.Set(&tls.Certificate{})
	if _, ok := m.Current(); ok {
		t.Fatal("served an unreadable certificate")
	}
}

type waitErr struct{ d time.Duration }

func (e waitErr) Error() string             { return "rate limited" }
func (e waitErr) RetryAfter() time.Duration { return e.d }

func TestBackoff(t *testing.T) {
	plain := errors.New("x")
	for failures, want := range map[int]time.Duration{
		1: 15 * time.Minute, 2: 30 * time.Minute, 3: time.Hour, 5: 4 * time.Hour, 6: 4 * time.Hour, 500: 4 * time.Hour,
	} {
		if got := backoff(failures, plain); got != want {
			t.Errorf("backoff(%d) = %s, want %s", failures, got, want)
		}
	}
	if got := backoff(1, fmt.Errorf("newOrder: %w", waitErr{7 * time.Hour})); got != 7*time.Hour {
		t.Errorf("Retry-After ignored: %s", got)
	}
	if got := backoff(3, waitErr{time.Second}); got != time.Hour {
		t.Errorf("a short Retry-After shortened the backoff: %s", got)
	}
}

func TestBackoffSpacesFailedValidations(t *testing.T) {
	if 5*retryBackoff < time.Hour {
		t.Fatalf("%s between failures can exceed 5 failed validations an hour", retryBackoff)
	}
}
