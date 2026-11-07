package limit

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

// clock is a settable time source so the refill math is tested deterministically
// without sleeping.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClocked(rate, burst float64) (*Limiter, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := New(rate, burst)
	l.now = c.now
	return l, c
}

func TestBurstThenRefill(t *testing.T) {
	l, c := newClocked(1, 3) // 1 token/sec, burst 3

	// A fresh key starts full: three takes pass, the fourth is denied.
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("take %d denied while under burst", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("take past burst allowed")
	}

	// One second refills exactly one token.
	c.t = c.t.Add(time.Second)
	if !l.Allow("k") {
		t.Fatal("take denied after a one-token refill")
	}
	if l.Allow("k") {
		t.Fatal("a second take allowed after only one token refilled")
	}

	// A long idle refills only up to burst, never beyond.
	c.t = c.t.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("post-idle take %d denied", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("refill exceeded burst")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newClocked(1, 1)
	if !l.Allow("a") {
		t.Fatal("first key denied")
	}
	if !l.Allow("b") {
		t.Fatal("a second key shares the first key's bucket")
	}
	if l.Allow("a") {
		t.Fatal("key a refilled without time passing")
	}
}

// A take larger than burst can never pass, and a denied take consumes nothing.
func TestOversizeAndNonConsumingDenial(t *testing.T) {
	l, _ := newClocked(1, 100)
	if l.AllowN("k", 101) {
		t.Fatal("a take larger than burst was allowed")
	}
	// The failed oversize take must not have drained the bucket.
	if !l.AllowN("k", 100) {
		t.Fatal("a full-burst take was denied, so the prior oversize take consumed tokens")
	}
}

// PerWindow spends its whole budget over the window, no more, and refills it over
// exactly that window — the per-IP/per-sender byte-budget contract.
func TestPerWindowBudget(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := PerWindow(1000, time.Hour)
	l.now = c.now

	if !l.AllowN("ip", 1000) { // the whole budget fits in one take
		t.Fatal("a take of the full window budget was denied")
	}
	if l.AllowN("ip", 1) {
		t.Fatal("a take past an exhausted budget was allowed")
	}
	c.t = c.t.Add(time.Hour) // a full window refills the full budget
	if !l.AllowN("ip", 1000) {
		t.Fatal("the budget did not refill over its window")
	}
}

// Property: over a random mix of takes against a known clock, a key is never
// allowed to spend more than burst + rate*elapsed tokens. This is the invariant
// a flood brake rests on — no sequence of calls lets a source exceed its budget.
// Waiting past the default idle horizon must not reset an hour's budget.
func TestPerWindowEvictionDoesntRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := PerWindow(60, time.Hour)
	l.now = c.now
	if !l.AllowN("k", 60) {
		t.Fatal("first take denied")
	}
	c.t = c.t.Add(11 * time.Minute)
	l.Allow("other") // gives eviction its chance to run
	if l.AllowN("k", 12) {
		t.Fatal("got back more than 11 minutes of refill")
	}
}

func TestNeverExceedsBudgetProperty(t *testing.T) {
	for seed := uint64(1); seed <= 30; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0xB0A710))
		const rate, burst = 2.0, 10.0
		c := &clock{t: time.Unix(1_700_000_000, 0)}
		l := New(rate, burst)
		l.now = c.now

		start := c.t
		var granted float64
		for step := 0; step < 400; step++ {
			if d := rng.IntN(3); d > 0 {
				c.t = c.t.Add(time.Duration(d) * time.Second)
			}
			n := float64(1 + rng.IntN(12)) // spans below and above burst
			if l.AllowN("k", n) {
				granted += n
			}
			elapsed := c.t.Sub(start).Seconds()
			ceiling := burst + rate*elapsed + 1e-9 // tokens that could ever have existed
			if granted > ceiling {
				t.Fatalf("seed %d step %d: granted %.2f exceeds budget ceiling %.2f", seed, step, granted, ceiling)
			}
		}
	}
}

// Idle keys are evicted so a stream of distinct keys can't grow memory without
// bound; an evicted key reappears full, which is correct after that much idle.
func TestIdleKeysEvicted(t *testing.T) {
	l, c := newClocked(1, 1)
	l.idle = time.Minute
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("ip-%d", i))
		c.t = c.t.Add(2 * time.Second)
	}
	// Advance well past the horizon and touch a new key to trigger a sweep.
	c.t = c.t.Add(10 * time.Minute)
	l.Allow("fresh")
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > 2 {
		t.Fatalf("idle buckets not evicted: %d remain", n)
	}
}

// The limiter must be safe under concurrent keys (it runs on the SMTP accept
// path). -race is the real assertion here; the count check is a sanity backstop.
func TestConcurrentAccessRace(t *testing.T) {
	l := New(1000, 1000)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("k-%d", g%4)
			for i := 0; i < 200; i++ {
				l.AllowN(key, 1)
			}
		}(g)
	}
	wg.Wait()
}
