// Package limit provides a small, in-memory, per-enclave rate and volume
// limiter. It backs the flood brakes the design calls for (§6 "limits on stored
// bytes per IP and per sender domain", §7 connection limits, §8 "GET /handle …
// rate limited"): the edge can't verify a sender, so these cap how much a single
// source IP or sender domain can push, and how fast one caller can probe handle
// availability.
//
// State is per-process and resets on reboot by design. These are a brake on a
// live flood, not durable accounting — a reboot that clears them only re-opens a
// budget a reboot's worth of downtime already interrupted. Durable per-mailbox
// storage quotas (the 30-day / ~2 GB cap, §6) are a separate, store-level
// concern and are not this package's job.
package limit

import (
	"sync"
	"time"
)

// Limiter is a keyed token-bucket limiter. Each distinct key gets its own bucket
// that refills at Rate tokens per second up to Burst. A call takes some number of
// tokens (1 for a request-rate limit, the byte count for a volume limit) and is
// allowed only if that many are available. A single take can never exceed Burst,
// so Burst must be at least the largest unit a caller will ask for (e.g. the max
// message size for a per-IP byte budget), or every take fails.
//
// Buckets for keys untouched for longer than the idle horizon are evicted, so a
// stream of distinct keys (many source IPs) can't grow memory without bound.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
	idle    time.Duration
	now     func() time.Time // overridable in tests
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time // last access, for refill and eviction
}

// New returns a limiter whose buckets refill at rate tokens/sec up to burst.
func New(rate, burst float64) *Limiter {
	return &Limiter{
		rate:    rate,
		burst:   burst,
		idle:    10 * time.Minute,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// PerWindow builds a limiter that allows up to `total` tokens over `window`,
// refilling smoothly. Burst equals total, so one take as large as the whole
// budget still passes (a single max-size message fits a per-IP byte budget).
// Buckets last the whole window, because evicting a part-spent one hands its key a
// full budget.
func PerWindow(total float64, window time.Duration) *Limiter {
	secs := window.Seconds()
	if secs <= 0 {
		secs = 1
	}
	l := New(total/secs, total)
	if window > l.idle {
		l.idle = window
	}
	return l
}

// Allow is AllowN with a cost of one token.
func (l *Limiter) Allow(key string) bool { return l.AllowN(key, 1) }

// AllowN takes n tokens from key's bucket, returning true if they were available.
// A rejected call takes nothing, so the budget isn't consumed by the attempt.
func (l *Limiter) AllowN(key string, n float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, seen: now}
		l.buckets[key] = b
	} else if elapsed := now.Sub(b.seen).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.seen = now

	if n > b.tokens {
		return false
	}
	b.tokens -= n
	return true
}

// gc evicts buckets untouched for longer than the idle horizon. It runs at most
// once per horizon so a hot path stays cheap; an evicted key is simply recreated
// full on its next use, which is correct — a key idle that long has refilled.
func (l *Limiter) gc(now time.Time) {
	if !l.lastGC.IsZero() && now.Sub(l.lastGC) < l.idle {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > l.idle {
			delete(l.buckets, k)
		}
	}
}
