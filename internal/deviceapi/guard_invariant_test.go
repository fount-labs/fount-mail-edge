package deviceapi

// Tier-2 verification (design §8a/§21): property/invariant tests for the Device
// API guard's replay defenses and the cross-license binding. Tier-1 fuzzes the
// bytes a caller sends; these drive the signed request path through a randomized
// space of timestamps, nonces, and license/mailbox pairings and assert the
// authorization invariant holds universally. A valid signed POST /entitlement
// reaches its stub (501) when it should be accepted and is refused at the guard
// (401) when it should not, so the two outcomes are distinguishable.

import (
	"crypto/ed25519"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/entitlement"
)

// Property: a request is accepted iff its timestamp is within ±timestampSkew of
// now. Offsets are sampled continuously across a range that spans well past the
// window on both sides; a narrow guard band around the exact boundary is skipped
// so the millisecond of execution time between signing and checking can't make
// the property flaky (the real boundary is exercised by the fixed-point unit
// test TestStaleTimestampRejected).
func TestTimestampWindowProperty(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	rng := rand.New(rand.NewPCG(1, 0xB0A))
	const skewSec = int(timestampSkew / time.Second)
	for i := 0; i < 400; i++ {
		off := rng.IntN(2*skewSec+200+1) - (skewSec + 100) // [-skew-100, skew+100] seconds
		if a := absInt(off); a >= skewSec-5 && a <= skewSec+5 {
			continue // skip the boundary band
		}
		ts := time.Now().Add(time.Duration(off) * time.Second)
		req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), ts, fmt.Sprintf("ts-%d", i))
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)

		within := absInt(off) < skewSec
		if within && rec.Code != http.StatusNotImplemented {
			t.Fatalf("offset %+ds is within the window but got %d", off, rec.Code)
		}
		if !within && rec.Code != http.StatusUnauthorized {
			t.Fatalf("offset %+ds is outside the window but got %d (want 401)", off, rec.Code)
		}
	}
}

// Property: within the retention window a nonce is accepted at most once. A small
// nonce alphabet forces frequent collisions; every first use of a nonce reaches
// the handler and every later use of the same nonce is refused.
func TestNonceSingleUseProperty(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	rng := rand.New(rand.NewPCG(7, 0x11CE))
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		nonce := fmt.Sprintf("n%d", rng.IntN(60))
		req := signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), time.Now(), nonce)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if seen[nonce] {
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("replay of nonce %q accepted: got %d, want 401", nonce, rec.Code)
			}
		} else {
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("first use of nonce %q rejected: got %d, want 501", nonce, rec.Code)
			}
			seen[nonce] = true
		}
	}
}

// Property (race): when many requests carrying the same nonce race, exactly one
// wins. This is the concurrency guarantee useOnce must give — the nonce cache is a
// live-concurrent path (the broker can pipeline), and two acceptances of one nonce
// would defeat replay protection. Run under `go test -race`.
func TestNonceConcurrentSingleAccept(t *testing.T) {
	api, priv, keyID := newTestAPI(t)
	const g = 64
	ts := time.Now()
	// Build every request on the test goroutine; the workers only serve them.
	reqs := make([]*http.Request, g)
	for i := range reqs {
		reqs[i] = signedRequest(t, priv, keyID, "POST", "/entitlement", []byte(`{}`), ts, "race-nonce")
	}

	codes := make([]int, g)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			<-start
			api.ServeHTTP(rec, reqs[i])
			codes[i] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for _, c := range codes {
		switch c {
		case http.StatusNotImplemented:
			accepted++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("unexpected status %d racing for the nonce", c)
		}
	}
	if accepted != 1 {
		t.Fatalf("exactly one racing request should win the nonce, got %d", accepted)
	}
}

// Property: an entitlement carrying license B cannot renew a mailbox bound to
// license A, even when the token correctly names mailbox A's request-signing key
// (so it clears the signature and device-key checks and fails only on the license
// binding). Over the full mailbox × license matrix, a renewal is accepted (200)
// iff the licenses match, every cross-license renewal is refused (409), and a
// refused renewal leaves the mailbox's stored expiry unchanged. This is the §4
// cross-license-authorization defense exercised through the whole guard stack.
func TestEntitlementCrossLicenseRefusedProperty(t *testing.T) {
	rt, _ := newRoutingStore(t)
	api, backend := mutatorAPI(t, rt)

	const n = 5
	boxes := make([]mbox, n)
	lics := make([]string, n)
	exps := make([]int64, n)
	for i := range boxes {
		lics[i] = fmt.Sprintf("lic-%d", i)
		boxes[i] = createMbox(t, rt, fmt.Sprintf("worker%d@fountbox.com", i), lics[i])
		snap, _ := rt.Snapshot(boxes[i].id)
		exps[i] = snap.EntitlementExp
	}

	for i := range boxes {
		for j := range lics {
			newExp := time.Unix(exps[i], 0).Add(time.Duration(100+j) * time.Second)
			tok := mintToken(t, backend, boxes[i].sign.Public().(ed25519.PublicKey), lics[j], newExp)
			req := signedRequest(t, boxes[i].sign, boxes[i].idHex, "POST", "/entitlement", []byte("{}"), time.Now(), fmt.Sprintf("x-%d-%d", i, j))
			req.Header.Set("Fount-Entitlement", tok)
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, req)

			snap, _ := rt.Snapshot(boxes[i].id)
			if i == j {
				if rec.Code != http.StatusOK {
					t.Fatalf("mailbox %d own-license renewal: got %d, want 200: %s", i, rec.Code, rec.Body.String())
				}
				if snap.EntitlementExp != newExp.Unix() {
					t.Fatalf("mailbox %d expiry = %d, want %d", i, snap.EntitlementExp, newExp.Unix())
				}
				exps[i] = newExp.Unix()
			} else {
				if rec.Code != http.StatusConflict {
					t.Fatalf("mailbox %d (license %d) accepted license %d: got %d, want 409", i, i, j, rec.Code)
				}
				if snap.EntitlementExp != exps[i] {
					t.Fatalf("mailbox %d expiry changed on a cross-license renewal: %d, want %d", i, snap.EntitlementExp, exps[i])
				}
			}
		}
	}
}

// mintToken signs an entitlement for a chosen device key and license hash, so a
// property test can present a token whose license deliberately matches or differs
// from a mailbox's. entToken in the unit tests fixes both; this parameterizes them.
func mintToken(t *testing.T, backend ed25519.PrivateKey, deviceKey ed25519.PublicKey, license string, exp time.Time) string {
	t.Helper()
	tok, err := entitlement.Sign(entitlement.Claims{
		LicenseHash: []byte(license),
		DeviceKey:   deviceKey,
		IssuedAt:    time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:   exp.Unix(),
	}, backend)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
