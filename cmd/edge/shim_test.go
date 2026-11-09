package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
)

// shimPaths reads shim.paths from the release config. The format is plain enough
// to read without a YAML parser, which keeps go.mod empty.
func shimPaths(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, shim, ok := strings.Cut(string(data), "\nshim:\n")
	if !ok {
		t.Fatal("no shim section")
	}
	_, list, ok := strings.Cut(shim, "\n  paths:\n")
	if !ok {
		t.Fatal("no shim.paths")
	}
	var out []string
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, ok := strings.CutPrefix(line, "- ")
		if !ok {
			break
		}
		out = append(out, strings.TrimSpace(p))
	}
	if len(out) == 0 {
		t.Fatal("shim.paths is empty, which the shim reads as every path")
	}
	return out
}

// shimAllows is the shim's own rule (tinfoilsh/cvmimage tinfoil/cmd/shim/api.go
// pathMatchesPattern, CVM 0.14.17): an exact match, or a trailing * for a prefix
// that stops at a segment boundary.
func shimAllows(patterns []string, path string) bool {
	for _, pattern := range patterns {
		prefix, wildcard := strings.CutSuffix(pattern, "*")
		switch {
		case !wildcard:
			if pattern == path {
				return true
			}
		case strings.HasSuffix(prefix, "/"):
			if strings.HasPrefix(path, prefix) {
				return true
			}
		case path == prefix || strings.HasPrefix(path, prefix+"/"):
			return true
		}
	}
	return false
}

var wildcardSegment = regexp.MustCompile(`\{[^}]+\}`)

// samplePath turns "GET /mail/{id}" into "/mail/x".
func samplePath(pattern string) string {
	_, path, _ := strings.Cut(pattern, " ")
	return wildcardSegment.ReplaceAllString(path, "x")
}

// The shim is the Device API's only way in from outside, so every M2 route must be
// on it, and the routes still to come must not be until they're built.
func TestShimPathsMatchDeviceAPI(t *testing.T) {
	paths := shimPaths(t)
	for _, r := range deviceapi.Routes() {
		allowed := shimAllows(paths, samplePath(r.Pattern))
		switch {
		case r.Phase == "M2" && !allowed:
			t.Errorf("%s is an M2 route the shim doesn't forward", r.Pattern)
		case r.Phase != "M2" && allowed:
			t.Errorf("%s is a %s route the shim forwards before it's built", r.Pattern, r.Phase)
		}
	}
}

// Every shim path must reach something the edge serves on the shim's port, so the
// list can't quietly open a path to whatever is added there later.
func TestShimPathsAreServed(t *testing.T) {
	reached := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	}
	h := health(certs.NewManager(), reached(nil), reached(nil))
	for _, p := range shimPaths(t) {
		sample := strings.TrimSuffix(p, "*")
		if strings.HasSuffix(sample, "/") {
			sample += "x"
		}
		served := false
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(m, sample, nil))
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				served = true
				break
			}
		}
		if !served {
			t.Errorf("shim path %s reaches nothing on the shim's port", p)
		}
	}
}

// The Device API on the shim's port answers 503 until storage loads, then serves
// the API, and goes back to 503 while a restore drains.
func TestShimPortServesDeviceAPIOnceSet(t *testing.T) {
	late := &lateHandler{}
	h := health(certs.NewManager(), nil, late)
	get := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code
	}
	if got := get("/boots/x"); got != http.StatusServiceUnavailable {
		t.Fatalf("before storage: %d, want 503", got)
	}
	late.set(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	if got := get("/boots/x"); got != http.StatusTeapot {
		t.Fatalf("after storage: %d, want the API", got)
	}
	if got := get("/health"); got != http.StatusOK {
		t.Fatalf("/health: %d", got)
	}
	if got := get("/nothing"); got != http.StatusNotFound {
		t.Fatalf("/nothing: %d, want 404", got)
	}
	late.set(nil)
	if got := get("/mail"); got != http.StatusServiceUnavailable {
		t.Fatalf("draining: %d, want 503", got)
	}
}
