package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// fakeBucket is an in-process S3 that checks every request carries a SigV4
// Authorization header and an x-amz-content-sha256, then serves Put/Get/List/
// Delete over an in-memory map. It paginates List at one key per page so the
// continuation-token path is exercised.
type fakeBucket struct {
	t    *testing.T
	objs map[string][]byte
}

func (f *fakeBucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		f.t.Errorf("missing SigV4 authorization on %s %s", r.Method, r.URL)
		http.Error(w, "unsigned", http.StatusForbidden)
		return
	}
	if r.Header.Get("X-Amz-Content-Sha256") == "" {
		f.t.Errorf("missing x-amz-content-sha256 on %s %s", r.Method, r.URL)
	}
	key := strings.TrimPrefix(r.URL.Path, "/")

	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			f.list(w, r)
			return
		}
		b, ok := f.objs[key]
		if !ok {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.objs[key] = b
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(f.objs, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeBucket) list(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	var keys []string
	for k := range f.objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	start := 0
	if tok := r.URL.Query().Get("continuation-token"); tok != "" {
		for i, k := range keys {
			if k == tok {
				start = i
				break
			}
		}
	}
	w.Header().Set("Content-Type", "application/xml")
	if start >= len(keys) {
		fmt.Fprint(w, `<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
		return
	}
	k := keys[start]
	truncated := start+1 < len(keys)
	var next string
	if truncated {
		next = keys[start+1]
	}
	fmt.Fprintf(w, `<?xml version="1.0"?><ListBucketResult>`+
		`<IsTruncated>%t</IsTruncated>`+
		`<Contents><Key>%s</Key><Size>%d</Size></Contents>`+
		`<NextContinuationToken>%s</NextContinuationToken>`+
		`</ListBucketResult>`, truncated, k, len(f.objs[k]), next)
}

func newTestClient(t *testing.T) (*Client, *fakeBucket) {
	t.Helper()
	fb := &fakeBucket{t: t, objs: map[string][]byte{}}
	srv := httptest.NewServer(fb)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Endpoint:        srv.URL,
		Region:          "us-east-1",
		AccessKeyID:     "AKID",
		SecretAccessKey: "secret",
		HTTPClient:      srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, fb
}

func TestPutGetDelete(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()
	key := "edge/mail/" + strings.Repeat("ab", 32) + "/" + strings.Repeat("cd", 16)

	if err := c.Put(ctx, key, []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Get = %q", got)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after delete err = %v, want ErrNotFound", err)
	}
}

func TestGetMissingIsNotFound(t *testing.T) {
	c, _ := newTestClient(t)
	if _, err := c.Get(context.Background(), "edge/routing/current"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteAbsentIsOK(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Delete(context.Background(), "edge/mail/none"); err != nil {
		t.Fatalf("Delete absent: %v", err)
	}
}

func TestListPaginates(t *testing.T) {
	c, fb := newTestClient(t)
	ctx := context.Background()
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		k := fmt.Sprintf("edge/mail/box/%02d", i)
		fb.objs[k] = []byte{byte(i)}
		want[k] = true
	}
	fb.objs["edge/other/x"] = []byte("x") // excluded by prefix

	got, err := c.List(ctx, "edge/mail/box/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("List returned %d keys, want %d: %v", len(got), len(want), got)
	}
	for _, k := range got {
		if !want[k] {
			t.Fatalf("unexpected key %q", k)
		}
	}
}

// New rejects an incomplete config rather than signing against a bad endpoint.
func TestNewValidates(t *testing.T) {
	for _, cfg := range []Config{
		{Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"},   // no endpoint
		{Endpoint: "https://x", AccessKeyID: "a", SecretAccessKey: "b"}, // no region
		{Endpoint: "https://x", Region: "us-east-1"},                    // no creds
		{Endpoint: "not-a-url", Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) should have failed", cfg)
		}
	}
}
