package link

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

type fakeStore struct {
	got []store.Envelope
	raw [][]byte
	err error
}

func (f *fakeStore) Put(_ context.Context, env store.Envelope, raw []byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.got = append(f.got, env)
	f.raw = append(f.raw, raw)
	return "msg-1", nil
}

type fakeRecipients map[string]smtp.RecipientStatus

func (f fakeRecipients) Status(_ context.Context, r string) (smtp.RecipientStatus, error) {
	if r == "broken@x" {
		return 0, errors.New("routing down")
	}
	return f[r], nil
}

var hosts = []string{"mx1.example", "mx2.example"}

func newPair(t *testing.T, maxBytes int64) (*Server, *Client) {
	t.Helper()
	s := NewServer(hosts, "", maxBytes, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("challenge")) }))
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, &Client{Base: ts.URL}
}

func TestMailCrossesTheLink(t *testing.T) {
	s, c := newPair(t, 1<<10)
	st := &fakeStore{}
	s.SetMail(&Mail{Store: st, Recipients: fakeRecipients{"a@x": smtp.RecipientAccepting, "old@x": smtp.RecipientExpired}})
	ctx := context.Background()

	for addr, want := range map[string]smtp.RecipientStatus{"a@x": smtp.RecipientAccepting, "old@x": smtp.RecipientExpired, "nobody@x": smtp.RecipientUnknown} {
		if got, err := c.Status(ctx, addr); err != nil || got != want {
			t.Errorf("Status(%s) = %v, %v; want %v", addr, got, err, want)
		}
	}
	if _, err := c.Status(ctx, "broken@x"); err == nil {
		t.Error("a failed check came back as a verdict")
	}

	env := store.Envelope{Sender: "s@y", Recipient: "a@x", ClientIP: "198.51.100.7", HELO: "mail.y"}
	raw := []byte("Subject: hi\r\n\r\nbody\r\n")
	id, err := c.Put(ctx, env, raw)
	if err != nil || id != "msg-1" {
		t.Fatalf("Put = %q, %v", id, err)
	}
	if len(st.got) != 1 || st.got[0] != env || !bytes.Equal(st.raw[0], raw) {
		t.Fatalf("core stored %+v %q", st.got, st.raw)
	}

	if _, err := c.Put(ctx, env, bytes.Repeat([]byte("x"), 1<<10+1)); err == nil {
		t.Error("core took a message over the limit")
	}
	st.err = store.ErrConflict
	if _, err := c.Put(ctx, env, raw); !errors.Is(err, store.ErrConflict) {
		t.Errorf("conflict came back as %v", err)
	}
	st.err = errors.New("s3 down")
	if _, err := c.Put(ctx, env, raw); err == nil {
		t.Error("a failed store came back as stored")
	}

	// A draining core answers neither, so front gives senders a temporary failure.
	s.SetMail(nil)
	if _, err := c.Status(ctx, "a@x"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("draining Status: %v", err)
	}
	if _, err := c.Put(ctx, env, raw); !errors.Is(err, ErrUnavailable) {
		t.Errorf("draining Put: %v", err)
	}
}

func TestPutNeedsAnEnvelope(t *testing.T) {
	s, c := newPair(t, 1<<10)
	s.SetMail(&Mail{Store: &fakeStore{}})
	for name, hdr := range map[string]string{"none": "", "garbage": "!!", "no recipient": "e30="} {
		req, _ := http.NewRequest(http.MethodPost, c.Base+"/link/put", strings.NewReader("x"))
		if hdr != "" {
			req.Header.Set(envelopeHeader, hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

func csrFor(t *testing.T, key any, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheckCSR(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	good := csrFor(t, key, &x509.CertificateRequest{DNSNames: []string{"mx2.example", "mx1.example"}})
	if got, _, err := CheckCSR(good, hosts, ""); err != nil || !got.Equal(&key.PublicKey) {
		t.Fatalf("good CSR: %v", err)
	}
	evil, _ := url.Parse("https://evil.example")
	for name, der := range map[string][]byte{
		"one name":   csrFor(t, key, &x509.CertificateRequest{DNSNames: []string{"mx1.example"}}),
		"extra name": csrFor(t, key, &x509.CertificateRequest{DNSNames: []string{"mx1.example", "mx2.example", "evil.example"}}),
		"ip":         csrFor(t, key, &x509.CertificateRequest{DNSNames: hosts, IPAddresses: []net.IP{net.IPv4(1, 2, 3, 4)}}),
		"email":      csrFor(t, key, &x509.CertificateRequest{DNSNames: hosts, EmailAddresses: []string{"a@b"}}),
		"uri":        csrFor(t, key, &x509.CertificateRequest{DNSNames: hosts, URIs: []*url.URL{evil}}),
		"p384":       csrFor(t, p384, &x509.CertificateRequest{DNSNames: hosts}),
		"ed25519":    csrFor(t, ed, &x509.CertificateRequest{DNSNames: hosts}),
		"garbage":    []byte("not a csr"),
		"bad sig":    append(append([]byte(nil), good[:len(good)-4]...), 0, 0, 0, 0),
	} {
		if _, _, err := CheckCSR(der, hosts, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckCSRWithBootDomain(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	boot := "abcdefghijklmnopqrstuvwxyz.boot.example"
	good := csrFor(t, key, &x509.CertificateRequest{DNSNames: []string{"mx1.example", boot, "mx2.example"}})
	_, names, err := CheckCSR(good, hosts, "boot.example")
	if err != nil {
		t.Fatalf("good CSR: %v", err)
	}
	if !slices.Equal(names, []string{"mx1.example", boot, "mx2.example"}) {
		t.Fatalf("names = %v", names)
	}
	if _, _, err := CheckCSR(good, hosts, ""); err == nil {
		t.Error("a boot name accepted with no boot domain")
	}
	for name, dns := range map[string][]string{
		"no boot name":     hosts,
		"two boot names":   {"mx1.example", "mx2.example", boot, "bcdefghijklmnopqrstuvwxyza.boot.example"},
		"wrong domain":     {"mx1.example", "mx2.example", "abcdefghijklmnopqrstuvwxyz.evil.example"},
		"not a boot label": {"mx1.example", "mx2.example", "www.boot.example"},
		"missing mx2":      {"mx1.example", boot},
	} {
		if _, _, err := CheckCSR(csrFor(t, key, &x509.CertificateRequest{DNSNames: dns}), hosts, "boot.example"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOneCSRKeyPerBoot(t *testing.T) {
	s, c := newPair(t, 1<<10)
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := c.SubmitCSR(ctx, csrFor(t, key, &x509.CertificateRequest{DNSNames: hosts})); err != nil {
		t.Fatal(err)
	}
	// A restarted front has the same attested key, and sends it again.
	if err := c.SubmitCSR(ctx, csrFor(t, key, &x509.CertificateRequest{DNSNames: hosts})); err != nil {
		t.Fatalf("same key again: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := c.SubmitCSR(ctx, csrFor(t, other, &x509.CertificateRequest{DNSNames: hosts})); err == nil {
		t.Fatal("core took a second key in one boot")
	}
	_, _, pub, err := s.CSR(ctx)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("core's CSR key changed: %v", err)
	}
}

func TestCertAndFrontHas(t *testing.T) {
	s, c := newPair(t, 1<<10)
	ctx := context.Background()
	if _, ok, err := c.Cert(ctx, ""); ok || err != nil {
		t.Fatalf("no cert yet: ok %v, %v", ok, err)
	}
	chain := []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
	s.SetCert(func() []byte { return chain })
	got, ok, err := c.Cert(ctx, "")
	if err != nil || !ok || !bytes.Equal(got, chain) {
		t.Fatalf("Cert = %q, %v, %v", got, ok, err)
	}
	leaf := []byte("leaf der")
	if s.FrontHas(leaf) {
		t.Fatal("front has it before saying so")
	}
	if _, _, err := c.Cert(ctx, LeafHash(leaf)); err != nil {
		t.Fatal(err)
	}
	if !s.FrontHas(leaf) || s.FrontHas([]byte("another")) {
		t.Fatal("FrontHas doesn't track front's leaf")
	}
}

func TestUnknownLinkPathsAndChallenges(t *testing.T) {
	_, c := newPair(t, 1<<10)
	for path, want := range map[string]int{"/link/nope": 404, "/link/put": 404, "/": 200, ChallengePrefix + "tok": 200} {
		resp, err := http.Get(c.Base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

// An address as long as an SMTP line still crosses in the envelope header.
func TestLongEnvelopeCrosses(t *testing.T) {
	s, c := newPair(t, 1<<10)
	st := &fakeStore{}
	s.SetMail(&Mail{Store: st})
	env := store.Envelope{Sender: strings.Repeat("a", 8000) + "@y", Recipient: "b@x", HELO: strings.Repeat("h", 255)}
	if _, err := c.Put(context.Background(), env, []byte("x")); err != nil || len(st.got) != 1 || st.got[0] != env {
		t.Fatalf("long envelope: %v", err)
	}
}
