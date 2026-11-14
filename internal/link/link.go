// Package link is the API between a split edge's two containers, on their own
// closed network (docs/CONTAINER-SPLIT.md). mail-front holds the mail-tls key and
// terminates TLS and SMTP; mail-core holds the keyset, seals and stores mail, and
// runs ACME. Front is always the client, so core never dials front.
//
//	POST /link/rcpt  RCPT's verdict for one address
//	POST /link/put   one message for one recipient, envelope in a header
//	POST /link/csr   front's CSR for the mail hostnames, signed by mail-tls
//	GET  /link/cert  the chain core holds for that key; ?have= is front's leaf hash
//
// Anything else on the listener is the ACME HTTP-01 responder, which front
// forwards to from the tunnelled challenge port. Front forwards only GETs of /
// and /.well-known/acme-challenge/, so nothing from outside reaches /link/.
//
// The traffic is plain HTTP inside the enclave. The closed network admits only
// the two containers the measured config names.
package link

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const (
	envelopeHeader = "Fount-Envelope"
	maxSmallBody   = 64 << 10
)

// ChallengePrefix is the only path, besides /, that front forwards from the
// challenge port.
const ChallengePrefix = "/.well-known/acme-challenge/"

// Mail is what core serves front's SMTP from. Draining sets it to nil, and front
// answers senders with a temporary failure.
type Mail struct {
	Store      smtp.Storer
	Recipients smtp.RecipientChecker // nil accepts any address in the domain, as a dev edge does
}

// Server is core's side.
type Server struct {
	hostnames  []string
	bootDomain string
	maxBytes   int64
	challenges http.Handler

	mail atomic.Pointer[Mail]

	mu       sync.Mutex
	csrKey   *ecdsa.PublicKey
	csr      []byte
	csrNames []string
	csrReady chan struct{}
	cert     func() []byte // the chain core holds, or nil
	frontHas string
}

// NewServer serves hostnames' CSRs and certificates, messages up to maxBytes, and
// the ACME responder for everything off /link/. With a bootDomain, a CSR must also
// name one boot name under it (acme.WithBootName).
func NewServer(hostnames []string, bootDomain string, maxBytes int64, challenges http.Handler) *Server {
	return &Server{hostnames: slices.Clone(hostnames), bootDomain: bootDomain, maxBytes: maxBytes, challenges: challenges, csrReady: make(chan struct{})}
}

// SetMail starts or, with nil, stops serving RCPT and messages.
func (s *Server) SetMail(m *Mail) { s.mail.Store(m) }

// SetCert tells the server where to read the current chain.
func (s *Server) SetCert(chain func() []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert = chain
}

// CSR waits for front's CSR and returns it with the names it holds, which are
// the names to order, and its public key.
func (s *Server) CSR(ctx context.Context) ([]byte, []string, *ecdsa.PublicKey, error) {
	select {
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	case <-s.csrReady:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csr, slices.Clone(s.csrNames), s.csrKey, nil
}

// FrontHas reports whether front has loaded the chain whose leaf is leafDER.
func (s *Server) FrontHas(leafDER []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frontHas != "" && s.frontHas == LeafHash(leafDER)
}

// LeafHash names a leaf certificate in ?have=.
func LeafHash(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/link/rcpt":
		s.rcpt(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/link/put":
		s.put(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/link/csr":
		s.submitCSR(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/link/cert":
		s.serveCert(w, r)
	case strings.HasPrefix(r.URL.Path, "/link/"):
		http.NotFound(w, r)
	case s.challenges != nil:
		s.challenges.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

type rcptRequest struct {
	Recipient string `json:"recipient"`
}

type rcptResponse struct {
	Status smtp.RecipientStatus `json:"status"`
}

func (s *Server) rcpt(w http.ResponseWriter, r *http.Request) {
	m := s.mail.Load()
	if m == nil {
		http.Error(w, "not serving mail", http.StatusServiceUnavailable)
		return
	}
	var req rcptRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxSmallBody)).Decode(&req); err != nil || req.Recipient == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	st := smtp.RecipientAccepting
	if m.Recipients != nil {
		var err error
		if st, err = m.Recipients.Status(r.Context(), req.Recipient); err != nil {
			http.Error(w, "recipient check failed", http.StatusServiceUnavailable)
			return
		}
	}
	writeJSON(w, rcptResponse{Status: st})
}

type putResponse struct {
	ID string `json:"id"`
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	m := s.mail.Load()
	if m == nil {
		http.Error(w, "not serving mail", http.StatusServiceUnavailable)
		return
	}
	env, err := decodeEnvelope(r.Header.Get(envelopeHeader))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.maxBytes+1))
	if err != nil {
		http.Error(w, "reading message", http.StatusBadRequest)
		return
	}
	if int64(len(raw)) > s.maxBytes {
		http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
		return
	}
	id, err := m.Store.Put(r.Context(), env, raw)
	switch {
	case errors.Is(err, store.ErrConflict):
		http.Error(w, "conflict", http.StatusConflict)
	case err != nil:
		http.Error(w, "store failed", http.StatusBadGateway)
	default:
		writeJSON(w, putResponse{ID: id})
	}
}

func (s *Server) submitCSR(w http.ResponseWriter, r *http.Request) {
	der, err := io.ReadAll(io.LimitReader(r.Body, maxSmallBody))
	if err != nil {
		http.Error(w, "reading CSR", http.StatusBadRequest)
		return
	}
	key, names, err := CheckCSR(der, s.hostnames, s.bootDomain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.csrKey != nil {
		// A front restart within a boot keeps the attested key, so it sends the same
		// key again. Another key is a different front, which this boot doesn't take.
		if !s.csrKey.Equal(key) {
			http.Error(w, "this boot already has a CSR for another key", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.csr, s.csrNames, s.csrKey = der, names, key
	close(s.csrReady)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) serveCert(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if have := r.URL.Query().Get("have"); len(have) == sha256.Size*2 {
		s.frontHas = have
	}
	chain := s.cert
	s.mu.Unlock()
	var pemBytes []byte
	if chain != nil {
		pemBytes = chain()
	}
	if len(pemBytes) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pemBytes)
}

// CheckCSR accepts a CSR only for exactly the mail hostnames, plus one boot name
// under bootDomain when it's set, with no other names, over a P-256 key, with a
// valid signature. It returns the key and the CSR's names.
func CheckCSR(der []byte, hostnames []string, bootDomain string) (*ecdsa.PublicKey, []string, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature: %w", err)
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, nil, errors.New("CSR key isn't ECDSA P-256, the mail-tls key's type")
	}
	if len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 {
		return nil, nil, errors.New("CSR names something other than the mail hostnames")
	}
	got, want := slices.Clone(csr.DNSNames), slices.Clone(hostnames)
	if bootDomain != "" {
		i := slices.IndexFunc(got, func(n string) bool { return acme.IsBootName(n, bootDomain) })
		if i < 0 {
			return nil, nil, fmt.Errorf("CSR names %v, with no boot name under %s", csr.DNSNames, bootDomain)
		}
		got = slices.Delete(got, i, i+1)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return nil, nil, fmt.Errorf("CSR names %v, want %v and one boot name", csr.DNSNames, hostnames)
	}
	return key, slices.Clone(csr.DNSNames), nil
}

// Client is front's side. It is smtp's Storer and RecipientChecker.
type Client struct {
	Base string // http://mail-core:7025
	HTTP *http.Client
}

var (
	_ smtp.Storer           = (*Client)(nil)
	_ smtp.RecipientChecker = (*Client)(nil)
)

// ErrUnavailable is core not serving mail, as while it drains for a restore.
var ErrUnavailable = errors.New("link: core isn't serving mail")

func (c *Client) Status(ctx context.Context, recipient string) (smtp.RecipientStatus, error) {
	body, _ := json.Marshal(rcptRequest{Recipient: recipient})
	resp, err := c.do(ctx, http.MethodPost, "/link/rcpt", bytes.NewReader(body), nil)
	if err != nil {
		return smtp.RecipientUnknown, err
	}
	defer resp.Body.Close()
	if err := statusErr(resp); err != nil {
		return smtp.RecipientUnknown, err
	}
	var out rcptResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSmallBody)).Decode(&out); err != nil {
		return smtp.RecipientUnknown, fmt.Errorf("link rcpt: %w", err)
	}
	return out.Status, nil
}

func (c *Client) Put(ctx context.Context, env store.Envelope, raw []byte) (string, error) {
	hdr, err := encodeEnvelope(env)
	if err != nil {
		return "", err
	}
	resp, err := c.do(ctx, http.MethodPost, "/link/put", bytes.NewReader(raw), http.Header{envelopeHeader: {hdr}})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return "", store.ErrConflict
	}
	if err := statusErr(resp); err != nil {
		return "", err
	}
	var out putResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSmallBody)).Decode(&out); err != nil {
		return "", fmt.Errorf("link put: %w", err)
	}
	return out.ID, nil
}

// SubmitCSR hands core the CSR it orders certificates with.
func (c *Client) SubmitCSR(ctx context.Context, der []byte) error {
	resp, err := c.do(ctx, http.MethodPost, "/link/csr", bytes.NewReader(der), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return statusErr(resp)
}

// Cert fetches core's chain, telling core which leaf front already has. ok is
// false when core has none yet.
func (c *Client) Cert(ctx context.Context, have string) (pemBytes []byte, ok bool, err error) {
	path := "/link/cert"
	if have != "" {
		path += "?have=" + have
	}
	resp, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if err := statusErr(resp); err != nil {
		return nil, false, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSmallBody))
	return b, err == nil, err
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

func statusErr(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return ErrUnavailable
	case resp.StatusCode/100 != 2:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return fmt.Errorf("link: core answered %s: %s", resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

func encodeEnvelope(env store.Envelope) (string, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decodeEnvelope(v string) (store.Envelope, error) {
	var env store.Envelope
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) == 0 {
		return env, errors.New("missing or unreadable envelope")
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return env, fmt.Errorf("envelope: %w", err)
	}
	if env.Recipient == "" {
		return env, errors.New("envelope has no recipient")
	}
	return env, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ChallengeOnly lets through what the gateway's challenge backend sends: GET /
// (HAProxy's health check) and GETs under ChallengePrefix. Anything else from
// outside, /link/ included, is refused before it reaches core.
func ChallengeOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || (r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, ChallengePrefix)) ||
			strings.Contains(r.URL.Path, "..") || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}
