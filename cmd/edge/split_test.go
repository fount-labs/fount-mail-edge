package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	netsmtp "net/smtp"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const splitConfig = "../../tinfoil-config.yml"

// containerBlock is the text from "- name: <name>" to the next container or section.
func containerBlock(t *testing.T, text, name string) string {
	t.Helper()
	_, after, ok := strings.Cut(text, "  - name: "+name+"\n")
	if !ok {
		t.Fatalf("no container %s", name)
	}
	if i := strings.Index(after, "\n  - name: "); i >= 0 {
		after = after[:i]
	}
	if i := strings.Index(after, "\nshim:"); i >= 0 {
		after = after[:i]
	}
	return after
}

func yamlField(block, key string) (string, bool) {
	_, v, ok := strings.Cut(block, "\n    "+key+": ")
	if !ok {
		return "", false
	}
	v, _, _ = strings.Cut(v, "\n")
	v, _, _ = strings.Cut(v, " #")
	return strings.TrimSpace(v), true
}

// envOf reads a container's `- NAME: "value"` lines.
func envOf(block string) map[string]string {
	env := map[string]string{}
	_, list, ok := strings.Cut(block, "\n    env:\n")
	if !ok {
		return env
	}
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") {
			break
		}
		k, v, _ := strings.Cut(strings.TrimPrefix(line, "- "), ":")
		v, _, _ = strings.Cut(v, " #")
		env[k] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return env
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The proposed split config gives mail-front the TLS key and nothing else, and
// keeps every vault, S3 and send setting off it.
func TestSplitConfigIsolatesFront(t *testing.T) {
	text := readFile(t, splitConfig)
	front := containerBlock(t, text, "mail-front")
	core := containerBlock(t, text, "mail-core")

	want := map[string]string{"keys": "[mail-tls]", "networks": "[frontlink]", "command": `["front"]`, "ipc": "none"}
	for k, v := range want {
		if got, _ := yamlField(front, k); got != v {
			t.Errorf("mail-front %s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"attestation", "secrets", "cvm_admin", "cap_add"} {
		if _, ok := yamlField(front, k); ok {
			t.Errorf("mail-front has %s", k)
		}
	}
	allowed := []string{"MAIL_HOSTNAMES", "BOOT_HOSTNAME_DOMAIN", "MAIL_DOMAIN", "GATEWAY_CLIENT_PINS", "CORE_LINK", "CORE_API"}
	for k := range envOf(front) {
		if !slices.Contains(allowed, k) {
			t.Errorf("mail-front sets %s", k)
		}
	}
	if !strings.Contains(text, "\n  frontlink: {}") {
		t.Error("frontlink isn't a closed network")
	}

	if got, _ := yamlField(core, "keys"); got != "[mail-sign, transfer]" {
		t.Errorf("mail-core keys = %s", got)
	}
	if got, _ := yamlField(core, "command"); got != `["core"]` {
		t.Errorf("mail-core command = %s", got)
	}
	if got, _ := yamlField(core, "attestation"); got != "true" {
		t.Error("mail-core has no attestation socket, so it can't pull its keys")
	}
	if _, ok := envOf(core)["GATEWAY_CLIENT_PINS"]; ok {
		t.Error("mail-core has gateway pins, but front terminates the tunnels")
	}
	if !strings.Contains(text, "\nshim:\n  upstream-container: mail-core\n") {
		t.Error("the shim doesn't target mail-core")
	}
	// Tinfoil requires each attested key granted to exactly one container.
	for _, id := range []string{"mail-tls", "mail-sign", "transfer", "send-transfer"} {
		holders := 0
		for _, name := range splitContainers {
			ks, _ := yamlField(containerBlock(t, text, name), "keys")
			if slices.Contains(strings.Split(strings.Trim(ks, "[]"), ", "), id) {
				holders++
			}
		}
		if holders != 1 {
			t.Errorf("%s is granted to %d containers", id, holders)
		}
	}
}

var splitContainers = []string{"mail-core", "mail-front", "mail-send", "forwarder"}

// Sending stays off in the split layout too, and only mail-send may carry the
// send settings.
func TestOnlyMailSendCarriesSendSettings(t *testing.T) {
	text := readFile(t, splitConfig)
	for _, name := range []string{"mail-core", "mail-front", "forwarder"} {
		env := envOf(containerBlock(t, text, name))
		for _, k := range config.SendSettings {
			if _, ok := env[k]; ok {
				t.Errorf("%s carries %s", name, k)
			}
		}
	}
}

// networkAllow reads a network's allow list from the networks section.
func networkAllow(t *testing.T, text, name string) []string {
	t.Helper()
	nets, _, _ := strings.Cut(text, "\ncontainers:")
	_, block, ok := strings.Cut(nets, "\n  "+name+":\n")
	if !ok {
		t.Fatalf("no network %s", name)
	}
	var out []string
	_, list, ok := strings.Cut(block, "    allow:\n")
	if !ok {
		return nil
	}
	for _, line := range strings.Split(list, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ") {
			break
		}
		out = append(out, strings.TrimPrefix(line, "- "))
	}
	return out
}

// mail-send holds send-transfer and nothing else, reaches the vaults and, through
// sendnet, mail-core; mail-core holds no send key and no send setting.
func TestSplitConfigIsolatesSend(t *testing.T) {
	text := readFile(t, splitConfig)
	snd := containerBlock(t, text, "mail-send")
	core := containerBlock(t, text, "mail-core")
	want := map[string]string{"keys": "[send-transfer]", "networks": "[sendnet, sendout]", "command": `["send"]`, "ipc": "none", "attestation": "true"}
	for k, v := range want {
		if got, _ := yamlField(snd, k); got != v {
			t.Errorf("mail-send %s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"ports", "secrets", "cvm_admin", "cap_add"} {
		if _, ok := yamlField(snd, k); ok {
			t.Errorf("mail-send has %s", k)
		}
	}
	allowed := append([]string{"MAIL_HOSTNAMES", "MAIL_DOMAIN", "VAULT_HOSTS"}, config.SendSettings...)
	for k := range envOf(snd) {
		if !slices.Contains(allowed, k) {
			t.Errorf("mail-send sets %s", k)
		}
	}
	if !strings.Contains(text, "\n  sendnet: {}") {
		t.Error("sendnet isn't a closed network")
	}
	if got, _ := yamlField(core, "networks"); !strings.Contains(got, "sendnet") {
		t.Errorf("mail-core networks = %s, no sendnet", got)
	}
	if got, _ := yamlField(core, "keys"); strings.Contains(got, "send-transfer") {
		t.Error("mail-core holds send-transfer")
	}
	_, port, _ := strings.Cut(config.SendLinkAddr(), ":")
	if got := envOf(core)["SEND_LINK"]; got != "mail-send:"+port {
		t.Errorf("mail-core SEND_LINK = %q, want mail-send:%s", got, port)
	}
	// Its way out reaches the vaults it pulls from, and nothing else the release
	// doesn't name: the relay host joins when sending is turned on.
	out := networkAllow(t, text, "sendout")
	vaults := strings.Split(envOf(snd)["VAULT_HOSTS"], ",")
	for _, v := range vaults {
		if !slices.Contains(out, v) {
			t.Errorf("sendout doesn't allow %s", v)
		}
	}
	relay, _, _ := strings.Cut(envOf(snd)["SEND_RELAY_ADDR"], ":")
	for _, h := range out {
		if !slices.Contains(vaults, h) && h != relay {
			t.Errorf("sendout allows %s, which mail-send doesn't use", h)
		}
	}
}

// Each container's env, as the split config sets it, loads.
func TestSplitConfigLoads(t *testing.T) {
	text := readFile(t, splitConfig)
	set := func(t *testing.T, env map[string]string) {
		for _, k := range append(append(append([]string{"EDGE_DEV", "GATEWAY_CLIENT_PINS", "CORE_LINK", "CORE_API"}, config.FrontForbidden...), config.SendForbidden...), config.SecretNames...) {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
		for k, v := range env {
			t.Setenv(k, v)
		}
	}
	t.Run("front", func(t *testing.T) {
		set(t, envOf(containerBlock(t, text, "mail-front")))
		f, err := config.LoadFront()
		if err != nil {
			t.Fatal(err)
		}
		if f.CoreLink != "mail-core:7025" || len(f.GatewayPins) != 2 {
			t.Fatalf("front config: %+v", f)
		}
	})
	t.Run("core", func(t *testing.T) {
		set(t, envOf(containerBlock(t, text, "mail-core")))
		c, err := config.LoadCore()
		if err != nil {
			t.Fatal(err)
		}
		if c.SendLink == "" || c.SendKeysetCommitment != "" {
			t.Fatalf("core send config: link %q commitment %q", c.SendLink, c.SendKeysetCommitment)
		}
	})
	t.Run("send", func(t *testing.T) {
		set(t, envOf(containerBlock(t, text, "mail-send")))
		c, err := config.LoadSend()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.VaultHosts) != 2 || !c.SendEnabled || c.SendEHLOName != "out.fountbox.com" {
			t.Fatalf("send config: %+v", c)
		}
		// Without the send keyset, which only a vault hands over, it stays off.
		if _, st := newOutbox(c); !strings.HasPrefix(st.State, "off: ") {
			t.Fatalf("the split config's mail-send is %q with no send keyset", st.State)
		}
	})
}

// testCA signs leaves for whatever key a CSR carries, standing in for ACME.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{key: key, cert: cert}
}

func (ca *testCA) chainFor(t *testing.T, pub *ecdsa.PublicKey, hosts []string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: hosts, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
}

// Front makes the CSR, core orders with it and holds only the chain, front
// installs the chain with its own key, and core's /ready passes only once front
// holds that chain.
func TestFrontAndCoreShareTheCertificate(t *testing.T) {
	hosts := []string{"mx1.example", "mx2.example"}
	ls := link.NewServer(hosts, "", 1<<20, nil)
	coreMgr := certs.NewManager()
	ls.SetCert(func() []byte {
		if c, ok := coreMgr.Current(); ok {
			return certs.ChainPEM(c)
		}
		return nil
	})
	srv := httptest.NewServer(ls)
	defer srv.Close()
	ready := frontReady{coreMgr, ls}

	k := testKeys(t)
	frontMgr := certs.NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go frontCertLoop(ctx, &link.Client{Base: srv.URL}, k.TLS, frontMgr, hosts, frontCertTiming{retry: 10 * time.Millisecond, poll: 10 * time.Millisecond})

	_, _, pub, err := ls.CSR(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(&k.TLS.PublicKey) {
		t.Fatal("core got a CSR for another key")
	}
	if _, ok := ready.Current(); ok {
		t.Fatal("ready before any certificate")
	}
	chain, err := certs.ParseChain(newTestCA(t).chainFor(t, pub, hosts))
	if err != nil {
		t.Fatal(err)
	}
	if chain.PrivateKey != nil {
		t.Fatal("core's chain carries a private key")
	}
	coreMgr.Set(chain)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := ready.Current(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core's /ready never saw front load the chain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got, ok := frontMgr.Current()
	if !ok || got.PrivateKey != k.TLS {
		t.Fatalf("front's certificate: %v, ok %v", got, ok)
	}
	// It serves a TLS handshake with the attested key.
	if _, err := tls.X509KeyPair(certs.ChainPEM(got), keyPEM(t, k.TLS)); err != nil {
		t.Fatalf("front's certificate and key don't pair: %v", err)
	}
}

// A chain for another key never installs in front.
func TestFrontRefusesAChainForAnotherKey(t *testing.T) {
	hosts := []string{"mx1.example"}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemBytes := newTestCA(t).chainFor(t, &other.PublicKey, hosts)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(pemBytes) }))
	defer srv.Close()
	k := testKeys(t)
	mgr := certs.NewManager()
	if changed, err := fetchChain(context.Background(), &link.Client{Base: srv.URL}, k.TLS, mgr, ""); err == nil || changed {
		t.Fatalf("installed another key's chain: %v", err)
	}
	if _, ok := mgr.Current(); ok {
		t.Fatal("front has a certificate")
	}
}

func keyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// mail-front forwards only the Device API's routes to core, not /operator, and
// the challenge port only challenge GETs, not the link API.
func TestFrontForwardsOnlyWhatItShould(t *testing.T) {
	var hits []string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path)
	}))
	defer core.Close()
	host := strings.TrimPrefix(core.URL, "http://")

	api := deviceAPIProxy(host)
	for path, want := range map[string]int{"/operator/status": http.StatusNotFound, "/link/put": http.StatusNotFound} {
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != want {
			t.Errorf("device API port %s answered %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mail", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("device API port GET /mail answered %d", rec.Code)
	}

	acme := link.ChallengeOnly(proxyTo(host))
	for _, c := range []struct {
		method, path string
		pass         bool
	}{
		{http.MethodGet, "/", true},
		{http.MethodGet, "/.well-known/acme-challenge/abc", true},
		{http.MethodPost, "/link/put", false},
		{http.MethodGet, "/link/cert", false},
		{http.MethodPost, "/.well-known/acme-challenge/abc", false},
		{http.MethodGet, "/.well-known/acme-challenge/../../link/cert", false},
	} {
		before := len(hits)
		rec := httptest.NewRecorder()
		acme.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if passed := len(hits) > before; passed != c.pass {
			t.Errorf("challenge port %s %s: forwarded %v", c.method, c.path, passed)
		}
	}
	if slices.ContainsFunc(hits, func(h string) bool { return strings.Contains(h, "/link/") || strings.Contains(h, "/operator/") }) {
		t.Fatalf("core saw %v", hits)
	}
}

type capture struct {
	envs []store.Envelope
	raws [][]byte
}

func (c *capture) Put(_ context.Context, env store.Envelope, raw []byte) (string, error) {
	c.envs, c.raws = append(c.envs, env), append(c.raws, raw)
	return "id", nil
}

type onlyBob struct{}

func (onlyBob) Status(_ context.Context, r string) (smtp.RecipientStatus, error) {
	if r == "bob@fountbox.com" {
		return smtp.RecipientAccepting, nil
	}
	return smtp.RecipientUnknown, nil
}

// A sender's message goes through mail-front's SMTP, over the link, into
// mail-core's store, with the envelope intact; RCPT is core's verdict.
func TestMailGoesFromFrontToCore(t *testing.T) {
	hosts := []string{"mx1.fountbox.com"}
	ls := link.NewServer(hosts, "", 1<<20, nil)
	st := &capture{}
	ls.SetMail(&link.Mail{Store: st, Recipients: onlyBob{}})
	core := httptest.NewServer(ls)
	defer core.Close()
	client := &link.Client{Base: core.URL}

	k := testKeys(t)
	mgr := certs.NewManager()
	ca := newTestCA(t)
	cert, err := certs.ParseChain(ca.chainFor(t, &k.TLS.PublicKey, hosts))
	if err != nil {
		t.Fatal(err)
	}
	cert.PrivateKey = k.TLS
	mgr.Set(cert)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.New(smtp.Options{Hostname: hosts[0], Domain: "@fountbox.com", Certs: mgr, Store: client, Recipients: client, MaxBytes: 1 << 20, Idle: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("PROXY TCP4 198.51.100.7 203.0.113.1 40000 25\r\n")); err != nil {
		t.Fatal(err)
	}
	c, err := netsmtp.NewClient(conn, hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("sender.example"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if err := c.StartTLS(&tls.Config{ServerName: hosts[0], RootCAs: roots}); err != nil {
		t.Fatalf("STARTTLS with front's certificate: %v", err)
	}
	if err := c.Mail("alice@sender.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("nobody@fountbox.com"); err == nil {
		t.Fatal("front accepted an address core doesn't know")
	}
	if err := c.Rcpt("bob@fountbox.com"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("Subject: hi\r\n\r\nthrough the link\r\n"))
	if err := w.Close(); err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if len(st.envs) != 1 {
		t.Fatalf("core stored %d messages", len(st.envs))
	}
	env := st.envs[0]
	if env.Sender != "alice@sender.example" || env.Recipient != "bob@fountbox.com" || env.ClientIP != "198.51.100.7" || env.HELO != "sender.example" {
		t.Fatalf("envelope %+v", env)
	}
	if !strings.Contains(string(st.raws[0]), "through the link") {
		t.Fatalf("message %q", st.raws[0])
	}
}

// With a boot domain, front adds one boot name to its CSR, and core orders
// exactly the names the CSR holds.
func TestFrontAndCoreAgreeOnTheBootName(t *testing.T) {
	hosts := []string{"mx1.example", "mx2.example"}
	ls := link.NewServer(hosts, "boot.example", 1<<20, nil)
	srv := httptest.NewServer(ls)
	defer srv.Close()

	k := testKeys(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	names := acme.WithBootName(hosts, "boot.example")
	go frontCertLoop(ctx, &link.Client{Base: srv.URL}, k.TLS, certs.NewManager(), names, frontCertTiming{retry: 10 * time.Millisecond, poll: 10 * time.Millisecond})

	_, got, _, err := ls.CSR(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, names) {
		t.Fatalf("core would order %v, want %v", got, names)
	}
	if !acme.IsBootName(got[2], "boot.example") {
		t.Fatalf("%q isn't a boot name", got[2])
	}
}

// Front makes the CSR with the boot name and core checks it, so both must name
// the same boot domain.
func TestSplitConfigBootDomainMatches(t *testing.T) {
	text := readFile(t, splitConfig)
	front, core := envOf(containerBlock(t, text, "mail-front")), envOf(containerBlock(t, text, "mail-core"))
	if front["BOOT_HOSTNAME_DOMAIN"] == "" || front["BOOT_HOSTNAME_DOMAIN"] != core["BOOT_HOSTNAME_DOMAIN"] {
		t.Errorf("BOOT_HOSTNAME_DOMAIN: front %q, core %q", front["BOOT_HOSTNAME_DOMAIN"], core["BOOT_HOSTNAME_DOMAIN"])
	}
}
