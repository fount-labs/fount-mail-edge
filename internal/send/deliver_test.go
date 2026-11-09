package send

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

type rig struct {
	ca      *testCA
	mx      *fakeMX
	relay   *fakeRelay
	dialer  *Relay
	resolve fakeResolver
}

// newRig wires a deliverer to an MX for smithcpa.com through a pinned relay.
func newRig(t *testing.T, mxCertNames ...string) *rig {
	t.Helper()
	ca := newCA(t)
	if len(mxCertNames) == 0 {
		mxCertNames = []string{"mx.smithcpa.com"}
	}
	mx := newFakeMX(t, ca.leaf(t, mxCertNames...))
	relayCert := ca.leaf(t, "relay")
	clientCert := ca.leaf(t, "edge")
	relay := newFakeRelay(t, relayCert, pinOf(leafOf(t, clientCert)), map[string]string{
		"mx.smithcpa.com:25":  mx.ln.Addr().String(),
		"mx2.smithcpa.com:25": mx.ln.Addr().String(),
	})
	return &rig{
		ca:    ca,
		mx:    mx,
		relay: relay,
		dialer: &Relay{
			Addr:       relay.ln.Addr().String(),
			ClientCert: clientCert,
			Pins:       []gatewaytls.Pin{pinOf(leafOf(t, relayCert))},
		},
		resolve: fakeResolver{mx: map[string][]MX{"smithcpa.com": {{10, "mx.smithcpa.com"}}}},
	}
}

func (r *rig) deliverer() *Deliverer {
	return &Deliverer{
		Hostname: "mx1.fountbox.com",
		Resolver: r.resolve,
		Dial:     r.dialer.DialContext,
		Roots:    r.ca.pool,
		Timeout:  10 * time.Second,
	}
}

const signedMsg = "From: " + worker + "\r\nTo: pat@smithcpa.com\r\nSubject: s\r\n\r\n.leading dot\r\nbody\r\n"

func TestDeliver(t *testing.T) {
	r := newRig(t)
	res := r.deliverer().Deliver(context.Background(), worker,
		[]string{"pat@smithcpa.com", "nobody@smithcpa.com"}, []byte(signedMsg))
	if len(res) != 2 || res[0].Status != Sent || res[1].Status != Permanent {
		t.Fatalf("results %+v", res)
	}
	if len(r.mx.received) != 1 || string(r.mx.received[0]) != signedMsg {
		t.Fatalf("MX got %q", r.mx.received)
	}
	// Nothing but EHLO and STARTTLS went in the clear.
	for _, c := range r.mx.plainCmd {
		if u := strings.ToUpper(c); !strings.HasPrefix(u, "EHLO") && u != "STARTTLS" {
			t.Fatalf("%q sent before TLS", c)
		}
	}
}

func TestDeliverRequiresValidatedTLS(t *testing.T) {
	// A certificate for another name: the gateway, or anyone it hands the
	// connection to, can't get one for the owner's MX.
	r := newRig(t, "mx.elsewhere.com")
	res := r.deliverer().Deliver(context.Background(), worker, []string{"pat@smithcpa.com"}, []byte(signedMsg))
	if res[0].Status != Temporary || !strings.Contains(res[0].Detail, "certificate") {
		t.Fatalf("wrong-name cert: %+v", res)
	}
	if len(r.mx.received) != 0 {
		t.Fatal("delivered over an unvalidated connection")
	}

	r = newRig(t)
	r.mx.noTLS = true
	res = r.deliverer().Deliver(context.Background(), worker, []string{"pat@smithcpa.com"}, []byte(signedMsg))
	if res[0].Status != Temporary || !strings.Contains(res[0].Detail, "STARTTLS") {
		t.Fatalf("no STARTTLS: %+v", res)
	}
	if len(r.mx.received) != 0 {
		t.Fatal("delivered in plaintext")
	}
}

func TestDeliverMTASTSEnforce(t *testing.T) {
	r := newRig(t)
	r.resolve.txt = map[string][]string{"_mta-sts.smithcpa.com": {"v=STSv1; id=1"}}
	policy := "version: STSv1\r\nmode: enforce\r\nmx: mx2.smithcpa.com\r\nmax_age: 86400\r\n"
	d := r.deliverer()
	d.STS = &STS{Resolver: r.resolve, Client: r.policyClient(t, policy)}
	res := d.Deliver(context.Background(), worker, []string{"pat@smithcpa.com"}, []byte(signedMsg))
	if res[0].Status != Temporary || res[0].Detail != "MX not in the domain's MTA-STS policy" {
		t.Fatalf("unlisted MX: %+v", res)
	}
	r.resolve.mx["smithcpa.com"] = []MX{{5, "mx.smithcpa.com"}, {10, "mx2.smithcpa.com"}}
	// mx2 presents mx.smithcpa.com's certificate in this rig, so allow both names.
	r2 := newRig(t, "mx.smithcpa.com", "mx2.smithcpa.com")
	r2.resolve = r.resolve
	d = r2.deliverer()
	d.STS = &STS{Resolver: r.resolve, Client: r2.policyClient(t, policy)}
	res = d.Deliver(context.Background(), worker, []string{"pat@smithcpa.com"}, []byte(signedMsg))
	if res[0].Status != Sent {
		t.Fatalf("listed MX: %+v", res)
	}
	if got := r2.relay.asked; len(got) != 1 || got[0] != "mx2.smithcpa.com:25" {
		t.Fatalf("relay asked for %v, want only the listed MX", got)
	}
}

// policyClient serves body as mta-sts.smithcpa.com's policy, over TLS the
// client validates, the way the edge fetches it through the relay.
func (r *rig) policyClient(t *testing.T, body string) *http.Client {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != "mta-sts.smithcpa.com" || req.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{r.ca.leaf(t, "mta-sts.smithcpa.com")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
		TLSClientConfig: &tls.Config{RootCAs: r.ca.pool},
	}, CheckRedirect: noRedirects}
}

func TestDeliverNoMX(t *testing.T) {
	r := newRig(t)
	res := r.deliverer().Deliver(context.Background(), worker, []string{"a@nomail.example"}, []byte(signedMsg))
	if res[0].Status != Permanent {
		t.Fatalf("%+v", res)
	}
	r.resolve.mx["null.example"] = []MX{{0, ""}}
	res = r.deliverer().Deliver(context.Background(), worker, []string{"a@null.example"}, []byte(signedMsg))
	if res[0].Status != Permanent {
		t.Fatalf("null MX: %+v", res)
	}
}

func TestRelayPins(t *testing.T) {
	r := newRig(t)
	other := r.ca.leaf(t, "not the relay")
	r.dialer.Pins = []gatewaytls.Pin{pinOf(leafOf(t, other))}
	if _, err := r.dialer.DialContext(context.Background(), "tcp", "mx.smithcpa.com:25"); err == nil {
		t.Fatal("dialed a relay whose key isn't pinned")
	}
	r = newRig(t)
	for _, addr := range []string{"mx.smithcpa.com:587", "mx.smithcpa.com:80", "x y:25"} {
		if _, err := r.dialer.DialContext(context.Background(), "tcp", addr); err == nil {
			t.Errorf("relayed %s", addr)
		}
	}
	if len(r.relay.asked) != 0 {
		t.Fatalf("relay was asked for %v", r.relay.asked)
	}
	// A client key the relay doesn't know.
	r = newRig(t)
	r.dialer.ClientCert = r.ca.leaf(t, "stranger")
	if c, err := r.dialer.DialContext(context.Background(), "tcp", "mx.smithcpa.com:25"); err == nil {
		// TLS 1.3 reports a refused client certificate on the first read.
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err == nil {
			t.Fatal("relay accepted an unknown client key")
		}
	}
}

func TestServiceSend(t *testing.T) {
	r := newRig(t)
	dir, id := newDir("pat@smithcpa.com")
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	svc := &Service{
		Policy:    NewPolicy(PolicyOptions{Directory: dir, MailDomain: "@fountbox.com"}),
		Signers:   []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: ek}},
		Deliverer: r.deliverer(),
	}
	res, err := svc.Send(context.Background(), id, good())
	if err != nil || len(res) != 1 || res[0].Status != Sent {
		t.Fatalf("%+v %v", res, err)
	}
	got := string(r.mx.received[0])
	if !strings.HasPrefix(got, "DKIM-Signature: v=1; a=ed25519-sha256;") || !strings.HasSuffix(got, string(good())) {
		t.Fatalf("delivered %q", got)
	}
	if _, err := svc.Send(context.Background(), id, good("Cc: stranger@example.net")); err == nil {
		t.Fatal("sent to a stranger")
	}
	if len(r.mx.received) != 1 {
		t.Fatal("refused message reached the MX")
	}
}

func TestDeliverSeveralDomains(t *testing.T) {
	r := newRig(t)
	r.resolve.mx["other.example"] = []MX{{10, "mx.smithcpa.com"}}
	res := r.deliverer().Deliver(context.Background(), worker,
		[]string{"pat@smithcpa.com", "jo@other.example", "al@smithcpa.com"}, []byte(signedMsg))
	if len(res) != 3 {
		t.Fatalf("%+v", res)
	}
	for _, x := range res {
		if x.Status != Sent {
			t.Fatalf("%+v", res)
		}
	}
	if len(r.mx.received) != 2 {
		t.Fatalf("%d sessions, want one per domain", len(r.mx.received))
	}
}
