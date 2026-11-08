package send

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

// One send end to end: both DoH lookups, the MTA-STS lookup, and SMTP all go
// through the one relay, and nothing else is dialed.
func TestNewEndToEnd(t *testing.T) {
	r := newRig(t)
	_, relayKey, _ := ed25519.GenerateKey(rand.Reader)
	clientCert, err := RelayClientCert(relayKey)
	if err != nil {
		t.Fatal(err)
	}
	r.relay.clientPin = pinOf(leafOf(t, clientCert))

	mxAnswer := `{"Status":0,"Answer":[{"name":"smithcpa.com.","type":15,"data":"10 mx.smithcpa.com."}]}`
	for _, name := range []string{"dns-a.test", "dns-b.test"} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Query().Get("type") == "15" && req.URL.Query().Get("name") == "smithcpa.com" {
				w.Write([]byte(mxAnswer))
				return
			}
			w.Write([]byte(`{"Status":3}`))
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{r.ca.leaf(t, name)}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		r.relay.routes[name+":443"] = srv.Listener.Addr().String()
	}

	dir, id := newDir("pat@smithcpa.com")
	_, dk, _ := ed25519.GenerateKey(rand.Reader)
	svc, err := New(Options{
		Directory:  dir,
		MailDomain: "@fountbox.com",
		Hostname:   "mx1.fountbox.com",
		Relay:      &Relay{Addr: r.dialer.Addr, ClientCert: clientCert, Pins: r.dialer.Pins},
		Signers:    []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: dk}},
		DoH:        []string{"https://dns-a.test/resolve", "https://dns-b.test/resolve"},
		Roots:      r.ca.pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.Send(context.Background(), id, good())
	if err != nil || len(res) != 1 || res[0].Status != Sent {
		t.Fatalf("%+v %v", res, err)
	}
	asked := strings.Join(r.relay.asked, ",")
	for _, want := range []string{"dns-a.test:443", "dns-b.test:443", "mx.smithcpa.com:25"} {
		if !strings.Contains(asked, want) {
			t.Errorf("relay never asked for %s (asked %s)", want, asked)
		}
	}
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	dir, _ := newDir()
	_, dk, _ := ed25519.GenerateKey(rand.Reader)
	cert, _ := RelayClientCert(dk)
	relay := &Relay{Addr: "relay:1", ClientCert: cert, Pins: []gatewaytls.Pin{{1}}}
	signers := []*dkim.Signer{{Domain: "fountbox.com", Selector: "s", Key: dk}}
	full := Options{Directory: dir, MailDomain: "@fountbox.com", Hostname: "mx1", Relay: relay, Signers: signers}
	if _, err := New(full); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Options){
		"no directory": func(o *Options) { o.Directory = nil },
		"no relay":     func(o *Options) { o.Relay = nil },
		"no pins":      func(o *Options) { o.Relay = &Relay{Addr: "relay:1", ClientCert: cert} },
		"no signers":   func(o *Options) { o.Signers = nil },
		"no hostname":  func(o *Options) { o.Hostname = "" },
	} {
		o := full
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}
