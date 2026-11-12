package send

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

// The signer checks what it can see in the message again, whoever handed it over.
func TestCheckHandoff(t *testing.T) {
	two := good("Cc: jo@smithcpa.com")
	if err := CheckHandoff("@fountbox.com", worker, []string{"pat@smithcpa.com", "jo@smithcpa.com"}, two); err != nil {
		t.Fatal(err)
	}
	if err := CheckHandoff("@fountbox.com", worker, []string{"jo@smithcpa.com"}, two); err != nil {
		t.Fatalf("a subset of the message's recipients: %v", err)
	}
	var many []string
	for i := range MaxRecipients + 1 {
		many = append(many, strings.Repeat("a", i+1)+"@smithcpa.com")
	}
	for name, c := range map[string]struct {
		domain, from string
		rcpts        []string
		raw          []byte
	}{
		"bad shape":          {"@fountbox.com", worker, []string{"pat@smithcpa.com"}, good("Bcc: x@y.z")},
		"another sender":     {"@fountbox.com", "other@fountbox.com", []string{"pat@smithcpa.com"}, good()},
		"sender off domain":  {"@smithcpa.com", worker, []string{"pat@smithcpa.com"}, good()},
		"no domain":          {"", worker, []string{"pat@smithcpa.com"}, good()},
		"no recipients":      {"@fountbox.com", worker, nil, good()},
		"too many":           {"@fountbox.com", worker, many, good()},
		"not in the message": {"@fountbox.com", worker, []string{"stranger@example.net"}, good()},
		"repeated":           {"@fountbox.com", worker, []string{"pat@smithcpa.com", "pat@smithcpa.com"}, good()},
		"to a worker":        {"@fountbox.com", worker, []string{"b@fountbox.com"}, good("Cc: b@fountbox.com")},
	} {
		if err := CheckHandoff(c.domain, c.from, c.rcpts, c.raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOutboxRefusesBeforeSigning(t *testing.T) {
	r := newRig(t)
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	out := &Outbox{MailDomain: "@fountbox.com", Signers: []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1e", Key: ek}}, Deliverer: r.deliverer()}
	if _, err := out.Transmit(context.Background(), worker, []string{"stranger@example.net"}, good()); !errors.Is(err, ErrBadMessage) {
		t.Fatalf("err = %v", err)
	}
	if len(r.mx.received) != 0 {
		t.Fatal("a refused handoff reached the MX")
	}
	res, err := out.Transmit(context.Background(), worker, []string{"pat@smithcpa.com"}, good())
	if err != nil || len(res) != 1 || res[0].Status != Sent {
		t.Fatalf("%+v %v", res, err)
	}
	if got := string(r.mx.received[0]); !strings.HasPrefix(got, "DKIM-Signature: v=1; a=ed25519-sha256;") {
		t.Fatalf("delivered %q", got)
	}
}
