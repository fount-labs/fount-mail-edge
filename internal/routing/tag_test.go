package routing_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/hpke"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

// A "<local>+<tag>" recipient is mail for "<local>": the tag is a thread's reply
// token, which the broker checks.
func TestTaggedRecipientResolvesToTheUntaggedMailbox(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	id := s.MailboxID("worker@fountbox.com")
	ks := newKeyset(t)
	if err := s.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}

	for _, rcpt := range []string{"worker+abc@fountbox.com", "Worker+ABC@FountBox.com", "worker+a+b@fountbox.com"} {
		if st, err := s.Status(ctx, rcpt); err != nil || st != smtp.RecipientAccepting {
			t.Errorf("Status(%s) = %v %v, want Accepting", rcpt, st, err)
		}
		got, err := s.Resolve(ctx, rcpt)
		if err != nil {
			t.Fatalf("Resolve(%s): %v", rcpt, err)
		}
		if !bytes.Equal(got.MailboxID, id) || !bytes.Equal(got.PublicKey, ks.dec.PublicKey().Bytes()) {
			t.Errorf("Resolve(%s) is not worker@'s mailbox", rcpt)
		}
	}

	for _, rcpt := range []string{"worker+@fountbox.com", "nobody+abc@fountbox.com", "+abc@fountbox.com"} {
		if st, _ := s.Status(ctx, rcpt); st != smtp.RecipientUnknown {
			t.Errorf("Status(%s) = %v, want Unknown", rcpt, st)
		}
		if _, err := s.Resolve(ctx, rcpt); !errors.Is(err, store.ErrNoRecipient) {
			t.Errorf("Resolve(%s) = %v, want ErrNoRecipient", rcpt, err)
		}
	}
}

func TestTaggedRecipientOfALapsedMailboxIsExpired(t *testing.T) {
	routingKey, macKey := keys(t)
	s := newStore(t, newMemBlobs(), routingKey, macKey)
	ctx := context.Background()
	dead := newKeyset(t).record(s.MailboxID("dead@fountbox.com"))
	dead.EntitlementExp = time.Now().Add(-time.Hour).Unix()
	if err := s.Upsert(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(ctx, "dead+abc@fountbox.com"); st != smtp.RecipientExpired {
		t.Fatalf("Status = %v, want Expired", st)
	}
}

// "fount+<token>" is a proof reply even when a mailbox named "fount" exists: a
// wrong token is unknown, not mail for that mailbox.
func TestProofTagTakesPrecedence(t *testing.T) {
	f := newOwnerFixture(t)
	f.set(t, f.id, 1, "jane@example.com")
	ctx := context.Background()
	if err := f.s.Upsert(ctx, newKeyset(t).record(f.s.MailboxID("fount@fountbox.com"))); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.s.Status(ctx, "fount+wrong@fountbox.com"); st != smtp.RecipientUnknown {
		t.Fatalf("wrong proof token: %v, want Unknown", st)
	}
	next := &countingStorer{}
	if _, err := f.s.ProofIntake(next).Put(ctx, store.Envelope{Recipient: "fount+wrong@fountbox.com"}, nil); !errors.Is(err, store.ErrNoRecipient) || next.n != 0 {
		t.Fatalf("wrong proof token Put: %v, stored %d", err, next.n)
	}
	ns := pending(t, f.s)
	if len(ns) != 1 {
		t.Fatalf("pending %+v", ns)
	}
	if st, _ := f.s.Status(ctx, ns[0].ReplyTo); st != smtp.RecipientAccepting {
		t.Fatalf("right proof token: %v, want Accepting", st)
	}
	if _, err := f.s.ProofIntake(next).Put(ctx, store.Envelope{Recipient: ns[0].ReplyTo}, nil); err != nil || next.n != 0 {
		t.Fatalf("right proof token Put: %v, stored %d", err, next.n)
	}
}

// Mail to a tagged address is stored in the untagged mailbox, on its sequence,
// and the sealed envelope keeps the tag for the device to read.
func TestTaggedMailKeepsItsTagInTheSealedEnvelope(t *testing.T) {
	routingKey, macKey := keys(t)
	blobs := newMemBlobs()
	rt := newStore(t, blobs, routingKey, macKey)
	ctx := context.Background()
	id := rt.MailboxID("worker@fountbox.com")
	ks := newKeyset(t)
	if err := rt.Upsert(ctx, ks.record(id)); err != nil {
		t.Fatal(err)
	}
	_, sign, _ := ed25519.GenerateKey(rand.Reader)
	st := store.New(rt, blobs, sign, make([]byte, 16))

	if _, err := st.Put(ctx, store.Envelope{Recipient: "worker@fountbox.com", Sender: "a@example.com"}, []byte("one")); err != nil {
		t.Fatal(err)
	}
	const tagged = "worker+t0ken@fountbox.com"
	edgeID, err := st.Put(ctx, store.Envelope{Recipient: tagged, Sender: "a@example.com"}, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := blobs.Get(ctx, "edge/mail/"+hex.EncodeToString(id)+"/"+edgeID)
	if err != nil {
		t.Fatalf("not in worker@'s mailbox: %v", err)
	}
	p, err := store.Parse(obj, sign.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.MailboxID, id) || p.Sequence != 2 {
		t.Fatalf("mailbox %x sequence %d, want worker@'s and 2", p.MailboxID, p.Sequence)
	}
	aadLen := len(obj) - ed25519.SignatureSize - 4 - len(p.Ct) - len(p.Enc) - 2
	plain, err := hpke.Open(ks.dec.Bytes(), p.Enc, []byte("fount-mail-edge/v1/stored-message"), obj[:aadLen], p.Ct)
	if err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(plain))
	plain = plain[2+n:]
	if got := string(plain[2 : 2+int(binary.BigEndian.Uint16(plain))]); got != tagged {
		t.Fatalf("sealed recipient %q, want %q", got, tagged)
	}
	if strings.Contains(string(obj[:aadLen]), "t0ken") {
		t.Fatal("the tag is outside the seal")
	}
}
