package sendercheck

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

const recipient = "worker@fountbox.com"

var received = time.Date(2026, 11, 8, 10, 0, 30, 0, time.UTC)

// vector is one message from testdata/go-msgauth-vectors.json, made by a
// throwaway program with go-msgauth, the library fount-broker's verifier uses:
// it signed each message and recorded go-msgauth's result for each signature.
type vector struct {
	Name    string              `json:"name"`
	Raw     string              `json:"raw"`
	TXT     map[string][]string `json:"txt"`
	Temp    []string            `json:"temp"`
	Results []string            `json:"results"`
}

func vectors(t *testing.T) map[string]vector {
	t.Helper()
	b, err := os.ReadFile("testdata/go-msgauth-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	out := map[string]vector{}
	for _, v := range vs {
		out[v.Name] = v
	}
	return out
}

func (v vector) lookup(name string) ([]string, error) {
	if slices.Contains(v.Temp, name) {
		return nil, errTemporary
	}
	r, ok := v.TXT[name]
	if !ok {
		return nil, errNoRecord
	}
	return r, nil
}

func checkVector(t *testing.T, v vector) *Verdict {
	t.Helper()
	got, err := Check(Input{Raw: []byte(v.Raw), Recipient: recipient, ReceivedAt: received}, v.lookup)
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	return got
}

// Every signature gets the result go-msgauth gave it.
func TestResultsMatchGoMsgauth(t *testing.T) {
	vs := vectors(t)
	if len(vs) < 40 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for name, v := range vs {
		got := checkVector(t, v)
		var results []string
		for _, s := range got.DKIM {
			results = append(results, s.Result)
		}
		if !slices.Equal(results, v.Results) {
			t.Errorf("%s: got %v, go-msgauth %v (%+v)", name, results, v.Results, got.DKIM)
		}
	}
}

func TestAlignedSignatures(t *testing.T) {
	vs := vectors(t)
	for _, name := range []string{"ed25519 relaxed", "rsa relaxed", "rsa simple", "relaxed/simple", "simple/relaxed", "rsa 1024", "oversigned"} {
		v := checkVector(t, vs[name])
		if !v.Aligned || !v.RecipientSigned || len(v.DKIM) != 1 || v.DKIM[0].Result != "pass" || v.DKIM[0].Hash == "" || !v.DKIM[0].Covers {
			t.Fatalf("%s: %+v", name, v)
		}
		if v.From.Address != "owner@example.com" || v.From.Name != "Owner" || v.From.Domain != "example.com" {
			t.Fatalf("%s from: %+v", name, v.From)
		}
		if v.Headers.Subject != "Q3 numbers" || v.Headers.MessageID != "<a1@example.com>" || !slices.Equal(v.Headers.To, []string{recipient}) {
			t.Fatalf("%s headers: %+v", name, v.Headers)
		}
		if v.DateSkewSeconds == nil || *v.DateSkewSeconds != -30 {
			t.Fatalf("%s skew %v", name, v.DateSkewSeconds)
		}
	}
	if k := checkVector(t, vs["rsa relaxed"]).DKIM[0]; k.KeyBits != 2048 || k.Algorithm != "rsa-sha256" || k.Selector != "s1" || k.Domain != "example.com" {
		t.Fatalf("rsa facts %+v", k)
	}
	if k := checkVector(t, vs["ed25519 relaxed"]).DKIM[0]; k.KeyBits != 256 || k.Algorithm != "ed25519-sha256" {
		t.Fatalf("ed25519 facts %+v", k)
	}
	two := checkVector(t, vs["two signatures, one key gone"])
	if !two.Aligned || two.DKIM[0].Aligned || !two.DKIM[1].Aligned {
		t.Fatalf("two signatures: %+v", two.DKIM)
	}
}

func TestWeakSignaturesArentAligned(t *testing.T) {
	vs := vectors(t)
	for _, name := range []string{"body length", "testing key", "signature from another domain", "tampered body",
		"no key", "rsa-sha1", "temp DNS", "oversigned then added From", "expired"} {
		v := checkVector(t, vs[name])
		if name == "signature from another domain" {
			// Only the example.org signature counts as another domain's.
			if v.DKIM[0].Aligned || v.DKIM[0].Domain != "example.org" {
				t.Errorf("%s: %+v", name, v.DKIM)
			}
			continue
		}
		if v.Aligned || v.RecipientSigned {
			t.Errorf("%s: aligned: %+v", name, v.DKIM)
		}
	}
	if s := checkVector(t, vs["body length"]).DKIM[0]; !s.BodyLength {
		t.Errorf("l= %+v", s)
	}
	if s := checkVector(t, vs["testing key"]).DKIM[0]; !s.Testing || s.Result != "pass" {
		t.Errorf("t=y %+v", s)
	}
	if v := checkVector(t, vs["oversigned then added From"]); v.From.Error == "" {
		t.Errorf("added From: %+v", v.From)
	}
	// A Cc added after signing is a signed field's unsigned copy.
	cc := vs["ed25519 relaxed"]
	cc.Raw = "Cc: attacker@example.net\r\n" + cc.Raw
	if s := checkVector(t, cc).DKIM[0]; s.Covers || s.Aligned || !slices.Contains(s.Unsigned, "cc") {
		t.Errorf("cc %+v", s)
	}
	// Subject not signed.
	sub := vs["ed25519 relaxed"]
	sub.Raw = strings.Replace(sub.Raw, "h=From:To:Subject:Date:Message-ID", "h=From:To:Date:Message-ID", 1)
	if s := checkVector(t, sub).DKIM[0]; s.Covers || !slices.Contains(s.Unsigned, "subject") {
		t.Errorf("subject %+v", s)
	}
}

// The edge's own signer and this verifier agree, for both its algorithms.
func TestVerifiesTheEdgesOwnSignatures(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("From: Worker <worker@fountbox.com>\r\nTo: owner@example.com\r\nSubject: Re: Q3\r\nDate: Sun, 08 Nov 2026 10:00:00 +0000\r\n\r\nDone.\r\n")
	txt := map[string][]string{}
	var signed []byte
	for _, s := range []*dkim.Signer{{Domain: "fountbox.com", Selector: "f1", Key: rk}, {Domain: "fountbox.com", Selector: "f1e", Key: ed}} {
		field, err := s.Sign(msg, received)
		if err != nil {
			t.Fatal(err)
		}
		rec, _ := dkim.TXTRecord(s.Key)
		txt[s.Selector+"._domainkey.fountbox.com"] = []string{rec}
		signed = append(field, signed...)
	}
	signed = append(signed, msg...)
	v, err := Check(Input{Raw: signed, Recipient: "owner@example.com", ReceivedAt: received}, func(name string) ([]string, error) {
		if r, ok := txt[name]; ok {
			return r, nil
		}
		return nil, errNoRecord
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.DKIM) != 2 || !v.DKIM[0].Aligned || !v.DKIM[1].Aligned || !v.RecipientSigned {
		t.Fatalf("%+v", v.DKIM)
	}
}

func TestFromIsStrict(t *testing.T) {
	for from, ok := range map[string]bool{
		"owner@example.com":                     true,
		"\"Owner, CPA\" <owner@Example.COM>":    false, // comma
		"Owner <owner@example.com> (work)":      false,
		"=?utf-8?q?Owner?= <owner@example.com>": false,
		"a@example.com, b@example.com":          false,
		"Team: a@example.com;":                  false,
		"Owner <owner@example.com>":             true,
		"<owner@EXAMPLE.com>":                   true,
		"owner":                                 false,
	} {
		got := parseFrom([]field{{Name: "From", Value: from}})
		if (got.Error == "") != ok {
			t.Errorf("%q: %+v", from, got)
		}
	}
	if got := parseFrom([]field{{Name: "From", Value: "<owner@EXAMPLE.com>"}}); got.Domain != "example.com" {
		t.Errorf("domain %+v", got)
	}
	if got := parseFrom(nil); got.Error == "" {
		t.Error("no From")
	}
}

func TestDuplicatedHeadersAreLeftEmpty(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: one\r\nSubject: two\r\nMessage-ID: <x@y>\r\n\r\nhi\r\n"
	v, err := Check(Input{Raw: []byte(raw), Recipient: recipient, ReceivedAt: received}, func(string) ([]string, error) { return nil, errNoRecord })
	if err != nil {
		t.Fatal(err)
	}
	if v.Headers.Subject != "" || !slices.Equal(v.Headers.Duplicated, []string{"subject"}) || v.Headers.MessageID != "<x@y>" {
		t.Fatalf("%+v", v.Headers)
	}
	if v.DateSkewSeconds != nil || len(v.DKIM) != 0 || v.DKIM == nil {
		t.Fatalf("%+v", v)
	}
}

func TestUnreadableHeaders(t *testing.T) {
	for _, raw := range []string{"no header end", "\r\n bad: continuation first\r\n\r\n", "Bad Name: x\r\n\r\n"} {
		if _, err := Check(Input{Raw: []byte(raw)}, nil); err == nil {
			t.Errorf("%q read", raw)
		}
	}
	// A header with no body is fine.
	if _, err := Check(Input{Raw: []byte("From: a@example.com\r\n")}, nil); err != nil {
		t.Error(err)
	}
}

func TestRemoveSignatureKeepsEverythingButB(t *testing.T) {
	in := "DKIM-Signature: v=1; bh=abc=;\r\n b=AAAA\r\n BBBB; d=x"
	if got := string(removeSignature([]byte(in))); got != "DKIM-Signature: v=1; bh=abc=;\r\n b=; d=x" {
		t.Fatalf("%q", got)
	}
}

// The stored JSON has exactly the contract's fields.
func TestVerdictFields(t *testing.T) {
	v := checkVector(t, vectors(t)["ed25519 relaxed"])
	b, _ := json.Marshal(v)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"aligned", "checked_by", "date_skew_seconds", "dkim", "from", "headers", "raw_sha256", "recipient_signed", "v"}
	if !slices.Equal(keys, want) {
		t.Fatalf("fields %v", keys)
	}
	if v.V != 1 || v.CheckedBy != "edge" || len(v.RawSHA256) != 64 || strings.ToLower(v.RawSHA256) != v.RawSHA256 {
		t.Fatalf("%+v", v)
	}
	var f map[string]any
	_ = json.Unmarshal(Failed("x"), &f)
	if len(f) != 3 || f["v"] != float64(1) || f["checked_by"] != "edge" || f["error"] != "x" {
		t.Fatalf("failed %v", f)
	}
}
