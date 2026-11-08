package send

import (
	"fmt"
	"strings"
	"testing"
)

const worker = "ap.smithcpa@fountbox.com"

func msg(headers ...string) []byte {
	return []byte(strings.Join(headers, "\r\n") + "\r\n\r\nYour result is ready.\r\n")
}

func good(extra ...string) []byte {
	h := []string{
		"From: Accounts payable <" + worker + ">",
		"To: Pat Smith <pat@smithcpa.com>",
		"Subject: Your result is ready",
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <1@fountbox.com>",
	}
	return msg(append(h, extra...)...)
}

func TestParse(t *testing.T) {
	m, err := Parse(good("Cc: jo@smithcpa.com, PAT@smithcpa.com", "Reply-To: <ap.smithcpa+t0k3n@fountbox.com>"))
	if err != nil {
		t.Fatal(err)
	}
	if m.From != worker {
		t.Fatalf("From = %q", m.From)
	}
	if got := strings.Join(m.Recipients, ","); got != "pat@smithcpa.com,jo@smithcpa.com" {
		t.Fatalf("recipients = %q", got)
	}
}

func TestParseRefuses(t *testing.T) {
	base := []string{
		"To: pat@smithcpa.com",
		"Subject: s",
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <1@fountbox.com>",
	}
	with := func(h ...string) []byte { return msg(append(append([]string{}, h...), base...)...) }
	cases := map[string][]byte{
		"no From":           msg(base...),
		"two From fields":   with("From: "+worker, "From: "+worker),
		"two mailboxes":     with("From: " + worker + ", other@fountbox.com"),
		"group":             with("From: team: " + worker + ";"),
		"comment":           with("From: " + worker + " (the worker)"),
		"encoded word":      with("From: =?utf-8?q?AP?= <" + worker + ">"),
		"quoted local part": with(`From: "ap"@fountbox.com`),
		"Bcc":               with("From: "+worker, "Bcc: stranger@example.net"),
		"Sender":            with("From: "+worker, "Sender: stranger@example.net"),
		"own DKIM":          with("From: "+worker, "DKIM-Signature: v=1"),
		"Resent-To":         with("From: "+worker, "Resent-To: stranger@example.net"),
		"two Subjects":      with("From: "+worker, "Subject: again"),
		"Reply-To stranger": with("From: "+worker, "Reply-To: stranger@example.net"),
		"8-bit body":        []byte("From: " + worker + "\r\n" + strings.Join(base, "\r\n") + "\r\n\r\ncaf\xc3\xa9\r\n"),
		"too many":          with("From: "+worker, "Cc: "+manyAddrs(MaxRecipients)),
		"bare LF":           []byte("From: " + worker + "\n" + strings.Join(base, "\r\n") + "\r\n\r\n"),
		"no Message-ID":     msg("From: "+worker, "To: pat@smithcpa.com", "Subject: s", "Date: x"),
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseMailbox(t *testing.T) {
	ok := map[string]string{
		"a@example.com":                  "a@example.com",
		"  A.B+c@Example.COM ":           "a.b+c@example.com",
		"Pat Smith <pat@example.com>":    "pat@example.com",
		`"Smith, Pat" <pat@example.com>`: "",
		`"Pat Smith" <pat@example.com>`:  "pat@example.com",
		"<pat@example.com>":              "pat@example.com",
	}
	for in, want := range ok {
		got, err := parseMailbox(in)
		if want == "" {
			if err == nil {
				t.Errorf("%q: accepted %q", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "a", "a@b", "a@-b.com", "a..b@example.com", ".a@example.com",
		"a@example.com>", "<a@example.com", "x <a@example.com> <b@example.com>",
		"a b@example.com", "@example.com", "a@@example.com", "a@exa_mple.com",
		"Pat  Smith <a@example.com>", `"Pat\" <a@example.com>`,
	} {
		if got, err := parseMailbox(bad); err == nil {
			t.Errorf("%q: accepted as %q", bad, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(good())
	f.Add(good("Cc: a@example.com, \"B\" <b@example.com>"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Parse(raw)
		if err != nil {
			return
		}
		// Whatever is accepted names one sender and only plain addresses.
		if len(m.Recipients) == 0 || len(m.Recipients) > MaxRecipients {
			t.Fatalf("%d recipients", len(m.Recipients))
		}
		for _, a := range append([]string{m.From}, m.Recipients...) {
			if !validAddrSpec(a) || a != strings.ToLower(a) {
				t.Fatalf("accepted address %q", a)
			}
		}
	})
}

func FuzzParseMailbox(f *testing.F) {
	f.Add("Pat <pat@example.com>")
	f.Add(`"x" <a@b.co>`)
	f.Fuzz(func(t *testing.T, s string) {
		a, err := parseMailbox(s)
		if err != nil {
			return
		}
		if !validAddrSpec(a) || strings.ContainsAny(a, "<>\" \r\n") {
			t.Fatalf("%q gave %q", s, a)
		}
	})
}

func manyAddrs(n int) string {
	var a []string
	for i := 0; i < n; i++ {
		a = append(a, fmt.Sprintf("r%d@example.com", i))
	}
	return strings.Join(a, ", ")
}
