package header

import (
	"bytes"
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	msg := []byte("From: a@example.com\r\nSubject: one\r\n two\r\nTo: b@example.com\r\n\r\nHi.\r\n")
	fields, body, err := Split(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 {
		t.Fatalf("got %d fields, want 3", len(fields))
	}
	if got := string(fields[1].Raw); got != "Subject: one\r\n two" {
		t.Fatalf("folded raw = %q", got)
	}
	if got := fields[1].Value(); got != "one two" {
		t.Fatalf("value = %q", got)
	}
	if string(body) != "Hi.\r\n" {
		t.Fatalf("body = %q", body)
	}
	if n := len(Get(fields, "to")); n != 1 {
		t.Fatalf("Get(to) = %d", n)
	}
}

func TestSplitEmptyBody(t *testing.T) {
	_, body, err := Split([]byte("From: a@example.com\r\n\r\n"))
	if err != nil || len(body) != 0 {
		t.Fatalf("body %q err %v", body, err)
	}
}

func TestSplitRefuses(t *testing.T) {
	long := "Subject: " + strings.Repeat("x", MaxLine) + "\r\n\r\n"
	cases := map[string]string{
		"bare LF in header":    "From: a@example.com\nTo: b\r\n\r\n",
		"bare CR in header":    "From: a@ex\rample.com\r\n\r\n",
		"bare LF in body":      "From: a@example.com\r\n\r\nhi\nthere\r\n",
		"no blank line":        "From: a@example.com\r\n",
		"leading continuation": " From: a@example.com\r\n\r\n",
		"no colon":             "From a@example.com\r\n\r\n",
		"space before colon":   "From : a@example.com\r\n\r\n",
		"8-bit header":         "Subject: caf\xc3\xa9\r\n\r\n",
		"long line":            long,
		"whitespace-only fold": "Subject: x\r\n \r\n\r\n",
		"NUL":                  "Subject: x\x00\r\n\r\n",
		"long body line":       "From: a@example.com\r\n\r\n" + strings.Repeat("y", MaxLine+1) + "\r\n",
	}
	for name, msg := range cases {
		if _, _, err := Split([]byte(msg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzSplit(f *testing.F) {
	f.Add([]byte("From: a@example.com\r\nSubject: x\r\n y\r\n\r\nbody\r\n"))
	f.Add([]byte("A: b\r\n\r\n"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		fields, body, err := Split(msg)
		if err != nil {
			return
		}
		// Every field is a contiguous piece of the header, and nothing the parser
		// accepted can smuggle a line break into a value.
		for _, fl := range fields {
			if !bytes.Contains(msg, fl.Raw) {
				t.Fatalf("field %q not in message", fl.Raw)
			}
			if strings.ContainsAny(fl.Value(), "\r\n") {
				t.Fatalf("value %q holds a line break", fl.Value())
			}
		}
		if !bytes.HasSuffix(msg, body) {
			t.Fatal("body is not the message's tail")
		}
	})
}
