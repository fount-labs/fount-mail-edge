package smtp

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// FuzzExtractAddr exercises the MAIL/RCPT address extractor on arbitrary command
// arguments. It must never panic and must never emit a CR or LF — a returned
// address flows into the recipient/sender used for storage and logging, so a
// control character leaking through would be an injection seam (§6).
func FuzzExtractAddr(f *testing.F) {
	f.Add("FROM:<a@b.com>")
	f.Add("TO:<worker@fountbox.com>")
	f.Add("FROM:<>")
	f.Add("  TO: plain@addr ")
	f.Add("<a<b>c>")
	f.Add(":")
	f.Add("")
	f.Fuzz(func(t *testing.T, rest string) {
		// extractAddr only ever sees a command argument that readLine already
		// stripped of CR/LF, so that is its precondition. Given clean input the
		// address it returns must stay clean — it flows into stored/logged
		// recipient and sender fields (§6).
		if strings.ContainsAny(rest, "\r\n") {
			return
		}
		got := extractAddr(rest)
		if strings.ContainsAny(got, "\r\n") {
			t.Fatalf("extractAddr leaked CR/LF: %q -> %q", rest, got)
		}
	})
}

// FuzzSplitVerb checks the command splitter never panics and that the verb it
// returns is a prefix-shaped token with no embedded space (the switch in handle
// matches it exactly).
func FuzzSplitVerb(f *testing.F) {
	f.Add("EHLO mx.example.com")
	f.Add("  starttls  ")
	f.Add("QUIT")
	f.Add("")
	f.Fuzz(func(t *testing.T, line string) {
		verb, _ := splitVerb(line)
		// splitVerb cuts at the first space, so the verb the switch matches must
		// never contain one.
		if strings.IndexByte(verb, ' ') >= 0 {
			t.Fatalf("verb contains a space: %q -> %q", line, verb)
		}
	})
}

// FuzzReadLine feeds arbitrary bytes to the command-line reader. A line returned
// without error is a command the state machine will act on, so it must honour
// the strict framing (§7): no bare CR/LF survives, and nothing over the cap is
// accepted.
func FuzzReadLine(f *testing.F) {
	f.Add([]byte("EHLO x\r\n"))
	f.Add([]byte("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n"))
	f.Add([]byte("bare\nlf\r\n"))
	f.Add([]byte("no-terminator"))
	f.Fuzz(func(t *testing.T, data []byte) {
		se := &session{r: bufio.NewReader(bytes.NewReader(data))}
		for i := 0; i < 1000; i++ {
			line, err := se.readLine()
			if err != nil {
				break
			}
			if strings.ContainsAny(line, "\r\n") {
				t.Fatalf("readLine returned embedded CR/LF: %q", line)
			}
			if len(line) > 8192 {
				t.Fatalf("readLine returned over-long line: %d bytes", len(line))
			}
		}
	})
}

// FuzzReadData feeds arbitrary bytes to the DATA-body reader. Whatever it
// accepts must respect the size cap; it must never panic or loop unbounded on
// truncated or adversarial framing.
func FuzzReadData(f *testing.F) {
	const maxBytes = 4096
	f.Add([]byte("hello\r\n.\r\n"))
	f.Add([]byte("..dotstuffed\r\n.\r\n"))
	f.Add([]byte("no terminator ever"))
	f.Add([]byte(".\r\n"))
	f.Add([]byte("a\n.\r\nb\r\n.\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		se := &session{
			s: &Server{opt: Options{MaxBytes: maxBytes}},
			r: bufio.NewReader(bytes.NewReader(data)),
		}
		raw, err := se.readData()
		if err == nil && int64(len(raw)) > maxBytes {
			t.Fatalf("readData returned %d bytes, over cap %d", len(raw), maxBytes)
		}
		if err == nil {
			// An accepted body has only CRLF line endings.
			stripped := bytes.ReplaceAll(raw, []byte("\r\n"), nil)
			if bytes.ContainsAny(stripped, "\r\n") {
				t.Fatalf("readData accepted a bare CR or LF: %q", raw)
			}
		}
	})
}
