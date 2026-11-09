// Package header splits an RFC 5322 message into its header fields and body,
// strictly. It's the only header parser on the send path (design §14): the DKIM
// signer and the send checks both read fields through it, so they can't disagree
// about which From a message has.
//
// It refuses anything a lenient parser would have to guess at: bare CR or LF,
// lines over 998 bytes, 8-bit bytes in the header, a field with no colon, a
// continuation line before the first field, and a header with no blank line after
// it. The device writes these messages, so a refusal is a bug to fix there, never
// something to repair here.
package header

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// MaxLine is RFC 5322's hard limit on a line, excluding the CRLF.
const MaxLine = 998

var (
	ErrBareNewline = errors.New("bare CR or LF")
	ErrNoBody      = errors.New("no blank line after the header")
)

// Field is one header field as it appears in the message.
type Field struct {
	Name string // as written; compare with strings.EqualFold
	Raw  []byte // the whole field, name and folded value, without the final CRLF
}

// Value is the field's unfolded value with surrounding whitespace trimmed.
func (f Field) Value() string {
	v := f.Raw[len(f.Name)+1:]
	v = bytes.ReplaceAll(v, []byte("\r\n"), nil)
	return strings.Trim(string(v), " \t")
}

// Split parses msg into its fields and body. The body is everything after the
// blank line, and is checked for bare CR and LF and line length too.
func Split(msg []byte) ([]Field, []byte, error) {
	var fields []Field
	rest := msg
	start := 0 // offset of the field being built, in msg
	building := false
	for {
		i := bytes.Index(rest, []byte("\r\n"))
		if i < 0 {
			return nil, nil, ErrNoBody
		}
		line := rest[:i]
		off := len(msg) - len(rest)
		if err := checkLine(line, true); err != nil {
			return nil, nil, err
		}
		rest = rest[i+2:]
		if len(line) == 0 {
			if building {
				fields = appendField(fields, msg[start:off])
			}
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !building {
				return nil, nil, errors.New("continuation line before the first field")
			}
			if len(bytes.Trim(line, " \t")) == 0 {
				return nil, nil, errors.New("whitespace-only continuation line")
			}
			continue
		}
		if building {
			fields = appendField(fields, msg[start:off-2])
		}
		if _, err := fieldName(line); err != nil {
			return nil, nil, err
		}
		start, building = off, true
	}
	body := rest
	for b := body; len(b) > 0; {
		i := bytes.Index(b, []byte("\r\n"))
		line := b
		if i >= 0 {
			line, b = b[:i], b[i+2:]
		} else {
			b = nil
		}
		if err := checkLine(line, false); err != nil {
			return nil, nil, fmt.Errorf("body: %w", err)
		}
	}
	return fields, body, nil
}

func appendField(fields []Field, raw []byte) []Field {
	name, _ := fieldName(raw)
	return append(fields, Field{Name: name, Raw: raw})
}

// fieldName returns the name before the colon. RFC 5322 allows printable ASCII
// except the colon, with no whitespace before it.
func fieldName(line []byte) (string, error) {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return "", errors.New("header line with no field name")
	}
	for _, c := range line[:i] {
		if c < 33 || c > 126 {
			return "", errors.New("bad character in a field name")
		}
	}
	return string(line[:i]), nil
}

func checkLine(line []byte, inHeader bool) error {
	if len(line) > MaxLine {
		return errors.New("line over 998 bytes")
	}
	for _, c := range line {
		switch {
		case c == '\r' || c == '\n':
			return ErrBareNewline
		case c == 0:
			return errors.New("NUL byte")
		case inHeader && c >= 0x80:
			return errors.New("8-bit byte in the header")
		}
	}
	return nil
}

// Get returns every field named name, in message order.
func Get(fields []Field, name string) []Field {
	var out []Field
	for _, f := range fields {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f)
		}
	}
	return out
}
