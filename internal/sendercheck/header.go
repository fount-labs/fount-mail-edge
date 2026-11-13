package sendercheck

import (
	"bytes"
	"errors"
	"strings"
)

// field is one top-level header field.
type field struct {
	Name  string // as written
	Value string // unfolded, trimmed
	Raw   []byte // the whole field as it appears, folding kept, without the final CRLF
}

const (
	maxFields      = 1000
	maxHeaderBytes = 1 << 20
)

var errHeader = errors.New("message header is malformed")

// splitHeader returns the top-level header fields of raw, in order, and the
// body. It never interprets a value. Its rules are the broker verifier's, so both
// read the same fields from the same message. Unlike package header, which reads
// mail the device wrote, it accepts 8-bit bytes: inbound mail has them.
func splitHeader(raw []byte) ([]field, []byte, error) {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	var body []byte
	if end < 0 {
		if !bytes.HasSuffix(raw, []byte("\r\n")) {
			return nil, nil, errHeader
		}
		end = len(raw) - 2 // headers only, no body
	} else {
		body = raw[end+4:]
	}
	if end > maxHeaderBytes {
		return nil, nil, errHeader
	}
	var out []field
	start, fieldStart := 0, 0
	for _, line := range strings.Split(string(raw[:end]), "\r\n") {
		lineStart := start
		start += len(line) + 2
		if line == "" {
			return nil, nil, errHeader
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(out) == 0 {
				return nil, nil, errHeader
			}
			last := &out[len(out)-1]
			last.Value += " " + strings.TrimSpace(line)
			last.Raw = raw[fieldStart : lineStart+len(line)]
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return nil, nil, errHeader
		}
		fieldStart = lineStart
		out = append(out, field{Name: name, Value: strings.TrimSpace(value), Raw: raw[lineStart : lineStart+len(line)]})
		if len(out) > maxFields {
			return nil, nil, errHeader
		}
	}
	for i := range out {
		out[i].Value = strings.TrimSpace(out[i].Value)
	}
	return out, body, nil
}

// all returns the values of every field named name, case-insensitively.
func all(fields []field, name string) []string {
	var out []string
	for _, f := range fields {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// tags parses a DKIM tag-list (RFC 6376 §3.2): "k=v; k=v". Whitespace inside a
// value is kept for the caller to strip where the RFC says to.
func tags(s string) (map[string]string, bool) {
	out := map[string]string{}
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, false
		}
		if _, dup := out[k]; dup {
			return nil, false
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, true
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}
