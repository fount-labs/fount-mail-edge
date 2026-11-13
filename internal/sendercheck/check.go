// Package sendercheck checks who sent an inbound message, when it arrives
// (fount m4-cloud-runners.md §3.2). The result is sealed inside the stored object
// (design §9, version 3), so it's covered by the object's signature, and the
// broker and the Cloud coordinator read it instead of parsing the mail again.
//
// It reports facts, with the meanings of fount-broker's internal/mail/verify,
// whose field names it keeps: the From mailbox, each DKIM signature's result and
// whether it is aligned, whether the Fount address is in a signed To or Cc, the
// signed Date's distance from arrival, and the headers intake threads on. The app
// decides what a message may do. SPF and DMARC aren't checked here.
//
// The parsing runs in a child process (Process), which has no keys and asks the
// parent for every DNS answer. A parser bug can crash or mislead the child, not
// reach the edge's keys.
package sendercheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/mail"
	"slices"
	"strings"
	"time"
)

// Version is the check's format version, the "v" field.
const Version = 1

// MaxBytes bounds the check JSON. A check is a few kilobytes; the limit leaves
// room for long Subject and address lists.
const MaxBytes = 256 << 10

// Verdict is the sender check, as stored. Its JSON is the contract with the broker
// and the coordinator.
type Verdict struct {
	V         int         `json:"v"`
	CheckedBy string      `json:"checked_by"`
	From      From        `json:"from"`
	DKIM      []Signature `json:"dkim"`
	// Aligned is true when at least one signature in DKIM is Aligned.
	Aligned bool `json:"aligned"`
	// RecipientSigned is true when the Fount address is in the To or Cc field an
	// aligned signature covers.
	RecipientSigned bool `json:"recipient_signed"`
	// DateSkewSeconds is the signed Date minus the edge's received_at. Absent
	// when there's no single parseable Date.
	DateSkewSeconds *int64 `json:"date_skew_seconds,omitempty"`
	// Headers are the values intake threads on, so the app never re-parses them.
	Headers Headers `json:"headers"`
	// RawSHA256 is the hex SHA-256 of the raw message the check is about.
	RawSHA256 string `json:"raw_sha256"`
}

// From is the single author mailbox, or why there isn't one.
type From struct {
	Address string `json:"address,omitempty"` // lowercase domain, local part as written
	Domain  string `json:"domain,omitempty"`
	Name    string `json:"name,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Signature is one DKIM-Signature field's result.
type Signature struct {
	Domain    string `json:"domain"`
	Selector  string `json:"selector"`
	Algorithm string `json:"algorithm"`
	// Result is pass, fail, temperror or permerror.
	Result  string   `json:"result"`
	Error   string   `json:"error,omitempty"`
	KeyBits int      `json:"key_bits,omitempty"`
	Headers []string `json:"headers"`
	// BodyLength is true when the signature has an l= tag, which lets anyone
	// append to the body.
	BodyLength bool `json:"body_length"`
	// Testing is true when the key record has t=y.
	Testing bool `json:"testing"`
	// Covers is true when every required field is signed, and no signed field has
	// an unsigned second copy.
	Covers bool `json:"covers"`
	// Unsigned lists the required fields that fail Covers.
	Unsigned []string `json:"unsigned,omitempty"`
	// Hash is the SHA-256 of the b= value, for the app's replay check.
	Hash string `json:"hash"`
	// Aligned: Result is pass, d= equals the From domain, the algorithm and key
	// are strong enough, there's no l=, the key isn't t=y, and Covers.
	Aligned bool `json:"aligned"`
}

type Headers struct {
	MessageID  string   `json:"message_id,omitempty"`
	InReplyTo  string   `json:"in_reply_to,omitempty"`
	References string   `json:"references,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Date       string   `json:"date,omitempty"`
	To         []string `json:"to,omitempty"`
	Cc         []string `json:"cc,omitempty"`
	ReplyTo    []string `json:"reply_to,omitempty"`
	// Duplicated lists the fields above that appear more than once. Their values
	// are left empty rather than guessed.
	Duplicated []string `json:"duplicated,omitempty"`
}

// failed is the check when it couldn't run. Nothing else in it is trusted.
type failed struct {
	V         int    `json:"v"`
	CheckedBy string `json:"checked_by"`
	Error     string `json:"error"`
}

// Failed is the stored check for a message the edge couldn't check. why must be
// generic: it is stored, and must not carry the message's content.
func Failed(why string) []byte {
	b, _ := json.Marshal(failed{V: Version, CheckedBy: "edge", Error: why})
	return b
}

// required are always signed; whenPresent are signed if the message has them.
var (
	required    = []string{"from", "to", "date", "subject"}
	whenPresent = []string{"cc", "content-type", "mime-version", "reply-to", "in-reply-to", "references"}
)

const maxSignatures = 8

// Input is one message to check.
type Input struct {
	Raw []byte
	// Recipient is the Fount address the edge delivered to.
	Recipient string
	// ReceivedAt is the edge's clock when the message arrived.
	ReceivedAt time.Time
}

// signatureFields are the DKIM-Signature fields Check verifies, in order.
func signatureFields(fields []field) []field {
	var out []field
	for _, f := range fields {
		if strings.EqualFold(f.Name, "DKIM-Signature") {
			out = append(out, f)
		}
	}
	if len(out) > maxSignatures {
		out = out[:maxSignatures]
	}
	return out
}

// KeyNames are the DNS names Check will ask about for raw: one per signature with
// a readable d= and s=, at most eight, without repeats.
func KeyNames(raw []byte) ([]string, error) {
	fields, _, err := splitHeader(raw)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, f := range signatureFields(fields) {
		t, ok := tags(f.Value)
		if !ok {
			continue
		}
		if n := keyName(t); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names, nil
}

// Check runs every check on in. It fails only when the message can't be read at
// all; a failed check is a result, not an error.
func Check(in Input, lookup Lookup) (*Verdict, error) {
	fields, body, err := splitHeader(in.Raw)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(in.Raw)
	v := &Verdict{V: Version, CheckedBy: "edge", DKIM: []Signature{}, RawSHA256: hex.EncodeToString(sum[:])}
	v.From = parseFrom(fields)
	v.Headers = threadHeaders(fields)
	if dates := all(fields, "Date"); len(dates) == 1 {
		if d, err := mail.ParseDate(dates[0]); err == nil && !in.ReceivedAt.IsZero() {
			skew := int64(d.Sub(in.ReceivedAt) / time.Second)
			v.DateSkewSeconds = &skew
		}
	}
	v.DKIM = checkDKIM(fields, body, v.From.Domain, in.ReceivedAt, lookup)
	for _, s := range v.DKIM {
		v.Aligned = v.Aligned || s.Aligned
	}
	v.RecipientSigned = v.Aligned && recipientIn(v.Headers, in.Recipient)
	return v, nil
}

func checkDKIM(fields []field, body []byte, fromDomain string, now time.Time, lookup Lookup) []Signature {
	sigs := []Signature{}
	counts := map[string]int{}
	for _, f := range fields {
		counts[strings.ToLower(f.Name)]++
	}
	for _, f := range signatureFields(fields) {
		s := Signature{Headers: []string{}, Hash: sigHash(f.Value), Result: resultPermError}
		t, ok := tags(f.Value)
		if !ok {
			s.Error = "DKIM-Signature tag list is malformed"
			sigs = append(sigs, s)
			continue
		}
		s.Domain = strings.ToLower(t["d"])
		s.Selector = strings.ToLower(t["s"])
		s.Algorithm = strings.ToLower(t["a"])
		_, s.BodyLength = t["l"]
		for h := range strings.SplitSeq(stripSpace(t["h"]), ":") {
			if h != "" {
				s.Headers = append(s.Headers, strings.ToLower(h))
			}
		}
		records, err := verifyOne(fields, body, f, now, lookup)
		if err == nil {
			s.Result = resultPass
		} else if ve, ok := err.(*verifyError); ok {
			s.Result, s.Error = ve.result, ve.msg
		} else {
			s.Result, s.Error = resultPermError, err.Error()
		}
		s.KeyBits, s.Testing = keyFacts(records)
		s.Unsigned = unsigned(s.Headers, counts)
		s.Covers = len(s.Unsigned) == 0
		goodAlg := s.Algorithm == "ed25519-sha256" || s.Algorithm == "rsa-sha256" && s.KeyBits >= 1024
		s.Aligned = s.Result == resultPass && fromDomain != "" && s.Domain == fromDomain && goodAlg && !s.BodyLength && !s.Testing && s.Covers
		sigs = append(sigs, s)
	}
	return sigs
}

// unsigned lists the required fields a signature doesn't fully cover. A field
// with n copies must be listed at least n times in h=, or an unsigned copy could
// be the one a reader shows.
func unsigned(h []string, counts map[string]int) []string {
	listed := map[string]int{}
	for _, name := range h {
		listed[name]++
	}
	var out []string
	for _, name := range required {
		if counts[name] == 0 || listed[name] < counts[name] {
			out = append(out, name)
		}
	}
	for _, name := range whenPresent {
		if listed[name] < counts[name] {
			out = append(out, name)
		}
	}
	return out
}

// parseFrom accepts exactly one From field holding exactly one plain mailbox.
// Comments, groups, lists and encoded words are refused, not interpreted.
func parseFrom(fields []field) From {
	froms := all(fields, "From")
	if len(froms) != 1 {
		return From{Error: fmt.Sprintf("%d From fields", len(froms))}
	}
	s := froms[0]
	switch {
	case strings.ContainsAny(s, "()"):
		return From{Error: "From has a comment"}
	case strings.ContainsAny(s, ",;:"):
		return From{Error: "From has more than one mailbox, or a group"}
	case strings.Contains(s, "=?"):
		return From{Error: "From has an encoded word"}
	case strings.ContainsFunc(s, func(r rune) bool { return r > 0x7e || r < 0x20 && r != '\t' }):
		return From{Error: "From isn't printable ASCII"}
	}
	a, err := (&mail.AddressParser{}).Parse(s)
	if err != nil {
		return From{Error: "From isn't a mailbox: " + err.Error()}
	}
	local, domain, ok := strings.Cut(a.Address, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return From{Error: "From isn't a mailbox"}
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return From{Address: local + "@" + domain, Domain: domain, Name: a.Name}
}

func threadHeaders(fields []field) Headers {
	var h Headers
	one := func(name string) (string, bool) {
		vs := all(fields, name)
		if len(vs) > 1 {
			h.Duplicated = append(h.Duplicated, strings.ToLower(name))
			return "", false
		}
		if len(vs) == 0 {
			return "", false
		}
		return vs[0], true
	}
	list := func(name string) []string {
		s, ok := one(name)
		if !ok {
			return nil
		}
		as, err := (&mail.AddressParser{WordDecoder: &mime.WordDecoder{}}).ParseList(s)
		if err != nil {
			return nil
		}
		out := make([]string, 0, len(as))
		for _, a := range as {
			out = append(out, a.Address)
		}
		return out
	}
	h.MessageID, _ = one("Message-ID")
	h.InReplyTo, _ = one("In-Reply-To")
	h.References, _ = one("References")
	if s, ok := one("Subject"); ok {
		if d, err := (&mime.WordDecoder{}).DecodeHeader(s); err == nil {
			s = d
		}
		h.Subject = s
	}
	h.Date, _ = one("Date")
	h.To = list("To")
	h.Cc = list("Cc")
	h.ReplyTo = list("Reply-To")
	return h
}

func recipientIn(h Headers, recipient string) bool {
	for _, a := range slices.Concat(h.To, h.Cc) {
		if strings.EqualFold(a, recipient) {
			return true
		}
	}
	return false
}
