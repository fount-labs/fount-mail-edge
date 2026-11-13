package sendercheck

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/dkim"
)

// The DKIM verifier: RFC 6376 with RFC 8463's ed25519-sha256. Every failure is a
// result, never an error, and the result names say what a receiver should do:
// pass, fail (the signature or body hash didn't verify), permerror (the signature
// or key can never verify) or temperror (DNS didn't answer).

const (
	resultPass      = "pass"
	resultFail      = "fail"
	resultPermError = "permerror"
	resultTempError = "temperror"
)

// verifyError is one signature's failure, with the result it maps to.
type verifyError struct {
	result string
	msg    string
}

func (e *verifyError) Error() string { return e.msg }

func permErr(format string, a ...any) error {
	return &verifyError{resultPermError, fmt.Sprintf(format, a...)}
}

func failErr(msg string) error { return &verifyError{resultFail, msg} }

// errNoRecord and errTemporary are what a Lookup returns for a name with no
// record and for one DNS couldn't answer.
var (
	errNoRecord  = errors.New("no such record")
	errTemporary = errors.New("DNS didn't answer")
)

// Lookup answers a TXT question. It returns errNoRecord when the name has no TXT
// record and errTemporary (or any other error) when it couldn't find out.
type Lookup func(name string) ([]string, error)

// keyName is where a signature's key lives, or "" if the tag list doesn't name one.
func keyName(t map[string]string) string {
	d, s := strings.ToLower(stripSpace(t["d"])), strings.ToLower(stripSpace(t["s"]))
	if d == "" || s == "" {
		return ""
	}
	return s + "._domainkey." + d
}

type canon int

const (
	canonSimple canon = iota
	canonRelaxed
)

func parseCanon(c string) (header, body canon, err error) {
	c = strings.ToLower(stripSpace(c))
	if c == "" {
		return canonSimple, canonSimple, nil
	}
	h, b, two := strings.Cut(c, "/")
	one := func(s string) (canon, error) {
		switch s {
		case "simple":
			return canonSimple, nil
		case "relaxed":
			return canonRelaxed, nil
		}
		return 0, permErr("unsupported canonicalization %q", s)
	}
	if header, err = one(h); err != nil {
		return
	}
	if !two {
		return header, canonSimple, nil
	}
	body, err = one(b)
	return
}

// verifyOne checks one DKIM-Signature field against the message. now is when the
// edge received it, for x=. It returns the key records it was given, for keyFacts.
func verifyOne(fields []field, body []byte, sigField field, now time.Time, lookup Lookup) ([]string, error) {
	// The checks run in go-msgauth's order, which the broker's verifier uses, so
	// a signature with several faults reports the same one.
	t, ok := tags(sigField.Value)
	if !ok {
		return nil, permErr("DKIM-Signature tag list is malformed")
	}
	if stripSpace(t["v"]) != "1" {
		return nil, permErr("incompatible signature version")
	}
	for _, k := range []string{"v", "a", "b", "bh", "d", "h", "s"} {
		if _, ok := t[k]; !ok {
			return nil, permErr("signature is missing the %s= tag", k)
		}
	}
	domain := strings.ToLower(stripSpace(t["d"]))
	if auid := strings.ToLower(stripSpace(t["i"])); auid != "" {
		if !strings.HasSuffix(auid, "@"+domain) && !strings.HasSuffix(auid, "."+domain) {
			return nil, permErr("AUID is not in the signing domain")
		}
	}
	var signed []string
	fromSigned := false
	for h := range strings.SplitSeq(stripSpace(t["h"]), ":") {
		if h == "" {
			continue
		}
		signed = append(signed, h)
		fromSigned = fromSigned || strings.EqualFold(h, "from")
	}
	if !fromSigned {
		return nil, permErr("From field not signed")
	}
	if x, ok := t["x"]; ok {
		exp, err := strconv.ParseInt(stripSpace(x), 10, 64)
		if err != nil {
			return nil, permErr("malformed expiration")
		}
		if now.Unix() > exp {
			return nil, permErr("signature has expired")
		}
	}
	if q, ok := t["q"]; ok && !slices.Contains(strings.Split(strings.ToLower(stripSpace(q)), ":"), "dns/txt") {
		return nil, permErr("unsupported key query method")
	}

	records, err := lookup(keyName(t))
	switch {
	case errors.Is(err, errNoRecord):
		return nil, permErr("no key for signature")
	case err != nil:
		return nil, &verifyError{resultTempError, "key unavailable"}
	case len(records) == 0:
		return records, permErr("no valid key found")
	case len(records) > 1:
		// RFC 6376 §3.6.2.2 leaves several records undefined.
		return records, permErr("multiple TXT records found for key")
	}
	key, err := parseKeyRecord(records[0])
	if err != nil {
		return records, err
	}

	keyType, hashName, ok := strings.Cut(strings.ToLower(stripSpace(t["a"])), "-")
	if !ok {
		return records, permErr("malformed algorithm name")
	}
	if key.hashes != nil && !slices.Contains(key.hashes, hashName) {
		return records, permErr("inappropriate hash algorithm")
	}
	switch hashName {
	case "sha1":
		// RFC 8301 §3.1: rsa-sha1 must not be used for verifying.
		return records, permErr("hash algorithm too weak: sha1")
	case "sha256":
	default:
		return records, permErr("unsupported hash algorithm")
	}
	if key.algo != keyType {
		return records, permErr("inappropriate key algorithm")
	}
	if key.services != nil && !slices.Contains(key.services, "email") {
		return records, permErr("inappropriate service")
	}
	hc, bc, err := parseCanon(t["c"])
	if err != nil {
		return records, err
	}
	if _, ok := t["l"]; ok {
		// l= lets anyone append to the body.
		return records, failErr("message contains an insecure body length tag")
	}
	bh, err := base64.StdEncoding.DecodeString(stripSpace(t["bh"]))
	if err != nil {
		return records, permErr("malformed body hash")
	}
	sig, err := base64.StdEncoding.DecodeString(stripSpace(t["b"]))
	if err != nil {
		return records, permErr("malformed signature")
	}

	sum := sha256.Sum256(canonBody(body, bc))
	if subtle.ConstantTimeCompare(sum[:], bh) != 1 {
		return records, failErr("body hash did not verify")
	}

	h := sha256.New()
	used := map[string]int{}
	for _, n := range signed {
		n = strings.ToLower(n)
		var copies []field
		for _, f := range fields {
			if strings.EqualFold(f.Name, n) {
				copies = append(copies, f)
			}
		}
		k := len(copies) - 1 - used[n]
		used[n]++
		if k < 0 {
			continue
		}
		h.Write(canonHeader(copies[k].Raw, hc))
		h.Write([]byte("\r\n"))
	}
	h.Write(canonHeader(removeSignature(sigField.Raw), hc))
	digest := h.Sum(nil)

	switch k := key.pub.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) != nil {
			return records, failErr("signature did not verify")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, sig) {
			return records, failErr("signature did not verify")
		}
	}
	return records, nil
}

type keyRecord struct {
	pub      crypto.PublicKey
	algo     string   // "rsa" or "ed25519"
	hashes   []string // h=, nil when absent
	services []string // s=, nil when absent or "*"
}

func tagList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(stripSpace(s), ":") {
		out = append(out, strings.ToLower(v))
	}
	return out
}

// parseKeyRecord reads a key record (RFC 6376 §3.6.1).
func parseKeyRecord(rec string) (*keyRecord, error) {
	t, ok := tags(rec)
	if !ok {
		return nil, permErr("key record is malformed")
	}
	if v, ok := t["v"]; ok && stripSpace(v) != "DKIM1" {
		return nil, permErr("incompatible public key version")
	}
	p, ok := t["p"]
	if !ok {
		return nil, permErr("key syntax error: missing public key data")
	}
	p = stripSpace(p)
	if p == "" {
		return nil, permErr("key revoked")
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, permErr("key syntax error: bad base64")
	}
	out := &keyRecord{}
	switch strings.ToLower(stripSpace(t["k"])) {
	case "rsa", "":
		var rk *rsa.PublicKey
		if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
			if rk, ok = pub.(*rsa.PublicKey); !ok {
				return nil, permErr("key syntax error: not an RSA public key")
			}
		} else if rk, err = x509.ParsePKCS1PublicKey(der); err != nil {
			return nil, permErr("key syntax error: not an RSA public key")
		}
		// RFC 8301 §3.2: RSA keys under 1024 bits never verify.
		if rk.Size()*8 < 1024 {
			return nil, permErr("key is too short: want 1024 bits, has %d bits", rk.Size()*8)
		}
		out.pub, out.algo = rk, "rsa"
	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return nil, permErr("invalid Ed25519 public key size: %d bytes", len(der))
		}
		out.pub, out.algo = ed25519.PublicKey(der), "ed25519"
	default:
		return nil, permErr("unsupported key algorithm")
	}
	if h, ok := t["h"]; ok {
		out.hashes = tagList(h)
	}
	if s, ok := t["s"]; ok {
		if svcs := tagList(s); !slices.Contains(svcs, "*") {
			out.services = svcs
		}
	}
	return out, nil
}

func canonHeader(raw []byte, c canon) []byte {
	if c == canonRelaxed {
		return dkim.RelaxedHeader(raw)
	}
	return raw
}

func canonBody(body []byte, c canon) []byte {
	if c == canonRelaxed {
		return dkim.RelaxedBody(body)
	}
	// simple (RFC 6376 §3.4.3): drop empty lines at the end, and end with one CRLF.
	for bytes.HasSuffix(body, []byte("\r\n\r\n")) {
		body = body[:len(body)-2]
	}
	if len(body) == 0 || !bytes.HasSuffix(body, []byte("\r\n")) {
		return append(bytes.Clone(body), "\r\n"...)
	}
	return body
}

// removeSignature empties the b= tag's value in a DKIM-Signature field (RFC 6376
// §3.5), keeping everything else, folding included, byte for byte.
func removeSignature(raw []byte) []byte {
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return raw
	}
	out := bytes.Clone(raw[:colon+1])
	rest := raw[colon+1:]
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, ';')
		part := rest
		if end >= 0 {
			part = rest[:end]
		}
		if k, _, ok := bytes.Cut(part, []byte("=")); ok && string(bytes.TrimSpace(k)) == "b" {
			eq := bytes.IndexByte(part, '=')
			part = part[:eq+1]
		}
		out = append(out, part...)
		if end < 0 {
			break
		}
		out = append(out, ';')
		rest = rest[end+1:]
	}
	return out
}

// sigHash is the SHA-256 of the b= value, whitespace stripped, for the app's
// replay check.
func sigHash(val string) string {
	t, ok := tags(val)
	if !ok {
		return ""
	}
	sum := sha256.Sum256([]byte(stripSpace(t["b"])))
	return hex.EncodeToString(sum[:])
}

// keyFacts reads a key record's size and its t=y flag.
func keyFacts(rec []string) (bits int, testing bool) {
	if len(rec) != 1 {
		return 0, false
	}
	t, ok := tags(rec[0])
	if !ok {
		return 0, false
	}
	for flag := range strings.SplitSeq(stripSpace(t["t"]), ":") {
		testing = testing || flag == "y"
	}
	der, err := base64.StdEncoding.DecodeString(stripSpace(t["p"]))
	if err != nil || len(der) == 0 {
		return 0, testing
	}
	if strings.EqualFold(t["k"], "ed25519") {
		if len(der) == ed25519.PublicKeySize {
			return 256, testing
		}
		return 0, testing
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := pub.(*rsa.PublicKey); ok {
			return rk.N.BitLen(), testing
		}
	}
	if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rk.N.BitLen(), testing
	}
	return 0, testing
}
