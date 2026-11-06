package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 (AWS4-HMAC-SHA256), implemented from the specification
// so the edge keeps its zero-dependency reproducible build — no AWS SDK. The
// construction is verified against the published sig-v4 test suite in sign_test.go.
//
// emptyPayloadHash is sha256("") — the hashed payload for a request with no body.
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type creds struct {
	accessKeyID string
	secret      string
}

// sign adds X-Amz-Date and the Authorization header to req, signing every header
// already present (plus host) with the given hashed payload. The caller sets any
// x-amz-* headers it wants covered (e.g. X-Amz-Content-Sha256) before calling.
func sign(req *http.Request, payloadHash, region, service string, c creds, t time.Time) {
	t = t.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)

	canonHeaders, signedHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery(req.URL.RawQuery),
		canonHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveKey(c.secret, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := "AWS4-HMAC-SHA256 " +
		"Credential=" + c.accessKeyID + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", auth)
}

// canonicalHeaders returns the canonical header block and the signed-headers
// list. Host comes from the request line, not the header map, so it is added
// explicitly; everything else is taken from req.Header, excluding Authorization.
func canonicalHeaders(req *http.Request) (canon, signed string) {
	values := map[string]string{"host": hostOf(req)}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" {
			continue
		}
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = trimAll(v)
		}
		values[lk] = strings.Join(trimmed, ",")
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

func hostOf(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

// trimAll collapses runs of internal spaces and trims the ends, per the spec's
// header-value normalization.
func trimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// canonicalURI URI-encodes each path segment, keeping the '/' separators. S3
// keys are not path-normalized (no dot-segment removal).
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s, false)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery sorts parameters by encoded key (then value) and encodes both,
// encoding '/' as well.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, p := range strings.Split(raw, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		// The raw query may already be percent/form-encoded (Go's url.Values
		// encoder). Decode each component, then re-encode once with AWS rules,
		// so a continuation token's + / = don't get double-encoded.
		pairs = append(pairs, kv{uriEncode(unescapeQuery(k), true), uriEncode(unescapeQuery(v), true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// uriEncode percent-encodes per RFC 3986 with AWS's rules: unreserved bytes
// (A-Za-z0-9-_.~) pass through, everything else is %XX with uppercase hex.
// Space becomes %20. '/' is encoded only when encodeSlash is set.
func uriEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0xf])
		}
	}
	return b.String()
}

// unescapeQuery reverses form/percent encoding, falling back to the raw token
// if it isn't validly encoded (so an already-canonical token survives).
func unescapeQuery(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

func deriveKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
