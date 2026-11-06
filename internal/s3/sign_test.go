package s3

import (
	"net/http"
	"testing"
	"time"
)

// Vectors from the AWS Signature Version 4 test suite, case "get-vanilla"
// (the canonical example used across SDKs). Asserting both the canonical
// request and the final Authorization pins canonicalization and the HMAC key
// chain independently.
const (
	exAccessKey = "AKIDEXAMPLE"
	exSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	exRegion    = "us-east-1"
	exService   = "service"
	exHost      = "example.amazonaws.com"
)

func exTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestSigV4GetVanilla(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://"+exHost+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = exHost

	sign(req, emptyPayloadHash, exRegion, exService, creds{exAccessKey, exSecret}, exTime(t))

	want := "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch:\n got %s\nwant %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Fatalf("X-Amz-Date = %s", got)
	}
}

func TestCanonicalRequestGetVanilla(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://"+exHost+"/", nil)
	req.Host = exHost
	req.Header.Set("X-Amz-Date", "20150830T123600Z")

	canon, signed := canonicalHeaders(req)
	cr := req.Method + "\n" + canonicalURI(req.URL.Path) + "\n" +
		canonicalQuery(req.URL.RawQuery) + "\n" + canon + "\n" + signed + "\n" + emptyPayloadHash

	want := "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\n" +
		"host;x-amz-date\n" + emptyPayloadHash
	if cr != want {
		t.Fatalf("canonical request mismatch:\n got %q\nwant %q", cr, want)
	}
}

func TestURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"abcABC123", true, "abcABC123"},
		{"-_.~", true, "-_.~"},
		{"a/b", false, "a/b"},
		{"a/b", true, "a%2Fb"},
		{"a b", true, "a%20b"},
		{"foo+bar=baz", true, "foo%2Bbar%3Dbaz"},
		{"é", true, "%C3%A9"},
	}
	for _, c := range cases {
		if got := uriEncode(c.in, c.encodeSlash); got != c.want {
			t.Errorf("uriEncode(%q, %v) = %q, want %q", c.in, c.encodeSlash, got, c.want)
		}
	}
}

func TestCanonicalQuerySortsAndEncodes(t *testing.T) {
	// Keys sorted; values encoded once even though Go pre-encoded the slash.
	got := canonicalQuery("prefix=edge%2Fmail%2F&list-type=2")
	want := "list-type=2&prefix=edge%2Fmail%2F"
	if got != want {
		t.Fatalf("canonicalQuery = %q, want %q", got, want)
	}
}
