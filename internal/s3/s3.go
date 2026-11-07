// Package s3 is a minimal, stdlib-only S3 client for the four operations the
// edge needs on its mail bucket: Put, Get, List (by prefix), and Delete. It
// signs every request with AWS Signature Version 4 (see sign.go) so the edge
// keeps its zero-dependency reproducible build — no AWS SDK.
//
// It targets virtual-hosted-style addressing (the bucket is part of the
// endpoint host), so each bucket has one fixed host and its own forwarder route
// (see internal/egress). The object key is the URL path.
//
// The client implements store.Blobs; Get returns store.ErrNotFound on a 404 so
// the routing and mail layers can distinguish a miss from a transient failure.
// GetVersioned and PutIfMatch add the conditional write routing needs.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/store"
)

const service = "s3"

// Client talks to one bucket at one endpoint. It is safe for concurrent use.
type Client struct {
	httpc    *http.Client
	base     *url.URL // scheme://<bucket-endpoint-host>, the bucket root
	region   string
	creds    creds
	now      func() time.Time
	maxPages int // bound on List pagination; 0 means the default
}

// Config configures a Client. Endpoint is the bucket root URL (for AWS,
// https://<bucket>.s3.<region>.amazonaws.com); it must already name the bucket,
// because egress is routed by exact host.
type Config struct {
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	HTTPClient      *http.Client
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" || cfg.Region == "" {
		return nil, fmt.Errorf("s3: endpoint and region are required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("s3: credentials are required")
	}
	base, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("s3: bad endpoint: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("s3: endpoint must be an absolute URL")
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		httpc:    httpc,
		base:     base,
		region:   cfg.Region,
		creds:    creds{cfg.AccessKeyID, cfg.SecretAccessKey},
		now:      time.Now,
		maxPages: 10_000,
	}, nil
}

func (c *Client) Put(ctx context.Context, key string, data []byte) error {
	resp, err := c.do(ctx, http.MethodPut, key, nil, data, nil)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return c.httpErr("put", key, resp)
	}
	return nil
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	data, _, err := c.GetVersioned(ctx, key)
	return data, err
}

// GetVersioned returns an object and the ETag PutIfMatch needs to replace it.
func (c *Client) GetVersioned(ctx context.Context, key string) ([]byte, string, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		return nil, "", err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", store.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", c.httpErr("get", key, resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return data, resp.Header.Get("ETag"), nil
}

// PutIfMatch writes an object only if it still has this ETag, or, with an empty
// etag, only if it doesn't exist. It returns the new ETag, or store.ErrConflict if
// the object changed. 412 is the normal answer, 409 means another conditional write
// raced this one, and 404 means the object has gone.
func (c *Client) PutIfMatch(ctx context.Context, key string, data []byte, etag string) (string, error) {
	h := http.Header{}
	if etag == "" {
		h.Set("If-None-Match", "*")
	} else {
		h.Set("If-Match", etag)
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, data, h)
	if err != nil {
		return "", err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusPreconditionFailed, http.StatusConflict, http.StatusNotFound:
		return "", store.ErrConflict
	default:
		return "", c.httpErr("put", key, resp)
	}
	next := resp.Header.Get("ETag")
	if next == "" {
		return "", fmt.Errorf("s3: put %q: no ETag in the response", key)
	}
	return next, nil
}

// Delete is idempotent: S3 answers 204 whether or not the object existed, which
// matches Blobs' "deleting an absent object is not an error".
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil, nil)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return c.httpErr("delete", key, resp)
	}
	return nil
}

type listResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	NextToken   string   `xml:"NextContinuationToken"`
	Contents    []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
}

// List returns the objects under prefix with their sizes, following
// continuation tokens so the result spans every page.
func (c *Client) List(ctx context.Context, prefix string) ([]store.Object, error) {
	var out []store.Object
	token := ""
	for page := 0; page < c.maxPages; page++ {
		q := url.Values{}
		q.Set("list-type", "2")
		if prefix != "" {
			q.Set("prefix", prefix)
		}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		drain(resp)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("s3: list %q: %s: %s", prefix, resp.Status, snippet(body))
		}
		var lr listResult
		if err := xml.Unmarshal(body, &lr); err != nil {
			return nil, fmt.Errorf("s3: list %q: parse: %w", prefix, err)
		}
		for _, o := range lr.Contents {
			// S3 reports LastModified in RFC3339 (ISO8601 with a Z). A parse
			// failure leaves Modified zero, which the sweep treats as "undatable,
			// don't delete" — the safe direction.
			mod, _ := time.Parse(time.RFC3339, o.LastModified)
			out = append(out, store.Object{Key: o.Key, Size: o.Size, Modified: mod})
		}
		if !lr.IsTruncated || lr.NextToken == "" {
			return out, nil
		}
		token = lr.NextToken
	}
	return nil, fmt.Errorf("s3: list %q: exceeded %d pages", prefix, c.maxPages)
}

// do builds, signs, and sends one request. key is a bucket-relative object key
// ("" for a bucket-level request such as List). query is the (unsigned) query
// values; do canonicalizes and signs them. header is added to the signed headers.
func (c *Client) do(ctx context.Context, method, key string, query url.Values, body []byte, header http.Header) (*http.Response, error) {
	u := *c.base
	u.Path = "/" + strings.TrimPrefix(key, "/")
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = c.base.Host
	for k, v := range header {
		req.Header[k] = v
	}
	payloadHash := emptyPayloadHash
	if len(body) > 0 {
		payloadHash = hexSHA256(body)
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if method == http.MethodPut {
		// S3 refuses uploads to an Object Lock bucket without a checksum header.
		sum := sha256.Sum256(body)
		req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(sum[:]))
	}
	req.ContentLength = int64(len(body))
	sign(req, payloadHash, c.region, service, c.creds, c.now())
	return c.httpc.Do(req)
}

func (c *Client) httpErr(op, key string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("s3: %s %q: %s: %s", op, key, resp.Status, snippet(body))
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
