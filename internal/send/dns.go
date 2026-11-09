package send

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The host may be able to tamper with enclave DNS (§22), so the edge asks two
// independent DNS-over-HTTPS resolvers, through the relay with TLS ending in the
// enclave, and uses an answer only if both give the same one.
var DefaultDoH = []string{
	"https://dns.google/resolve",
	"https://cloudflare-dns.com/dns-query",
}

const maxDoHBytes = 64 << 10

// MX is one mail exchanger.
type MX struct {
	Pref uint16
	Host string // without the trailing dot, lowercased
}

// Resolver looks up what delivery needs.
type Resolver interface {
	MX(ctx context.Context, domain string) ([]MX, error)
	TXT(ctx context.Context, name string) ([]string, error)
}

// ErrNoRecord means the name exists with no record of that type, or doesn't
// exist. Both resolvers had to say so.
var ErrNoRecord = errors.New("no such record")

// DoH queries every endpoint with the JSON API both providers serve, and
// requires the answers to match.
type DoH struct {
	Client    *http.Client
	Endpoints []string
}

func (d *DoH) MX(ctx context.Context, domain string) ([]MX, error) {
	answers, err := d.agree(ctx, domain, 15)
	if err != nil {
		return nil, err
	}
	var out []MX
	for _, a := range answers {
		pref, host, ok := strings.Cut(a, " ")
		p, err := strconv.ParseUint(pref, 10, 16)
		if !ok || err != nil {
			return nil, fmt.Errorf("bad MX answer %q", a)
		}
		out = append(out, MX{Pref: uint16(p), Host: strings.ToLower(strings.TrimSuffix(host, "."))})
	}
	slices.SortStableFunc(out, func(a, b MX) int { return int(a.Pref) - int(b.Pref) })
	return out, nil
}

func (d *DoH) TXT(ctx context.Context, name string) ([]string, error) {
	answers, err := d.agree(ctx, name, 16)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(answers))
	for _, a := range answers {
		s, err := joinTXT(a)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *DoH) agree(ctx context.Context, name string, qtype int) ([]string, error) {
	if len(d.Endpoints) < 2 {
		return nil, errors.New("doh: need two resolvers")
	}
	var first []string
	for i, ep := range d.Endpoints {
		got, err := d.query(ctx, ep, name, qtype)
		if err != nil {
			return nil, err
		}
		slices.Sort(got)
		if i == 0 {
			first = got
		} else if !slices.Equal(first, got) {
			return nil, errors.New("doh: resolvers disagree")
		}
	}
	if len(first) == 0 {
		return nil, ErrNoRecord
	}
	return first, nil
}

type dohAnswer struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (d *DoH) query(ctx context.Context, endpoint, name string, qtype int) ([]string, error) {
	q := url.Values{"name": {name}, "type": {strconv.Itoa(qtype)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s", resp.Status)
	}
	var ans dohAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDoHBytes)).Decode(&ans); err != nil {
		return nil, fmt.Errorf("doh: %w", err)
	}
	switch ans.Status {
	case 0:
	case 3: // NXDOMAIN
		return nil, nil
	default:
		return nil, fmt.Errorf("doh: rcode %d", ans.Status)
	}
	var out []string
	for _, a := range ans.Answer {
		if a.Type == qtype { // skips the CNAMEs a chain answer carries
			out = append(out, a.Data)
		}
	}
	return out, nil
}

// joinTXT reads a TXT answer, which arrives as one or more quoted strings, into
// one value. An unquoted answer is taken as is.
func joinTXT(a string) (string, error) {
	a = strings.TrimSpace(a)
	if !strings.HasPrefix(a, `"`) {
		return a, nil
	}
	var b strings.Builder
	for len(a) > 0 {
		if a[0] != '"' {
			return "", fmt.Errorf("bad TXT answer")
		}
		end := 1
		for end < len(a) && a[end] != '"' {
			if a[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(a) {
			return "", fmt.Errorf("bad TXT answer")
		}
		s, err := strconv.Unquote(a[:end+1])
		if err != nil {
			s = a[1:end]
		}
		b.WriteString(s)
		a = strings.TrimLeft(a[end+1:], " ")
	}
	return b.String(), nil
}
