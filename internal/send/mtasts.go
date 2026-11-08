package send

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MTA-STS (RFC 8461) tells the edge which MX hosts a domain really uses. The
// edge requires validated TLS to every MX either way (§14 step 3); a policy in
// enforce mode also drops MX hosts it doesn't list, which is what stops a forged
// MX answer that points at a host with a valid certificate of its own.

const (
	maxPolicyBytes = 64 << 10
	maxPolicyAge   = 7 * 24 * time.Hour
)

type STSMode string

const (
	STSNone    STSMode = "none"
	STSTesting STSMode = "testing"
	STSEnforce STSMode = "enforce"
)

type STSPolicy struct {
	Mode   STSMode
	MX     []string // patterns, lowercased; "*.example.com" matches one label
	MaxAge time.Duration
}

// Allows reports whether host is one the policy lists. Outside enforce mode,
// every host is allowed.
func (p *STSPolicy) Allows(host string) bool {
	if p == nil || p.Mode != STSEnforce {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range p.MX {
		if pat == host {
			return true
		}
		if rest, ok := strings.CutPrefix(pat, "*."); ok {
			if label, suffix, ok := strings.Cut(host, "."); ok && label != "" && suffix == rest {
				return true
			}
		}
	}
	return false
}

// ParseSTSPolicy reads a policy file. Unknown keys are ignored, as RFC 8461
// §3.2 says; a missing version, mode, or max_age is an error.
func ParseSTSPolicy(r io.Reader) (*STSPolicy, error) {
	p := &STSPolicy{}
	var version, age bool
	sc := bufio.NewScanner(io.LimitReader(r, maxPolicyBytes))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "version":
			if v != "STSv1" {
				return nil, fmt.Errorf("mta-sts: version %q", v)
			}
			version = true
		case "mode":
			switch STSMode(v) {
			case STSNone, STSTesting, STSEnforce:
				p.Mode = STSMode(v)
			default:
				return nil, fmt.Errorf("mta-sts: mode %q", v)
			}
		case "mx":
			p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(v, ".")))
		case "max_age":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("mta-sts: max_age %q", v)
			}
			p.MaxAge, age = time.Duration(n)*time.Second, true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !version || p.Mode == "" || !age {
		return nil, errors.New("mta-sts: incomplete policy")
	}
	if p.Mode == STSEnforce && len(p.MX) == 0 {
		return nil, errors.New("mta-sts: enforce with no mx")
	}
	return p, nil
}

// noRedirects is the CheckRedirect an STS client must use (RFC 8461 §3.3).
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// STS finds and caches policies. Fetches go through the relay with TLS validated
// in the enclave, because policy hosts are arbitrary and the allowlist can't
// reach them (§14 step 5).
type STS struct {
	Resolver Resolver
	Client   *http.Client // must not follow redirects (RFC 8461 §3.3)

	mu    sync.Mutex
	cache map[string]cachedPolicy
	now   func() time.Time
}

type cachedPolicy struct {
	id      string
	policy  *STSPolicy
	expires time.Time
}

// Policy returns domain's policy, or nil if it publishes none. A domain whose
// TXT record exists but whose policy can't be fetched is an error, so a blocked
// fetch can't downgrade enforce to nothing; a cached policy still counts.
func (s *STS) Policy(ctx context.Context, domain string) (*STSPolicy, error) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	s.mu.Lock()
	cached, haveCached := s.cache[domain]
	s.mu.Unlock()
	if haveCached && now().After(cached.expires) {
		haveCached = false
	}

	txts, err := s.Resolver.TXT(ctx, "_mta-sts."+domain)
	if errors.Is(err, ErrNoRecord) {
		if haveCached {
			return cached.policy, nil
		}
		return nil, nil
	}
	if err != nil {
		if haveCached {
			return cached.policy, nil
		}
		return nil, err
	}
	id, ok := stsID(txts)
	if !ok {
		if haveCached {
			return cached.policy, nil
		}
		return nil, nil
	}
	if haveCached && cached.id == id {
		return cached.policy, nil
	}
	p, err := s.fetch(ctx, domain)
	if err != nil {
		if haveCached {
			return cached.policy, nil
		}
		return nil, err
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]cachedPolicy{}
	}
	s.cache[domain] = cachedPolicy{id: id, policy: p, expires: now().Add(min(p.MaxAge, maxPolicyAge))}
	s.mu.Unlock()
	return p, nil
}

// stsID returns the id of the one TXT record that starts v=STSv1. RFC 8461
// §3.1: more than one is treated as none.
func stsID(txts []string) (string, bool) {
	var id string
	found := 0
	for _, t := range txts {
		if !strings.HasPrefix(t, "v=STSv1") {
			continue
		}
		found++
		for _, part := range strings.Split(t, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == "id" {
				id = v
			}
		}
	}
	return id, found == 1 && id != ""
}

func (s *STS) fetch(ctx context.Context, domain string) (*STSPolicy, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://mta-sts."+domain+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mta-sts: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mta-sts: %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return nil, fmt.Errorf("mta-sts: content type %q", ct)
	}
	return ParseSTSPolicy(resp.Body)
}
