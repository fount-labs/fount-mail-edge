package send

import (
	"errors"
	"strings"
)

// The address forms a sent message may use are a narrow subset of RFC 5322, the
// same narrowing §11 applies to inbound From: a bare addr-spec, or a plain
// display name and an addr-spec in angle brackets. Comments, groups, encoded
// words, quoted local parts, and route syntax are refused rather than read,
// because two readers can disagree about them.

var errBadAddress = errors.New("address is not in a supported form")

// parseMailbox reads one mailbox and returns its lowercased addr-spec.
func parseMailbox(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, `()\;:,`) || strings.Contains(s, "=?") {
		return "", errBadAddress
	}
	if i := strings.IndexByte(s, '<'); i >= 0 {
		if !strings.HasSuffix(s, ">") || strings.Count(s, "<") != 1 || strings.Count(s, ">") != 1 {
			return "", errBadAddress
		}
		if !validDisplayName(strings.TrimSpace(s[:i])) {
			return "", errBadAddress
		}
		s = s[i+1 : len(s)-1]
	} else if strings.ContainsAny(s, "> \t\"") {
		return "", errBadAddress
	}
	if !validAddrSpec(s) {
		return "", errBadAddress
	}
	return strings.ToLower(s), nil
}

// parseMailboxList reads a comma-separated list of mailboxes. Commas inside a
// quoted display name are the only ones that don't split.
func parseMailboxList(s string) ([]string, error) {
	var out []string
	inQuote := false
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] == '"' {
			inQuote = !inQuote
		}
		if i == len(s) || (s[i] == ',' && !inQuote) {
			if inQuote {
				return nil, errBadAddress
			}
			a, err := parseMailbox(s[start:i])
			if err != nil {
				return nil, err
			}
			out = append(out, a)
			start = i + 1
		}
	}
	return out, nil
}

// validDisplayName accepts an empty name, a run of atoms separated by single
// spaces, or one quoted string holding printable ASCII with no quote or
// backslash inside.
func validDisplayName(n string) bool {
	if n == "" {
		return true
	}
	if strings.HasPrefix(n, `"`) {
		if len(n) < 2 || !strings.HasSuffix(n, `"`) {
			return false
		}
		inner := n[1 : len(n)-1]
		for i := 0; i < len(inner); i++ {
			if c := inner[i]; c < 32 || c > 126 || c == '"' {
				return false
			}
		}
		return true
	}
	for _, word := range strings.Split(n, " ") {
		if word == "" {
			return false
		}
		for i := 0; i < len(word); i++ {
			if !isAtext(word[i]) && word[i] != '.' {
				return false
			}
		}
	}
	return true
}

// validAddrSpec accepts dot-atom@domain, with a domain of LDH labels.
func validAddrSpec(a string) bool {
	local, domain, ok := strings.Cut(a, "@")
	if !ok || strings.Contains(domain, "@") || len(local) == 0 || len(local) > 64 {
		return false
	}
	for _, part := range strings.Split(local, ".") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			if !isAtext(part[i]) {
				return false
			}
		}
	}
	return validDomain(domain)
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func isAtext(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// domainOf returns the part after the @ of an address parseMailbox returned.
func domainOf(addr string) string {
	_, d, _ := strings.Cut(addr, "@")
	return d
}

// withoutTag removes a +token from the local part (§14 "<address>+<token>@").
func withoutTag(addr string) string {
	local, domain, _ := strings.Cut(addr, "@")
	if i := strings.IndexByte(local, '+'); i >= 0 {
		local = local[:i]
	}
	return local + "@" + domain
}
