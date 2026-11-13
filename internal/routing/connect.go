package routing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Connecting an owner (2026-11-12, **proposed**). The device asks the edge, with
// POST /connect, to mail an owner from the worker's own address; the owner
// replies; the device recognises the reply by its In-Reply-To or References and
// hands the original Message-ID back on PUT /routing as the proof. The edge
// never reads the reply. It only mints the Message-ID, a MAC over the worker,
// the owner and the time, and checks it when it comes back. So nobody learns it
// but the owner, who got the mail, and whoever they reply to, who is the worker.

const (
	ownerConnectInfo = "fount-mail-edge/v1/owner-connect"

	// ConnectLifetime is how long a connect mail's proof is good for.
	ConnectLifetime = 24 * time.Hour

	// connectSkew lets a proof be issued a little in the future, for another
	// edge whose clock runs ahead during a deploy.
	connectSkew = 5 * time.Minute

	connectMACBytes = 16
	connectPrefix   = "c."
)

// ErrConnectProof means a connect proof on PUT /routing doesn't verify, has
// expired, or names an owner the request doesn't list (422).
var ErrConnectProof = errors.New("connect proof invalid or expired")

// ConnectProof is a connect mail's Message-ID, as the device presents it for an
// owner. IssuedAt and MAC come from ParseConnectID.
type ConnectProof struct {
	Owner    string
	IssuedAt int64
	MAC      []byte
}

// ConnectMAC is the MAC in a connect mail's Message-ID: HMAC-SHA256 under the
// connect key of mailboxID, the owner's hash, and issuedAt as 8 big-endian
// bytes, cut to 16 bytes. The owner is hashed the way SetOwners hashes it.
func (s *Store) ConnectMAC(mailboxID []byte, owner string, issuedAt int64) []byte {
	return s.connectMAC(mailboxID, s.keyedHash(owner), issuedAt)
}

func (s *Store) connectMAC(mailboxID, ownerHash []byte, issuedAt int64) []byte {
	mac := hmac.New(sha256.New, s.connectKey)
	mac.Write(mailboxID)
	mac.Write(ownerHash)
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(issuedAt))
	mac.Write(t[:])
	return mac.Sum(nil)[:connectMACBytes]
}

// ConnectID is a connect mail's Message-ID, angle brackets included:
// <c.<issuedAt>.<mac>@<domain>>, the MAC in lowercase unpadded base32. domain
// may carry its leading "@".
func ConnectID(issuedAt int64, mac []byte, domain string) string {
	return "<" + connectPrefix + strconv.FormatInt(issuedAt, 10) + "." + proofEncoding.EncodeToString(mac) +
		"@" + strings.TrimPrefix(domain, "@") + ">"
}

// ParseConnectID reads a ConnectID, with or without its angle brackets. Its
// domain must be domain.
func ParseConnectID(id, domain string) (issuedAt int64, mac []byte, ok bool) {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "<") || strings.HasSuffix(id, ">") {
		if len(id) < 2 || id[0] != '<' || id[len(id)-1] != '>' {
			return 0, nil, false
		}
		id = id[1 : len(id)-1]
	}
	local, d, found := strings.Cut(id, "@")
	if !found || !strings.EqualFold(d, strings.TrimPrefix(domain, "@")) {
		return 0, nil, false
	}
	rest, found := strings.CutPrefix(local, connectPrefix)
	if !found {
		return 0, nil, false
	}
	ts, enc, found := strings.Cut(rest, ".")
	if !found || ts == "" || ts[0] == '0' && len(ts) > 1 {
		return 0, nil, false
	}
	for _, c := range ts {
		if c < '0' || c > '9' {
			return 0, nil, false
		}
	}
	issuedAt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return 0, nil, false
	}
	mac, err = proofEncoding.DecodeString(enc)
	if err != nil || len(mac) != connectMACBytes || proofEncoding.EncodeToString(mac) != enc {
		return 0, nil, false
	}
	return issuedAt, mac, true
}

// checkConnect verifies proofs for mailboxID against the request's owner hashes
// and returns the hashes they prove. Caller holds s.mu.
func (s *Store) checkConnect(mailboxID []byte, hashes [][]byte, proofs []ConnectProof) (map[string]bool, error) {
	if len(proofs) == 0 {
		return nil, nil
	}
	now := s.now().Unix()
	proved := make(map[string]bool, len(proofs))
	for _, p := range proofs {
		h := s.keyedHash(p.Owner)
		if !slices.ContainsFunc(hashes, func(o []byte) bool { return hmac.Equal(o, h) }) {
			return nil, ErrConnectProof
		}
		if !hmac.Equal(s.connectMAC(mailboxID, h, p.IssuedAt), p.MAC) {
			return nil, ErrConnectProof
		}
		if p.IssuedAt > now+int64(connectSkew/time.Second) || now > p.IssuedAt+int64(ConnectLifetime/time.Second) {
			return nil, ErrConnectProof
		}
		proved[string(h)] = true
	}
	return proved, nil
}
