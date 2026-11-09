package send

import (
	"crypto/hmac"
	"errors"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/limit"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
)

// Proposed caps (§14 "Sending limits"); the M3 test sets the real values. They
// are per enclave and reset on a reboot, like every other limit.Limiter budget.
const (
	DefaultPerWorkerPerDay  = 50
	DefaultPerLicensePerDay = 200
)

var (
	ErrNoMailbox   = errors.New("no such mailbox")
	ErrLapsed      = errors.New("mailbox entitlement has lapsed")
	ErrPaused      = errors.New("this worker is paused")
	ErrNotWorker   = errors.New("the From address is not this worker's")
	ErrNotOwner    = errors.New("recipient is not an owner of this worker")
	ErrNotProven   = errors.New("owner has not proved they read this address")
	ErrRateLimited = errors.New("sending limit reached")
)

// Directory is the routing data the checks read. routing.Store implements it.
type Directory interface {
	MailboxID(address string) []byte // the address MAC; owners are hashed the same way
	Snapshot(mailboxID []byte) (routing.Mailbox, bool)
}

// ProofChecker reports whether the edge itself has seen an owner answer the
// "Reply to turn on email updates" mail (§10), and the new-owner wait is over.
// routing.Store.OwnerProven implements it.
type ProofChecker func(mailboxID, ownerHash []byte) bool

// Policy decides whether a worker may send a message (§14). Every rule is the
// edge's own: the owner list is only what the licensee's device wrote, so a
// license mustn't become a way to send signed mail to strangers.
type Policy struct {
	dir     Directory
	domain  string // "@fountbox.com"
	proven  ProofChecker
	worker  *limit.Limiter
	license *limit.Limiter
	now     func() time.Time
}

type PolicyOptions struct {
	Directory  Directory
	MailDomain string       // e.g. "@fountbox.com"
	Proven     ProofChecker // nil trusts the owner list alone, which only dev allows
	PerWorker  int          // messages per worker per day; 0 is the default
	PerLicense int          // messages per license per day; 0 is the default
}

func NewPolicy(o PolicyOptions) *Policy {
	perWorker, perLicense := o.PerWorker, o.PerLicense
	if perWorker <= 0 {
		perWorker = DefaultPerWorkerPerDay
	}
	if perLicense <= 0 {
		perLicense = DefaultPerLicensePerDay
	}
	return &Policy{
		dir:     o.Directory,
		domain:  strings.ToLower(o.MailDomain),
		proven:  o.Proven,
		worker:  limit.PerWindow(float64(perWorker), 24*time.Hour),
		license: limit.PerWindow(float64(perLicense), 24*time.Hour),
		now:     time.Now,
	}
}

// Check returns nil if mailboxID may send m. The limits are spent last, so a
// message refused for any other reason costs nothing.
func (p *Policy) Check(mailboxID []byte, m *Message) error {
	mb, ok := p.dir.Snapshot(mailboxID)
	if !ok {
		return ErrNoMailbox
	}
	// POST /pause stops sends as well as jobs (§12). It's read from the same
	// snapshot as the owner list, so no hook can be left unset.
	if mb.Paused {
		return ErrPaused
	}
	if mb.EntitlementExp != 0 && p.now().Unix() >= mb.EntitlementExp {
		return ErrLapsed
	}
	if !strings.HasSuffix(m.From, p.domain) || !hmac.Equal(p.dir.MailboxID(m.From), mailboxID) {
		return ErrNotWorker
	}
	for _, r := range m.Recipients {
		// No mail between workers: one worker's mail to another stays data (§22),
		// and it would loop through the gateway.
		if strings.HasSuffix(r, p.domain) {
			return ErrNotOwner
		}
		h := p.dir.MailboxID(r)
		if !hasHash(mb.OwnerHashes, h) {
			return ErrNotOwner
		}
		if p.proven != nil && !p.proven(mailboxID, h) {
			return ErrNotProven
		}
	}
	if !p.license.Allow(string(mb.LicenseHash)) {
		return ErrRateLimited
	}
	if !p.worker.Allow(string(mailboxID)) {
		return ErrRateLimited
	}
	return nil
}

func hasHash(list [][]byte, h []byte) bool {
	for _, v := range list {
		if hmac.Equal(v, h) {
			return true
		}
	}
	return false
}
