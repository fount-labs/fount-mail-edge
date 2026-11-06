// Package store is the seam for inbound message storage.
//
// The real edge (design §6, §9) encrypts each raw message with HPKE to the
// recipient address's public key, stores it whole in S3 with the envelope
// recipient inside the encryption, and answers SMTP 250 only after S3 confirms
// the write. No edge key can decrypt what it stores.
//
// This minimal version provides the interface and a discarding implementation so
// the SMTP path is exercisable end to end before HPKE + S3 land (M2 step 4).
package store

import "context"

type Store interface {
	// Put stores one raw message for one envelope recipient and returns its id
	// only after the write is durable. A non-nil error means SMTP must NOT
	// return 250. Sender is the (untrusted) envelope sender, kept only for
	// per-sender quota accounting.
	Put(ctx context.Context, recipient, sender string, raw []byte) (id string, err error)
}

type discard struct{}

// NewDiscard stores nothing and always succeeds. Smoke-testing only.
func NewDiscard() Store { return discard{} }

func (discard) Put(_ context.Context, _, _ string, _ []byte) (string, error) {
	// TODO(M2 step 4): HPKE-encrypt to the address public key, write to S3,
	// enforce per-mailbox quota and per-IP/per-sender byte caps, return the id
	// only after S3 confirms.
	return "discarded", nil
}
