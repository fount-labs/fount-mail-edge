package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/hpke"
)

// The stored-message object (design §9). This is a cross-service contract: the
// edge writes it, the broker (a separate repo) reads it, so the byte layout is
// explicit and versioned rather than a self-describing encoding whose
// serialization could drift.
//
// Signed region (big-endian), in order:
//
//	magic       4   "FME1"
//	version     1   formatVersion
//	suite       6   HPKE suite id (kem,kdf,aead as uint16s)
//	edgeID     16   random, assigned by the edge; never from the sender
//	mailboxID  32   keyed MAC of the address (routing + binding)
//	pubKeyHash 32   SHA-256 of the X25519 public key the message is sealed to
//	receivedAt  8   edge clock, unix milliseconds
//	sequence    8   per-mailbox counter (spots withheld mail)
//	bootID     16   which boot's signing key sealed this
//	encLen      2   | enc        HPKE encapsulated key
//	ctLen       4   | ct         HPKE ciphertext of (envelope + raw message)
//
// Then an ed25519 signature (64 bytes) over the whole signed region is
// appended. The ciphertext's AAD is the header up to and excluding enc/ct, so
// the sealed body is bound to its own header and cannot be moved onto another
// object. The plaintext inside the ciphertext is framed by messagePlaintext.
const (
	magic         = "FME1"
	formatVersion = 1

	// hpkeInfo domain-separates this use of the suite from any other.
	hpkeInfo = "fount-mail-edge/v1/stored-message"

	lenMagic      = 4
	lenSuite      = 6
	lenEdgeID     = 16
	lenMailboxID  = 32
	lenPubKeyHash = 32
	lenBootID     = 16

	// offset of enc/ct; also the length of the AAD-bound header region.
	headerLen = lenMagic + 1 + lenSuite + lenEdgeID + lenMailboxID + lenPubKeyHash + 8 + 8 + lenBootID
)

// Message is the §9 object before and after sealing. Enc/Ct are filled by Seal.
type Message struct {
	EdgeID     []byte
	MailboxID  []byte
	PubKeyHash []byte
	ReceivedAt time.Time
	Sequence   uint64
	BootID     []byte

	Enc []byte
	Ct  []byte
}

// header returns the AAD-bound region: every field above enc/ct, in order.
func (m *Message) header() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, magic...)
	b = append(b, formatVersion)
	b = append(b, hpke.SuiteID()...)
	b = append(b, m.EdgeID...)
	b = append(b, m.MailboxID...)
	b = append(b, m.PubKeyHash...)
	b = binary.BigEndian.AppendUint64(b, uint64(m.ReceivedAt.UnixMilli()))
	b = binary.BigEndian.AppendUint64(b, m.Sequence)
	b = append(b, m.BootID...)
	return b
}

// messagePlaintext frames the envelope and raw message for sealing. The
// plaintext address lives only here, inside the ciphertext (§9).
//
//	senderLen 2 | sender | recipientLen 2 | recipient | raw...
func messagePlaintext(sender, recipient string, raw []byte) []byte {
	b := make([]byte, 0, 2+len(sender)+2+len(recipient)+len(raw))
	b = binary.BigEndian.AppendUint16(b, uint16(len(sender)))
	b = append(b, sender...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(recipient)))
	b = append(b, recipient...)
	b = append(b, raw...)
	return b
}

// seal HPKE-encrypts the framed plaintext to recipientPub, binding the header
// as AAD, and fills Enc/Ct.
func (m *Message) seal(recipientPub []byte, sender, recipient string, raw []byte) error {
	enc, ct, err := hpke.Seal(recipientPub, []byte(hpkeInfo), m.header(), messagePlaintext(sender, recipient, raw))
	if err != nil {
		return err
	}
	m.Enc, m.Ct = enc, ct
	return nil
}

// MarshalSigned returns the full on-disk object: header, enc, ct, then the
// ed25519 signature over all of it. seal must have run first.
func (m *Message) MarshalSigned(sign ed25519.PrivateKey) []byte {
	b := m.header()
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Enc)))
	b = append(b, m.Enc...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(m.Ct)))
	b = append(b, m.Ct...)
	return append(b, ed25519.Sign(sign, b)...)
}

// pubKeyHash is the §9 "hash of the public key used".
func pubKeyHash(pub []byte) []byte {
	h := sha256.Sum256(pub)
	return h[:]
}

// --- Parsing + verification. The edge never reads a stored message back; this
// exists so tests (and the broker as a reference) can confirm the bytes the
// edge wrote verify and decrypt to the original. ---

// Parsed is a decoded object with its signature already verified.
type Parsed struct {
	Message
	Suite []byte
}

var errMalformed = errors.New("store: malformed message object")

// Parse decodes and verifies the ed25519 signature against signPub.
func Parse(b []byte, signPub ed25519.PublicKey) (*Parsed, error) {
	if len(b) < headerLen+2 {
		return nil, errMalformed
	}
	if string(b[:lenMagic]) != magic {
		return nil, fmt.Errorf("%w: bad magic", errMalformed)
	}
	p := &Parsed{}
	off := lenMagic
	if b[off] != formatVersion {
		return nil, fmt.Errorf("%w: version %d", errMalformed, b[off])
	}
	off++
	p.Suite = b[off : off+lenSuite]
	off += lenSuite
	p.EdgeID = b[off : off+lenEdgeID]
	off += lenEdgeID
	p.MailboxID = b[off : off+lenMailboxID]
	off += lenMailboxID
	p.PubKeyHash = b[off : off+lenPubKeyHash]
	off += lenPubKeyHash
	p.ReceivedAt = time.UnixMilli(int64(binary.BigEndian.Uint64(b[off : off+8])))
	off += 8
	p.Sequence = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	p.BootID = b[off : off+lenBootID]
	off += lenBootID

	if len(b) < off+2 {
		return nil, errMalformed
	}
	encLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if len(b) < off+encLen+4 {
		return nil, errMalformed
	}
	p.Enc = b[off : off+encLen]
	off += encLen
	ctLen := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4
	if len(b) < off+ctLen+ed25519.SignatureSize {
		return nil, errMalformed
	}
	p.Ct = b[off : off+ctLen]
	off += ctLen

	signed := b[:off]
	sig := b[off : off+ed25519.SignatureSize]
	if off+ed25519.SignatureSize != len(b) {
		return nil, fmt.Errorf("%w: trailing bytes", errMalformed)
	}
	if !ed25519.Verify(signPub, signed, sig) {
		return nil, errors.New("store: signature does not verify")
	}
	return p, nil
}
