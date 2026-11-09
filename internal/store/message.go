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
//	version     1   formatVersion (2); Parse also reads 1
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
// object. The plaintext inside the ciphertext is framed by messagePlaintext,
// whose layout the version byte names.
const (
	magic         = "FME1"
	formatVersion = 2

	// formatV1 is the framing before the sending server's IP and HELO were
	// recorded. Objects stored then are still read.
	formatV1 = 1

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
	Version    byte // 0 means formatVersion
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
	b = append(b, m.version())
	b = append(b, hpke.SuiteID()...)
	b = append(b, m.EdgeID...)
	b = append(b, m.MailboxID...)
	b = append(b, m.PubKeyHash...)
	b = binary.BigEndian.AppendUint64(b, uint64(m.ReceivedAt.UnixMilli()))
	b = binary.BigEndian.AppendUint64(b, m.Sequence)
	b = append(b, m.BootID...)
	return b
}

func (m *Message) version() byte {
	if m.Version == 0 {
		return formatVersion
	}
	return m.Version
}

// Envelope is the SMTP envelope sealed with each message. Every field is what the
// sending server or the gateway said, unverified; the broker checks them (SPF).
type Envelope struct {
	Sender    string // MAIL FROM
	Recipient string // RCPT TO

	// ClientIP is the sending server's address, as the edge read it from the
	// gateway's PROXY header: the full address, not the /64 the limits use, in
	// netip's canonical form. ClientIPFrom says where it came from, and is
	// ClientIPNone with an empty ClientIP when there was none.
	ClientIP     string
	ClientIPFrom ClientIPSource

	// HELO is the name from the session's last EHLO or HELO, or empty if the
	// sender never sent one.
	HELO string
}

// ClientIPSource says how the edge learned Envelope.ClientIP. It's one byte in
// the sealed framing, so values are fixed once released.
type ClientIPSource byte

const (
	// ClientIPNone: no address, and ClientIP is empty.
	ClientIPNone ClientIPSource = 0
	// ClientIPProxy: the source address of the gateway's PROXY v1 header, which
	// travels inside the gateway's mutual TLS (§7). It's the sender's address only
	// as far as the gateway, which nothing attests, reports it honestly.
	ClientIPProxy ClientIPSource = 1
)

const (
	maxClientIPBytes = 45  // the longest textual IPv6 address
	maxHELOBytes     = 255 // the longest domain RFC 5321 allows
)

var errEnvelope = errors.New("store: envelope field too long")

// messagePlaintext frames the envelope and raw message for sealing. The
// plaintext addresses, the client IP and the HELO name live only here, inside
// the ciphertext (§9). Version 2, lengths big-endian:
//
//	senderLen 2 | sender | recipientLen 2 | recipient |
//	clientIPFrom 1 | clientIPLen 1 | clientIP | heloLen 1 | helo | raw...
//
// Version 1 stopped after the recipient: senderLen 2 | sender | recipientLen 2 |
// recipient | raw...
func messagePlaintext(env Envelope, raw []byte) ([]byte, error) {
	if len(env.Sender) > 0xffff || len(env.Recipient) > 0xffff ||
		len(env.ClientIP) > maxClientIPBytes || len(env.HELO) > maxHELOBytes {
		return nil, errEnvelope
	}
	if (env.ClientIPFrom == ClientIPNone) != (env.ClientIP == "") {
		return nil, errors.New("store: client IP and its source disagree")
	}
	b := make([]byte, 0, envelopeLen(env)+len(raw))
	b = binary.BigEndian.AppendUint16(b, uint16(len(env.Sender)))
	b = append(b, env.Sender...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(env.Recipient)))
	b = append(b, env.Recipient...)
	b = append(b, byte(env.ClientIPFrom), byte(len(env.ClientIP)))
	b = append(b, env.ClientIP...)
	b = append(b, byte(len(env.HELO)))
	b = append(b, env.HELO...)
	b = append(b, raw...)
	return b, nil
}

// envelopeLen is the framed envelope's length in version 2, before the raw message.
func envelopeLen(env Envelope) int {
	return 2 + len(env.Sender) + 2 + len(env.Recipient) + 2 + len(env.ClientIP) + 1 + len(env.HELO)
}

// unframe splits a decrypted plaintext of the given version into its envelope and
// raw message. The edge never decrypts; this is the broker's reference and the
// tests' check.
func unframe(version byte, p []byte) (Envelope, []byte, error) {
	var env Envelope
	str16 := func() (string, bool) {
		if len(p) < 2 || len(p) < 2+int(binary.BigEndian.Uint16(p)) {
			return "", false
		}
		n := int(binary.BigEndian.Uint16(p))
		v := string(p[2 : 2+n])
		p = p[2+n:]
		return v, true
	}
	str8 := func() (string, bool) {
		if len(p) < 1 || len(p) < 1+int(p[0]) {
			return "", false
		}
		n := int(p[0])
		v := string(p[1 : 1+n])
		p = p[1+n:]
		return v, true
	}
	var ok bool
	if env.Sender, ok = str16(); !ok {
		return env, nil, errMalformed
	}
	if env.Recipient, ok = str16(); !ok {
		return env, nil, errMalformed
	}
	switch version {
	case formatV1:
		return env, p, nil
	case formatVersion:
	default:
		return env, nil, fmt.Errorf("%w: version %d", errMalformed, version)
	}
	if len(p) < 1 {
		return env, nil, errMalformed
	}
	env.ClientIPFrom = ClientIPSource(p[0])
	p = p[1:]
	if env.ClientIP, ok = str8(); !ok {
		return env, nil, errMalformed
	}
	if env.HELO, ok = str8(); !ok {
		return env, nil, errMalformed
	}
	return env, p, nil
}

// seal HPKE-encrypts the framed plaintext to recipientPub, binding the header
// as AAD, and fills Enc/Ct.
func (m *Message) seal(recipientPub []byte, env Envelope, raw []byte) error {
	pt, err := messagePlaintext(env, raw)
	if err != nil {
		return err
	}
	enc, ct, err := hpke.Seal(recipientPub, []byte(hpkeInfo), m.header(), pt)
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

// bootIDOf reads the boot a stored message names, which says whose key to verify it
// with. It's unverified until Parse succeeds with that key.
func bootIDOf(b []byte) ([]byte, bool) {
	if len(b) < headerLen || string(b[:lenMagic]) != magic {
		return nil, false
	}
	return b[headerLen-lenBootID : headerLen], true
}

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
	if b[off] != formatVersion && b[off] != formatV1 {
		return nil, fmt.Errorf("%w: version %d", errMalformed, b[off])
	}
	p.Version = b[off]
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
