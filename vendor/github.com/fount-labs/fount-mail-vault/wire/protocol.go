package wire

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	AttestationSocket = "/tinfoil/attestation.sock"
	MaxDocumentBytes  = 32 << 20
	MaxBodyBytes      = 2*MaxDocumentBytes + 1<<20
)

// BeginResponse carries the holder's one-use nonce.
type BeginResponse struct {
	Nonce string `json:"nonce"`
}

// FinishRequest is the requester's document for the holder's nonce, plus a nonce
// of its own for the holder's document.
type FinishRequest struct {
	Nonce       string `json:"nonce"`
	AnswerNonce string `json:"answer_nonce"`
	Document    []byte `json:"document"`
}

// FinishResponse carries the sealed payload. HolderKey is unauthenticated on its
// own: a vault checks it against Document, and the edge relies on the commitment.
type FinishResponse struct {
	Document  []byte `json:"document"`
	HolderKey []byte `json:"holder_key"`
	Sealed    []byte `json:"sealed"`
}

// Payload is what a keyset box holds. S3 credentials ride along when the vault
// has them; they rotate, so the commitment doesn't cover them.
type Payload struct {
	Keyset []byte         `json:"keyset"`
	S3     *S3Credentials `json:"s3,omitempty"`
}

type S3Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// Attester produces this enclave's attestation document for a nonce.
type Attester interface {
	Attest(ctx context.Context, nonce []byte) ([]byte, error)
}

// HolderCheck verifies the holder's document for the requester's nonce and
// returns its attested key. A vault passes one. The edge passes nil and relies on
// the commitment, because verifying would take tinfoil-go and its dependencies.
type HolderCheck func(doc, nonce []byte) (*ecdh.PublicKey, error)

type PullResult struct {
	Keyset    *Keyset
	S3        *S3Credentials
	HolderKey *ecdh.PublicKey
	Elapsed   time.Duration
}

// Pull fetches the keyset from a holder at base, such as https://vault-a.example.
// With an empty commitment it needs a HolderCheck, because nothing else would
// authenticate the keys.
func Pull(ctx context.Context, client *http.Client, base string, me *ecdh.PrivateKey, a Attester, check HolderCheck, commitment string) (*PullResult, error) {
	if commitment == "" && check == nil {
		return nil, errors.New("pulling with no commitment needs a holder check")
	}
	start := time.Now()
	var begun BeginResponse
	if err := PostJSON(ctx, client, base+"/transfer/begin", nil, &begun); err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	issued, err := DecodeNonce(begun.Nonce)
	if err != nil {
		return nil, fmt.Errorf("holder's nonce: %w", err)
	}
	answer, err := RandomNonce()
	if err != nil {
		return nil, err
	}
	doc, err := a.Attest(ctx, issued)
	if err != nil {
		return nil, fmt.Errorf("attesting to holder: %w", err)
	}
	var finished FinishResponse
	req := FinishRequest{Nonce: begun.Nonce, AnswerNonce: hex.EncodeToString(answer), Document: doc}
	if err := PostJSON(ctx, client, base+"/transfer/finish", req, &finished); err != nil {
		return nil, fmt.Errorf("finish: %w", err)
	}
	holder, err := ParseRawKey(finished.HolderKey)
	if err != nil {
		return nil, fmt.Errorf("holder key: %w", err)
	}
	if check != nil {
		attested, err := check(finished.Document, answer)
		if err != nil {
			return nil, fmt.Errorf("verifying holder: %w", err)
		}
		if !attested.Equal(holder) {
			return nil, errors.New("verifying holder: its key isn't the one its document endorses")
		}
	}
	plaintext, err := Open(PurposeKeyset, me, holder, Nonces{Issued: issued, Answer: answer}, finished.Sealed)
	if err != nil {
		return nil, err
	}
	var payload Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	keyset, err := ParseKeyset(payload.Keyset)
	if err != nil {
		return nil, err
	}
	if commitment != "" && !keyset.Matches(commitment) {
		return nil, fmt.Errorf("keyset %s doesn't match the commitment %s", keyset.Commitment(), commitment)
	}
	return &PullResult{Keyset: keyset, S3: payload.S3, HolderKey: holder, Elapsed: time.Since(start)}, nil
}

// PostJSON posts in (or nothing) and decodes a 200 into out. Any other status is
// an error carrying the peer's own reason.
func PostJSON(ctx context.Context, client *http.Client, url string, in, out any) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer answered %d: %.400s", resp.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}

// SocketAttester asks Tinfoil's attestation socket for a document.
type SocketAttester struct{ client *http.Client }

func NewSocketAttester(path string) *SocketAttester {
	return &SocketAttester{client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Attest retries a 503, which the socket returns until it's ready and while the
// release has no current freshness witness.
func (a *SocketAttester) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	url := "http://localhost/.well-known/tinfoil-attestation?nonce=" + hex.EncodeToString(nonce)
	var last error
	for range 10 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("attestation socket: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading attestation: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusServiceUnavailable:
			last = fmt.Errorf("attestation socket answered 503: %.200s", body)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		default:
			return nil, fmt.Errorf("attestation socket answered %d: %.200s", resp.StatusCode, body)
		}
	}
	return nil, last
}
