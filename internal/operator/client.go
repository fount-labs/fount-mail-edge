package operator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// Client is the operator's side, for edgectl.
type Client struct {
	HTTP *http.Client
	Base string // e.g. https://mail-edge.example
	Key  ed25519.PrivateKey
}

// Do signs payload for op with a fresh nonce, sends it, and decodes the answer.
func (c *Client) Do(ctx context.Context, op string, payload, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var begun BeginResponse
	if err := wire.PostJSON(ctx, c.HTTP, c.Base+"/operator/begin", struct{}{}, &begun); err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	req := Request{Nonce: begun.Nonce, Payload: raw, Signature: ed25519.Sign(c.Key, Message(op, begun.Nonce, raw))}
	return wire.PostJSON(ctx, c.HTTP, c.Base+"/operator/"+op, req, out)
}

// Status reports where the edge is in its boot, and its ACME account URL once known.
// It needs no operator key.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/operator/status", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("edge answered %d: %.400s", resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}
