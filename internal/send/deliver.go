package send

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// Status is how one recipient's delivery ended.
type Status string

const (
	Sent      Status = "sent"
	Temporary Status = "temporary" // the device may retry
	Permanent Status = "permanent" // don't retry
)

// Result is one recipient's outcome. Detail is for the device, which already
// knows the recipient; the edge never logs it.
type Result struct {
	Recipient string `json:"recipient"`
	Status    Status `json:"status"`
	Detail    string `json:"detail,omitempty"`
}

const (
	defaultSessionTimeout = 2 * time.Minute
	maxMXTried            = 5
)

// Deliverer sends a signed message straight to each recipient domain's MX,
// through the relay. There's no queue: the device holds the message and retries
// a temporary failure, so a reboot never loses mail the edge said it had.
type Deliverer struct {
	Hostname string // EHLO name, e.g. "mx1.fountbox.com"
	Resolver Resolver
	STS      *STS
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	Roots    *x509.CertPool // nil uses the system roots; tests set their own
	Timeout  time.Duration  // per SMTP session; 0 is the default
}

// Deliver sends data from `from` to every recipient, one session per domain.
func (d *Deliverer) Deliver(ctx context.Context, from string, recipients []string, data []byte) []Result {
	byDomain := map[string][]string{}
	var order []string
	for _, r := range recipients {
		dom := domainOf(r)
		if _, ok := byDomain[dom]; !ok {
			order = append(order, dom)
		}
		byDomain[dom] = append(byDomain[dom], r)
	}
	var out []Result
	for _, dom := range order {
		out = append(out, d.deliverDomain(ctx, dom, from, byDomain[dom], data)...)
	}
	return out
}

func all(rcpts []string, s Status, detail string) []Result {
	out := make([]Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = Result{Recipient: r, Status: s, Detail: detail}
	}
	return out
}

func (d *Deliverer) deliverDomain(ctx context.Context, domain, from string, rcpts []string, data []byte) []Result {
	mxs, err := d.Resolver.MX(ctx, domain)
	switch {
	case errors.Is(err, ErrNoRecord):
		// No implicit MX: an owner's domain without one isn't a mail domain the
		// edge should guess at.
		return all(rcpts, Permanent, "domain has no MX")
	case err != nil:
		return all(rcpts, Temporary, "MX lookup failed")
	}
	if len(mxs) == 1 && mxs[0].Host == "" {
		return all(rcpts, Permanent, "domain accepts no mail (null MX)")
	}
	var policy *STSPolicy
	if d.STS != nil {
		if policy, err = d.STS.Policy(ctx, domain); err != nil {
			return all(rcpts, Temporary, "MTA-STS policy fetch failed")
		}
	}
	lastErr := "no usable MX"
	tried := 0
	for _, mx := range mxs {
		if !policy.Allows(mx.Host) {
			lastErr = "MX not in the domain's MTA-STS policy"
			continue
		}
		if tried++; tried > maxMXTried {
			break
		}
		res, err := d.session(ctx, mx.Host, from, rcpts, data)
		if err == nil {
			return res
		}
		lastErr = err.Error()
	}
	return all(rcpts, Temporary, lastErr)
}

// session runs one SMTP conversation. An error means this MX couldn't take the
// message at all, so the next one is worth trying; per-recipient answers come
// back as results.
func (d *Deliverer) session(ctx context.Context, mxHost, from string, rcpts []string, data []byte) ([]Result, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = defaultSessionTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.Dial(ctx, "tcp", net.JoinHostPort(mxHost, "25"))
	if err != nil {
		return nil, errors.New("could not connect to MX")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer conn.Close()

	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return nil, errors.New("MX greeting failed")
	}
	defer c.Close()
	if err := c.Hello(d.Hostname); err != nil {
		return nil, errors.New("EHLO refused")
	}
	// No fallback to plaintext, or the gateway could read it (§14 step 3).
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return nil, errors.New("MX does not offer STARTTLS")
	}
	if err := c.StartTLS(&tls.Config{
		ServerName: mxHost,
		RootCAs:    d.Roots,
		MinVersion: tls.VersionTLS12,
	}); err != nil {
		return nil, errors.New("MX certificate did not validate")
	}
	if ok, param := c.Extension("SIZE"); ok && param != "" {
		var max int
		if _, err := fmt.Sscan(param, &max); err == nil && max > 0 && len(data) > max {
			return all(rcpts, Permanent, "message larger than the MX accepts"), nil
		}
	}
	if err := c.Mail(from); err != nil {
		return failAll(rcpts, err), nil
	}
	out := make([]Result, len(rcpts))
	accepted := 0
	for i, r := range rcpts {
		out[i] = Result{Recipient: r, Status: Sent}
		if err := c.Rcpt(r); err != nil {
			out[i] = classify(r, err)
			continue
		}
		accepted++
	}
	if accepted == 0 {
		_ = c.Quit()
		return out, nil
	}
	w, err := c.Data()
	if err != nil {
		return markSent(out, err), nil
	}
	if _, err := w.Write(data); err != nil {
		return markSent(out, err), nil
	}
	if err := w.Close(); err != nil {
		return markSent(out, err), nil
	}
	_ = c.Quit()
	return out, nil
}

// markSent turns every recipient the MX had accepted into err's outcome, because
// the message didn't make it past DATA.
func markSent(out []Result, err error) []Result {
	for i := range out {
		if out[i].Status == Sent {
			out[i] = classify(out[i].Recipient, err)
		}
	}
	return out
}

func failAll(rcpts []string, err error) []Result {
	out := make([]Result, len(rcpts))
	for i, r := range rcpts {
		out[i] = classify(r, err)
	}
	return out
}

// classify maps an SMTP reply to a status. Only a 5xx is permanent; anything
// else, including a dropped connection, may work on a retry.
func classify(rcpt string, err error) Result {
	var te *textproto.Error
	if errors.As(err, &te) {
		s := Temporary
		if te.Code >= 500 {
			s = Permanent
		}
		return Result{Recipient: rcpt, Status: s, Detail: fmt.Sprintf("%d %s", te.Code, firstLine(te.Msg))}
	}
	return Result{Recipient: rcpt, Status: Temporary, Detail: "connection failed"}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
