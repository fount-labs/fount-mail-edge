package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/send"
	"github.com/fount-labs/fount-mail-vault/wire"
)

// sendRetryMax caps the wait between rounds of asking the vaults for the send
// keyset. Receiving doesn't wait on mail-send, so it can be patient.
const sendRetryMax = 10 * time.Minute

// runSend is mail-send in a split edge (docs/CONTAINER-SPLIT.md, stage 2). It
// holds the send-transfer key and pulls the send keyset itself; the vault seals
// that alone to send-transfer, so mail-core, which holds transfer, never sees it.
// It signs and delivers what mail-core hands it over the send link, after
// checking the message's own From and recipients again. Every send gate is the
// one-container edge's; until all are met the link answers that sending is off.
func runSend() error {
	cfg, err := config.LoadSend()
	if err != nil {
		return err
	}
	k, err := keys.LoadSend(cfg.AttestedKeyDir)
	if err != nil {
		return err
	}
	log.Printf("edge: send booting domain=%s vaults=%v", cfg.MailDomain, cfg.VaultHosts)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	_, healthPort, err := net.SplitHostPort(cfg.HealthAddr)
	if err != nil {
		return err
	}
	healthSrv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", healthPort), // the container's own check only
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ls := link.NewSendServer(cfg.MaxMessageBytes)
	linkSrv := deviceAPIServer(config.SendLinkAddr(), ls, nil)
	ln, err := net.Listen("tcp", linkSrv.Addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	go func() { errc <- ignoreClosed(linkSrv.Serve(ln)) }()
	log.Printf("edge: send link on %s", linkSrv.Addr)

	go func() {
		if cfg.SendKeysetCommitment != "" && !cfg.Dev {
			ls.Set(nil, link.SendStatus{State: "off: waiting for a vault's send keyset"})
			if err := pullSendKeys(ctx, cfg, k, ls); err != nil {
				return
			}
		}
		out, st := newOutbox(cfg)
		var tr send.Transmitter
		if out != nil {
			tr = out
		}
		ls.Set(tr, link.SendStatus{State: st.State, Commitment: st.Commitment})
		log.Printf("edge: sending %s", st.State)
	}()

	select {
	case <-ctx.Done():
		log.Printf("edge: send shutdown signal")
		err = nil
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = linkSrv.Shutdown(sctx)
	_ = healthSrv.Shutdown(sctx)
	return err
}

// pullSendKeys asks the vaults for the send keyset until one hands it over. The
// vault seals it to send-transfer only, and wire.PullSendKeyset refuses any but
// the committed one, so a fake vault gets nothing and gives nothing.
func pullSendKeys(ctx context.Context, cfg *config.Config, k *keys.Keys, ls *link.SendServer) error {
	client := &http.Client{Timeout: 90 * time.Second}
	attester := wire.NewSocketAttester(wire.AttestationSocket)
	pull := func(ctx context.Context, host string) (*wire.SendKeyset, error) {
		res, err := wire.PullSendKeyset(ctx, client, "https://"+host, k.SendTransfer, attester, nil, cfg.SendKeysetCommitment)
		if err != nil {
			return nil, err
		}
		return res.SendKeyset, nil
	}
	wait := vaultRetryFirst
	for round := 1; ; round++ {
		if sendPullRound(ctx, cfg.VaultHosts, pull, cfg.InstallSendKeyset) {
			return nil
		}
		ls.Set(nil, link.SendStatus{State: fmt.Sprintf("off: no vault has handed over the send keyset (%d rounds)", round)})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, sendRetryMax)
	}
}

type sendPullFunc func(ctx context.Context, host string) (*wire.SendKeyset, error)

// sendPullRound asks each vault once and reports whether the send keyset is
// installed. A vault with none, or one that predates the separate box, answers
// with no keyset, and the next is asked.
func sendPullRound(ctx context.Context, hosts []string, pull sendPullFunc, install func(*wire.SendKeyset) error) bool {
	for _, host := range hosts {
		got, err := pull(ctx, host)
		if err == nil && got == nil {
			log.Printf("edge: %s has no send keyset for this release", host)
			continue
		}
		if err == nil {
			err = install(got)
		}
		if err != nil {
			log.Printf("edge: send keyset from %s: %v", host, err)
			continue
		}
		log.Printf("edge: send keyset %s from %s", got.Commitment(), host)
		return true
	}
	return false
}

// remoteSender is mail-core's POST /send in a split edge. Core holds the routing
// data, so the edge's own checks (owners, proof, pause, limits) run here; mail-send
// signs and delivers. While mail-send reports sending off, it answers send.ErrOff
// before any check, so no limit is spent.
type remoteSender struct {
	svc   *send.Service
	state *atomic.Pointer[sendState]
}

func (r remoteSender) Send(ctx context.Context, mailboxID, raw []byte) ([]send.Result, error) {
	if s := r.state.Load(); s == nil || s.State != "on" {
		return nil, send.ErrOff
	}
	return r.svc.Send(ctx, mailboxID, raw)
}

// newCoreSender builds mail-core's Sender. It is nil, so POST /send stays 501,
// with no mail-send to reach or no routing; otherwise it follows mail-send's state.
func newCoreSender(cfg *config.Config, rt sendRouting, out send.Transmitter, state *atomic.Pointer[sendState]) (deviceapi.Sender, string) {
	switch {
	case cfg.SendLink == "":
		return nil, "off: SEND_LINK unset, so there's no mail-send"
	case rt == nil:
		return nil, "off: no routing"
	}
	pol := send.NewPolicy(send.PolicyOptions{Directory: rt, MailDomain: cfg.MailDomain, Proven: rt.OwnerProven})
	return remoteSender{svc: &send.Service{Policy: pol, Out: out}, state: state}, ""
}

// sendWatchEvery is how often mail-core asks mail-send whether sending is on.
var sendWatchEvery = 15 * time.Second

type sendStatuser interface {
	Status(ctx context.Context) (link.SendStatus, error)
}

// watchSend keeps state in step with mail-send's and calls on once, the first
// time mail-send reports sending on.
func watchSend(ctx context.Context, c sendStatuser, state *atomic.Pointer[sendState], on func()) {
	started := false
	t := time.NewTicker(sendWatchEvery)
	defer t.Stop()
	for {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := c.Status(sctx)
		cancel()
		next := sendState{State: "off: mail-send unreachable"}
		if err == nil {
			next = sendState{State: st.State, Commitment: st.Commitment}
			if st.State != "on" {
				next.State = "off: mail-send: " + strings.TrimPrefix(st.State, "off: ")
			}
		}
		if prev := state.Load(); prev == nil || *prev != next {
			log.Printf("edge: sending %s", next.State)
		}
		state.Store(&next)
		if next.State == "on" && !started {
			started = true
			on()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
