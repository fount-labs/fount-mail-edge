package main

import (
	"context"
	"log"

	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/notice"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/send"
)

// noticeQueue is what owner notices read from routing.Store.
type noticeQueue interface {
	notice.Queue
	LicenseOf(mailboxID []byte) ([]byte, bool)
}

var _ noticeQueue = (*routing.Store)(nil)

// startNotices sends queued owner notices (§10) through POST /send's own send
// path: the same DKIM keys, validated TLS and locked relay, in this container or
// in mail-send. It runs only once sending is on, so with sending off (the live
// release) nothing drains the queue and every notice waits in routing data.
func startNotices(ctx context.Context, cfg *config.Config, out send.Transmitter, q noticeQueue) bool {
	if out == nil || q == nil {
		log.Printf("edge: owner notices queued, not sent (sending off)")
		return false
	}
	m, err := notice.New(notice.Options{
		MailDomain: cfg.MailDomain,
		Out:        out,
		License:    q.LicenseOf,
	})
	if err != nil {
		log.Printf("edge: owner notices queued, not sent: %v", err)
		return false
	}
	go notice.Run(ctx, q, m, cfg.MailDomain, notice.DrainEvery)
	log.Printf("edge: owner notices on")
	return true
}

// transmitterOf is the one-container edge's send path, or nil with sending off.
func transmitterOf(sender deviceapi.Sender) send.Transmitter {
	if svc, ok := sender.(*send.Service); ok && svc != nil {
		return svc.Out
	}
	return nil
}
