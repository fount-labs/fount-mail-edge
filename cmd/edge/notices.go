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
// path: the same DKIM keys, validated TLS and locked relay. It runs only when
// newSender built a sender, so with sending off (the live release) nothing drains
// the queue and every notice waits in routing data.
func startNotices(ctx context.Context, cfg *config.Config, sender deviceapi.Sender, q noticeQueue) bool {
	svc, ok := sender.(*send.Service)
	if !ok || svc == nil || q == nil {
		log.Printf("edge: owner notices queued, not sent (sending off)")
		return false
	}
	m, err := notice.New(notice.Options{
		MailDomain: cfg.MailDomain,
		Out:        svc.Out,
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
