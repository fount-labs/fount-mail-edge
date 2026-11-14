package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
)

// certSource is what /ready reads. *certs.Manager is one.
type certSource interface {
	Current() (*tls.Certificate, bool)
}

// frontReady is mail-core's /ready: core holds a servable chain, and mail-front,
// which serves it, has loaded that same chain. The gateway opens its backend on
// this, so it must not pass before front can answer STARTTLS.
type frontReady struct {
	mgr  *certs.Manager
	link *link.Server
}

func (f frontReady) Current() (*tls.Certificate, bool) {
	c, ok := f.mgr.Current()
	if !ok || len(c.Certificate) == 0 || !f.link.FrontHas(c.Certificate[0]) {
		return c, false
	}
	return c, true
}

// listeners are the servers a mode runs besides the health listener.
type listeners struct {
	serve    func(ctx context.Context, errc chan<- error)
	drain    func(ctx context.Context) // a restore stops mail
	shutdown func(ctx context.Context)
}

// allListeners is the one-container edge: SMTP and ACME on the tunnelled ports
// behind gateway mutual TLS, and the Device API over the attested TLS key.
func allListeners(cfg *config.Config, k *keys.Keys, api http.Handler, certMgr *certs.Manager, challenges *acme.Challenges, st smtp.Storer, rc smtp.RecipientChecker) (listeners, error) {
	apiSrv := deviceAPIServer(cfg.DeviceAPIAddr, api, k.DeviceAPITLSConfig())
	acmeSrv := &http.Server{
		Addr:              cfg.ACMEChallengeAddr,
		Handler:           challenges.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	smtpSrv := smtp.New(smtp.Options{
		Addr:       cfg.SMTPAddr,
		Hostname:   cfg.MailHostnames[0],
		Domain:     cfg.MailDomain,
		Certs:      certMgr,
		Store:      st,
		Recipients: rc,
		MaxBytes:   cfg.MaxMessageBytes,
	})
	smtpLn, err := tunnelListener(cfg.GatewayPins, k, cfg.SMTPAddr)
	if err != nil {
		return listeners{}, err
	}
	acmeLn, err := tunnelListener(cfg.GatewayPins, k, cfg.ACMEChallengeAddr)
	if err != nil {
		_ = smtpLn.Close()
		return listeners{}, err
	}
	return listeners{
		serve: func(ctx context.Context, errc chan<- error) {
			go func() { errc <- smtpSrv.Serve(ctx, smtpLn) }()
			go func() { errc <- ignoreClosed(apiSrv.ListenAndServeTLS("", "")) }()
			go func() { errc <- ignoreClosed(acmeSrv.Serve(acmeLn)) }()
		},
		drain: func(ctx context.Context) {
			_ = apiSrv.Shutdown(ctx)
			_ = smtpSrv.Shutdown(ctx)
		},
		shutdown: func(ctx context.Context) {
			_ = apiSrv.Shutdown(ctx)
			_ = acmeSrv.Shutdown(ctx)
			_ = smtpSrv.Shutdown(ctx)
		},
	}, nil
}

// coreListeners is mail-core: only the link listener, on the closed network it
// shares with mail-front. Front reaches the Device API on the health listener.
func coreListeners(cfg *config.Config, ls *link.Server, st smtp.Storer, rc smtp.RecipientChecker) (listeners, error) {
	ls.SetMail(&link.Mail{Store: st, Recipients: rc})
	srv := deviceAPIServer(config.LinkAddr(), ls, nil)
	// The envelope rides in a header, and a sender address can fill an SMTP line.
	srv.MaxHeaderBytes = 64 << 10
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return listeners{}, err
	}
	log.Printf("edge: core link on %s", srv.Addr)
	return listeners{
		serve: func(_ context.Context, errc chan<- error) {
			go func() { errc <- ignoreClosed(srv.Serve(ln)) }()
		},
		drain: func(context.Context) { ls.SetMail(nil) },
		shutdown: func(ctx context.Context) {
			_ = srv.Shutdown(ctx)
		},
	}, nil
}

// startCoreCertLoop is startCertLoop for mail-core: it waits for mail-front's
// CSR, orders with it, and holds only the chain, which front fetches. The cache
// binds chains to the CSR's key, so a restart of core within a boot reloads it.
func startCoreCertLoop(ctx context.Context, cfg *config.Config, mgr *certs.Manager, challenges *acme.Challenges, issuer *acme.Issuer, ls *link.Server) {
	log.Printf("edge: waiting for mail-front's CSR")
	csr, names, pub, err := ls.CSR(ctx)
	if err != nil {
		return
	}
	log.Printf("edge: ACME via %s for %v, CSR from mail-front", cfg.ACMEDirectory, names)
	certs.RunLoop(ctx, mgr, coreCertCache(cfg, pub), challenges.Reachable(), cfg.MailHostnames[0],
		func(ctx context.Context, _ string) (*tls.Certificate, error) {
			chain, err := issuer.IssueCSR(ctx, names, csr)
			if err != nil {
				return nil, err
			}
			return certs.ParseChain(chain)
		})
}

func coreCertCache(cfg *config.Config, pub *ecdsa.PublicKey) certs.Cache {
	if cfg.Dev {
		return nil
	}
	blobs, err := newBlobs(cfg, cfg.S3EndpointURL())
	if err != nil {
		log.Printf("edge: certificate cache disabled (%v); a crash loop may re-run ACME", err)
		return nil
	}
	return certs.NewS3ChainCache(blobs, pub)
}
