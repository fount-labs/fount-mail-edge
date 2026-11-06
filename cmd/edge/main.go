// Command edge is the Fount Fleet mail edge: a small, reproducible Go service
// that runs inside a Tinfoil enclave, terminates inbound SMTP with an attested
// key, and serves the Device API to the broker over the attested tunnel.
//
// Boot sequence (design §5, §6, §8):
//  1. Load non-secret config; load keyserver secrets from env (fail fast).
//  2. Load the per-boot attested keys (TLS ecdsa-p256, signing ed25519).
//  3. Start the SMTP, Device API, and health listeners.
//  4. (TODO M2 step 3) Run ACME for the attested TLS key once the gateway's
//     first health check lands; answer 421 until the certificate loads.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

func main() {
	log.SetFlags(log.LUTC | log.Ldate | log.Ltime | log.Lmicroseconds)
	if err := run(); err != nil {
		log.Fatalf("edge: fatal: %v", err)
	}
	log.Printf("edge: stopped")
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err // a missing attested key or keyserver secret must not boot
	}
	log.Printf("edge: booting hostname=%s domain=%s", cfg.Hostname, cfg.MailDomain)

	k, err := keys.Load(cfg.AttestedKeyDir)
	if err != nil {
		if cfg.Dev {
			return err // in dev the attested keys usually aren't present; see docs/DEV.md
		}
		return err
	}
	log.Printf("edge: attested TLS spki(sha256)=%s", k.TLSPublicSPKI())
	log.Printf("edge: attested signing pub(ed25519)=%s", k.SignPublicB64())

	st := store.NewDiscard()
	certMgr := certs.NewManager()

	api := deviceapi.New(st, nil) // key resolver lands with storage (M2 step 4)
	apiSrv := &http.Server{
		Addr:              cfg.DeviceAPIAddr,
		Handler:           api,
		TLSConfig:         k.DeviceAPITLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	smtpSrv := smtp.New(smtp.Options{
		Addr:     cfg.SMTPAddr,
		Hostname: "mx." + trimAt(cfg.MailDomain),
		Domain:   cfg.MailDomain,
		Certs:    certMgr,
		Store:    st,
		MaxBytes: cfg.MaxMessageBytes,
	})

	healthSrv := &http.Server{
		Addr:              cfg.HealthAddr,
		Handler:           health(certMgr),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errc := make(chan error, 3)
	go func() { errc <- smtpSrv.ListenAndServe(ctx) }()
	go func() { errc <- ignoreClosed(apiSrv.ListenAndServeTLS("", "")) }()
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	log.Printf("edge: listening smtp=%s device-api=%s health=%s", cfg.SMTPAddr, cfg.DeviceAPIAddr, cfg.HealthAddr)

	select {
	case <-ctx.Done():
		log.Printf("edge: shutdown signal")
	case err := <-errc:
		if err != nil {
			return err
		}
	}

	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(sctx)
	_ = healthSrv.Shutdown(sctx)
	_ = smtpSrv.Shutdown(sctx)
	return nil
}

// health serves the shim's /health and /ready probes. /ready is not-ready until
// the SMTP certificate loads, which is what gates the gateway opening the backend.
func health(c *certs.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		if _, ok := c.Current(); ok {
			_, _ = w.Write([]byte("ready\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("certificate not ready\n"))
	})
	return mux
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func trimAt(domain string) string {
	if len(domain) > 0 && domain[0] == '@' {
		return domain[1:]
	}
	return domain
}
