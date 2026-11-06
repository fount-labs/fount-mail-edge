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
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
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

	// ACME: get a CA cert for the attested TLS key via the gateway HTTP-01 path.
	challenges := acme.NewChallenges()
	acmeSrv := &http.Server{
		Addr:              cfg.ACMEChallengeAddr,
		Handler:           challenges.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

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

	errc := make(chan error, 4)
	go func() { errc <- smtpSrv.ListenAndServe(ctx) }()
	go func() { errc <- ignoreClosed(apiSrv.ListenAndServeTLS("", "")) }()
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	go func() { errc <- ignoreClosed(acmeSrv.ListenAndServe()) }()
	go startCertLoop(ctx, cfg, k, certMgr, challenges)
	log.Printf("edge: listening smtp=%s device-api=%s health=%s acme=%s",
		cfg.SMTPAddr, cfg.DeviceAPIAddr, cfg.HealthAddr, cfg.ACMEChallengeAddr)

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
	_ = acmeSrv.Shutdown(sctx)
	_ = smtpSrv.Shutdown(sctx)
	return nil
}

// startCertLoop builds the ACME issuer and drives certificate acquisition. If the
// account key can't be parsed (EDGE_DEV placeholder), it logs and skips — the
// edge then serves 421 forever, which is correct for a dev boot with no CA.
func startCertLoop(ctx context.Context, cfg *config.Config, k *keys.Keys, mgr *certs.Manager, challenges *acme.Challenges) {
	issuer, err := acme.NewIssuer(cfg.Secrets.ACMEAccountKeyPEM, cfg.ACMEDirectory, challenges)
	if err != nil {
		log.Printf("edge: ACME disabled (%v); SMTP will answer 421 until a cert loads", err)
		return
	}
	var cache certs.Cache
	if cfg.CertCacheDir != "" {
		cache = certs.NewDiskCache(cfg.CertCacheDir)
	}
	log.Printf("edge: ACME via %s for %s", cfg.ACMEDirectory, cfg.Hostname)
	certs.RunLoop(ctx, mgr, cache, challenges.Reachable(), cfg.Hostname,
		func(ctx context.Context, host string) (*tls.Certificate, error) {
			return issuer.Issue(ctx, host, k.TLS)
		})
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
