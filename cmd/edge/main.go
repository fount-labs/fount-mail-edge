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
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
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
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/s3"
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

	st, rt, err := storage(cfg, k)
	if err != nil {
		return err
	}
	var (
		resolver    deviceapi.KeyResolver
		recipients  smtp.RecipientChecker
		provisioner deviceapi.Provisioner
	)
	if rt != nil { // nil in dev (discard store, no routing)
		resolver = deviceapi.NewKeyResolver(rt)
		recipients = rt
		provisioner = rt
	}
	certMgr := certs.NewManager()

	// ACME: get a CA cert for the attested TLS key via the gateway HTTP-01 path.
	challenges := acme.NewChallenges()
	acmeSrv := &http.Server{
		Addr:              cfg.ACMEChallengeAddr,
		Handler:           challenges.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	api := deviceapi.New(deviceapi.Options{
		Store:       st,
		Resolver:    resolver,
		Entitlement: cfg.Secrets.EntitlementVerifyKey,
		Provisioner: provisioner,
		MailDomain:  cfg.MailDomain,
	})
	apiSrv := &http.Server{
		Addr:              cfg.DeviceAPIAddr,
		Handler:           api,
		TLSConfig:         k.DeviceAPITLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	smtpSrv := smtp.New(smtp.Options{
		Addr:       cfg.SMTPAddr,
		Hostname:   "mx." + trimAt(cfg.MailDomain),
		Domain:     cfg.MailDomain,
		Certs:      certMgr,
		Store:      st,
		Recipients: recipients,
		MaxBytes:   cfg.MaxMessageBytes,
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

// storage wires the durable layer. In production it is the real store over S3:
// routing.Store (directory + key resolver + recipient checker + provisioner) and
// the HPKE message store sealing each inbound message to the address key, with a
// fresh 16-byte boot id in every object (§9). In dev there is no S3, so it falls
// back to the discard store and a nil routing store, which the caller treats as
// no resolver (signed Device API routes answer 401), no recipient checker (SMTP
// uses the domain suffix), and no provisioner (creation routes stay 501) —
// enough to smoke-test the listeners. Until a mailbox is created, a production
// edge has none, so every RCPT is correctly refused.
func storage(cfg *config.Config, k *keys.Keys) (store.Store, *routing.Store, error) {
	if cfg.Dev {
		log.Printf("edge: *** EDGE_DEV=1 — discard store, no routing; NEVER in a release ***")
		return store.NewDiscard(), nil, nil
	}
	endpoint := cfg.S3EndpointURL()
	if endpoint == "" {
		return nil, nil, fmt.Errorf("S3 endpoint unset: set S3_ENDPOINT or S3_BUCKET+S3_REGION")
	}
	blobs, err := s3.New(s3.Config{
		Endpoint:        endpoint,
		Region:          cfg.S3Region,
		AccessKeyID:     cfg.Secrets.S3AccessKeyID,
		SecretAccessKey: cfg.Secrets.S3SecretAccessKey,
	})
	if err != nil {
		return nil, nil, err
	}
	rt, err := routing.New(context.Background(), blobs, cfg.Secrets.RoutingDataKey, cfg.Secrets.AddressMACKey)
	if err != nil {
		return nil, nil, err
	}
	bootID := make([]byte, 16)
	if _, err := rand.Read(bootID); err != nil {
		return nil, nil, err
	}
	log.Printf("edge: storage=s3 endpoint=%s boot-id=%x", endpoint, bootID)
	return store.New(rt, blobs, k.Sign, bootID), rt, nil
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
