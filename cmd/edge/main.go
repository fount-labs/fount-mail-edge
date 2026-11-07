// Command edge is the Fount Fleet mail edge: a small, reproducible Go service
// that runs inside a Tinfoil enclave, terminates inbound SMTP with an attested
// key, and serves the Device API to the broker over the attested tunnel.
//
// Boot sequence (design §5, §6, §8):
//  1. Load non-secret config; load keyserver secrets from env (fail fast).
//  2. Load the per-boot attested keys (TLS ecdsa-p256, signing ed25519).
//  3. Start the SMTP, Device API, and health listeners.
//  4. Run ACME for the attested TLS key once the gateway's first health check
//     lands; answer 421 until the certificate loads.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/egress"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/routing"
	"github.com/fount-labs/fount-mail-edge/internal/s3"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
	"github.com/fount-labs/fount-mail-edge/internal/store"
)

func main() {
	log.SetFlags(log.LUTC | log.Ldate | log.Ltime | log.Lmicroseconds)
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := healthcheck(config.HealthAddr()); err != nil {
			log.Fatalf("edge: unhealthy: %v", err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "egress-forward" {
		if err := forward(); err != nil {
			log.Fatalf("edge: forwarder: %v", err)
		}
		return
	}
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
	log.Printf("edge: booting hostnames=%v domain=%s", cfg.MailHostnames, cfg.MailDomain)

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
		mutator     deviceapi.Mutator
	)
	if rt != nil { // nil in dev (discard store, no routing)
		resolver = deviceapi.NewKeyResolver(rt)
		recipients = rt
		provisioner = rt
		mutator = rt
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
		Store:          st,
		Resolver:       resolver,
		Entitlement:    cfg.Secrets.EntitlementVerifyKey,
		Provisioner:    provisioner,
		Mutator:        mutator,
		MailDomain:     cfg.MailDomain,
		RecoveryRPID:   cfg.RecoveryRPID,
		RecoveryOrigin: cfg.RecoveryOrigin,
	})
	apiSrv := deviceAPIServer(cfg.DeviceAPIAddr, api, k.DeviceAPITLSConfig())

	smtpSrv := smtp.New(smtp.Options{
		Addr:       cfg.SMTPAddr,
		Hostname:   cfg.MailHostnames[0],
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

	smtpLn, err := tunnelListener(cfg, k, cfg.SMTPAddr)
	if err != nil {
		return err
	}
	acmeLn, err := tunnelListener(cfg, k, cfg.ACMEChallengeAddr)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errc := make(chan error, 4)
	go func() { errc <- smtpSrv.Serve(ctx, smtpLn) }()
	go func() { errc <- ignoreClosed(apiSrv.ListenAndServeTLS("", "")) }()
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	go func() { errc <- ignoreClosed(acmeSrv.Serve(acmeLn)) }()
	go startCertLoop(ctx, cfg, k, certMgr, challenges)
	go startRetentionSweep(ctx, st)
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

// forward runs the S3 forwarder container (§6). It starts before config.Load
// because it needs no secrets, and refuses to run with any in reach.
func forward() error {
	if name := config.VisibleSecret(); name != "" {
		return fmt.Errorf("%s is visible here, and this container must hold no secrets", name)
	}
	routes, err := egress.ParseRoutes(os.Getenv("EGRESS_ROUTES"))
	if err != nil {
		return fmt.Errorf("EGRESS_ROUTES: %w", err)
	}
	_, port, err := net.SplitHostPort(config.HealthAddr())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	healthSrv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", port),
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 2)
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	go func() { errc <- (&egress.Forwarder{Routes: routes}).Serve(ctx) }()
	log.Printf("edge: forwarding %d routes", len(routes))
	err = <-errc
	_ = healthSrv.Close()
	return err
}

// deviceAPIServer bounds what one request can hold: a stalled client can't keep a
// tunnel forever, and headers can't use the default 1 MiB when they carry only a
// signature and a short token. WriteTimeout has to cover a full 25 MB message.
func deviceAPIServer(addr string, h http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
}

// tunnelListener binds a tunnelled port behind gateway mutual TLS (§7). config.Load
// refuses a production boot with no pins, so the plain branch is dev only.
func tunnelListener(cfg *config.Config, k *keys.Keys, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if len(cfg.GatewayPins) == 0 {
		log.Printf("edge: *** %s has no gateway mutual TLS (dev only) ***", addr)
		return ln, nil
	}
	return gatewaytls.Listen(ln, k.DeviceAPITLSConfig(), cfg.GatewayPins), nil
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
	blobs, err := newBlobs(cfg, cfg.S3EndpointURL())
	if err != nil {
		return nil, nil, err
	}
	logBlobs, err := newBlobs(cfg, cfg.BucketURL(cfg.S3BootLogBucket))
	if err != nil {
		return nil, nil, fmt.Errorf("boot log: %w", err)
	}
	backupBlobs, err := newBlobs(cfg, cfg.BucketURL(cfg.S3BackupBucket))
	if err != nil {
		return nil, nil, fmt.Errorf("routing backup: %w", err)
	}
	bootID := make([]byte, 16)
	if _, err := rand.Read(bootID); err != nil {
		return nil, nil, err
	}
	rt, err := routing.New(context.Background(), blobs, cfg.Secrets.RoutingDataKey, cfg.Secrets.AddressMACKey,
		routing.WithBackup(backupBlobs, k.Sign, bootID))
	if err != nil {
		return nil, nil, err
	}
	log.Printf("edge: storage=s3 endpoint=%s boot-id=%x", cfg.S3EndpointURL(), bootID)
	st := store.New(rt, blobs, k.Sign, bootID, store.WithLogBlobs(logBlobs))
	// Publish this boot's attestation (§9) so the broker can check stored
	// messages' signatures against it, even after this enclave is gone. A failure
	// here is loud but not fatal: the edge can still serve mail, and the broker
	// alerts on a missing attestation.
	if bs, ok := st.(store.BootStore); ok {
		if err := bs.WriteBoot(context.Background()); err != nil {
			log.Printf("edge: WARNING could not publish boot attestation (boot-id=%x): %v", bootID, err)
		}
	}
	return st, rt, nil
}

// newBlobs builds an S3 client for one bucket. It fails if the endpoint is empty,
// because a production edge must have all of its buckets.
func newBlobs(cfg *config.Config, endpoint string) (*s3.Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("S3 bucket unset: set S3_ENDPOINT or the bucket's env var + S3_REGION")
	}
	return s3.New(s3.Config{
		Endpoint:        endpoint,
		Region:          cfg.S3Region,
		AccessKeyID:     cfg.Secrets.S3AccessKeyID,
		SecretAccessKey: cfg.Secrets.S3SecretAccessKey,
		HTTPClient:      egress.NewHTTPClient(cfg.EgressForwarder, cfg.EgressRoutes),
	})
}

// certCache picks the certificate cache: S3 in production (so a crash loop
// reloads the cert instead of re-running ACME, §6), a local disk cache when
// CertCacheDir is set for development, or none. The cache is only consulted once
// ACME is live, so a dev boot with a placeholder account key never reaches it.
func certCache(cfg *config.Config, k *keys.Keys) certs.Cache {
	if cfg.CertCacheDir != "" {
		return certs.NewDiskCache(cfg.CertCacheDir)
	}
	if cfg.Dev {
		return nil
	}
	blobs, err := newBlobs(cfg, cfg.S3EndpointURL())
	if err != nil {
		log.Printf("edge: certificate cache disabled (%v); a crash loop may re-run ACME", err)
		return nil
	}
	return certs.NewS3Cache(blobs, k.TLS)
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
	cache := certCache(cfg, k)
	log.Printf("edge: ACME via %s for %v", cfg.ACMEDirectory, cfg.MailHostnames)
	certs.RunLoop(ctx, mgr, cache, challenges.Reachable(), cfg.MailHostnames[0],
		func(ctx context.Context, _ string) (*tls.Certificate, error) {
			return issuer.Issue(ctx, cfg.MailHostnames, k.TLS)
		})
}

// startRetentionSweep runs the §6 retention sweep once at startup and then daily,
// expiring unfetched mail past the hold and writing a signed expiry record for
// each. The discard store (dev) is not a Sweeper, so this is a no-op there.
func startRetentionSweep(ctx context.Context, st store.Store) {
	sweeper, ok := st.(store.Sweeper)
	if !ok {
		return
	}
	run := func() {
		n, err := sweeper.Sweep(ctx, time.Now())
		if err != nil {
			log.Printf("edge: retention sweep error: %v", err)
			return
		}
		if n > 0 {
			log.Printf("edge: retention sweep expired %d message(s)", n)
		}
	}
	run()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
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

// healthcheck is the container's health check. The image is FROM scratch, so it
// has no curl to call /health with. This checks /health rather than /ready: the
// certificate depends on the gateways, and a gateway outage isn't a reason to
// fail a deployment.
func healthcheck(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	client := http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/health")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("/health answered %s", res.Status)
	}
	return nil
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
