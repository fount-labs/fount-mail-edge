// Command edge is the Fount Fleet mail edge: a small, reproducible Go service
// that runs inside a Tinfoil enclave, terminates inbound SMTP with an attested
// key, and serves the Device API to the broker over the attested tunnel.
//
// Boot sequence (design §5, §6, §8):
//  1. Load the measured config (fail fast).
//  2. Load the per-boot attested keys (TLS ecdsa-p256, signing ed25519,
//     transfer x25519).
//  3. Start the health listener, which also serves the signed operator routes,
//     then pull the keyset from a vault, checked against KEYSET_COMMITMENT, and
//     the send keyset if SEND_KEYSET_COMMITMENT is set. Nothing else starts
//     until the keyset arrives; a missing send keyset only leaves sending off.
//  4. Load the routing object. If it's missing or unreadable, wait for a signed
//     edgectl init or restore instead of exiting.
//  5. Start the SMTP and Device API listeners.
//  6. Run ACME for the attested TLS key once the gateway's first health check
//     lands; answer 421 until the certificate loads.
//
// `edge` runs all of that in one container. A split edge (docs/CONTAINER-SPLIT.md)
// runs `edge core`, which is the above without TLS, SMTP, the tunnelled ports or
// the send keyset, with the link listener for mail-front and a link client for
// mail-send; `edge front` (front.go), which holds only the mail-tls key; and
// `edge send` (mailsend.go), which holds only send-transfer and the send keyset,
// and signs and delivers what core hands it. `edge egress-forward` is the S3
// forwarder.
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/egress"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/operator"
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
	if len(os.Args) == 2 && os.Args[1] == "send" {
		if err := runSend(); err != nil {
			log.Fatalf("edge: send: fatal: %v", err)
		}
		log.Printf("edge: send stopped")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "front" {
		if err := runFront(); err != nil {
			log.Fatalf("edge: front: fatal: %v", err)
		}
		log.Printf("edge: front stopped")
		return
	}
	m := modeAll
	if len(os.Args) == 2 && os.Args[1] == "core" {
		m = modeCore
	}
	if err := run(m); err != nil {
		log.Fatalf("edge: fatal: %v", err)
	}
	log.Printf("edge: stopped")
}

// mode is how much of the edge this process runs. modeAll is one container, as
// every release up to v0.3.0 runs. modeCore is mail-core in a split edge
// (docs/CONTAINER-SPLIT.md): everything but TLS and SMTP, which mail-front runs.
type mode int

const (
	modeAll mode = iota
	modeCore
)

func run(m mode) error {
	loadCfg := config.Load
	if m == modeCore {
		loadCfg = config.LoadCore
	}
	cfg, err := loadCfg()
	if err != nil {
		return err // a bad measured config must not boot
	}
	log.Printf("edge: booting hostnames=%v domain=%s core-only=%t", cfg.MailHostnames, cfg.MailDomain, m == modeCore)

	load := keys.Load
	if m == modeCore {
		load = keys.LoadCore
	}
	k, err := load(cfg.AttestedKeyDir) // in dev the attested keys usually aren't present; see docs/DEV.md
	if err != nil {
		return err
	}
	if k.TLS != nil {
		log.Printf("edge: attested TLS spki(sha256)=%s", k.TLSPublicSPKI())
	}
	log.Printf("edge: attested signing pub(ed25519)=%s", k.SignPublicB64())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The health listener comes first, so the container stays healthy while it
	// waits for a vault or an operator. /ready stays 503 until the certificate loads.
	certMgr := certs.NewManager()
	ops := operator.NewRouting()
	var opHandler http.Handler
	if !cfg.Dev {
		opHandler = operator.NewHandler(cfg.OperatorKey, ops)
	}
	// ACME: get a CA cert for the attested TLS key via the gateway HTTP-01 path.
	// The issuer is built after the vault pull, which delivers its account key;
	// /operator/status reads the account URL through this pointer until then.
	challenges := acme.NewChallenges()
	var issuer atomic.Pointer[acme.Issuer]
	if h, ok := opHandler.(*operator.Handler); ok {
		h.SetACMEAccount(func() string {
			if i := issuer.Load(); i != nil {
				return i.AccountURL()
			}
			return ""
		})
	}
	var sending atomic.Pointer[sendState]
	if h, ok := opHandler.(*operator.Handler); ok {
		h.SetSend(func() (string, string) {
			if s := sending.Load(); s != nil {
				return s.State, s.Commitment
			}
			return "", ""
		})
	}
	// The shim forwards one port, so the Device API is served here too, once
	// storage loads. Until then its routes answer 503.
	late := &lateHandler{}
	var linkSrv *link.Server
	var ready certSource = certMgr
	if m == modeCore {
		linkSrv = link.NewServer(cfg.MailHostnames, cfg.MaxMessageBytes, challenges.Handler())
		linkSrv.SetCert(func() []byte {
			if c, ok := certMgr.Current(); ok {
				return certs.ChainPEM(c)
			}
			return nil
		})
		ready = frontReady{certMgr, linkSrv}
	}
	healthSrv := deviceAPIServer(cfg.HealthAddr, health(ready, opHandler, late), nil)
	errc := make(chan error, 4)
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	if !cfg.Dev {
		if err := pullKeys(ctx, cfg, k); err != nil {
			return err
		}
	}

	st, rt, err := storage(ctx, cfg, k, ops)
	if err != nil {
		return err
	}
	var (
		resolver    deviceapi.KeyResolver
		recipients  smtp.RecipientChecker
		provisioner deviceapi.Provisioner
		mutator     deviceapi.Mutator
		smtpStore   smtp.Storer = st
	)
	if rt != nil { // nil in dev (discard store, no routing)
		resolver = deviceapi.NewKeyResolver(rt)
		smtpStore = rt.ProofIntake(st) // owner-proof replies record the proof and aren't stored (§10)
		recipients = rt
		provisioner = rt
		mutator = rt
	}
	var sendRt sendRouting
	if rt != nil {
		sendRt = rt
	}
	var (
		sender     deviceapi.Sender
		sendClient *link.SendClient
	)
	if m == modeCore {
		sendClient = &link.SendClient{Base: "http://" + cfg.SendLink, HTTP: &http.Client{Timeout: 2 * time.Minute}}
		var why string
		if sender, why = newCoreSender(cfg, sendRt, sendClient, &sending); sender == nil {
			sending.Store(&sendState{State: why})
		} else {
			sending.Store(&sendState{State: "off: waiting for mail-send"})
		}
	} else {
		var st sendState
		sender, st = newSender(cfg, sendRt)
		sending.Store(&st)
	}
	log.Printf("edge: sending %s", sending.Load().State)
	var connector deviceapi.Connector
	switch {
	case rt == nil:
	case m == modeCore && sender != nil:
		connector = newConnector(cfg, sendClient, rt, sendingOn(&sending))
	case m != modeCore:
		connector = newConnector(cfg, transmitterOf(sender), rt, nil)
	}
	api := deviceapi.New(deviceapi.Options{
		Store:          st,
		Resolver:       resolver,
		Entitlement:    cfg.EntitlementVerifyKey,
		Provisioner:    provisioner,
		Mutator:        mutator,
		MailDomain:     cfg.MailDomain,
		RecoveryRPID:   cfg.RecoveryRPID,
		RecoveryOrigin: cfg.RecoveryOrigin,
		Sender:         sender,
		Connector:      connector,
	})
	late.set(api)

	var l listeners
	if m == modeCore {
		l, err = coreListeners(cfg, linkSrv, smtpStore, recipients)
	} else {
		l, err = allListeners(cfg, k, api, certMgr, challenges, smtpStore, recipients)
	}
	if err != nil {
		return err
	}

	// A restore that replaces the object this edge serves from stops mail first,
	// then the edge restarts against the restored object.
	var draining atomic.Bool
	if rt != nil {
		keylog, _ := st.(store.KeyLog)
		ops.Serve(rt, keylog, func(ctx context.Context) {
			draining.Store(true)
			late.set(nil)
			l.drain(ctx)
		})
	}

	l.serve(ctx, errc)
	if i, err := acme.NewIssuer(cfg.Secrets.ACMEAccountKeyPEM, cfg.ACMEDirectory, challenges); err != nil {
		log.Printf("edge: ACME disabled (%v); SMTP will answer 421 until a cert loads", err)
	} else {
		issuer.Store(i)
		go registerAccount(ctx, i, accountRetries)
		if m == modeCore {
			go startCoreCertLoop(ctx, cfg, certMgr, challenges, i, linkSrv)
		} else {
			go startCertLoop(ctx, cfg, k, certMgr, challenges, i)
		}
	}
	go startRetentionSweep(ctx, st)
	switch {
	case rt == nil:
	case m == modeCore && sender != nil:
		// Notices start once mail-send first reports sending on, and not before.
		go watchSend(ctx, sendClient, &sending, func() { startNotices(ctx, cfg, sendClient, rt) })
	default:
		startNotices(ctx, cfg, transmitterOf(sender), rt)
	}
	if m == modeCore {
		log.Printf("edge: core listening health=%s link=%s", cfg.HealthAddr, config.LinkAddr())
	} else {
		log.Printf("edge: listening smtp=%s device-api=%s health=%s acme=%s",
			cfg.SMTPAddr, cfg.DeviceAPIAddr, cfg.HealthAddr, cfg.ACMEChallengeAddr)
	}

wait:
	for {
		select {
		case <-ctx.Done():
			log.Printf("edge: shutdown signal")
			break wait
		case <-ops.Restart():
			log.Printf("edge: restarting to load the restored routing object")
			break wait
		case err := <-errc:
			if draining.Load() {
				continue // the restore stopped these, and will restart the edge
			}
			if err != nil {
				return err
			}
			break wait
		}
	}

	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = healthSrv.Shutdown(sctx)
	l.shutdown(sctx)
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
func tunnelListener(pins []gatewaytls.Pin, k *keys.Keys, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		log.Printf("edge: *** %s has no gateway mutual TLS (dev only) ***", addr)
		return ln, nil
	}
	return gatewaytls.Listen(ln, k.DeviceAPITLSConfig(), pins), nil
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
func storage(ctx context.Context, cfg *config.Config, k *keys.Keys, ops *operator.Routing) (store.Store, *routing.Store, error) {
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
	rt, err := ops.Load(ctx, operator.Backend{Blobs: blobs, RoutingDataKey: cfg.Secrets.RoutingDataKey, MailDomain: cfg.MailDomain},
		func(ctx context.Context) (*routing.Store, error) {
			return routing.New(ctx, blobs, cfg.Secrets.RoutingDataKey, cfg.Secrets.AddressMACKey,
				routing.WithBackup(backupBlobs, k.Sign, bootID))
		})
	if err != nil {
		return nil, nil, err
	}
	log.Printf("edge: storage=s3 endpoint=%s boot-id=%x", cfg.S3EndpointURL(), bootID)
	st := store.New(rt, blobs, k.Sign, bootID, store.WithLogBlobs(logBlobs))
	if bs, ok := st.(store.BootStore); ok {
		if err := publishBoot(context.Background(), bs, bootRetries); err != nil {
			return nil, nil, fmt.Errorf("publish boot attestation (boot-id=%x): %w", bootID, err)
		}
	}
	return st, rt, nil
}

// bootRetries are the waits between tries at the boot record, about a minute in all.
var bootRetries = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}

// publishBoot writes this boot's attestation (§9) before any mail is accepted. The
// broker checks stored messages' signatures against it, even after this enclave is
// gone, so mail from a boot without one can't be verified. If it keeps failing the
// edge exits, and the restart policy tries again.
func publishBoot(ctx context.Context, bs store.BootStore, retries []time.Duration) error {
	err := bs.WriteBoot(ctx)
	for _, wait := range retries {
		if err == nil {
			return nil
		}
		log.Printf("edge: boot attestation not written, retrying in %s: %v", wait, err)
		time.Sleep(wait)
		err = bs.WriteBoot(ctx)
	}
	return err
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

// accountRetries are the waits between tries at the ACME account; the last repeats.
var accountRetries = []time.Duration{30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// registerAccount looks up (or creates) the ACME account so /operator/status can
// publish its URL for CAA `accounturi`. Issuance also registers, but a boot that
// reloads a cached certificate never issues, and CAA should be pinnable before the
// first order. newAccount reaches only the CA, not the gateways, so it runs at once.
func registerAccount(ctx context.Context, issuer *acme.Issuer, retries []time.Duration) {
	for n := 0; ; n++ {
		err := issuer.Register(ctx)
		if err == nil {
			log.Printf("edge: ACME account %s", issuer.AccountURL())
			return
		}
		wait := retries[min(n, len(retries)-1)]
		log.Printf("edge: ACME account lookup failed, retrying in %s: %v", wait, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// startCertLoop drives certificate acquisition. With no issuer (an EDGE_DEV
// placeholder account key) it never runs, and the edge serves 421 forever, which is
// correct for a dev boot with no CA.
func startCertLoop(ctx context.Context, cfg *config.Config, k *keys.Keys, mgr *certs.Manager, challenges *acme.Challenges, issuer *acme.Issuer) {
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
		res, err := sweeper.Sweep(ctx, time.Now())
		if err != nil {
			log.Printf("edge: retention sweep error: %v", err)
		}
		if res.Expired > 0 {
			log.Printf("edge: retention sweep expired %d message(s)", res.Expired)
		}
		if res.Skipped > 0 {
			log.Printf("edge: WARNING retention sweep skipped %d message(s) it couldn't verify", res.Skipped)
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
// The signed operator routes share the listener, because it's the one the shim
// exposes and the only one up before routing loads. So does the Device API, whose
// routes are registered here by pattern and passed to api; shim.paths in
// tinfoil-config.yml decides which of them the outside reaches.
func health(c certSource, op http.Handler, api http.Handler) http.Handler {
	mux := http.NewServeMux()
	if op != nil {
		mux.Handle("/operator/", op)
	}
	if api != nil {
		for _, r := range deviceapi.Routes() {
			mux.Handle(r.Pattern, api)
		}
	}
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

// lateHandler serves the Device API on the shim's listener, which starts before
// storage loads and outlives a restore's drain. With no API set it answers 503.
type lateHandler struct{ h atomic.Pointer[http.Handler] }

func (l *lateHandler) set(h http.Handler) {
	if h == nil {
		l.h.Store(nil)
		return
	}
	l.h.Store(&h)
}

func (l *lateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := l.h.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Retry-After", "5")
	http.Error(w, "device API not serving yet", http.StatusServiceUnavailable)
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
