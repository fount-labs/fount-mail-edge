package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"syscall"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/acme"
	"github.com/fount-labs/fount-mail-edge/internal/certs"
	"github.com/fount-labs/fount-mail-edge/internal/config"
	"github.com/fount-labs/fount-mail-edge/internal/deviceapi"
	"github.com/fount-labs/fount-mail-edge/internal/keys"
	"github.com/fount-labs/fount-mail-edge/internal/link"
	"github.com/fount-labs/fount-mail-edge/internal/smtp"
)

// runFront is mail-front in a split edge (docs/CONTAINER-SPLIT.md). It holds the
// mail-tls key and nothing from the vault. It terminates gateway mutual TLS on
// the tunnelled ports, speaks SMTP with STARTTLS, and hands each RCPT and message
// to mail-core over the link. It forwards ACME challenges and the Device API's
// TLS port to core, and makes the CSR core orders certificates with.
func runFront() error {
	cfg, err := config.LoadFront()
	if err != nil {
		return err
	}
	k, err := keys.LoadFront(cfg.AttestedKeyDir)
	if err != nil {
		return err
	}
	log.Printf("edge: front booting hostnames=%v core=%s", cfg.MailHostnames, cfg.CoreLink)
	log.Printf("edge: attested TLS spki(sha256)=%s", k.TLSPublicSPKI())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	core := &link.Client{Base: "http://" + cfg.CoreLink, HTTP: &http.Client{Timeout: 3 * time.Minute}}
	certMgr := certs.NewManager()

	_, healthPort, err := net.SplitHostPort(cfg.HealthAddr)
	if err != nil {
		return err
	}
	healthSrv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", healthPort), // the container's own check only
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	apiSrv := deviceAPIServer(cfg.DeviceAPIAddr, deviceAPIProxy(cfg.CoreAPI), k.DeviceAPITLSConfig())
	acmeSrv := &http.Server{
		Handler:           link.ChallengeOnly(proxyTo(cfg.CoreLink)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	smtpSrv := smtp.New(smtp.Options{
		Addr:       cfg.SMTPAddr,
		Hostname:   cfg.MailHostnames[0],
		Domain:     cfg.MailDomain,
		Certs:      certMgr,
		Store:      core,
		Recipients: core,
		MaxBytes:   cfg.MaxMessageBytes,
	})
	smtpLn, err := tunnelListener(cfg.GatewayPins, k, cfg.SMTPAddr)
	if err != nil {
		return err
	}
	acmeLn, err := tunnelListener(cfg.GatewayPins, k, cfg.ACMEChallengeAddr)
	if err != nil {
		return err
	}

	errc := make(chan error, 4)
	go func() { errc <- ignoreClosed(healthSrv.ListenAndServe()) }()
	go func() { errc <- smtpSrv.Serve(ctx, smtpLn) }()
	go func() { errc <- ignoreClosed(apiSrv.ListenAndServeTLS("", "")) }()
	go func() { errc <- ignoreClosed(acmeSrv.Serve(acmeLn)) }()
	go frontCertLoop(ctx, core, k.TLS, certMgr, acme.WithBootName(cfg.MailHostnames, cfg.BootDomain), frontCertTiming{})
	log.Printf("edge: front listening smtp=%s device-api=%s acme=%s", cfg.SMTPAddr, cfg.DeviceAPIAddr, cfg.ACMEChallengeAddr)

	select {
	case <-ctx.Done():
		log.Printf("edge: front shutdown signal")
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(sctx)
	_ = acmeSrv.Shutdown(sctx)
	_ = smtpSrv.Shutdown(sctx)
	_ = healthSrv.Shutdown(sctx)
	return err
}

// proxyTo forwards to mail-core over the closed network.
func proxyTo(hostport string) http.Handler {
	p := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: hostport})
	p.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("edge: front: core unreachable: %v", err)
		w.Header().Set("Retry-After", "5")
		http.Error(w, "core unreachable", http.StatusBadGateway)
	}
	return p
}

// deviceAPIProxy forwards the Device API's routes, and nothing else, to core.
// core's operator routes stay reachable only through the shim.
func deviceAPIProxy(coreAPI string) http.Handler {
	p := proxyTo(coreAPI)
	mux := http.NewServeMux()
	for _, r := range deviceapi.Routes() {
		mux.Handle(r.Pattern, p)
	}
	return mux
}

// frontCertTiming is how often front asks core for the chain. Zero values are
// the defaults; tests shorten them.
type frontCertTiming struct {
	retry, poll time.Duration
}

// frontCertLoop sends core the CSR until it takes it, then keeps fetching the
// chain, installing any whose leaf is for front's own key. Each fetch tells core
// which leaf front holds, which is what core's /ready waits for.
func frontCertLoop(ctx context.Context, core *link.Client, key *ecdsa.PrivateKey, mgr *certs.Manager, hostnames []string, t frontCertTiming) {
	if t.retry == 0 {
		t.retry = 5 * time.Second
	}
	if t.poll == 0 {
		t.poll = 30 * time.Second
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: hostnames}, key)
	if err != nil {
		log.Printf("edge: front: CSR: %v", err)
		return
	}
	for {
		err := core.SubmitCSR(ctx, csr)
		if err == nil {
			log.Printf("edge: front: core took the CSR")
			break
		}
		log.Printf("edge: front: CSR not taken yet: %v", err)
		if !wait(ctx, t.retry) {
			return
		}
	}
	for {
		have := ""
		if c, _ := mgr.Current(); c != nil && len(c.Certificate) > 0 {
			have = link.LeafHash(c.Certificate[0])
		}
		changed, err := fetchChain(ctx, core, key, mgr, have)
		if err != nil {
			log.Printf("edge: front: chain: %v", err)
		}
		next := t.poll
		switch {
		case changed:
			next = 0 // tell core at once, so /ready passes
		case have == "":
			next = t.retry
		}
		if !wait(ctx, next) {
			return
		}
	}
}

func fetchChain(ctx context.Context, core *link.Client, key *ecdsa.PrivateKey, mgr *certs.Manager, have string) (bool, error) {
	pemBytes, ok, err := core.Cert(ctx, have)
	if err != nil || !ok {
		return false, err
	}
	cert, err := certs.ParseChain(pemBytes)
	if err != nil {
		return false, err
	}
	if have != "" && link.LeafHash(cert.Certificate[0]) == have {
		return false, nil
	}
	pub, isEC := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !isEC || !pub.Equal(&key.PublicKey) {
		return false, errors.New("core's chain isn't for this front's key")
	}
	if time.Now().After(cert.Leaf.NotAfter) {
		return false, fmt.Errorf("core's chain expired %s", cert.Leaf.NotAfter)
	}
	cert.PrivateKey = key
	mgr.Set(cert)
	log.Printf("edge: front: certificate installed, leaf %s", link.LeafHash(cert.Certificate[0]))
	return true, nil
}

func wait(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
