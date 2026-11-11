// Package config loads the edge's boot-time configuration.
//
// Two sources, deliberately separate:
//
//   - Runtime settings come from the environment, which tinfoil-config.yml sets
//     and measures, so none of them is secret.
//   - Secrets come from a Fount Mail vault after boot (InstallVaultKeys). The vault
//     verifies this release before it seals them to the attested transfer key, and
//     the edge checks them against KEYSET_COMMITMENT. The edge holds NO long-lived
//     secret of its own, and there is deliberately no fallback to a Tinfoil-managed
//     secret, because that path is reachable by Tinfoil's own infrastructure
//     (design §5).
//
// For local development only, EDGE_DEV=1 fills placeholder secrets so the binary
// can boot for smoke tests. It logs loudly and must never be set in a release.
package config

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/fount-labs/fount-mail-edge/internal/egress"
	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
	"github.com/fount-labs/fount-mail-vault/wire"
)

const defaultMaxMessageBytes = 25 * 1024 * 1024 // 25 MB, matches the probe's SIZE

// Let's Encrypt directories. Default to STAGING so development and the first
// tunnel tests don't burn the production rate limit (5 certs/week per exact name
// set). A release must set ACME_DIRECTORY to the production URL, because real
// senders reject staging certs; Load refuses to boot one that doesn't.
const (
	acmeStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

// SecretNames are the edge's secrets, by the env var names the routing commands
// read them from. A release never sets them: they come from the vault.
var SecretNames = []string{
	"ACME_ACCOUNT_KEY", "ADDRESS_MAC_KEY", "ROUTING_DATA_KEY",
	"S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY",
}

// VisibleSecret names a secret in this process's environment, or returns "" if
// there is none. The forwarder checks this at startup, as a tripwire against a
// config that puts one back in the environment.
func VisibleSecret() string {
	for _, name := range SecretNames {
		if _, ok := os.LookupEnv(name); ok {
			return name
		}
	}
	return ""
}

// Secrets come from the vault. The first three are the keyset KEYSET_COMMITMENT
// pins; the S3 credentials are issued by AWS and imported into the vault.
type Secrets struct {
	ACMEAccountKeyPEM []byte // CAA-pinned ACME account key (accounturi)
	AddressMACKey     []byte // keyed hash of addresses, stable across boots
	RoutingDataKey    []byte // decrypts the versioned owner/routing list
	S3AccessKeyID     string
	S3SecretAccessKey string
	// Send is the send keyset, or nil when SEND_KEYSET_COMMITMENT is unset or no
	// vault had it. It can't read mail, so it rides apart from the keys above.
	Send *SendKeys
}

// SendKeys are the send keyset's keys (fount-mail-vault docs/SEND-KEYS.md), which
// wire.PullKeysets has already checked against SendKeysetCommitment.
type SendKeys struct {
	Commitment  string
	DKIMRSA     *rsa.PrivateKey    // rsa-sha256, selector DKIM_SELECTOR
	DKIMEd25519 ed25519.PrivateKey // ed25519-sha256, selector DKIM_SELECTOR + "e"
	RelayClient ed25519.PrivateKey // the client key the gateway relay pins
}

type Config struct {
	MailHostnames     []string // the MX names; the SMTP certificate covers all of them, first is the HELO name
	MailDomain        string   // recipient domain, e.g. @fountbox.com
	AttestedKeyDir    string   // where the Tinfoil runtime writes per-boot attested keys
	SMTPAddr          string
	DeviceAPIAddr     string
	HealthAddr        string
	ACMEChallengeAddr string
	ACMEDirectory     string // Let's Encrypt directory URL (staging by default)
	CertCacheDir      string // where issued certs are cached; "" disables (prod uses S3)
	MaxMessageBytes   int64
	GatewayPins       []gatewaytls.Pin // gateway client keys for the tunnelled ports; measured with the config, so not a secret
	S3Bucket          string           // mail bucket name
	S3BootLogBucket   string           // Object Lock bucket for the boot and key logs
	S3BackupBucket    string           // versioned bucket for routing backups
	S3Region          string           // bucket region, e.g. us-east-1
	S3Endpoint        string           // bucket root URL; derived from bucket+region if unset
	EgressForwarder   string           // the forwarder container's name
	EgressRoutes      []egress.Route   // one per bucket hostname; measured with the config
	RecoveryRPID      string           // WebAuthn RP id POST /recover verifies passkey assertions against; "" leaves recovery 501
	RecoveryOrigin    string           // optional: pins the assertion's clientDataJSON origin (e.g. https://fount.sh)
	VaultHosts        []string         // vaults to pull the keyset from, tried in order
	KeysetCommitment  string           // the only keyset this release accepts
	// SendKeysetCommitment is the only send keyset this release accepts. Empty
	// means the edge takes none, so sending stays off whatever else is set.
	SendKeysetCommitment string
	// EntitlementVerifyKey is the Ed25519 public key that verifies device
	// entitlements (§4/§8). It's public, so it's measured config, not a secret.
	EntitlementVerifyKey []byte
	// OperatorKey is the Ed25519 public key that signs edgectl requests: routing
	// init, role mailboxes, and restores. The same key signs vault imports.
	OperatorKey ed25519.PublicKey
	// SendEnabled turns on POST /send (M3). It launches dark: a release may set it
	// only with a send commitment, a relay and a DKIM selector, and sending still
	// stays off unless a vault hands over the committed send keyset. The shim
	// doesn't forward /send either, until that route is marked built.
	SendEnabled   bool
	SendRelayAddr string           // host:port of the gateway relay's listener
	SendRelayPins []gatewaytls.Pin // the relay's server keys
	DKIMSelector  string           // RSA selector, e.g. "f1"; Ed25519 signs as "f1e"
	Dev           bool
	Secrets       Secrets
}

// S3EndpointURL is the mail bucket root the S3 client talks to. An explicit
// S3_ENDPOINT wins (for an S3-compatible host); otherwise it is AWS
// virtual-hosted-style, so each bucket has its own hostname to route.
func (c *Config) S3EndpointURL() string {
	if c.S3Endpoint != "" {
		return c.S3Endpoint
	}
	return c.BucketURL(c.S3Bucket)
}

// BucketURL is a bucket's virtual-hosted root, or "" if it isn't configured.
func (c *Config) BucketURL(bucket string) string {
	if bucket == "" || c.S3Region == "" {
		return ""
	}
	return "https://" + bucket + ".s3." + c.S3Region + ".amazonaws.com"
}

// Load reads the environment and returns a validated Config. It holds no secrets
// until InstallVaultKeys runs, except with EDGE_DEV=1, which fills placeholders.
func Load() (*Config, error) {
	dev := os.Getenv("EDGE_DEV") == "1"
	c := &Config{
		MailHostnames:     splitList(env("MAIL_HOSTNAMES", "mx1.fountbox.com,mx2.fountbox.com")),
		MailDomain:        env("MAIL_DOMAIN", "@fountbox.com"),
		AttestedKeyDir:    env("ATTESTED_KEY_DIR", "/run/tinfoil/keys"),
		SMTPAddr:          env("SMTP_ADDR", ":2525"),
		DeviceAPIAddr:     env("DEVICE_API_ADDR", ":8443"),
		HealthAddr:        HealthAddr(),
		ACMEChallengeAddr: env("ACME_CHALLENGE_ADDR", ":8088"),
		ACMEDirectory:     env("ACME_DIRECTORY", acmeStaging),
		CertCacheDir:      os.Getenv("CERT_CACHE_DIR"),
		MaxMessageBytes:   defaultMaxMessageBytes,
		S3Bucket:          os.Getenv("S3_BUCKET"),
		S3BootLogBucket:   os.Getenv("S3_BOOT_LOG_BUCKET"),
		S3BackupBucket:    os.Getenv("S3_BACKUP_BUCKET"),
		S3Region:          os.Getenv("S3_REGION"),
		S3Endpoint:        os.Getenv("S3_ENDPOINT"),
		RecoveryRPID:      os.Getenv("RECOVERY_RP_ID"), // the Fount RP domain serving the passkey AASA: fount.sh in tinfoil-config.yml
		RecoveryOrigin:    os.Getenv("RECOVERY_ORIGIN"),
		Dev:               dev,
	}
	if v := os.Getenv("MAX_MESSAGE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("MAX_MESSAGE_BYTES: %w", err)
		}
		c.MaxMessageBytes = n
	}

	if len(c.MailHostnames) == 0 {
		return nil, fmt.Errorf("MAIL_HOSTNAMES is empty")
	}
	if !dev && c.ACMEDirectory == acmeStaging {
		return nil, fmt.Errorf("ACME_DIRECTORY is Let's Encrypt staging: senders refuse those certificates, so a release must set the production directory")
	}
	// A release with no pins would leave the tunnelled ports open to any tk_ key,
	// so it's fatal. Only a dev boot may run them in the clear.
	if v := os.Getenv("GATEWAY_CLIENT_PINS"); v != "" || !dev {
		pins, err := gatewaytls.ParsePins(v)
		if err != nil {
			return nil, fmt.Errorf("GATEWAY_CLIENT_PINS: %w", err)
		}
		c.GatewayPins = pins
	}
	if v := os.Getenv("SEND_ENABLED"); v != "" {
		if v != "1" {
			return nil, fmt.Errorf("SEND_ENABLED must be 1 or unset, got %q", v)
		}
		c.SendEnabled = true
	}
	if err := c.loadSend(dev); err != nil {
		return nil, err
	}
	if dev {
		devSecrets(c)
		return c, nil
	}
	if err := c.loadEgress(); err != nil {
		return nil, err
	}
	if err := c.loadVault(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadVault reads where the keyset comes from and which one to accept. The
// entitlement key rides along because it used to be a keyserver secret.
func (c *Config) loadVault() error {
	c.VaultHosts = splitList(os.Getenv("VAULT_HOSTS"))
	if len(c.VaultHosts) == 0 {
		return fmt.Errorf("VAULT_HOSTS is empty: a release gets its keys only from a vault")
	}
	for _, h := range c.VaultHosts {
		if strings.ContainsAny(h, "/?#@: ") {
			return fmt.Errorf("VAULT_HOSTS entry %q must be a bare hostname", h)
		}
	}
	c.KeysetCommitment = os.Getenv("KEYSET_COMMITMENT")
	if err := wire.ValidateCommitment(c.KeysetCommitment); err != nil {
		return fmt.Errorf("KEYSET_COMMITMENT: %w", err)
	}
	verify, err := RequireKey("ENTITLEMENT_VERIFY_KEY")
	if err != nil {
		return err
	}
	// A wrong-length key would boot and then reject every entitlement. KMS hands
	// out a 44-byte DER key, so this is the likely mistake when filling it.
	if len(verify) != ed25519.PublicKeySize {
		return fmt.Errorf("ENTITLEMENT_VERIFY_KEY is %d bytes, want %d raw Ed25519 bytes", len(verify), ed25519.PublicKeySize)
	}
	c.EntitlementVerifyKey = verify
	// Without it nobody could initialize routing or restore a backup, so a release
	// that can't parse it must not boot.
	operator, err := hex.DecodeString(os.Getenv("OPERATOR_KEY"))
	if err != nil || len(operator) != ed25519.PublicKeySize {
		return fmt.Errorf("OPERATOR_KEY must be a hex Ed25519 public key, from vaultctl operator-keygen")
	}
	c.OperatorKey = operator
	return nil
}

// loadSend reads the send settings. SEND_KEYSET_COMMITMENT alone makes the edge
// take the send keyset; SEND_ENABLED also needs the relay and a DKIM selector, so
// a release can't turn sending on with nowhere to send through.
func (c *Config) loadSend(dev bool) error {
	c.SendKeysetCommitment = os.Getenv("SEND_KEYSET_COMMITMENT")
	if c.SendKeysetCommitment != "" {
		if err := wire.ValidateCommitment(c.SendKeysetCommitment); err != nil {
			return fmt.Errorf("SEND_KEYSET_COMMITMENT: %w", err)
		}
	}
	c.SendRelayAddr = os.Getenv("SEND_RELAY_ADDR")
	c.DKIMSelector = os.Getenv("DKIM_SELECTOR")
	if v := os.Getenv("SEND_RELAY_PINS"); v != "" {
		pins, err := gatewaytls.ParsePins(v)
		if err != nil {
			return fmt.Errorf("SEND_RELAY_PINS: %w", err)
		}
		c.SendRelayPins = pins
	}
	if c.DKIMSelector != "" && !validSelector(c.DKIMSelector) {
		return fmt.Errorf("DKIM_SELECTOR %q must be letters, digits and hyphens", c.DKIMSelector)
	}
	if !c.SendEnabled || dev {
		return nil
	}
	switch {
	case c.SendKeysetCommitment == "":
		return fmt.Errorf("SEND_ENABLED needs SEND_KEYSET_COMMITMENT: a release signs only with the committed send keyset")
	case c.SendRelayAddr == "":
		return fmt.Errorf("SEND_ENABLED needs SEND_RELAY_ADDR: outbound mail goes only through the gateway relay")
	case len(c.SendRelayPins) == 0:
		return fmt.Errorf("SEND_ENABLED needs SEND_RELAY_PINS: the relay is pinned, not named")
	case c.DKIMSelector == "":
		return fmt.Errorf("SEND_ENABLED needs DKIM_SELECTOR, the selector the send keyset's TXT records are under")
	}
	if _, _, err := net.SplitHostPort(c.SendRelayAddr); err != nil {
		return fmt.Errorf("SEND_RELAY_ADDR: %w", err)
	}
	return nil
}

func validSelector(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

// InstallVaultKeys fills Secrets from a pull, which wire.PullKeysets has already
// checked against KeysetCommitment and, when it's set, SendKeysetCommitment. A
// pull with no send keyset installs the rest, and sending stays off.
func (c *Config) InstallVaultKeys(r *wire.PullResult) error {
	if r.S3 == nil || r.S3.AccessKeyID == "" || r.S3.SecretAccessKey == "" {
		return fmt.Errorf("the vault holds no S3 credentials: import them with vaultctl import-s3")
	}
	var send *SendKeys
	if r.SendKeyset != nil && c.SendKeysetCommitment != "" {
		// PullKeysets checked it, but a send keyset only ever installs here.
		if !r.SendKeyset.Matches(c.SendKeysetCommitment) {
			return fmt.Errorf("send keyset %s doesn't match SEND_KEYSET_COMMITMENT", r.SendKeyset.Commitment())
		}
		var err error
		if send, err = sendKeys(r.SendKeyset); err != nil {
			return err
		}
	}
	c.Secrets = Secrets{
		ACMEAccountKeyPEM: r.Keyset.ACMEAccountKeyPEM(),
		AddressMACKey:     append([]byte(nil), r.Keyset.AddressMACKey[:]...),
		RoutingDataKey:    append([]byte(nil), r.Keyset.RoutingDataKey[:]...),
		S3AccessKeyID:     r.S3.AccessKeyID,
		S3SecretAccessKey: r.S3.SecretAccessKey,
		Send:              send,
	}
	return nil
}

func sendKeys(k *wire.SendKeyset) (*SendKeys, error) {
	rsaKey, err := k.DKIMRSA()
	if err != nil {
		return nil, err
	}
	edKey, err := k.DKIMEd25519()
	if err != nil {
		return nil, err
	}
	relay, err := k.RelayClient()
	if err != nil {
		return nil, err
	}
	return &SendKeys{Commitment: k.Commitment(), DKIMRSA: rsaKey, DKIMEd25519: edKey, RelayClient: relay}, nil
}

// loadEgress is fatal on a gap, because a bucket with no route would otherwise fail
// only when the edge first touches it.
func (c *Config) loadEgress() error {
	c.EgressForwarder = os.Getenv("EGRESS_FORWARDER")
	if c.EgressForwarder == "" {
		return fmt.Errorf("EGRESS_FORWARDER is unset: a release reaches S3 only through the forwarder")
	}
	routes, err := egress.ParseRoutes(os.Getenv("EGRESS_ROUTES"))
	if err != nil {
		return fmt.Errorf("EGRESS_ROUTES: %w", err)
	}
	c.EgressRoutes = routes
	routed := make(map[string]bool, len(routes))
	for _, r := range routes {
		routed[r.Host] = true
	}
	for _, endpoint := range []string{c.S3EndpointURL(), c.BucketURL(c.S3BootLogBucket), c.BucketURL(c.S3BackupBucket)} {
		if endpoint == "" {
			continue // newBlobs reports a missing bucket
		}
		u, err := url.Parse(endpoint)
		if err != nil {
			return fmt.Errorf("S3 endpoint %q: %w", endpoint, err)
		}
		if !routed[u.Host] {
			return fmt.Errorf("EGRESS_ROUTES has no route to %s", u.Host)
		}
	}
	return nil
}

func devSecrets(c *Config) {
	log.Printf("edge: *** EDGE_DEV=1 — using placeholder secrets; NEVER set this in a release ***")
	c.EntitlementVerifyKey = make([]byte, ed25519.PublicKeySize) // dev: all-zero, verifies nothing real
	c.Secrets = Secrets{
		ACMEAccountKeyPEM: []byte("DEV-PLACEHOLDER"),
		AddressMACKey:     []byte("dev-address-mac-key-not-secret"),
		RoutingDataKey:    []byte("dev-routing-data-key-not-secret"),
		S3AccessKeyID:     "DEV",
		S3SecretAccessKey: "DEV",
	}
}

// HealthAddr is the health listener's address. It's separate from Load because
// the container's health check runs as its own process, with no secrets to load.
func HealthAddr() string { return env("HEALTH_ADDR", ":8080") }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func requireStr(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("missing %s (no fallback by design)", key)
	}
	return v, nil
}

// RequireKey reads a binary key from the environment. If it decodes cleanly as
// standard base64 we use the decoded bytes, otherwise the raw bytes.
func RequireKey(key string) ([]byte, error) {
	v, err := requireStr(key)
	if err != nil {
		return nil, err
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	return []byte(v), nil
}
