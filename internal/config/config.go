// Package config loads the edge's boot-time configuration.
//
// Two sources, deliberately separate:
//
//   - Non-secret runtime settings come from the environment with safe defaults
//     (hostnames, listen addresses, limits).
//   - Secrets come from the keyserver. The Tinfoil runtime fetches them after
//     attestation and injects them as environment variables (see
//     tinfoil-config.yml). The edge holds NO long-lived secret of its own;
//     everything that must survive a boot comes from here. A missing secret is
//     a FATAL boot error — there is deliberately no fallback to a Tinfoil-managed
//     secret of the same name, because that path is reachable by Tinfoil's own
//     infrastructure (design §5).
//
// For local development only, EDGE_DEV=1 fills placeholder secrets so the binary
// can boot for smoke tests. It logs loudly and must never be set in a release.
package config

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
)

const defaultMaxMessageBytes = 25 * 1024 * 1024 // 25 MB, matches the probe's SIZE

// Let's Encrypt directories. Default to STAGING so development and the first
// tunnel tests don't burn the production rate limit (5 certs/week per exact name
// set). Set ACME_DIRECTORY to the production URL at deploy — real senders reject
// staging certs.
const (
	acmeStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

// Secrets are delivered by the keyserver and injected as env vars. Every field
// here must have a matching entry in the keyserver policy.yaml workload and in
// tinfoil-config.yml's `secrets:` list, or the enclave will not boot.
type Secrets struct {
	ACMEAccountKeyPEM []byte // CAA-pinned ACME account key (accounturi)
	AddressMACKey     []byte // keyed hash of addresses, stable across boots
	RoutingDataKey    []byte // decrypts the versioned owner/routing list
	S3AccessKeyID     string
	S3SecretAccessKey string
}

type Config struct {
	Hostname          string // public name the edge serves ACME for, e.g. mail-edge.fount.sh
	MailDomain        string // recipient domain, e.g. @fountbox.com
	AttestedKeyDir    string // where the Tinfoil runtime writes per-boot attested keys
	SMTPAddr          string
	DeviceAPIAddr     string
	HealthAddr        string
	ACMEChallengeAddr string
	ACMEDirectory     string // Let's Encrypt directory URL (staging by default)
	CertCacheDir      string // where issued certs are cached; "" disables (prod uses S3)
	MaxMessageBytes   int64
	S3Bucket          string // mail bucket name
	S3Region          string // bucket region, e.g. us-east-1
	S3Endpoint        string // bucket root URL; derived from bucket+region if unset
	Dev               bool
	Secrets           Secrets
}

// S3EndpointURL is the bucket root the S3 client talks to. An explicit
// S3_ENDPOINT wins (for an S3-compatible host); otherwise it is AWS
// virtual-hosted-style, which Tinfoil's exact-hostname egress allowlist needs.
func (c *Config) S3EndpointURL() string {
	if c.S3Endpoint != "" {
		return c.S3Endpoint
	}
	if c.S3Bucket == "" || c.S3Region == "" {
		return ""
	}
	return "https://" + c.S3Bucket + ".s3." + c.S3Region + ".amazonaws.com"
}

// Load reads the environment and returns a validated Config, or a fatal error if
// a required keyserver secret is absent (unless EDGE_DEV=1).
func Load() (*Config, error) {
	dev := os.Getenv("EDGE_DEV") == "1"
	c := &Config{
		Hostname:          env("MAIL_HOSTNAME", "mail-edge.fount.sh"),
		MailDomain:        env("MAIL_DOMAIN", "@fountbox.com"),
		AttestedKeyDir:    env("ATTESTED_KEY_DIR", "/run/tinfoil/keys"),
		SMTPAddr:          env("SMTP_ADDR", ":2525"),
		DeviceAPIAddr:     env("DEVICE_API_ADDR", ":8443"),
		HealthAddr:        env("HEALTH_ADDR", ":8080"),
		ACMEChallengeAddr: env("ACME_CHALLENGE_ADDR", ":8088"),
		ACMEDirectory:     env("ACME_DIRECTORY", acmeStaging),
		CertCacheDir:      os.Getenv("CERT_CACHE_DIR"),
		MaxMessageBytes:   defaultMaxMessageBytes,
		S3Bucket:          os.Getenv("S3_BUCKET"),
		S3Region:          os.Getenv("S3_REGION"),
		S3Endpoint:        os.Getenv("S3_ENDPOINT"),
		Dev:               dev,
	}
	if v := os.Getenv("MAX_MESSAGE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("MAX_MESSAGE_BYTES: %w", err)
		}
		c.MaxMessageBytes = n
	}

	s, err := loadSecrets(dev)
	if err != nil {
		return nil, err
	}
	c.Secrets = s
	return c, nil
}

func loadSecrets(dev bool) (Secrets, error) {
	if dev {
		log.Printf("edge: *** EDGE_DEV=1 — using placeholder secrets; NEVER set this in a release ***")
		return Secrets{
			ACMEAccountKeyPEM: []byte("DEV-PLACEHOLDER"),
			AddressMACKey:     []byte("dev-address-mac-key-not-secret"),
			RoutingDataKey:    []byte("dev-routing-data-key-not-secret"),
			S3AccessKeyID:     "DEV",
			S3SecretAccessKey: "DEV",
		}, nil
	}
	acme, err := requireRaw("ACME_ACCOUNT_KEY")
	if err != nil {
		return Secrets{}, err
	}
	mac, err := requireKey("ADDRESS_MAC_KEY")
	if err != nil {
		return Secrets{}, err
	}
	routing, err := requireKey("ROUTING_DATA_KEY")
	if err != nil {
		return Secrets{}, err
	}
	id, err := requireStr("S3_ACCESS_KEY_ID")
	if err != nil {
		return Secrets{}, err
	}
	secret, err := requireStr("S3_SECRET_ACCESS_KEY")
	if err != nil {
		return Secrets{}, err
	}
	return Secrets{
		ACMEAccountKeyPEM: []byte(acme),
		AddressMACKey:     mac,
		RoutingDataKey:    routing,
		S3AccessKeyID:     id,
		S3SecretAccessKey: secret,
	}, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requireStr(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("missing keyserver secret %s (no fallback by design)", key)
	}
	return v, nil
}

func requireRaw(key string) (string, error) { return requireStr(key) }

// requireKey reads a binary key. The keyserver may store it base64-encoded; if it
// decodes cleanly as standard base64 we use the decoded bytes, otherwise the raw
// bytes. (The exact encoding is pinned when the secrets are provisioned.)
func requireKey(key string) ([]byte, error) {
	v, err := requireStr(key)
	if err != nil {
		return nil, err
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	return []byte(v), nil
}
