package config

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/fount-labs/fount-mail-edge/internal/gatewaytls"
)

// Front is mail-front's config in a split edge (docs/CONTAINER-SPLIT.md). It
// holds the mail-tls key and nothing from the vault, so it reads no secrets, no
// vault or S3 settings, and no send settings.
type Front struct {
	MailHostnames     []string
	BootDomain        string
	MailDomain        string
	AttestedKeyDir    string
	SMTPAddr          string
	DeviceAPIAddr     string
	HealthAddr        string
	ACMEChallengeAddr string
	MaxMessageBytes   int64
	GatewayPins       []gatewaytls.Pin
	CoreLink          string // host:port of mail-core's link listener
	CoreAPI           string // host:port of mail-core's Device API (its shim port)
	Dev               bool
}

// FrontForbidden are settings that belong to mail-core or mail-send.
// mail-front refuses to start if any is set, as the forwarder does with secrets,
// so a config can't hand front more than the TLS key and the SMTP settings.
var FrontForbidden = append([]string{
	"KEYSET_COMMITMENT", "VAULT_HOSTS", "ENTITLEMENT_VERIFY_KEY", "OPERATOR_KEY",
	"S3_BUCKET", "S3_BOOT_LOG_BUCKET", "S3_BACKUP_BUCKET", "EGRESS_ROUTES", "EGRESS_FORWARDER",
	"ACME_DIRECTORY", "SEND_LINK",
}, SendSettings...)

// SendSettings are the settings only a sending container may carry: mail-edge in
// one container, and only mail-send in a split edge.
var SendSettings = []string{
	"SEND_ENABLED", "SEND_KEYSET_COMMITMENT", "SEND_RELAY_ADDR", "SEND_RELAY_PINS", "DKIM_SELECTOR",
	"SEND_EHLO_NAME",
}

// LoadFront reads mail-front's config.
func LoadFront() (*Front, error) {
	if name := VisibleSecret(); name != "" {
		return nil, fmt.Errorf("%s is visible here, and mail-front must hold no vault secret", name)
	}
	for _, name := range FrontForbidden {
		if _, ok := os.LookupEnv(name); ok {
			return nil, fmt.Errorf("%s is set, and it belongs to mail-core, not mail-front", name)
		}
	}
	dev := os.Getenv("EDGE_DEV") == "1"
	f := &Front{
		MailHostnames:     splitList(env("MAIL_HOSTNAMES", "mx1.fountbox.com,mx2.fountbox.com")),
		BootDomain:        os.Getenv("BOOT_HOSTNAME_DOMAIN"),
		MailDomain:        env("MAIL_DOMAIN", "@fountbox.com"),
		AttestedKeyDir:    env("ATTESTED_KEY_DIR", "/run/tinfoil/keys"),
		SMTPAddr:          env("SMTP_ADDR", ":2525"),
		DeviceAPIAddr:     env("DEVICE_API_ADDR", ":8443"),
		HealthAddr:        HealthAddr(),
		ACMEChallengeAddr: env("ACME_CHALLENGE_ADDR", ":8088"),
		MaxMessageBytes:   defaultMaxMessageBytes,
		CoreLink:          os.Getenv("CORE_LINK"),
		CoreAPI:           os.Getenv("CORE_API"),
		Dev:               dev,
	}
	if v := os.Getenv("MAX_MESSAGE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("MAX_MESSAGE_BYTES: %w", err)
		}
		f.MaxMessageBytes = n
	}
	if len(f.MailHostnames) == 0 {
		return nil, fmt.Errorf("MAIL_HOSTNAMES is empty")
	}
	if err := checkBootDomain(f.BootDomain, f.MailHostnames); err != nil {
		return nil, err
	}
	for name, v := range map[string]string{"CORE_LINK": f.CoreLink, "CORE_API": f.CoreAPI} {
		if _, _, err := net.SplitHostPort(v); err != nil {
			return nil, fmt.Errorf("%s must be mail-core's host:port: %w", name, err)
		}
	}
	if v := os.Getenv("GATEWAY_CLIENT_PINS"); v != "" || !dev {
		pins, err := gatewaytls.ParsePins(v)
		if err != nil {
			return nil, fmt.Errorf("GATEWAY_CLIENT_PINS: %w", err)
		}
		f.GatewayPins = pins
	}
	return f, nil
}

// LinkAddr is where mail-core listens for mail-front in a split edge.
func LinkAddr() string { return env("LINK_ADDR", ":7025") }
