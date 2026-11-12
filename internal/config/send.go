package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// SendForbidden are settings that belong to mail-core or mail-front. mail-send
// refuses to start if any is set, so a config can't hand it the keyset, S3 or
// the tunnels. It reads the send settings, the vaults it pulls the send keyset
// from, and the mail names it signs and says EHLO as.
var SendForbidden = []string{
	"KEYSET_COMMITMENT", "ENTITLEMENT_VERIFY_KEY", "OPERATOR_KEY",
	"S3_BUCKET", "S3_BOOT_LOG_BUCKET", "S3_BACKUP_BUCKET", "S3_ENDPOINT", "EGRESS_ROUTES", "EGRESS_FORWARDER",
	"ACME_DIRECTORY", "GATEWAY_CLIENT_PINS", "CORE_LINK", "CORE_API", "SEND_LINK",
	"RECOVERY_RP_ID", "RECOVERY_ORIGIN",
}

// LoadSend reads mail-send's config in a split edge (docs/CONTAINER-SPLIT.md,
// stage 2). It holds the send-transfer key and, once a vault hands it over, the
// send keyset; it has no mail keyset, so Secrets stays empty but for Send. The
// send gates are Load's: SEND_ENABLED still needs every send setting.
func LoadSend() (*Config, error) {
	if name := VisibleSecret(); name != "" {
		return nil, fmt.Errorf("%s is visible here, and mail-send must hold no keyset secret", name)
	}
	for _, name := range SendForbidden {
		if _, ok := os.LookupEnv(name); ok {
			return nil, fmt.Errorf("%s is set, and it doesn't belong to mail-send", name)
		}
	}
	dev := os.Getenv("EDGE_DEV") == "1"
	c := &Config{
		MailHostnames:   splitList(env("MAIL_HOSTNAMES", "mx1.fountbox.com,mx2.fountbox.com")),
		MailDomain:      env("MAIL_DOMAIN", "@fountbox.com"),
		AttestedKeyDir:  env("ATTESTED_KEY_DIR", "/run/tinfoil/keys"),
		HealthAddr:      HealthAddr(),
		MaxMessageBytes: defaultMaxMessageBytes,
		Dev:             dev,
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
	if err := c.loadSend(dev); err != nil {
		return nil, err
	}
	if dev {
		return c, nil
	}
	// With no send commitment mail-send takes no keys, so it needs no vault.
	if os.Getenv("VAULT_HOSTS") != "" || c.SendKeysetCommitment != "" {
		hosts, err := vaultHosts()
		if err != nil {
			return nil, err
		}
		c.VaultHosts = hosts
	}
	return c, nil
}

// InstallSendKeyset fills Secrets.Send from mail-send's own pull, which
// wire.PullSendKeyset has already checked against SendKeysetCommitment.
func (c *Config) InstallSendKeyset(k *wire.SendKeyset) error {
	if c.SendKeysetCommitment == "" || !k.Matches(c.SendKeysetCommitment) {
		return fmt.Errorf("send keyset %s doesn't match SEND_KEYSET_COMMITMENT", k.Commitment())
	}
	send, err := sendKeys(k)
	if err != nil {
		return err
	}
	c.Secrets.Send = send
	return nil
}

// SendLinkAddr is where mail-send listens for mail-core in a split edge.
func SendLinkAddr() string { return env("SEND_LINK_ADDR", ":7026") }
