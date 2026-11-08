package operator

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RolePrivateKeys are the private halves of a role mailbox's keys. Whoever reads
// abuse@ or postmaster@ holds them; the edge never sees them. The passkey key is a
// software P-256 key, because a role mailbox has no person with a device to hold a
// real passkey.
type RolePrivateKeys struct {
	Role           string `json:"role"`
	DecryptionKey  []byte `json:"decryption_key"`   // X25519 private key
	SigningKey     []byte `json:"signing_key"`      // Ed25519 seed
	MailboxKey     []byte `json:"mailbox_key"`      // Ed25519 seed
	OwnerChangeKey []byte `json:"owner_change_key"` // Ed25519 seed
	PasskeyKey     []byte `json:"passkey_key"`      // P-256 scalar, 32 bytes big-endian
}

// GenerateRoleKeys makes a fresh set of keys for a role mailbox.
func GenerateRoleKeys(role string) (RolePrivateKeys, PublicKeys, error) {
	if !roles[role] {
		return RolePrivateKeys{}, PublicKeys{}, fmt.Errorf("role %q: want abuse or postmaster", role)
	}
	dec, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RolePrivateKeys{}, PublicKeys{}, err
	}
	seeds := make([][]byte, 3)
	pubs := make([][]byte, 3)
	for i := range seeds {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return RolePrivateKeys{}, PublicKeys{}, err
		}
		seeds[i], pubs[i] = priv.Seed(), pub
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RolePrivateKeys{}, PublicKeys{}, err
	}
	pkPub, err := pk.PublicKey.Bytes()
	if err != nil {
		return RolePrivateKeys{}, PublicKeys{}, err
	}
	pkPriv, err := pk.Bytes()
	if err != nil {
		return RolePrivateKeys{}, PublicKeys{}, err
	}
	priv := RolePrivateKeys{
		Role:           role,
		DecryptionKey:  dec.Bytes(),
		SigningKey:     seeds[0],
		MailboxKey:     seeds[1],
		OwnerChangeKey: seeds[2],
		PasskeyKey:     pkPriv,
	}
	pub := PublicKeys{
		DecryptionKey:  dec.PublicKey().Bytes(),
		SigningKey:     pubs[0],
		MailboxKey:     pubs[1],
		OwnerChangeKey: pubs[2],
		PasskeyKey:     pkPub,
	}
	return priv, pub, nil
}

// WriteRoleKeys generates a role's keys into dir: ROLE.private.json with mode
// 0600, and ROLE.public.json, which is edgectl provision's -keys file. It refuses
// a dir inside a git work tree, and never overwrites either file.
func WriteRoleKeys(dir, role string) (privPath, pubPath string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	if repo := enclosingRepo(abs); repo != "" {
		return "", "", fmt.Errorf("%s is inside the git repo at %s; private keys must live outside any repo", abs, repo)
	}
	priv, pub, err := GenerateRoleKeys(role)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", "", err
	}
	privPath = filepath.Join(abs, role+".private.json")
	pubPath = filepath.Join(abs, role+".public.json")
	for _, p := range []string{privPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists; refusing to overwrite a role's keys", p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
	}
	if err := writeNew(privPath, 0o600, priv); err != nil {
		return "", "", err
	}
	if err := writeNew(pubPath, 0o644, pub); err != nil {
		return "", "", err
	}
	return privPath, pubPath, nil
}

func writeNew(path string, mode os.FileMode, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// enclosingRepo returns the nearest ancestor of dir (or dir itself) holding .git,
// or "" if there's none. dir needn't exist yet.
func enclosingRepo(dir string) string {
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if parent := filepath.Dir(d); parent == d {
			return ""
		}
	}
}
