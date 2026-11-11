// Command edgectl asks a running edge to change its routing data, signed with the
// operator key. Only the edge holds ROUTING_DATA_KEY and ADDRESS_MAC_KEY, so it
// does the work itself; this only signs and sends. docs/RESTORE.md covers restores.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fount-labs/fount-mail-edge/internal/operator"
)

const usage = `usage:
  edgectl role-keygen -role abuse|postmaster -out DIR
  edgectl status    -edge HOST   (routing state, ACME account URL, sending state; no key needed)
  edgectl init      -edge HOST -operator-key FILE
  edgectl provision -edge HOST -operator-key FILE -role abuse|postmaster -keys FILE
  edgectl restore   -edge HOST -operator-key FILE -backup FILE [-boot-record FILE]
                    [-skip-sequences N] [-write] [-replace]
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	host := fs.String("edge", "", "the edge's shim hostname")
	keyPath := fs.String("operator-key", "", "operator key file, from vaultctl operator-keygen")
	role := fs.String("role", "", "abuse or postmaster")
	keysPath := fs.String("keys", "", "JSON file of the mailbox's public keys, with POST /mailbox's field names")
	backup := fs.String("backup", "", "a backup object downloaded from the routing backup bucket")
	bootRecord := fs.String("boot-record", "", "the signing boot's record, if edge/boots no longer has it")
	skip := fs.Uint64("skip-sequences", 0, "move every sequence counter forward by this much")
	write := fs.Bool("write", false, "install the backup; without this, only verify it")
	replace := fs.Bool("replace", false, "allow replacing an existing routing object")
	outDir := fs.String("out", "", "directory for a role's key files, outside any repo")
	fs.Parse(os.Args[2:])
	if os.Args[1] == "role-keygen" {
		roleKeygen(*role, *outDir)
		return
	}
	if *host == "" {
		fail("-edge is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := &operator.Client{HTTP: &http.Client{Timeout: 2 * time.Minute}, Base: "https://" + *host}
	if os.Args[1] != "status" {
		key, err := readOperatorKey(*keyPath)
		if err != nil {
			fail(err.Error())
		}
		c.Key = key
	}

	var out any
	var err error
	switch os.Args[1] {
	case "status":
		out, err = c.Status(ctx)
	case "init":
		out, err = do(ctx, c, operator.OpInit, struct{}{})
	case "provision":
		var p operator.ProvisionPayload
		p.Role = *role
		if err = readJSON(*keysPath, &p.Keys); err == nil {
			out, err = do(ctx, c, operator.OpProvision, p)
		}
	case "restore":
		p := operator.RestorePayload{SkipSequences: *skip, Write: *write, Replace: *replace}
		if p.Backup, err = readFile(*backup, "-backup"); err == nil && *bootRecord != "" {
			p.BootRecord, err = os.ReadFile(*bootRecord)
		}
		if err == nil {
			out, err = do(ctx, c, operator.OpRestore, p)
		}
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "edgectl:", err)
		os.Exit(1)
	}
	pretty, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(pretty))
}

// roleKeygen writes a role mailbox's keys. It prints only paths and public keys.
func roleKeygen(role, dir string) {
	if role == "" || dir == "" {
		fail("-role and -out are required")
	}
	privPath, pubPath, err := operator.WriteRoleKeys(dir, role)
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("private keys: %s (mode 0600; keep it off any repo and backed up)\n", privPath)
	fmt.Printf("public keys:  %s (pass to edgectl provision -keys)\n", pubPath)
}

func do(ctx context.Context, c *operator.Client, op string, payload any) (any, error) {
	var out map[string]any
	err := c.Do(ctx, op, payload, &out)
	return out, err
}

func readFile(path, flagName string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s is required", flagName)
	}
	return os.ReadFile(path)
}

func readJSON(path string, v any) error {
	raw, err := readFile(path, "-keys")
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// readOperatorKey reads the file vaultctl operator-keygen writes: a hex seed.
func readOperatorKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-operator-key is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s isn't a hex Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "edgectl:", msg)
	os.Exit(2)
}
