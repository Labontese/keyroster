package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "ca",
		Summary: "certificate authority operations (issue)",
		Run:     runCA,
	})
}

// stringList collects a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runCA(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: keyroster ca issue [flags]")
		return errUsage
	}
	switch args[0] {
	case "issue":
		return runCAIssue(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "keyroster ca: unknown subcommand %q\n", args[0])
		return errUsage
	}
}

func runCAIssue(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("ca issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/keyroster-signer/signer.sock", "keyroster-signer Unix socket")
	caName := fs.String("ca", "user", "certificate authority: user, host or machine")
	pubkeyPath := fs.String("pubkey", "", "OpenSSH public key file of the subject (required)")
	subject := fs.String("subject", "", "subject recorded in the key ID, e.g. u:alice (required)")
	ttl := fs.Duration("ttl", time.Hour, "certificate validity")
	out := fs.String("out", "", "certificate output file (default: {pubkey without .pub}-cert.pub)")
	var principals stringList
	fs.Var(&principals, "principal", "principal to certify (repeatable, at least one)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *pubkeyPath == "" || *subject == "" || len(principals) == 0 {
		_, _ = fmt.Fprintln(stderr, "ca issue: --pubkey, --subject and at least one --principal are required")
		return errUsage
	}
	role, err := parseCARole(*caName)
	if err != nil {
		return err
	}
	if *ttl <= 0 || *ttl%time.Second != 0 || *ttl/time.Second > math.MaxUint32 {
		return errors.New("--ttl must be a positive whole number of seconds")
	}

	pub, err := readPublicKey(*pubkeyPath)
	if err != nil {
		return err
	}
	req := &wire.IssueRequest{
		CARole:          role,
		SubjectKey:      pub.Marshal(),
		Subject:         *subject,
		Principals:      principals,
		ValidForSeconds: uint32(*ttl / time.Second), //nolint:gosec // G115: bounded by math.MaxUint32 above
		CreatedAt:       uint64(time.Now().Unix()),  //nolint:gosec // G115: the clock is after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return fmt.Errorf("request id: %w", err)
	}

	resp, err := signerclient.Issue(ctx, *socket, req)
	if err != nil {
		return err
	}
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		return fmt.Errorf("signer returned an unparsable certificate: %w", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return errors.New("signer returned a key, not a certificate")
	}
	if !bytes.Equal(c.Key.Marshal(), pub.Marshal()) || c.Serial != resp.Serial {
		return errors.New("signer returned a certificate for another key or serial")
	}

	dest := *out
	if dest == "" {
		dest = strings.TrimSuffix(*pubkeyPath, ".pub") + "-cert.pub"
	}
	if err := os.WriteFile(dest, ssh.MarshalAuthorizedKey(c), 0o644); err != nil { //nolint:gosec // G306: a certificate is public
		return err
	}
	_, _ = fmt.Fprintf(stderr, "serial: %d\nkey id: %s\nlog leaf: %d\ncertificate: %s\n", c.Serial, c.KeyId, resp.LeafIndex, dest)
	return nil
}

func parseCARole(s string) (wire.CARole, error) {
	switch s {
	case "user":
		return wire.CARoleUser, nil
	case "host":
		return wire.CARoleHost, nil
	case "machine":
		return wire.CARoleMachine, nil
	default:
		return 0, fmt.Errorf("--ca %q: want user, host or machine", s)
	}
}

// readPublicKey reads an OpenSSH public key file. A file that contains a
// private key is refused before anything is sent (CA-06): keyroster never
// handles a user's private key.
func readPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, fmt.Errorf("%s contains a private key; pass the .pub file (keyroster never handles private keys)", path)
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s: more than one key", path)
	}
	return pub, nil
}
