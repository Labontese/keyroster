package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "init",
		Summary: "pin a keyroster server's TLS roots and trust roots and save the client config",
		Run:     runInit,
	})
}

// initDialTimeout bounds init's TLS probe of the server.
const initDialTimeout = 15 * time.Second

// errInitUntrusted is init's refusal of a server chain that ends in none
// of the roots it verifies with.
var errInitUntrusted = errors.New("the server's TLS certificate does not chain to a root in --tls-root-file, " +
	"or to a system root when --tls-root-file is not given (or the server is not sending its full chain)")

// observedRoot is a root certificate that ends a chain the server
// presented, with its pin.
type observedRoot struct {
	cert *x509.Certificate
	pin  string
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("init", flag.ContinueOnError)
	fset.SetOutput(stderr)
	server := fset.String("server", "", "server URL, https://HOST[:PORT]; HOST is the server's DNS name (required)")
	var tlsPins, rootPins stringList
	fset.Var(&tlsPins, "tls-pin", "sha256/<base64> pin of a TLS root the server presents, confirmed out of band (repeatable); without it init only prints the roots it sees")
	rootFile := fset.String("tls-root-file", "", "PEM file of the TLS root CA(s) to verify the server with, for a private CA (default: the system roots)")
	fset.Var(&rootPins, "root-pin", "SHA256 fingerprint of a trust root, obtained out of band (repeatable)")
	threshold := fset.Int("threshold", 0, "number of trust roots that must have signed the trust bundle")
	user := fset.String("user", "", "your keyroster user name")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent, if you are an admin")
	force := fset.Bool("force", false, "replace an existing config")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 || *server == "" {
		_, _ = fmt.Fprintln(stderr, "init: --server is required; no positional arguments")
		return errUsage
	}
	base, err := serverclient.ParseServerURL(*server)
	if err != nil {
		return err
	}
	for _, p := range tlsPins {
		if err := serverclient.CheckPin(p); err != nil {
			return err
		}
	}
	if len(tlsPins) > 0 {
		if err := trust.CheckPins(rootPins, *threshold); err != nil {
			return fmt.Errorf("--root-pin and --threshold: %w", err)
		}
		if *adminKey != "" {
			if err := trust.CheckPins([]string{*adminKey}, 1); err != nil {
				return fmt.Errorf("--admin-key: %w", err)
			}
		}
		if exists, err := configExists(); err != nil {
			return err
		} else if exists && !*force {
			return errConfigExists
		}
	}

	pool, err := initRootPool(*rootFile)
	if err != nil {
		return err
	}
	observed, err := observeRoots(ctx, base.Host, base.Hostname(), base.Port(), pool)
	if err != nil {
		return err
	}
	for _, r := range observed {
		_, _ = fmt.Fprintf(stdout, "TLS root: %s\n  pin %s\n", r.cert.Subject.String(), r.pin)
	}
	if len(tlsPins) == 0 {
		_, _ = fmt.Fprintln(stderr, "init: compare these with your invite and re-run with --tls-pin")
		return errUsage
	}
	var keep []observedRoot
	for _, p := range tlsPins {
		i := slices.IndexFunc(observed, func(r observedRoot) bool { return r.pin == p })
		if i < 0 {
			return fmt.Errorf("--tls-pin %s: the server presented no chain to a root with that pin; nothing was saved", p)
		}
		if !slices.ContainsFunc(keep, func(r observedRoot) bool { return r.pin == p }) {
			keep = append(keep, observed[i])
		}
	}
	cfg := &Config{
		Server:         base.String(),
		TrustPins:      append([]string(nil), rootPins...),
		TrustThreshold: *threshold,
		User:           *user,
		AdminKey:       *adminKey,
	}
	for _, r := range keep {
		cfg.TLSRootsPEM = append(cfg.TLSRootsPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.cert.Raw})))
		cfg.TLSPins = append(cfg.TLSPins, r.pin)
	}

	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	b, p, err := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold)
	if err != nil {
		return err
	}
	if err := printTrustSummary(stdout, b, p); err != nil {
		return err
	}
	path, err := saveConfig(cfg, *force)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "saved %s\n", path)
	return nil
}

// initRootPool returns the pool init verifies the server with: the CA
// certificates of file, or the system roots when file is empty.
func initRootPool(file string) (*x509.CertPool, error) {
	if file == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system roots: %w (pass --tls-root-file)", err)
		}
		return pool, nil
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: the user names the file
	if err != nil {
		return nil, err
	}
	roots, err := serverclient.ParseRoots(data)
	if err != nil {
		return nil, fmt.Errorf("--tls-root-file %s: %w", file, err)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	return pool, nil
}

// observeRoots connects to the server, verifies its chain against pool
// and the host name, and returns the root of every verified chain, once
// per pin. Servers do not send their root, so init cannot read it from the
// handshake; it takes it from Go's verified chains (RESEARCH Q1).
func observeRoots(ctx context.Context, hostPort, host, port string, pool *x509.CertPool) ([]observedRoot, error) {
	if port == "" {
		hostPort = net.JoinHostPort(host, "443")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: initDialTimeout},
		Config:    &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: host},
	}
	dctx, cancel := context.WithTimeout(ctx, initDialTimeout)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", hostPort)
	if err != nil {
		// A handshake error repeats names from the peer's certificates,
		// which an attacker chooses: ConnectError never prints them.
		return nil, fmt.Errorf("connect to %s: %w", hostPort, serverclient.ConnectError(host, err, errInitUntrusted))
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("not a TLS connection")
	}
	var out []observedRoot
	for _, chain := range tc.ConnectionState().VerifiedChains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		pin := serverclient.PinOf(root)
		if !slices.ContainsFunc(out, func(r observedRoot) bool { return r.pin == pin }) {
			out = append(out, observedRoot{cert: root, pin: pin})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s presented no verified chain", hostPort)
	}
	return out, nil
}

// printTrustSummary prints what init verified, from the root-signed
// bundle: its version, the roots, each online key with its custody, and
// the policy's relying party.
func printTrustSummary(w io.Writer, b *trust.Bundle, p *trust.Policy) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "trust bundle version %d, policy version %d (verified against your root pins)\n", b.Version, p.Version)
	for _, r := range b.Root.Keys {
		fp, err := keyFP(r.Key)
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "root %s (custody %s)\n", fp, r.Custody)
	}
	for _, ca := range b.CAs {
		fp, err := keyFP(ca.Key)
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s CA %s (custody %s, %s)\n", ca.Role, fp, ca.Custody, ca.State)
	}
	for _, k := range []struct{ name, key, custody string }{{"ops", b.OpsKey.Key, b.OpsKey.Custody}, {"log", b.Log.Key, b.Log.Custody}} {
		fp, err := keyFP(k.key)
		if err != nil {
			return err
		}
		fmt.Fprintf(&sb, "%s key %s (custody %s)\n", k.name, fp, k.custody)
	}
	if p.WebAuthn != nil {
		fmt.Fprintf(&sb, "WebAuthn RP %s\n", p.WebAuthn.RPID)
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

func keyFP(key string) (string, error) {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(pub), nil
}
