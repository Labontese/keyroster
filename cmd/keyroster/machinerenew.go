package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// machineRenewBeforeRename runs between the write of the temporary
// certificate file and its rename over CERTFILE. Tests set it to inject a
// fault there; it is nil otherwise.
var machineRenewBeforeRename func() error

// runMachineRenew is keyroster machine renew NAME --key FILE --out CERTFILE
// (03-11b, D-15, D-04): an automation host renews its own machine
// certificate by proof of possession of its key. It signs the request
// locally, so the private key is never sent and never written; it checks
// the server's answer against the root-verified trust bundle and writes
// only the certificate, by temporary file and rename. No admin key and no
// user are needed: keyroster init without --user is enough. Exit 0 when
// the certificate is written, 1 on any refusal or failure, 2 for usage
// (b-C8).
func runMachineRenew(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("machine renew", flag.ContinueOnError)
	fset.SetOutput(stderr)
	keyFile := fset.String("key", "", "the machine's private key file (an unencrypted Ed25519 key)")
	out := fset.String("out", "", "where to write the certificate (required)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "machine renew", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("machine", name)
	}
	if *keyFile == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "machine renew: --key and --out are required")
		return errUsage
	}
	if err := checkOutNotKey(*out, *keyFile); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := checkInviteConfig(cfg); err != nil {
		return err
	}
	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	bundle, pol, err := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold)
	if err != nil {
		return err
	}
	if pol.PoP == nil || !pol.PoP.Machines {
		return errors.New("the root-signed policy does not allow machine renewal (pop.machines); nothing was sent")
	}
	if _, err := machineCap(pol); err != nil {
		return err
	}
	if bundle.InstallationID == "" {
		return errors.New("the trust bundle has no installation ID; machine renewal needs one; nothing was sent")
	}
	data, err := readMachineKeyFile(*keyFile)
	if err != nil {
		return err
	}
	defer clear(data)
	signer, wipe, err := machineFileSigner(*keyFile, data)
	if err != nil {
		return err
	}
	defer wipe()
	req, raw, err := machineRenewRequest(bundle.InstallationID, name, signer)
	if err != nil {
		return err
	}
	ans, err := client.MachineRenew(ctx, &serverclient.MachineRenewRequest{Request: raw})
	if err != nil {
		if errors.Is(err, serverclient.ErrSignerUnavailable) {
			return err
		}
		return fmt.Errorf("the server refused the renewal: %w", err)
	}
	c, err := checkMachineCertificate(ans.Certificate, req, bundle, name)
	if err != nil {
		serial := "unknown"
		if pk, perr := ssh.ParsePublicKey(ans.Certificate); perr == nil {
			if pc, ok := pk.(*ssh.Certificate); ok {
				serial = fmt.Sprint(pc.Serial)
			}
		}
		return fmt.Errorf("the signer issued a certificate (serial %s), but this CLI refused it: %w; nothing was written. "+
			"The issuance counts toward the machine's 12 renewals per hour", serial, err)
	}
	if err := writeMachineCert(*out, c); err != nil {
		return err
	}
	return printMachineRenewed(stdout, name, *out, c)
}

// machineRenewRequest builds and signs the request: the bundle's
// installation ID, NAME, the signer's public key, a fresh request ID, the
// local clock, and the machine-pop/v1 proof of possession over the signing
// bytes.
func machineRenewRequest(installation, name string, signer ssh.Signer) (*wire.MachineIssueRequest, []byte, error) {
	req := &wire.MachineIssueRequest{
		InstallationID: installation,
		MachineName:    name,
		MachineKey:     signer.PublicKey().Marshal(),
		CreatedAt:      uint64(max(time.Now().Unix(), 0)), //nolint:gosec // G115: >= 0
	}
	for req.RequestID == [16]byte{} {
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			return nil, nil, err
		}
	}
	pop, err := sshsig.Sign(rand.Reader, signer, wire.MachinePoPNamespace, req.SigningBytes())
	if err != nil {
		return nil, nil, fmt.Errorf("sign the proof of possession: %w", err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: pop}}
	if err := req.Validate(); err != nil {
		return nil, nil, err
	}
	raw, err := req.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return req, raw, nil
}

// machineCAKeys returns the machine CA keys of the verified bundle that
// hosts trust, those in state active or next (b-C3); never a retired one,
// so not krl.RoleCAKeys, which returns every state.
func machineCAKeys(b *trust.Bundle) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, ca := range b.CAs {
		if ca.Role != trust.RoleMachine || (ca.State != "active" && ca.State != "next") {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pub)
	}
	return keys, nil
}

// checkMachineCertificate checks the server's answer against the
// root-verified bundle and this request (03-11b), each by its own explicit
// test, because x/crypto's CertChecker.CheckCert never calls
// IsUserAuthority and never looks at the certificate type: the signature
// key is an active or next machine CA key of the bundle; it is a user
// certificate; it has principals, and its signature and window verify; it
// is for the request's key; its key ID is kr3 for the machine CA, NAME and
// this request's ID.
func checkMachineCertificate(blob []byte, req *wire.MachineIssueRequest, b *trust.Bundle, name string) (*ssh.Certificate, error) {
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, errors.New("it does not parse")
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("it is not a certificate")
	}
	cas, err := machineCAKeys(b)
	if err != nil {
		return nil, err
	}
	signedByCA := false
	for _, ca := range cas {
		if bytes.Equal(c.SignatureKey.Marshal(), ca.Marshal()) {
			signedByCA = true
		}
	}
	if !signedByCA {
		return nil, errors.New("it is not signed by an active or next machine CA key of your root-signed trust bundle")
	}
	if c.CertType != ssh.UserCert {
		return nil, errors.New("it is not a user certificate")
	}
	if len(c.ValidPrincipals) == 0 {
		return nil, errors.New("it has no principals")
	}
	issuedAt := time.Unix(int64(min(c.ValidAfter, 1<<62))+int64(certBackdate), 0) //nolint:gosec // G115: bounded
	checker := ssh.CertChecker{Clock: func() time.Time { return issuedAt }}
	if err := checker.CheckCert(c.ValidPrincipals[0], c); err != nil {
		return nil, errors.New("its CA signature or validity does not verify")
	}
	if !bytes.Equal(c.Key.Marshal(), req.MachineKey) {
		return nil, errors.New("it is for another key")
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || !kid.V3 || kid.CA != wire.CARoleMachine.String() || kid.Subject != name || kid.Request != hex.EncodeToString(req.RequestID[:]) {
		return nil, errors.New("its key ID does not name this machine and request")
	}
	return c, nil
}

// checkOutNotKey refuses --out naming the key file, by path or as the
// same file (b-C6), before anything is sent.
func checkOutNotKey(out, key string) error {
	errSame := errors.New("--out names the key file; refusing to overwrite a private key")
	ao, err1 := filepath.Abs(out)
	ak, err2 := filepath.Abs(key)
	if err1 == nil && err2 == nil && filepath.Clean(ao) == filepath.Clean(ak) {
		return errSame
	}
	fo, err := os.Stat(out)
	if err != nil {
		return nil //nolint:nilerr // CERTFILE does not exist yet: it cannot be the key file
	}
	if fk, err := os.Stat(key); err == nil && os.SameFile(fo, fk) {
		return errSame
	}
	return nil
}

// writeMachineCert writes c to out in authorized-key form, by a temporary
// file in out's directory and a rename, so an existing CERTFILE is either
// the old certificate or the new one, never a partial write. The private
// key is never written.
func writeMachineCert(out string, c *ssh.Certificate) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(out), ".keyroster-cert-*")
	if err != nil {
		return fmt.Errorf("write the certificate: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(ssh.MarshalAuthorizedKey(c)); err != nil {
		return fmt.Errorf("write the certificate: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("write the certificate: %w", err)
	}
	if err = tmp.Chmod(0o644); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return fmt.Errorf("write the certificate: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("write the certificate: %w", err)
	}
	if machineRenewBeforeRename != nil {
		if err = machineRenewBeforeRename(); err != nil {
			return fmt.Errorf("write the certificate: %w", err)
		}
	}
	if err = os.Rename(tmp.Name(), out); err != nil {
		return fmt.Errorf("write the certificate: %w", err)
	}
	return nil
}

// printMachineRenewed prints the summary of a written certificate.
func printMachineRenewed(stdout io.Writer, name, out string, c *ssh.Certificate) error {
	lifetime := time.Duration(c.ValidBefore-c.ValidAfter-certBackdate) * time.Second //nolint:gosec // G115: checked window
	_, err := fmt.Fprintf(stdout, "machine certificate for %s written to %s\n"+
		"  serial:      %d\n  valid until: %s\n  lifetime:    %s\n  principals:  %s\n  CA:          %s\n  key:         %s\n"+
		"The principals are the signer's choice from the machine's roles; they are not checked against the directory except by --expect-principal.\n",
		name, out, c.Serial, time.Unix(int64(min(c.ValidBefore, 1<<62)), 0).UTC().Format(time.RFC3339), lifetime, //nolint:gosec // G115: bounded
		strings.Join(c.ValidPrincipals, ", "), ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(c.Key))
	return err
}
