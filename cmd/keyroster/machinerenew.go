package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

const (
	// machineBackdate is how far before the issuance second cert.Build puts
	// ValidAfter, the same 300 s as the host agent's (03-11b); the tests
	// prove it by building their certificates with cert.Build.
	machineBackdate = 300
	// machineSkew is how far after the request's CreatedAt the CLI accepts
	// the issuance second: the signer accepts CreatedAt within 300 s of its
	// clock, plus a minute for the round trip.
	machineSkew = 360
	// machineMinLifetime is the shortest lifetime the CLI accepts.
	machineMinLifetime = 60
	// maxMachineCertFileBytes bounds the CERTFILE --if-due reads.
	maxMachineCertFileBytes = 64 << 10
)

// machineRenewBeforeRename runs between the write of the temporary
// certificate file and its rename over CERTFILE. Tests set it to inject a
// fault there; it is nil otherwise.
var machineRenewBeforeRename func() error

// machineRenewTimeNow is the clock of machine renew (tests replace it).
var machineRenewTimeNow = time.Now

// runMachineRenew is keyroster machine renew NAME (--agent-key FP | --key
// FILE [--passphrase-fd N]) --out CERTFILE [--expect-principal P]...
// [--if-due] (03-11b, D-15, D-04): an automation host renews its own
// machine certificate by proof of possession of its key. It signs the
// request locally, so the private key is never sent and never written; it
// checks the server's answer against the root-verified trust bundle and
// writes only the certificate, by temporary file and rename. No admin key
// and no user are needed: keyroster init without --user is enough. Exit 0
// when the certificate is written or not due, 1 on any refusal or
// failure, 2 for usage (b-C8).
func runMachineRenew(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("machine renew", flag.ContinueOnError)
	fset.SetOutput(stderr)
	keyFile := fset.String("key", "", "the machine's private key file (Ed25519 or ECDSA, plain or encrypted)")
	agentKey := fset.String("agent-key", "", "the SHA256 fingerprint of the machine key in ssh-agent")
	passFD := fset.Int("passphrase-fd", -1, "read the key file's passphrase from this inherited file descriptor (needs --key)")
	out := fset.String("out", "", "where to write the certificate (required)")
	var expect stringList
	fset.Var(&expect, "expect-principal", "a principal the certificate must carry (repeatable)")
	ifDue := fset.Bool("if-due", false, "renew only when CERTFILE is missing, for another key, name or CA, or due")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "machine renew", pos)
	if err != nil {
		return err
	}
	switch {
	case (*keyFile == "") == (*agentKey == ""):
		_, _ = fmt.Fprintln(stderr, "machine renew: exactly one of --key and --agent-key is required")
		return errUsage
	case *passFD != -1 && *keyFile == "":
		_, _ = fmt.Fprintln(stderr, "machine renew: --passphrase-fd needs --key")
		return errUsage
	case *out == "":
		_, _ = fmt.Fprintln(stderr, "machine renew: --out is required")
		return errUsage
	}
	if !directory.ValidUserName(name) {
		return errHostName("machine", name)
	}
	if *keyFile != "" {
		if err := checkOutNotKey(*out, *keyFile); err != nil {
			return err
		}
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
	maxTTL, err := machineCap(pol)
	if err != nil {
		return err
	}
	if bundle.InstallationID == "" {
		return errors.New("the trust bundle has no installation ID; machine renewal needs one; nothing was sent")
	}

	// The signer: an agent key, or a key file whose secrets are cleared
	// after the signing.
	var (
		signer ssh.Signer
		pub    ssh.PublicKey
		data   []byte
		mk     *machineKey
	)
	if *agentKey != "" {
		s, closeAgent, err := machineAgentSigner(*agentKey)
		if err != nil {
			return err
		}
		defer closeAgent()
		signer, pub = s, s.PublicKey()
	} else {
		if data, err = readMachineKeyFile(*keyFile); err != nil {
			return err
		}
		defer func() {
			if mk != nil {
				mk.wipe(data)
			} else {
				clear(data)
			}
		}()
		pub = machineKeyHeaderPub(data)
	}
	if *ifDue {
		if pub == nil {
			// No clear public key: parse the key as a renewal would.
			if mk, err = parseMachineKey(data, *keyFile, *passFD); err != nil {
				return err
			}
			pub = mk.signer.PublicKey()
		}
		if due, current := machineCertCurrent(*out, pub, name, bundle, maxTTL); current {
			_, err := fmt.Fprintf(stdout, "not due: %s renews from %s; nothing was sent\n", *out, time.Unix(int64(min(due, 1<<62)), 0).UTC().Format(time.RFC3339)) //nolint:gosec // G115: bounded
			return err
		}
	}
	if signer == nil {
		if mk == nil {
			if mk, err = parseMachineKey(data, *keyFile, *passFD); err != nil {
				return err
			}
		}
		signer = mk.signer
	}
	req, raw, err := machineRenewRequest(bundle.InstallationID, name, signer)
	if err != nil {
		return err
	}
	ans, err := client.MachineRenew(ctx, &serverclient.MachineRenewRequest{Request: raw})
	if err != nil {
		return machineRenewRefusal(err)
	}
	c, err := checkMachineCertificate(ans.Certificate, req, bundle, pol, name, expect)
	if err != nil {
		serial := "unknown"
		if pk, perr := ssh.ParsePublicKey(ans.Certificate); perr == nil {
			if pc, ok := pk.(*ssh.Certificate); ok {
				serial = fmt.Sprint(pc.Serial)
			}
		}
		return fmt.Errorf("the server's answer was issued but refused by this CLI's check (%w); nothing was written. "+
			"The signer logged the issuance (serial %s) and it counts toward the 12 per hour for this key", err, serial)
	}
	if err := writeMachineCert(*out, c); err != nil {
		return err
	}
	return printMachineRenewed(stdout, name, *out, c)
}

// machineAgentSigner returns the ssh-agent signer of the key whose SHA256
// fingerprint is fp (certificates are skipped). An sk key in the agent
// asks for a touch at the signing step. A Windows named pipe is UNVERIFIED:
// the tests replace dialAgent.
func machineAgentSigner(fp string) (ssh.Signer, func(), error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil, err
	}
	keys, err := agent.NewClient(conn).List()
	_ = conn.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			continue
		}
		if _, isCert := pub.(*ssh.Certificate); isCert || ssh.FingerprintSHA256(pub) != fp {
			continue
		}
		return agentSigner(pub)
	}
	return nil, nil, fmt.Errorf("ssh-agent does not hold the machine key %s; load it with ssh-add; nothing was sent", fp)
}

// machineRenewRefusals are the CLI's words for each detail the renew route
// answers, matched by detail whatever the HTTP status (03-11b).
var machineRenewRefusals = map[string]string{
	serverclient.MachineErrNotAuthenticated: "the server does not authenticate this renewal (machine_not_authenticated): the machine name is unknown, " +
		"the key is not the one the directory lists for it, or the signature did not verify; the server does not say which, and its log does; nothing was issued",
	serverclient.MachineErrPoPNotEnabled: "the policy in force does not allow machine renewal (machine_pop_not_enabled, pop.machines is off); nothing was issued",
	"request_time_skew":                  "this host's clock differs from the signer's by more than 5 minutes (request_time_skew); fix the clock and run again; nothing was issued",
	"machine_issue_installation_mismatch": "the server's signer belongs to another installation than the trust bundle your root pins verify (machine_issue_installation_mismatch); " +
		"check the server URL and the root pins that keyroster init saved; nothing was issued",
	"machine_issue_no_installation_id": "the signer's trust bundle has no installation ID, or the request lost its own (machine_issue_no_installation_id); " +
		"check the server URL and the root pins that keyroster init saved; nothing was issued",
	"directory_not_installed":           "the signer holds no usable directory (directory_not_installed); ask an admin to install one; nothing was issued",
	"directory_not_authorized":          "the signer holds no usable directory (directory_not_authorized); ask an admin to install one; nothing was issued",
	"machine_name_reserved":             "machine names starting with probe. are reserved (machine_name_reserved); nothing was issued",
	"machine_key_revoked":               "this key is revoked for good (machine_key_revoked); an admin must list a new key under a new name; nothing was issued",
	"cert_revoked":                      "a revocation holds this machine until the admins install a newer directory version (cert_revoked); ask an admin; nothing was issued",
	"machine_disabled":                  "the directory lists this machine as disabled (machine_disabled); ask an admin; nothing was issued",
	"machine_key_unusable":              "the key listed for this machine is a key of this installation's trust bundle and never gets a machine certificate (machine_key_unusable); nothing was issued",
	"machine_issue_valid_for_not_zero":  "the request did not reach the signer unchanged (machine_issue_valid_for_not_zero): this CLI always sends 0; nothing was issued",
	"bad_principal":                     "the installation cannot issue this certificate (bad_principal); ask an admin; nothing was issued",
	"ca_not_configured":                 "the installation cannot issue this certificate (ca_not_configured); ask an admin; nothing was issued",
	"duplicate_request":                 "the signer already accepted a request with this ID (duplicate_request); run the command again",
	"machine_renew_too_often":           "12 certificates were issued for this key in the last hour (machine_renew_too_often); refused attempts do not count; wait and run again",
	serverclient.MachineErrSignerTooOld: "the signer predates machine certificates (signer_too_old); upgrade keyroster-signer, then keyroster-server; nothing was issued",
}

// machineRenewRefusal states a failed renewal in the CLI's own words; any
// other detail is the server's peer text, cut, with no advice.
func machineRenewRefusal(err error) error {
	var he *serverclient.HTTPError
	if errors.As(err, &he) {
		for detail, text := range machineRenewRefusals {
			if he.APIErrorIs(detail) {
				return errors.New(text)
			}
		}
		if secs, ok := he.RateLimited(); ok {
			return fmt.Errorf("the server rate limited this renewal; run it again after %d seconds", secs)
		}
	}
	if errors.Is(err, serverclient.ErrSignerUnavailable) {
		return errors.New("the server cannot reach its signer (HTTP 503); the outcome is unknown: if the certificate was issued, a retry costs one of the 12 per hour for this key")
	}
	return fmt.Errorf("the server refused the renewal: %w", err)
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
		CreatedAt:      uint64(max(machineRenewTimeNow().Unix(), 0)), //nolint:gosec // G115: >= 0
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

// signedByMachineCA reports whether c's signature key is an active or next
// machine CA key of b.
func signedByMachineCA(c *ssh.Certificate, b *trust.Bundle) (bool, error) {
	cas, err := machineCAKeys(b)
	if err != nil {
		return false, err
	}
	for _, ca := range cas {
		if bytes.Equal(c.SignatureKey.Marshal(), ca.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}

// machineLifetime is L = ValidBefore - (ValidAfter + machineBackdate), or
// 0 when the window is shorter than the backdate.
func machineLifetime(c *ssh.Certificate) uint64 {
	if c.ValidAfter > c.ValidBefore || c.ValidBefore-c.ValidAfter < machineBackdate {
		return 0
	}
	return c.ValidBefore - c.ValidAfter - machineBackdate
}

// checkMachineCertificate checks the server's answer against the
// root-verified bundle and policy and this request (03-11b, T-03-408),
// each by its own explicit test, because x/crypto's CertChecker.CheckCert
// never calls IsUserAuthority and never looks at the certificate type: the
// signature key is an active or next machine CA key of the bundle; it is a
// user certificate; it has principals and no critical option, and its
// signature and window verify; it is for the request's key; its key ID is
// kr3 for the machine CA, NAME, this request's ID and the verified
// policy's version; its issuance is within the request's window; its
// lifetime is 60 s to the machine cap; its extensions are the machine
// profile's; every expected principal is present. Principals are otherwise
// not checked: the CLI holds no signed directory.
func checkMachineCertificate(blob []byte, req *wire.MachineIssueRequest, b *trust.Bundle, pol *trust.Policy, name string, expect []string) (*ssh.Certificate, error) {
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, errors.New("it does not parse")
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("it is not a certificate")
	}
	signedByCA, err := signedByMachineCA(c, b)
	if err != nil {
		return nil, err
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
	// Checked here, before CertChecker refuses them with a vaguer text.
	if len(c.CriticalOptions) != 0 {
		return nil, errors.New("it carries critical options, which a machine certificate never has")
	}
	issuedAt := time.Unix(int64(min(c.ValidAfter, 1<<62))+machineBackdate, 0) //nolint:gosec // G115: bounded
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
	if kid.Policy != pol.Version {
		return nil, fmt.Errorf("its key ID names policy v%d, but the verified policy is v%d: the policy changed while renewing; run again", kid.Policy, pol.Version)
	}
	if c.ValidAfter+machineBackdate+machineBackdate < req.CreatedAt || c.ValidAfter+machineBackdate > req.CreatedAt+machineSkew {
		return nil, errors.New("its validity does not start at this request's time")
	}
	maxTTL, err := machineCap(pol)
	if err != nil {
		return nil, err
	}
	if l := machineLifetime(c); l < machineMinLifetime || l > maxTTL {
		return nil, fmt.Errorf("its lifetime of %d s is outside 60 s to the machine cap of %d s", l, maxTTL)
	}
	i := slices.IndexFunc(pol.CAProfiles, func(p trust.CAProfile) bool { return p.Role == trust.RoleMachine })
	for e := range c.Extensions {
		if !slices.Contains(pol.CAProfiles[i].DefaultExtensions, e) && !slices.Contains(pol.CAProfiles[i].AllowedExtensions, e) {
			return nil, fmt.Errorf("it carries the extension %q, which the machine profile does not allow", e)
		}
	}
	for _, p := range expect {
		if !slices.Contains(c.ValidPrincipals, p) {
			return nil, fmt.Errorf("it lacks the expected principal %q", p)
		}
	}
	return c, nil
}

// machineDue is the renewal time of a certificate issued at issued with
// lifetime L (b-C5, PD7): issued + 2L/3 - j, where j is the first 8 bytes
// of digest read big-endian modulo m = min(3600, L/10), and 0 when m is 0.
// It keeps no state: every run computes the same time, and different
// certificates spread out (the host agent draws j once and stores it,
// internal/agent/hostcert; the CLI cannot).
func machineDue(issued, lifetime uint64, digest [32]byte) uint64 {
	m := min(3600, lifetime/10)
	var j uint64
	if m > 0 {
		j = binary.BigEndian.Uint64(digest[:8]) % m
	}
	return issued + 2*lifetime/3 - j
}

// machineCertDue is machineDue of c, whose digest is the SHA-256 of its
// wire bytes.
func machineCertDue(c *ssh.Certificate) uint64 {
	return machineDue(c.ValidAfter+machineBackdate, machineLifetime(c), sha256.Sum256(c.Marshal()))
}

// machineCertCurrent reports whether CERTFILE at path holds a certificate
// that --if-due keeps: a user certificate signed by an active or next
// machine CA key of the verified bundle, for pub, with kr3 subject name, a
// lifetime of 60 s to the cap, and now before its due time. A missing,
// unreadable, unparsable or expired file, or one for another key, name or
// CA, is due. It never reads the KRL.
func machineCertCurrent(path string, pub ssh.PublicKey, name string, b *trust.Bundle, maxTTL uint64) (due uint64, current bool) {
	f, err := os.Open(path) //nolint:gosec // G304: the CERTFILE the operator named
	if err != nil {
		return 0, false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxMachineCertFileBytes+1))
	_ = f.Close()
	if err != nil || len(data) > maxMachineCertFileBytes {
		return 0, false
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return 0, false
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok || c.CertType != ssh.UserCert || !bytes.Equal(c.Key.Marshal(), pub.Marshal()) {
		return 0, false
	}
	if signed, err := signedByMachineCA(c, b); err != nil || !signed {
		return 0, false
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || !kid.V3 || kid.CA != wire.CARoleMachine.String() || kid.Subject != name {
		return 0, false
	}
	if l := machineLifetime(c); l < machineMinLifetime || l > maxTTL {
		return 0, false
	}
	due = machineCertDue(c)
	now := uint64(max(machineRenewTimeNow().Unix(), 0)) //nolint:gosec // G115: >= 0
	return due, now < due && now < c.ValidBefore
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
	lifetime := time.Duration(machineLifetime(c)) * time.Second //nolint:gosec // G115: checked window
	_, err := fmt.Fprintf(stdout, "machine certificate for %s written to %s\n"+
		"  serial:      %d\n  valid until: %s\n  lifetime:    %s\n  principals:  %s\n  CA:          %s\n  key:         %s\n"+
		"The principals are the signer's choice from the machine's roles; they are not checked against the directory except by --expect-principal.\n",
		name, out, c.Serial, time.Unix(int64(min(c.ValidBefore, 1<<62)), 0).UTC().Format(time.RFC3339), lifetime, //nolint:gosec // G115: bounded
		strings.Join(c.ValidPrincipals, ", "), ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(c.Key))
	return err
}
