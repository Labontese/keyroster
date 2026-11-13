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
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
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
	installationID := fs.String("installation-id", "", "the installation ID the request is for: 32 lowercase hex digits from the installation id line of your ceremony transcript, keyroster init or keyroster trust verify; required when the signer's trust bundle names one, and never copied from the signer")
	var principals, adminKeys, extensions stringList
	fs.Var(&principals, "principal", "principal to certify (repeatable, at least one)")
	fs.Var(&adminKeys, "admin-key", "SHA256 fingerprint of an admin key in ssh-agent (SSH_AUTH_SOCK) that signs the request (repeatable, at least one; the policy's admin quorum decides how many)")
	fs.Var(&extensions, "extension", "certificate extension to request on top of the CA's defaults, if its policy profile allows it (repeatable)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *pubkeyPath == "" || *subject == "" || len(principals) == 0 || len(adminKeys) == 0 {
		_, _ = fmt.Fprintln(stderr, "ca issue: --pubkey, --subject, at least one --principal and at least one --admin-key are required")
		return errUsage
	}
	// The installation comes only from the flag, never from the signer or
	// a CLI config (03-14d, F15; owner decision OQ-1 = A).
	if *installationID != "" && !trust.IsInstallationID(*installationID) {
		_, _ = fmt.Fprintln(stderr, "ca issue: --installation-id wants 32 lowercase hex digits")
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
	// Custody comes only from the signer (D-18): ask it before issuing,
	// and never issue without knowing it.
	if err := warnCustody(ctx, *socket, stderr); err != nil {
		return err
	}
	req := &wire.IssueRequest{
		InstallationID:  *installationID,
		CARole:          role,
		SubjectKey:      pub.Marshal(),
		Subject:         *subject,
		Principals:      principals,
		ValidForSeconds: uint32(*ttl / time.Second), //nolint:gosec // G115: bounded by math.MaxUint32 above
		CreatedAt:       uint64(time.Now().Unix()),  //nolint:gosec // G115: the clock is after 1970
		Extensions:      extensions,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return fmt.Errorf("request id: %w", err)
	}
	evidence, err := adminEvidence(req.SigningBytes(), req.Namespace(), adminKeys)
	if err != nil {
		return err
	}
	req.Evidence = evidence

	resp, err := signerclient.Issue(ctx, *socket, req)
	if err != nil {
		return issueInstallationHint(err, *installationID != "")
	}
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		// x/crypto's text repeats the algorithm name the signer chose.
		return &ownWordsError{msg: "signer returned a certificate that does not parse; nothing was written", cause: err}
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return errors.New("signer returned a key, not a certificate")
	}
	if !bytes.Equal(c.Key.Marshal(), pub.Marshal()) || c.Serial != resp.Serial {
		return errors.New("signer returned a certificate for another key or serial")
	}
	// The key ID is printed below: it must be a keyroster key ID, whose
	// charset carries no control character, space or padding.
	if _, err := cert.ParseKeyID(c.KeyId); err != nil {
		return errors.New("signer returned a certificate whose key ID is not a keyroster key ID; nothing was written")
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

// issueInstallationHints are ca issue's hints on the signer's installation
// refusals (03-14d, F15).
var issueInstallationHints = map[string]string{
	"issue_installation_missing":  "the signer's trust bundle names an installation ID, so the request must name it: pass --installation-id",
	"issue_installation_mismatch": "--installation-id names another installation than the signer at --socket serves",
	"issue_installation_unknown": "this signer says its trust bundle names no installation ID; " +
		"leave out --installation-id only after keyroster trust verify shows installation id: none for the installation you mean to approve",
}

// issueOlderSignerHint is ca issue's hint on malformed_request when
// --installation-id was set: a signer older than 03-14d refuses any byte
// after the evidence, so it refuses a v2 body that way (reasoned from its
// parser; UNVERIFIED against a real older signer).
const issueOlderSignerHint = "a signer older than this keyroster does not read the installation ID: " +
	"upgrade the signer, or leave out --installation-id only if its trust bundle names no installation"

// issueInstallationHint returns err with a hint when it is one of the
// signer's installation refusals, or malformed_request while flagSet
// (--installation-id was given). It keeps the signer's own text, which is
// a reason code (wire.ValidMessage), and ends with "nothing was issued".
// Any other error is returned unchanged (03-14d, F15).
func issueInstallationHint(err error, flagSet bool) error {
	var er *wire.ErrorResponse
	if !errors.As(err, &er) {
		return err
	}
	hint, ok := issueInstallationHints[er.Message]
	if er.Message == "malformed_request" && flagSet {
		hint, ok = issueOlderSignerHint, true
	}
	if !ok {
		return err
	}
	return fmt.Errorf("%w: %s; nothing was issued", err, hint)
}

// ownWordsError states a failure only in the CLI's own words: its Error
// never includes the cause's text, which the signer may have chosen.
// Unwrap returns the cause, for errors.Is and errors.As.
type ownWordsError struct {
	msg   string
	cause error
}

func (e *ownWordsError) Error() string { return e.msg }
func (e *ownWordsError) Unwrap() error { return e.cause }

// bannerFrame is the line printed above and below a custody warning.
var bannerFrame = strings.Repeat("!", 76)

// warnCustody asks the signer at socket for its Status and, when the
// signer reports any key with custody software, writes the evaluation-only
// banner to stderr as its own block, framed by lines of '!'. No flag,
// environment variable or configuration suppresses it. A Status failure
// is an error: the caller must not issue without knowing custody.
func warnCustody(ctx context.Context, socket string, stderr io.Writer) error {
	st, err := signerclient.Status(ctx, socket)
	if err != nil {
		return fmt.Errorf("signer status (custody must be known before issuing): %w", err)
	}
	if roles := custodytext.SoftwareRoles(st.Keys); len(roles) > 0 {
		_, _ = fmt.Fprintf(stderr, "%s\n%s\n%s\n", bannerFrame, custodytext.SoftwareCABanner(roles), bannerFrame)
	}
	return nil
}

// adminEvidence signs msg, a request's signing bytes, with each named admin
// key from the ssh-agent at SSH_AUTH_SOCK, as admin-sshsig/v1 evidence
// under namespace: the request's own for ca issue (D-13; 03-14d, F15:
// keyroster/issue-request/v2 with --installation-id,
// keyroster/issue-request/v1 without),
// keyroster/host-forget-request/v1 for host forget (03-08c). The signer
// checks the signatures against the admins in its root-signed policy.
func adminEvidence(msg []byte, namespace string, fingerprints []string) ([]wire.Evidence, error) {
	if len(fingerprints) > wire.MaxEvidence {
		return nil, fmt.Errorf("at most %d --admin-key values", wire.MaxEvidence)
	}
	conn, err := dialAgent()
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		return nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	out := make([]wire.Evidence, 0, len(fingerprints))
	for _, fp := range fingerprints {
		if !strings.HasPrefix(fp, "SHA256:") {
			return nil, fmt.Errorf("--admin-key %q: want a SHA256:... fingerprint", fp)
		}
		var s ssh.Signer
		for _, c := range signers {
			if ssh.FingerprintSHA256(c.PublicKey()) == fp && !strings.HasSuffix(c.PublicKey().Type(), "-cert-v01@openssh.com") {
				s = c
				break
			}
		}
		if s == nil {
			return nil, fmt.Errorf("ssh-agent does not hold the admin key %s", fp)
		}
		sig, err := sshsig.Sign(rand.Reader, s, namespace, msg)
		if err != nil {
			return nil, fmt.Errorf("sign the request with %s: %w", fp, err)
		}
		out = append(out, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return out, nil
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
