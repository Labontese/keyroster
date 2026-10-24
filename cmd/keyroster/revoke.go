package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "revoke",
		Summary: "revoke an issued certificate (serial: by its serial and CA); the signer publishes a new KRL",
		Run:     runRevoke,
	})
}

func runRevoke(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "revoke: want a subcommand: serial")
		return errUsage
	}
	switch args[0] {
	case "serial":
		return runRevokeSerial(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "revoke: unknown subcommand %q; want serial\n", args[0])
		return errUsage
	}
}

// revokeCARoles maps --ca to the wire enum.
var revokeCARoles = map[string]wire.CARole{
	"user":    wire.CARoleUser,
	"host":    wire.CARoleHost,
	"machine": wire.CARoleMachine,
}

// runRevokeSerial is keyroster revoke serial SERIAL [--ca user|host|machine]
// [--reason TEXT] [--admin-key FP] (REVOKE-01, CLI only per D-12). It
// verifies the served trust bundle against the saved root pins, builds a
// RevokeRequest with a fresh random request ID and the current time, signs
// its signing bytes with the admin key in ssh-agent under
// keyroster/revoke-request/v1, and sends it through the admin API. The
// server forwards it to the signer, which alone decides and publishes the
// next KRL. The server's answer is unsigned, so the command reports it as
// the server's and confirms it against the signer-signed KRL manifest the
// server then serves (confirmRevokeAnswer); it exits non-zero when that
// fails. Hosts enforce the revocation only once they have that KRL; the
// command never claims they already refuse the certificate.
func runRevokeSerial(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke serial", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ca := fset.String("ca", "user", "the CA that issued the certificate: user, host or machine")
	reason := fset.String("reason", "", "a short reason, printable ASCII, recorded in the audit log (at most 256 bytes)")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "revoke serial: want SERIAL")
		return errUsage
	}
	serial, err := strconv.ParseUint(pos[0], 10, 64)
	if err != nil || serial == 0 {
		_, _ = fmt.Fprintf(stderr, "revoke serial: %q is not a certificate serial (a decimal number above 0)\n", pos[0])
		return errUsage
	}
	role, ok := revokeCARoles[*ca]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "revoke serial: --ca %q: want user, host or machine\n", *ca)
		return errUsage
	}
	req := &wire.RevokeRequest{
		Target:    wire.TargetSerial,
		CARole:    role,
		Serial:    serial,
		CreatedAt: uint64(max(time.Now().Unix(), 0)), //nolint:gosec // G115: >= 0
		Reason:    *reason,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return err
	}
	// Marshal checks every field limit (the reason's charset and length)
	// before the admin key signs anything.
	if _, err := req.Marshal(); err != nil {
		_, _ = fmt.Fprintf(stderr, "revoke serial: %v\n", err)
		return errUsage
	}

	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	bundle, _, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return err
	}
	sig, err := sshsig.Sign(rand.Reader, s.signer, wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		return fmt.Errorf("sign the revocation with %s: %w", s.adminFP, err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	body, err := req.Marshal()
	if err != nil {
		return err
	}
	var ans serverclient.RevokeAnswer
	if err := s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminRevokePath, serverclient.RevokeBody{Request: body}, &ans, s.signer); err != nil {
		return revokeRefusal(err)
	}
	m, err := confirmRevokeAnswer(ctx, s.client, bundle, ans)
	if err != nil {
		// The CLI's own advice stays out of an error that may carry a
		// PeerError excerpt.
		_, _ = fmt.Fprintln(stderr, "On the signer host, journalctl -u keyroster-signer shows a \"revoked\" line with the serial if the signer revoked it.")
		return fmt.Errorf("the server reports serial %d revoked, but that could not be confirmed: %w", serial, err)
	}
	_, _ = fmt.Fprintf(stdout, "The server reports serial %d (%s) revoked: KRL v%d published (log entries %d, %d).\n",
		serial, role, ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf)
	_, _ = fmt.Fprintf(stdout, "Checked: the server serves KRL v%d, signed by the ops key of your root-pinned trust bundle (log entry %d).\n"+
		"Not checked: that this KRL lists serial %d (this version cannot read a KRL); "+
		"the signer's \"revoked\" line (journalctl -u keyroster-signer) is the proof.\n",
		m.KRLVersion, m.LogIndex, serial)
	_, _ = fmt.Fprintln(stdout, "Hosts enforce it once their keyroster agent applies this KRL.")
	return nil
}

// confirmRevokeAnswer checks the server's answer to a revocation against
// what the signer signed. The answer itself is unsigned: a server could
// drop the request and invent it. The revoke and krl_publish leaves are
// adjacent and a KRL version is at least 1; the KRL the server then serves
// must verify against the root-pinned bundle and its installation ID
// (krl.VerifyManifest) with a version of at least the answer's and a
// krl_publish leaf of at least the answer's. A server that dropped the
// request cannot show a manifest the signer never signed; it can still
// show an earlier genuine one under an invented answer of that version,
// which only reading the KRL for the serial would catch.
func confirmRevokeAnswer(ctx context.Context, c *serverclient.Client, b *trust.Bundle, ans serverclient.RevokeAnswer) (*krl.Manifest, error) {
	if ans.KRLVersion < 1 || ans.PublishLeaf != ans.RevokeLeaf+1 {
		return nil, fmt.Errorf("its answer (KRL v%d, log entries %d, %d) is not one the signer gives", ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf)
	}
	doc, err := c.GetKRL(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the published KRL: %w", err)
	}
	if doc == nil {
		return nil, errors.New("the server serves no KRL")
	}
	m, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, b, b.InstallationID, ans.KRLVersion-1)
	if err != nil {
		return nil, fmt.Errorf("the KRL the server serves does not verify against your root-pinned trust bundle: %w", serverclient.PeerError(err))
	}
	if m.LogIndex < ans.PublishLeaf {
		return nil, fmt.Errorf("the KRL the server serves (v%d) was published at log entry %d, before the reported entry %d", m.KRLVersion, m.LogIndex, ans.PublishLeaf)
	}
	return m, nil
}

// revokeRefusal states a refused revocation in the CLI's own words for the
// refusals an admin can act on, and otherwise returns err.
func revokeRefusal(err error) error {
	var he *serverclient.HTTPError
	switch {
	case errors.As(err, &he) && he.APIErrorIs("unknown_serial"):
		return errors.New("the signer has issued no certificate with this serial; nothing was revoked (revocation by key, for a certificate this signer did not issue, arrives in a later version)")
	case errors.As(err, &he) && he.APIErrorIs("ca_role_mismatch"):
		return errors.New("the certificate with this serial was not issued by that CA; pass the right --ca; nothing was revoked")
	case errors.As(err, &he) && he.APIErrorIs("duplicate_request"):
		return errors.New("the signer has already accepted a request with this ID; run the command again; nothing new was revoked")
	case errors.As(err, &he) && he.Code == http.StatusForbidden:
		return fmt.Errorf("the signer refused the revocation (is --admin-key a policy admin?): %w", err)
	case errors.Is(err, serverclient.ErrSignerUnavailable):
		return fmt.Errorf("%w; the revocation may not have been recorded. The signer's log names the reason (krl_no_installation_id: the trust bundle in force has no installation ID; krl_too_large: see docs/runbooks/revoke.md)", err)
	}
	return err
}
