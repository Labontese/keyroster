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

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
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
// next KRL. Hosts enforce the revocation only once they have that KRL; the
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
	if _, _, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold); err != nil {
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
	_, _ = fmt.Fprintf(stdout, "revoked serial %d (%s): KRL v%d published (log entries %d, %d)\n",
		serial, role, ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf)
	_, _ = fmt.Fprintln(stdout, "Hosts enforce it once their keyroster agent applies this KRL.")
	return nil
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
