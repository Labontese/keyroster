package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "revoke",
		Summary: "revoke certificates (serial, key-id), a key (key), every certificate of a user (user), a host (host) or a machine (machine); the signer publishes a new KRL. recover: recover the revocations a signer restore lost (offline)",
		Run:     runRevoke,
	})
}

func runRevoke(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "revoke: want a subcommand: serial, key-id, key, user, host, machine or recover")
		return errUsage
	}
	switch args[0] {
	case "serial":
		return runRevokeSerial(ctx, args[1:], stdout, stderr)
	case "key-id":
		return runRevokeKeyID(ctx, args[1:], stdout, stderr)
	case "key":
		return runRevokeKey(ctx, args[1:], stdout, stderr)
	case "user":
		return runRevokeUser(ctx, args[1:], stdout, stderr)
	case "host":
		return runRevokeHost(ctx, args[1:], stdout, stderr)
	case "machine":
		return runRevokeMachine(ctx, args[1:], stdout, stderr)
	case "recover":
		// Offline (03-06b): no server call; see recover.go.
		return runRevokeRecover(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "revoke: unknown subcommand %q; want serial, key-id, key, user, host, machine or recover\n", args[0])
		return errUsage
	}
}

// revokeCARoles maps --ca to the wire enum.
var revokeCARoles = map[string]wire.CARole{
	"user":    wire.CARoleUser,
	"host":    wire.CARoleHost,
	"machine": wire.CARoleMachine,
}

// revokeFlags are the flags every revoke subcommand shares.
type revokeFlags struct {
	reason   *string
	adminKey *string
}

func addRevokeFlags(fset *flag.FlagSet) revokeFlags {
	return revokeFlags{
		reason:   fset.String("reason", "", "a short reason, printable ASCII, recorded in the audit log (at most 256 bytes)"),
		adminKey: fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)"),
	}
}

// placeholderInstallation stands in for the bundle's installation ID when
// a request is checked before the bundle is read: Validate refuses a
// request without one for every target but serial.
const placeholderInstallation = "00000000000000000000000000000000"

// checkRevokeRequest fills req's request ID, creation time and reason and
// checks every field limit (the reason's charset and length, the key ID,
// the key) before anything is sent or signed.
func checkRevokeRequest(req *wire.RevokeRequest, reason string) error {
	req.Reason = reason
	req.CreatedAt = uint64(max(time.Now().Unix(), 0)) //nolint:gosec // G115: >= 0
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return err
	}
	probe := *req
	probe.InstallationID = placeholderInstallation
	return probe.Validate()
}

// revocation is an admin session with the trust bundle verified against
// the saved root pins: every request it sends names that bundle's
// installation.
type revocation struct {
	s      *adminSession
	bundle *trust.Bundle
}

// openRevocation opens the admin session and reads the root-pinned trust
// bundle, which must carry an installation ID.
func openRevocation(ctx context.Context, adminKey string, stderr io.Writer) (*revocation, error) {
	s, err := openAdminSession(adminKey, stderr)
	if err != nil {
		return nil, err
	}
	bundle, _, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold, s.cfg.InstallationID)
	if err != nil {
		s.close()
		return nil, err
	}
	// The request names the installation of the root-pinned bundle
	// (keyroster/revoke-request/v2), so this admin signature revokes in no
	// other installation (the T-03-20 rule of directories).
	if bundle.InstallationID == "" {
		s.close()
		return nil, fmt.Errorf("trust bundle v%d in force has no installation ID, so the signer revokes nothing (krl_no_installation_id); see docs/runbooks/revoke.md", bundle.Version)
	}
	return &revocation{s: s, bundle: bundle}, nil
}

// confirmedRevoke is a revocation the server reported and the CLI
// confirmed: the answer, the manifest of the KRL the server then served
// and that KRL, parsed.
type confirmedRevoke struct {
	ans serverclient.RevokeAnswer
	m   *krl.Manifest
	krl *krl.Parsed
}

// send names the bundle's installation in req (already checked by
// checkRevokeRequest), signs its signing bytes with the admin key in
// ssh-agent under keyroster/revoke-request/v2 and sends it through the
// admin API. The server forwards it to the signer, which alone decides
// and publishes the next KRL. The answer is unsigned, so send confirms it
// against the KRL the server then serves (confirmRevokeAnswer) and runs
// listed on the parsed KRL, which refuses unless it lists what was
// revoked. what names the target for the refusal ("serial 1729"). A
// refusal by the server or the signer is revokeRefusal's; a failed
// confirmation prints where the signer's own record is and is never
// reported as revoked.
func (r *revocation) send(ctx context.Context, req *wire.RevokeRequest, what string, stderr io.Writer,
	listed func(ans serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error) (*confirmedRevoke, error) {
	req.InstallationID = r.bundle.InstallationID
	sig, err := sshsig.Sign(rand.Reader, r.s.signer, wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		return nil, fmt.Errorf("sign the revocation with %s: %w", r.s.adminFP, err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	var ans serverclient.RevokeAnswer
	if err := r.s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminRevokePath, serverclient.RevokeBody{Request: body}, &ans, r.s.signer); err != nil {
		return nil, revokeRefusal(err)
	}
	m, p, err := confirmRevokeAnswer(ctx, r.s.client, r.bundle, ans, req.CreatedAt)
	if err == nil {
		err = listed(ans, m, p)
	}
	if err != nil {
		// The CLI's own advice stays out of an error that may carry a
		// PeerError excerpt.
		_, _ = fmt.Fprintln(stderr, "On the signer host, journalctl -u keyroster-signer shows a \"revoked\" line for this target if the signer revoked it.")
		return nil, fmt.Errorf("the server reports %s revoked, but that could not be confirmed: %w", what, err)
	}
	return &confirmedRevoke{ans: ans, m: m, krl: p}, nil
}

// notListed is the refusal when the verified KRL does not list a target
// the command revoked. Pruning could explain an absent entry (an expired
// certificate leaves the KRL krl.PruneMargin seconds after its
// ValidBefore), but an absent entry is never reported as revoked.
func notListed(m *krl.Manifest, what string) error {
	return fmt.Errorf("KRL v%d, the one the server serves, does not list %s (not listed). Either the revocation is not effective "+
		"(the server did not forward it, or the signer did not revoke it), or the entry was pruned "+
		"(an expired certificate leaves the KRL %d s after its ValidBefore); neither is reported as revoked",
		m.KRLVersion, what, krl.PruneMargin)
}

// listsSerial reports whether p lists serial under one of the CA keys of
// role in b.
func listsSerial(b *trust.Bundle, role wire.CARole, p *krl.Parsed, serial uint64) (bool, error) {
	keys, err := krl.RoleCAKeys(b, role.String())
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if p.RevokesSerial(k, serial) {
			return true, nil
		}
	}
	return false, nil
}

// printConfirmed prints what the CLI checked: the served KRL against the
// root-pinned bundle and its issued_at window, then listedText, what the
// parsed KRL was checked to list.
func printConfirmed(stdout io.Writer, c *confirmedRevoke, listedText string) {
	_, _ = fmt.Fprintf(stdout, "Checked: the server serves KRL v%d, signed by the ops key of your root-pinned trust bundle (log entry %d), "+
		"issued at %s, at most %d s before this request.\n"+
		"Checked: KRL v%d lists %s.\n",
		c.m.KRLVersion, c.m.LogIndex, c.m.IssuedAt, wire.MaxRequestSkewSeconds, c.m.KRLVersion, listedText)
}

// runRevokeSerial is keyroster revoke serial SERIAL [--ca user|host|machine]
// [--reason TEXT] [--admin-key FP] (REVOKE-01, CLI only per D-12): the
// certificate with that serial issued under that CA role. The command
// reports the server's answer as the server's, and exits 0 only when the
// KRL the server then serves verifies against the root-pinned bundle and
// lists the serial under one of the role's CA keys. Hosts enforce the
// revocation only once they have that KRL; the command never claims they
// already refuse the certificate.
func runRevokeSerial(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke serial", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ca := fset.String("ca", "user", "the CA that issued the certificate: user, host or machine")
	f := addRevokeFlags(fset)
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
	req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: role, Serial: serial}
	if err := checkRevokeRequest(req, *f.reason); err != nil {
		_, _ = fmt.Fprintf(stderr, "revoke serial: %v\n", err)
		return errUsage
	}
	r, err := openRevocation(ctx, *f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer r.s.close()
	what := fmt.Sprintf("serial %d", serial)
	c, err := r.send(ctx, req, what, stderr, func(_ serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error {
		ok, err := listsSerial(r.bundle, role, p, serial)
		if err != nil {
			return err
		}
		if !ok {
			return notListed(m, fmt.Sprintf("serial %d under a %s CA key of your trust bundle", serial, role))
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "The server reports serial %d (%s) revoked: KRL v%d published (log entries %d, %d).\n",
		serial, role, c.ans.KRLVersion, c.ans.RevokeLeaf, c.ans.PublishLeaf)
	printConfirmed(stdout, c, fmt.Sprintf("serial %d under a %s CA key of your trust bundle, so it revokes that certificate", serial, role))
	_, _ = fmt.Fprintln(stdout, revokeEnforcement(role))
	return nil
}

// runRevokeKeyID is keyroster revoke key-id KEY_ID [--ca user|host|machine]
// [--reason TEXT] [--admin-key FP]: every certificate with that key ID
// signed by a CA key of the role under which this signer issued one (the
// signer refuses a key ID it never issued, key_id_not_issued). It exits 0
// only when the verified KRL lists the key ID under one of the role's CA
// keys.
func runRevokeKeyID(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke key-id", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ca := fset.String("ca", "user", "the CA whose certificates carry the key ID: user, host or machine")
	f := addRevokeFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "revoke key-id: want KEY_ID (ssh-keygen -L -f CERT shows it)")
		return errUsage
	}
	keyID := pos[0]
	role, ok := revokeCARoles[*ca]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "revoke key-id: --ca %q: want user, host or machine\n", *ca)
		return errUsage
	}
	req := &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: role, KeyID: keyID}
	if err := checkRevokeRequest(req, *f.reason); err != nil {
		_, _ = fmt.Fprintf(stderr, "revoke key-id: %v\n", err)
		return errUsage
	}
	r, err := openRevocation(ctx, *f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer r.s.close()
	c, err := r.send(ctx, req, fmt.Sprintf("key ID %q", keyID), stderr, func(_ serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error {
		keys, err := krl.RoleCAKeys(r.bundle, role.String())
		if err != nil {
			return err
		}
		for _, k := range keys {
			if p.RevokesKeyID(k, keyID) {
				return nil
			}
		}
		return notListed(m, fmt.Sprintf("key ID %q under a %s CA key of your trust bundle", keyID, role))
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "The server reports key ID %q (%s) revoked: KRL v%d published (log entries %d, %d).\n",
		keyID, role, c.ans.KRLVersion, c.ans.RevokeLeaf, c.ans.PublishLeaf)
	printConfirmed(stdout, c, fmt.Sprintf("key ID %q under a %s CA key of your trust bundle, so it revokes every certificate with that key ID that key signed", keyID, role))
	_, _ = fmt.Fprintln(stdout, revokeEnforcement(role))
	return nil
}

// maxRevokeKeyFile bounds the public key file revoke key reads: an
// authorized_keys line of the largest key the signer accepts
// (wire.MaxSubjectKeyLen in base64) with a comment fits well below it.
const maxRevokeKeyFile = 64 << 10

// runRevokeKey is keyroster revoke key FILE [--reason TEXT] [--admin-key
// FP]: the public key in FILE (authorized_keys format, such as a .pub
// file) as an explicit KRL key, which refuses the plain key and every
// certificate for it, whichever CA signed it. A certificate file revokes
// its key, with a note. It exits 0 only when the verified KRL lists the
// key.
func runRevokeKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke key", flag.ContinueOnError)
	fset.SetOutput(stderr)
	f := addRevokeFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "revoke key: want FILE, a public key such as id_ed25519.pub")
		return errUsage
	}
	pub, isCert, err := readRevokeKey(pos[0])
	if err != nil {
		return err
	}
	key := pub.Marshal()
	fp := ssh.FingerprintSHA256(pub)
	req := &wire.RevokeRequest{Target: wire.TargetKey, Key: key}
	if err := checkRevokeRequest(req, *f.reason); err != nil {
		_, _ = fmt.Fprintf(stderr, "revoke key: %v\n", err)
		return errUsage
	}
	if isCert {
		_, _ = fmt.Fprintf(stdout, "Note: %s holds a certificate; this revokes its key %s, which refuses that key plain and in every certificate for it.\n", pos[0], fp)
	}
	r, err := openRevocation(ctx, *f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer r.s.close()
	c, err := r.send(ctx, req, "key "+fp, stderr, func(_ serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error {
		if !p.RevokesKey(key) {
			return notListed(m, "key "+fp)
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "The server reports key %s revoked: KRL v%d published (log entries %d, %d).\n",
		fp, c.ans.KRLVersion, c.ans.RevokeLeaf, c.ans.PublishLeaf)
	printConfirmed(stdout, c, "key "+fp+" as an explicit key, so it revokes that key plain and in every certificate for it")
	_, _ = fmt.Fprintln(stdout, "sshd refuses the key once its host's keyroster agent applies this KRL. "+
		"As a host key, it is refused only by SSH clients whose RevokedHostKeys file holds this KRL.")
	return nil
}

// readRevokeKey reads the one public key of file (authorized_keys
// format). For a certificate it returns the certificate's key and true.
func readRevokeKey(file string) (ssh.PublicKey, bool, error) {
	fh, err := os.Open(file) //nolint:gosec // G304: the admin names the key file to revoke
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxRevokeKeyFile+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxRevokeKeyFile {
		return nil, false, fmt.Errorf("%s is larger than %d bytes; want one public key", file, maxRevokeKeyFile)
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, false, fmt.Errorf("%s holds no public key in authorized_keys format: %w", file, err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, false, fmt.Errorf("%s holds more than one key; revoke them one at a time", file)
	}
	if c, ok := pub.(*ssh.Certificate); ok {
		return c.Key, true, nil
	}
	return pub, false, nil
}

// Sentinels of revoke user's directory step, returned by its mutate
// function before anything is signed.
var (
	errUserAlreadyDisabled = errors.New("already disabled")
	errUserNotInDirectory  = errors.New("not in the installed directory")
)

// runRevokeUser is keyroster revoke user NAME [--yes] [--out DIR]
// [--reason TEXT] [--admin-key FP] (D-09): every live certificate of the
// user, then the user disabled, then the certificates issued in between.
// Revocation and the directory change are separate transactions under
// separate authority, so the order is fixed:
//
//  1. the subject revocation (the signer resolves every live user
//     certificate of NAME in its issuance records); it cuts off access at
//     once and is never undone;
//  2. NAME set disabled in a signed directory version, installed at admin
//     quorum 1 and written as a proposal otherwise, so nothing new is
//     issued;
//  3. once the install is reported, or when the served directory already
//     shows NAME disabled or absent (a disable another admin installed
//     after step 1 leaves the certificates of a login in between), a
//     second subject revocation (the second sweep), which revokes every
//     certificate issued between steps 1 and 2. Its answer re-lists those
//     of step 1, because no subject resolution excludes certificates
//     already revoked.
//
// Each answer's serials are printed and checked against the verified KRL
// (the answer is unsigned, so exactly the reported serials). Exit 3 is a
// partial result (revoked, but NAME not disabled, or the second sweep
// failed), exit 4 a disable that is only a proposal; both name the
// command to finish with, keyroster revoke user NAME again. A first
// revocation that fails still runs step 2, the fail-safe direction, and
// exits 1 without a second sweep (the re-run it names sweeps again).
func runRevokeUser(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke user", flag.ContinueOnError)
	fset.SetOutput(stderr)
	yes := fset.Bool("yes", false, "sign the directory version that disables the user without asking (needed when stdin is not a terminal)")
	out := fset.String("out", "", "write the disable as a proposal directory for co-signing instead of installing it")
	f := addRevokeFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "revoke user: want exactly one user name")
		return errUsage
	}
	name := pos[0]
	if !directory.ValidUserName(name) {
		return fmt.Errorf("user name %q: use 1 to 64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
	}
	// The directory step signs a version, which needs consent; refuse
	// before anything is revoked rather than revoke and stop half-way.
	if !*yes && !stdinIsTerminal() {
		return errors.New("refusing to start: disabling the user signs a directory version, and stdin is not a terminal; re-run with --yes. Nothing was revoked")
	}
	first := &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: name}
	if err := checkRevokeRequest(first, *f.reason); err != nil {
		_, _ = fmt.Fprintf(stderr, "revoke user: %v\n", err)
		return errUsage
	}
	r, err := openRevocation(ctx, *f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer r.s.close()

	// 1. The first sweep.
	_, firstErr := r.sweepSubject(ctx, first, wire.CARoleUser, name, "First revocation", stdout, stderr)

	// 2. The directory step, also after a failed first sweep: disabling
	// stops new certificates. served is the version the server serves
	// (0: none); d is the version after it.
	var served uint64
	outcome, dirErr := editDirectoryOutcome(ctx, r.s, editOpts{Yes: *yes, Out: *out, User: name}, stdout, func(d *directory.Directory, _ *trust.Policy) error {
		served = d.Version - 1
		for i := range d.Users {
			if d.Users[i].Name != name {
				continue
			}
			if d.Users[i].Status == directory.StatusDisabled {
				return errUserAlreadyDisabled
			}
			d.Users[i].Status = directory.StatusDisabled
			return nil
		}
		return errUserNotInDirectory
	})
	nothingNew := errors.Is(dirErr, errUserAlreadyDisabled) || errors.Is(dirErr, errUserNotInDirectory)
	if nothingNew {
		_, _ = fmt.Fprintf(stdout, "%s is %s, so no passkey login issues %s a certificate: no directory change.\n",
			name, dirErr, name)
		// Unverified: the served version may be stale, or none at all.
		if served == 0 {
			_, _ = io.WriteString(stdout, "That is the server's word: it serves no directory, so nothing admin-signed shows what the signer holds. ")
		} else {
			_, _ = fmt.Fprintf(stdout, "That is the server's word: the admins signed directory version %d, the one the server serves, "+
				"but the server may serve an older version than the signer holds. ", served)
		}
		_, _ = io.WriteString(stdout, "The signer's audit log is the proof (keyroster audit verify on an export from the signer host).\n")
	}
	if firstErr != nil {
		switch {
		case nothingNew:
			return fmt.Errorf("nothing is reported revoked: %w. Run keyroster revoke user %s again", firstErr, name)
		case dirErr != nil:
			return fmt.Errorf("nothing is reported revoked: %w. The directory step failed too, so %s is NOT disabled (%w). "+
				"Run keyroster user disable %s, then keyroster revoke user %s", firstErr, name, dirErr, name, name)
		case outcome == editProposed:
			return fmt.Errorf("nothing is reported revoked: %w. The disable is only a proposal; once it is installed, run keyroster revoke user %s again", firstErr, name)
		}
		return fmt.Errorf("nothing is reported revoked: %w. %s is disabled now, so nothing new is issued; run keyroster revoke user %s again", firstErr, name, name)
	}
	// state is what the second sweep's output says of NAME.
	state, label := "disabled", "Second revocation (after the disable)"
	switch {
	case nothingNew:
		// Still sweep: a login between step 1 and a disable another
		// admin installed has a live certificate the first missed.
		state, label = dirErr.Error()+" (the server's word)", "Second revocation (after reading the directory)"
	case dirErr != nil:
		return &exitError{code: 3, err: fmt.Errorf("revoked as reported above, but the user is NOT disabled: %w. "+
			"%s can still obtain certificates; run keyroster revoke user %s again (it revokes every live certificate again, those issued since included, "+
			"then disables and sweeps; keyroster user disable alone would leave the certificates issued in between)", dirErr, name, name)}
	case outcome == editProposed:
		return &exitError{code: 4, err: fmt.Errorf("revoked, disable pending: %s can still obtain certificates until the proposal is installed; "+
			"run keyroster revoke user %s again after the proposal is installed", name, name)}
	}

	// 3. The second sweep, after the install the server reported or the
	// directory read that showed NAME disabled or absent.
	second := &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: name}
	if err := checkRevokeRequest(second, *f.reason); err != nil {
		return err
	}
	if _, err := r.sweepSubject(ctx, second, wire.CARoleUser, name, label, stdout, stderr); err != nil {
		return &exitError{code: 3, err: fmt.Errorf("%s is %s, but the second revocation failed: %w; "+
			"certificates issued since the first revocation may still be live; run keyroster revoke user %s again", name, state, err, name)}
	}
	_, _ = fmt.Fprintf(stdout, "%s is %s, and the KRL lists every certificate of %s the server reported. %s\n",
		name, state, name, revokeEnforcement(wire.CARoleUser))
	return nil
}

// Sentinels of the directory step of revoke host and revoke machine,
// returned by its mutate function before anything is signed.
var (
	errHostAlreadyDisabled = errors.New("already disabled")
	errHostNotInDirectory  = errors.New("not in the installed directory")
)

// recoveryKeptNotice ends every revoke host and revoke machine run that
// sent a request (03-11b), and
// every loss revoke (03-09b, owner decision): a signer recovery keeps lost
// host certificates unless --revoke-lost names them, and those are in
// neither the issuance table nor audit's subject index.
const recoveryKeptNotice = "Certificates that a signer recovery kept are not covered by this revoke: revoke each with keyroster revoke key FILE " +
	"(revoke.md, section 3; the recovery summary prints the key, section 7). --keys covers a key still in the entry."

// revokeKind is what revoke host and revoke machine differ in (03-11b,
// PD8): runRevokeEntry runs both, so the steps, the exit codes, the base
// floor and the early refusal are one code path, and every text that
// differs is the kind's own. The host values are the texts revoke host
// printed before machines existed, unchanged.
type revokeKind struct {
	kind     string // "host" or "machine": the subcommand and the name's label
	subject  wire.SubjectKind
	role     wire.CARole
	keyLabel string // "host key" or "machine key", for revokeHostKey and the omissions
	// entry finds name in d: the entry's keys, sorted, and its status, which
	// the directory step sets to disabled.
	entry func(d *directory.Directory, name string) (keys []string, status *string, ok bool)
	// precheck refuses a name before anything is sent (nil: none).
	precheck func(name string, stderr io.Writer) error
	// formerNames is printed before the recovery notice on every run that
	// sent a request (nil: none).
	formerNames func(name string) string

	yesHelp, keysHelp, wantName, refuseNoTerminal, noKeys string
	keysUnreadable, keysNoEntry, unknown, hold            func(name string) string
	successTail                                           string
}

// hostRevokeKind is revoke host (03-09b, D2): every live certificate of the
// host, the host disabled, its host keys with --keys. The host's agent
// keeps receiving state until keyroster host forget: nothing here makes the
// server refuse it.
var hostRevokeKind = revokeKind{
	kind: "host", subject: wire.SubjectHost, role: wire.CARoleHost, keyLabel: "host key",
	entry: func(d *directory.Directory, name string) ([]string, *string, bool) {
		h, ok := d.HostByName(name)
		if !ok {
			return nil, nil, false
		}
		return slices.Sorted(slices.Values(h.Keys)), &h.Status, true
	},
	yesHelp:          "sign the directory version that disables the host without asking (needed when stdin is not a terminal)",
	keysHelp:         "also revoke the host keys of the entry as explicit keys (a compromised host key; explicit keys never leave the KRL)",
	wantName:         "revoke host: want exactly one host name",
	refuseNoTerminal: "refusing to start: disabling the host signs a directory version, and stdin is not a terminal; re-run with --yes. Nothing was revoked",
	noKeys:           "No host key was revoked as an explicit key (use --keys for a compromised host key; explicit keys never leave the KRL).",
	keysUnreadable: func(name string) string {
		return "--keys: the verified directory could not be read, so no host key of " + name + " is known; revoke a key file with keyroster revoke key FILE"
	},
	keysNoEntry: func(name string) string {
		return "--keys: " + name + " has no entry, so no host keys are known; revoke a key file with keyroster revoke key FILE"
	},
	unknown: func(name string) string {
		return fmt.Sprintf("Its live certificates are revoked as reported above. If %s was removed, its agent may still be enrolled and still receives state: "+
			"end that with keyroster host forget.\n", name)
	},
	hold: func(name string) string {
		return fmt.Sprintf("Revoked, disable pending. The certificates of %s are revoked, and the signer refuses %s's host keys new certificates (cert_revoked) "+
			"until a directory version newer than the one it holds is installed. ANY newer version releases that hold: install this proposal "+
			"(which disables %s) as the next version; if another version is installed first, %s can obtain certificates again while still active. "+
			"Once it is installed, run keyroster revoke host %s again: its second sweep revokes anything issued in between. "+
			"A host key with no certificate yet is not held", name, name, name, name, name)
	},
	successTail: "The host's agent keeps receiving state, and this KRL, until keyroster host forget.\n",
}

// machineRevokeKind is revoke machine (03-11b, D-09, D-12): every live
// certificate of the machine name, the entry disabled, the entry's key
// with --keys. The signer holds the name and the key's latest certificate
// after a subject revocation (03-11's default 2 and its amendment), so
// the exit-4 text names both holds and what releases them.
var machineRevokeKind = revokeKind{
	kind: "machine", subject: wire.SubjectMachine, role: wire.CARoleMachine, keyLabel: "machine key",
	entry: func(d *directory.Directory, name string) ([]string, *string, bool) {
		m, ok := d.MachineByName(name)
		if !ok {
			return nil, nil, false
		}
		return []string{m.Key}, &m.Status, true
	},
	// Probe certificates share the machine CA and are never revoked by
	// subject (D-06): without this check the first sweep would be refused
	// (subject_reserved) while the directory step still ran (b-C7).
	precheck: func(name string, stderr io.Writer) error {
		if !strings.HasPrefix(name, "probe.") {
			return nil
		}
		_, _ = fmt.Fprintf(stderr, "revoke machine: %q: machine names starting with probe. are reserved for probe certificates, "+
			"which are never revoked by subject; nothing was revoked\n", name)
		return errUsage
	},
	// The CLI cannot see former names: the admin API serves only the
	// installed directory (T-03-72, a stated residual; b-C9).
	formerNames: func(name string) string {
		return fmt.Sprintf("Certificates that %s's key obtained under a former machine name are not covered: run keyroster revoke machine OLDNAME for each former name, "+
			"or use --keys while the key is in %s's entry.", name, name)
	},
	yesHelp:          "sign the directory version that disables the machine without asking (needed when stdin is not a terminal)",
	keysHelp:         "also revoke the machine key of the entry as an explicit key (a compromised machine key; explicit keys never leave the KRL)",
	wantName:         "revoke machine: want exactly one machine name",
	refuseNoTerminal: "refusing to start: disabling the machine signs a directory version, and stdin is not a terminal; re-run with --yes. Nothing was revoked",
	noKeys:           "No machine key was revoked as an explicit key (use --keys for a compromised machine key; explicit keys never leave the KRL).",
	keysUnreadable: func(name string) string {
		return "--keys: the verified directory could not be read, so no machine key of " + name + " is known; revoke a key file with keyroster revoke key FILE"
	},
	keysNoEntry: func(name string) string {
		return "--keys: " + name + " has no entry, so no machine key is known; revoke a key file with keyroster revoke key FILE"
	},
	unknown: func(string) string {
		return "Its live certificates are revoked as reported above. A machine that is not in the directory obtains no new certificate under this name; " +
			"if its key is now listed under another name, run keyroster revoke machine OTHERNAME.\n"
	},
	hold: func(name string) string {
		return fmt.Sprintf("Revoked, disable pending. The certificates of %s are revoked, and the signer refuses %s new certificates (cert_revoked) "+
			"until a directory version newer than the one it holds is installed: by its name, whether or not a certificate was live, and on its key's latest certificate. "+
			"ANY newer version releases both holds: install this proposal (which disables %s) as the next version; "+
			"if another version is installed first, %s can obtain certificates again while still active. "+
			"Once it is installed, run keyroster revoke machine %s again: its second sweep revokes anything issued in between. "+
			"--keys blocks the key for good (machine_key_revoked). "+
			"After a signer restore, run this command again once the last lost directory version is back (docs/runbooks/revoke.md, section 4c)",
			name, name, name, name, name)
	},
}

// runRevokeHost is keyroster revoke host NAME [--keys] [--yes] [--out DIR]
// [--reason TEXT] [--admin-key FP] (03-09b, D2, REVOKE-01's host
// subject), runRevokeEntry with the host kind.
func runRevokeHost(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runRevokeEntry(ctx, hostRevokeKind, args, stdout, stderr)
}

// runRevokeMachine is keyroster revoke machine NAME [--keys] [--yes] [--out
// DIR] [--reason TEXT] [--admin-key FP] (03-11b, D-09, D-12, REVOKE-01's
// machine subject), runRevokeEntry with the machine kind.
func runRevokeMachine(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runRevokeEntry(ctx, machineRevokeKind, args, stdout, stderr)
}

// runRevokeEntry is revoke host and revoke machine (03-11b, PD8): every
// live certificate of the entry, the entry disabled, its keys as explicit
// keys when --keys asks, then the certificates issued in between.
//
//  1. The first sweep: a subject revocation of NAME under the kind's CA
//     (the signer resolves its certificates from its issuance records),
//     checked in the verified KRL under a CA key of that role.
//  2. The directory step, also after a failed first sweep: NAME disabled
//     in a signed version (installed at quorum 1, a proposal otherwise),
//     or already disabled, or not in the directory. The served directory
//     must not be older than the admin's host trust state
//     (checkHostTrustFloor).
//  3. With --keys, when the first sweep succeeded and the step found the
//     entry: one key revocation per key of the verified entry (never the
//     server's enrolled keys). A refused key is omitted with its reason
//     and the next one is still tried.
//  4. The second sweep, after an installed disable or an entry already
//     disabled.
//
// Exit 0 when all of it was done; 1 when the first sweep or the setup
// failed; 3 for a partial result (the directory step failed, the second
// sweep failed, an unknown name, any key omitted); 4 when only the
// disable is pending as a proposal. 3 beats 4 (both texts print) and 1
// beats both.
func runRevokeEntry(ctx context.Context, k revokeKind, args []string, stdout, stderr io.Writer) error {
	cmd := "revoke " + k.kind
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fset.SetOutput(stderr)
	yes := fset.Bool("yes", false, k.yesHelp)
	out := fset.String("out", "", "write the disable as a proposal directory for co-signing instead of installing it")
	keys := fset.Bool("keys", false, k.keysHelp)
	f := addRevokeFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, k.wantName)
		return errUsage
	}
	name := pos[0]
	if !directory.ValidUserName(name) {
		return errHostName(k.kind, name)
	}
	if k.precheck != nil {
		if err := k.precheck(name, stderr); err != nil {
			return err
		}
	}
	// The directory step signs a version, which needs consent; refuse
	// before anything is revoked rather than revoke and stop half-way.
	if !*yes && !stdinIsTerminal() {
		return errors.New(k.refuseNoTerminal)
	}
	subject := func() (*wire.RevokeRequest, error) {
		req := &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: k.subject, Subject: name}
		return req, checkRevokeRequest(req, *f.reason)
	}
	first, err := subject()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", cmd, err)
		return errUsage
	}
	r, err := openRevocation(ctx, *f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer r.s.close()
	// Every path from here sent a request, so the output ends with the
	// former-name line of the kind, if any, and the recovery notice.
	defer func() {
		if k.formerNames != nil {
			_, _ = fmt.Fprintln(stdout, k.formerNames(name))
		}
		_, _ = fmt.Fprintln(stdout, recoveryKeptNotice)
	}()

	// 1. The first sweep.
	_, firstErr := r.sweepSubject(ctx, first, k.role, name, "First revocation", stdout, stderr)

	// 2. The directory step. served is the version the server serves (0:
	// none), entryKeys the verified entry's keys.
	var (
		served      uint64
		dirRead     bool
		found       bool
		entryKeys   []string
		entryStatus string
	)
	var floorNote string
	floor := func(base *verifiedDirectory) (err error) {
		floorNote, err = checkHostTrustFloor(base, stderr)
		return err
	}
	outcome, dirErr := editDirectoryOutcome(ctx, r.s, editOpts{Yes: *yes, Out: *out, CheckBase: floor}, stdout, func(d *directory.Directory, _ *trust.Policy) error {
		dirRead, served = true, d.Version-1
		ks, status, ok := k.entry(d, name)
		if !ok {
			return errHostNotInDirectory
		}
		found, entryStatus = true, *status
		entryKeys = ks
		if *status == directory.StatusDisabled {
			return errHostAlreadyDisabled
		}
		*status = directory.StatusDisabled
		return nil
	})
	unknown := errors.Is(dirErr, errHostNotInDirectory)
	already := errors.Is(dirErr, errHostAlreadyDisabled)
	switch {
	case already:
		_, _ = fmt.Fprintf(stdout, "Directory version %d, the admin-signed version the server serves, lists %s as %s: no directory change. "+
			"That is the server's word: the CLI checks the admins' signatures, not that the signer holds that version, and %s.\n",
			served, name, entryStatus, floorNote)
	case unknown && served == 0:
		_, _ = fmt.Fprintf(stdout, "%s is in no directory: the server serves none, so there is no entry to disable. "+
			"That is the server's word: nothing admin-signed shows what the signer holds, and %s.\n", name, floorNote)
	case unknown:
		_, _ = fmt.Fprintf(stdout, "%s is not in directory version %d, the admin-signed version the server serves: there is no entry to disable. "+
			"That is the server's word: the CLI checks the admins' signatures, not that the signer holds that version, and %s.\n", name, served, floorNote)
	}
	if firstErr != nil {
		switch {
		case already || unknown:
			return fmt.Errorf("nothing is reported revoked: %w. Run keyroster %s %s again", firstErr, cmd, name)
		case dirErr != nil:
			return fmt.Errorf("nothing is reported revoked: %w. The directory step failed too, so %s is NOT disabled (%w). Run keyroster %s %s again",
				firstErr, name, dirErr, cmd, name)
		case outcome == editProposed:
			return fmt.Errorf("nothing is reported revoked: %w. The disable is only a proposal; once it is installed, run keyroster %s %s again", firstErr, cmd, name)
		}
		return fmt.Errorf("nothing is reported revoked: %w. %s is disabled now, so its keys obtain no new certificate; run keyroster %s %s again", firstErr, name, cmd, name)
	}
	var partial []string
	if unknown {
		_, _ = io.WriteString(stdout, k.unknown(name))
		partial = append(partial, fmt.Sprintf("%s is not in the directory, so nothing was disabled", name))
	}

	// 3. The entry's keys, with --keys.
	switch {
	case !*keys:
		_, _ = fmt.Fprintln(stdout, k.noKeys)
	case found:
		for _, key := range entryKeys {
			if err := r.revokeHostKey(ctx, k.keyLabel, key, *f.reason, stdout, stderr); err != nil {
				partial = append(partial, fmt.Sprintf("%s %s was not revoked as an explicit key: %v", k.keyLabel, hostKeyFingerprint(key), err))
			}
		}
	case !dirRead:
		partial = append(partial, k.keysUnreadable(name))
	default:
		partial = append(partial, k.keysNoEntry(name))
	}
	if dirErr != nil && !already && !unknown {
		partial = append(partial, fmt.Sprintf("%s is NOT disabled: %v. %s can still obtain certificates; run keyroster %s %s again", name, dirErr, name, cmd, name))
	}

	// 4. The second sweep, after the install the server reported or the
	// directory read that showed NAME disabled.
	if (dirErr == nil && outcome == editInstalled) || already {
		label := "Second revocation (after the disable)"
		if already {
			label = "Second revocation (after reading the directory)"
		}
		second, err := subject()
		if err == nil {
			_, err = r.sweepSubject(ctx, second, k.role, name, label, stdout, stderr)
		}
		if err != nil {
			partial = append(partial, fmt.Sprintf("the second revocation failed: %v; certificates issued since the first revocation may still be live; "+
				"run keyroster %s %s again", err, cmd, name))
		}
	}

	pending := dirErr == nil && outcome == editProposed
	var hold string
	if pending {
		hold = k.hold(name)
	}
	switch {
	case len(partial) > 0:
		text := "revoked as reported above, but not completely: " + strings.Join(partial, "; ")
		if pending {
			text = hold + ".\n" + text
		}
		return &exitError{code: 3, err: errors.New(text)}
	case pending:
		return &exitError{code: 4, err: errors.New(hold)}
	}
	state := name + " is disabled"
	if already {
		state = fmt.Sprintf("Directory version %d lists %s as disabled (the server's word)", served, name)
	}
	_, _ = fmt.Fprintf(stdout, "%s, and the KRL lists every certificate of %s the server reported. %s\n",
		state, name, revokeEnforcement(k.role))
	_, _ = io.WriteString(stdout, k.successTail)
	return nil
}

// checkHostTrustFloor is revoke host's base check (pre-merge review,
// 03-09b): fetchVerifiedDirectory has no version floor, so when this
// user's host-trust.json belongs to the bundle's installation, a served
// directory older than the version it records, or an equal version with
// another SHA-256, is refused (the writer's rule). The directory step then
// fails: the run neither reports NAME disabled from a stale version nor
// revokes keys from a stale entry. A state that cannot be read only warns,
// and the floor is not checked then. note says what was checked, for the lines that report the directory as
// the server's word: the floor and its version, no state of this
// installation, or a state that could not be read.
func checkHostTrustFloor(base *verifiedDirectory, stderr io.Writer) (note string, err error) {
	path, err := hostTrustStatePath()
	if err != nil {
		return "", err
	}
	st, err := readHostTrustState(path)
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "Warning: %v (%s), so the directory the server serves is not checked against the version your host trust files hold.\n", err, path)
		return "your host trust state could not be read (see the warning), so no version floor was checked", nil
	case st == nil || st.InstallationID != base.Bundle.InstallationID:
		return "there is no host trust state of this installation, so no version floor was checked", nil
	case base.Version < st.DirectoryVersion:
		return "", fmt.Errorf("the server serves directory version %d, older than version %d, which your host trust files hold (%s); refusing to build on it",
			base.Version, st.DirectoryVersion, path)
	case base.Version == st.DirectoryVersion && base.SHA256 != st.DirectorySHA256:
		return "", fmt.Errorf("the server serves directory version %d with another SHA-256 than the version %d your host trust files hold (%s); refusing to build on it",
			base.Version, base.Version, path)
	}
	return fmt.Sprintf("it is not older than directory version %d, which your host trust files hold", st.DirectoryVersion), nil
}

// hostKeyFingerprint is the SHA256 fingerprint of a host key in
// trust.FormatKey form, or the text itself when it does not parse.
func hostKeyFingerprint(k string) string {
	pub, err := trust.ParseKey(k)
	if err != nil {
		return k
	}
	return ssh.FingerprintSHA256(pub)
}

// revokeHostKey revokes one key of a verified entry as an explicit key
// (TargetKey: the cap, key_is_ca_of_this_installation and audit's
// derivation apply unchanged) and confirms it in the verified KRL. label
// names the key in the output: "host key" or "machine key" (03-11b).
func (r *revocation) revokeHostKey(ctx context.Context, label, k, reason string, stdout, stderr io.Writer) error {
	pub, err := trust.ParseKey(k)
	if err != nil {
		return err
	}
	key, fp := pub.Marshal(), ssh.FingerprintSHA256(pub)
	req := &wire.RevokeRequest{Target: wire.TargetKey, Key: key}
	if err := checkRevokeRequest(req, reason); err != nil {
		return err
	}
	c, err := r.send(ctx, req, label+" "+fp, stderr, func(_ serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error {
		if !p.RevokesKey(key) {
			return notListed(m, label+" "+fp)
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "The server reports %s %s revoked as an explicit key: KRL v%d published (log entries %d, %d).\n",
		label, fp, c.ans.KRLVersion, c.ans.RevokeLeaf, c.ans.PublishLeaf)
	printConfirmed(stdout, c, label+" "+fp+" as an explicit key, so it revokes that key plain and in every certificate for it, permanently")
	return nil
}

// sweepSubject sends one subject revocation of name, checks that the
// verified KRL lists every serial the answer reports under a CA key of
// role (the user role for revoke user, the host role for revoke host and
// the loss revokes, 03-09b, the machine role for revoke machine, 03-11b),
// and prints the answer's serials and what was
// checked, headed by label.
func (r *revocation) sweepSubject(ctx context.Context, req *wire.RevokeRequest, role wire.CARole, name, label string, stdout, stderr io.Writer) (*confirmedRevoke, error) {
	c, err := r.send(ctx, req, "the certificates of "+name, stderr, func(ans serverclient.RevokeAnswer, m *krl.Manifest, p *krl.Parsed) error {
		for _, serial := range ans.Serials {
			ok, err := listsSerial(r.bundle, role, p, serial)
			if err != nil {
				return err
			}
			if !ok {
				return notListed(m, fmt.Sprintf("serial %d, which the server's answer reports, under a %s CA key of your trust bundle", serial, role))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ans := c.ans
	var b strings.Builder
	fmt.Fprintf(&b, "%s of %s: the server reports %d certificate(s) revoked: KRL v%d published (log entries %d, %d).\n",
		label, name, ans.SerialCount, ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf)
	if ans.SerialCount == 0 {
		fmt.Fprintf(&b, "No live certificates of %s in this signer's records; revoke a certificate issued elsewhere with keyroster revoke key.\n", name)
	} else {
		serials := make([]string, len(ans.Serials))
		for i, s := range ans.Serials {
			serials[i] = strconv.FormatUint(s, 10)
		}
		fmt.Fprintf(&b, "Serials: %s\n", strings.Join(serials, " "))
	}
	if uint64(len(ans.Serials)) < uint64(ans.SerialCount) {
		fmt.Fprintf(&b, "The answer lists %d of the %d serials; the rest are not listed in the answer, so the KRL check below does not cover them. "+
			"keyroster audit verify on a log exported on the signer host checks them all.\n", len(ans.Serials), ans.SerialCount)
	}
	_, _ = io.WriteString(stdout, b.String())
	printConfirmed(stdout, c, fmt.Sprintf("each of the %d serial(s) the server's answer reports, under a %s CA key of your trust bundle. "+
		"The answer is unsigned, so a certificate it does not report is not checked here; keyroster audit verify on an exported log checks every revocation",
		len(ans.Serials), role))
	return c, nil
}

// revokeEnforcement says who enforces a revocation under role. sshd's
// RevokedKeys covers user authentication only, so it refuses user and
// machine certificates (both are user certificates); a host certificate
// is checked by SSH clients, through ssh_config's RevokedHostKeys.
func revokeEnforcement(role wire.CARole) string {
	if role == wire.CARoleHost {
		return "A host certificate is checked by SSH clients, not by sshd: clients refuse it once keyroster login or " +
			"keyroster known-hosts sync has written this KRL to ~/.ssh/keyroster_revoked_hosts.krl."
	}
	return "Hosts enforce it once their keyroster agent applies this KRL."
}

// confirmRevokeAnswer checks the server's answer to a revocation against
// what the signer signed, and returns the manifest and the parsed KRL. The
// answer itself is unsigned: a server could drop the request and invent
// it. The revoke and krl_publish leaves are adjacent and a KRL version is
// at least 1; the KRL the server then serves must verify against the
// root-pinned bundle and its installation ID (krl.VerifyManifest) with a
// version of at least the answer's and a krl_publish leaf of at least the
// answer's, and an issued_at no earlier than createdAt (the request's
// CreatedAt) minus wire.MaxRequestSkewSeconds: the signer sets issued_at
// from the clock reading it refused the request against unless it was
// within that window, so the KRL this revocation published can never fail
// it. A server that dropped the request cannot show a manifest the signer
// never signed, nor replay one published before that window under an
// invented answer. It can still show any genuine one issued later (there
// is no upper bound, and the signer re-publishes by itself every hour,
// D-10), so every caller then checks that the parsed KRL lists what it
// revoked; a KRL that does not parse (krl.Parse, strict) is a refusal.
func confirmRevokeAnswer(ctx context.Context, c *serverclient.Client, b *trust.Bundle, ans serverclient.RevokeAnswer, createdAt uint64) (*krl.Manifest, *krl.Parsed, error) {
	if ans.KRLVersion < 1 || ans.PublishLeaf != ans.RevokeLeaf+1 {
		return nil, nil, fmt.Errorf("its answer (KRL v%d, log entries %d, %d) is not one the signer gives", ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf)
	}
	doc, err := c.GetKRL(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the published KRL: %w", err)
	}
	if doc == nil {
		return nil, nil, errors.New("the server serves no KRL")
	}
	m, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, b, b.InstallationID, ans.KRLVersion-1)
	if err != nil {
		return nil, nil, fmt.Errorf("the KRL the server serves does not verify against your root-pinned trust bundle: %w", serverclient.PeerError(err))
	}
	if m.LogIndex < ans.PublishLeaf {
		return nil, nil, fmt.Errorf("the KRL the server serves (v%d) was published at log entry %d, before the reported entry %d", m.KRLVersion, m.LogIndex, ans.PublishLeaf)
	}
	issued, err := time.Parse(trust.TimeFormat, m.IssuedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("the KRL the server serves has issued_at %q: %w", m.IssuedAt, err)
	}
	if floor := int64(min(createdAt, uint64(1)<<62)) - wire.MaxRequestSkewSeconds; issued.Unix() < floor { //nolint:gosec // G115: clamped below 2^63
		return nil, nil, fmt.Errorf("the KRL the server serves (v%d) was issued at %s, more than %d s before this request, so this revocation did not publish it",
			m.KRLVersion, m.IssuedAt, wire.MaxRequestSkewSeconds)
	}
	// The bytes VerifyManifest checked against the signed digest.
	p, err := krl.Parse(doc.KRL)
	if err != nil {
		return nil, nil, fmt.Errorf("the KRL the server serves (v%d) is signed but does not parse, so nothing in it is reported: %w", m.KRLVersion, err)
	}
	return m, p, nil
}

// revokeRefusals are the signer's refusal details an admin can act on, in
// the CLI's own words. They are matched by detail, whatever the HTTP
// status (keyroster-server answers 400 for a malformed request and 403
// for every other refusal).
var revokeRefusals = map[string]string{
	"unknown_serial": "the signer has issued no certificate with this serial; nothing was revoked. " +
		"Revoke the certificate by its key ID (keyroster revoke key-id) or, for a certificate this signer did not issue, by its key (keyroster revoke key FILE)",
	"ca_role_mismatch":  "the certificate with this serial was not issued by that CA; pass the right --ca; nothing was revoked",
	"duplicate_request": "the signer has already accepted a request with this ID; run the command again; nothing new was revoked",
	"key_id_not_issued": "the signer has issued no certificate with this key ID under that CA; nothing was revoked. " +
		"Check the key ID and --ca; a certificate this signer did not issue is revoked by its key (keyroster revoke key FILE)",
	"explicit_key_cap_reached": "the KRL holds as many explicit keys as it may (explicit_key_cap_reached: 1000 keys or 1 MiB, and they never leave it); nothing was revoked. " +
		"Revoke the key's certificates by serial or key ID instead and remove the key from authorized_keys by hand; see docs/runbooks/revoke.md",
	"key_is_ca_of_this_installation": "the key is a key of this installation's trust bundle (a CA, ops, log or root key), which is never revoked as a key; nothing was revoked. " +
		"A compromised CA key is replaced by the emergency CA rotation (03-13)",
	"subject_kind_unsupported": "this signer does not revoke this kind of subject (subject_kind_unsupported): it is older than this CLI; " +
		"machine subjects need a signer with machine certificates. Upgrade keyroster-signer, then keyroster-server; nothing was revoked by that request",
	"subject_reserved": "the signer refuses a subject revocation of a probe. name (subject_reserved); nothing was revoked",
	"revoke_installation_missing": "the signer received the request without an installation ID (revoke_installation_missing), but this CLI always names one, " +
		"so the request did not reach the signer unchanged; nothing was revoked",
	"revoke_installation_mismatch": "the signer belongs to another installation than the trust bundle your root pins verify (revoke_installation_mismatch); nothing was revoked. " +
		"Check the server URL and root pins that keyroster init saved",
}

// revokeRefusal states a refused revocation in the CLI's own words for the
// refusals an admin can act on, and otherwise returns err.
func revokeRefusal(err error) error {
	var he *serverclient.HTTPError
	if errors.As(err, &he) {
		for detail, text := range revokeRefusals {
			if he.APIErrorIs(detail) {
				return errors.New(text)
			}
		}
	}
	switch {
	case errors.As(err, &he) && he.Code == http.StatusForbidden:
		// keyroster-server refuses a key that is not a policy admin itself
		// (401, admin authentication failed); a 403 is the signer's, for
		// example request_time_skew when ssh-agent took over five minutes
		// to sign. Its reason is peer text, so no advice joins it.
		return fmt.Errorf("the signer refused the revocation; nothing was revoked: %w", err)
	case errors.Is(err, serverclient.ErrSignerUnavailable):
		return fmt.Errorf("%w; the revocation may not have been recorded. The signer's log names the reason (krl_no_installation_id: the trust bundle in force has no installation ID; krl_too_large, revocations_not_logged: see docs/runbooks/revoke.md)", err)
	}
	return err
}
