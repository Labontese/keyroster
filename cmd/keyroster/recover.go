package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// nothingToRecover is the line keyroster revoke recover prints when no KRL
// was ever published, so no revocation can be lost from one.
const nothingToRecover = "nothing to recover: neither export's trust bundle has an installation ID and no server KRL copy was given, so no KRL was ever published"

// maxRecoverExport bounds one export file keyroster revoke recover reads.
const maxRecoverExport = 1 << 30

// recoverNow is keyroster revoke recover's clock (the request's
// CreatedAt); tests replace it.
var recoverNow = time.Now

// recoverRefusal is a refusal of keyroster revoke recover: the name the
// runbook quotes, then the reason.
func recoverRefusal(name, format string, args ...any) error {
	return fmt.Errorf("refused (%s): %s", name, fmt.Sprintf(format, args...))
}

// recoverImport is one KRL version to import, with where it came from.
type recoverImport struct {
	source string
	im     wire.RecoveryImport
	m      *krl.Manifest
	p      *krl.Parsed
}

// lostCert is one certificate the restore lost, with what the summary
// prints about it.
type lostCert struct {
	c      *ssh.Certificate
	raw    []byte
	kid    cert.KeyID
	live   bool
	revoke bool
}

// runRevokeRecover is keyroster revoke recover --restored FILE --saved FILE
// [--krl FILE ...] [--revoke-lost SERIAL ...] [--yes] [--admin-key FP]
// --out FILE (03-06b). It runs offline, as a policy admin, and prepares
// and signs the recovery of the revocations a signer restore lost, which
// keyroster-signer recover-revocations applies under the hold. Every input
// is read before anything is decided:
//
//  1. the restored and the saved export, and every --krl document (a
//     KRL document keyroster-server kept, krl-served.json), each decoded
//     strictly (recovery_import_invalid otherwise);
//  2. both exports verified on the saved config's trust pins and threshold
//     (audit.Verify);
//  3. one export a prefix of the other (the --previous rule); otherwise
//     they are a fork, which is refused. The lost certificates are those
//     of the saved export at or after the restored size;
//  4. the installation ID: when the restored export's trust bundle has
//     none, and the saved export's has one or any --krl document was
//     given, refused (recovery_installation_lost), because a KRL is
//     published only under a bundle with one and no successor drops it;
//     when neither has one and no --krl document was given, it prints
//     nothingToRecover and exits 0 without writing anything;
//  5. every import (the saved export's last KRL, re-derived by audit
//     verify, and each --krl document) verified under the restored
//     export's trust bundle and its installation ID
//     (recovery_import_invalid).
//
// Then it applies the owner's answer on lost certificates
// (revoke-users-list-others): every lost user certificate is revoked,
// whatever its clock says (PR #69 review round 2), a lost host or machine
// certificate only when --revoke-lost names its serial. It carries
// exactly the lost certificates krl.CheckCarriedLost admits at its one
// clock reading, which is the request's CreatedAt: every one it revokes,
// and each other host or machine certificate still live then minus the
// signer's 300 s skew bound; an expired one it only counts (PR #69
// review, D-R2). It prints
// a summary, asks for confirmation unless --yes, signs the request with
// the admin key in ssh-agent under keyroster/revoke-recovery/v1 and writes
// it to --out (mode 0600, never over an existing file).
func runRevokeRecover(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("revoke recover", flag.ContinueOnError)
	fset.SetOutput(stderr)
	restoredPath := fset.String("restored", "", "the export of the restored signer, taken before it ever started (required)")
	savedPath := fset.String("saved", "", "the latest export saved before the restore (required)")
	outPath := fset.String("out", "", "write the signed recovery request to this new file (required)")
	yes := fset.Bool("yes", false, "sign without asking (needed when stdin is not a terminal)")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	var krlPaths, revokeLost stringList
	fset.Var(&krlPaths, "krl", "a KRL document keyroster-server kept (krl-served.json) to import (repeatable)")
	fset.Var(&revokeLost, "revoke-lost", "the serial of a lost host or machine certificate to revoke as well (repeatable)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 0 || *restoredPath == "" || *savedPath == "" || *outPath == "" {
		_, _ = fmt.Fprintln(stderr, "revoke recover: --restored, --saved and --out are required; no positional arguments")
		return errUsage
	}
	named := map[uint64]bool{}
	for _, v := range revokeLost {
		serial, err := strconv.ParseUint(v, 10, 64)
		if err != nil || serial == 0 {
			_, _ = fmt.Fprintf(stderr, "revoke recover: --revoke-lost %q is not a certificate serial\n", v)
			return errUsage
		}
		named[serial] = true
	}
	if _, err := os.Lstat(*outPath); err == nil {
		return fmt.Errorf("--out %s exists; the recovery request is written only to a new file", *outPath)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := trust.CheckPins(cfg.TrustPins, cfg.TrustThreshold); err != nil {
		return fmt.Errorf("the saved config's trust pins: %w; run keyroster init again", err)
	}

	// 1. Every input, before anything is decided.
	restoredData, err := readLimited(*restoredPath, maxRecoverExport)
	if err != nil {
		return err
	}
	savedData, err := readLimited(*savedPath, maxRecoverExport)
	if err != nil {
		return err
	}
	var docs []recoverImport
	for _, p := range krlPaths {
		data, err := readLimited(p, krl.MaxKRLResponse)
		if err != nil {
			return recoverRefusal("recovery_import_invalid", "--krl %s: %v", p, err)
		}
		doc, err := serverclient.DecodeKRLDocument(data)
		if err != nil {
			return recoverRefusal("recovery_import_invalid", "--krl %s: %v", p, err)
		}
		m, err := krl.ParseManifest(doc.Manifest)
		if err != nil {
			return recoverRefusal("recovery_import_invalid", "--krl %s: %v", p, err)
		}
		docs = append(docs, recoverImport{source: p, im: wire.RecoveryImport{KRL: doc.KRL, Manifest: doc.Manifest, Sig: doc.Sig}, m: m})
	}

	// 2. Both exports, each on its own.
	opts := audit.Options{Pins: cfg.TrustPins, Threshold: cfg.TrustThreshold}
	zero := uint64(0)
	restored, err := audit.Verify(bytes.NewReader(restoredData), audit.Options{Pins: opts.Pins, Threshold: opts.Threshold, CertificatesFrom: &zero})
	if err != nil {
		return fmt.Errorf("the restored export %s does not verify on your trust pins: %w; escalate, do not release the hold", *restoredPath, err)
	}
	saved, err := audit.Verify(bytes.NewReader(savedData), opts)
	if err != nil {
		return fmt.Errorf("the saved export %s does not verify on your trust pins: %w; escalate, do not release the hold", *savedPath, err)
	}

	// 3. The prefix rule.
	var lost []audit.LoggedCertificate
	if saved.Size > restored.Size {
		prev, err := exportCheckpoint(restoredData)
		if err != nil {
			return err
		}
		from := restored.Size
		ext, err := audit.Verify(bytes.NewReader(savedData), audit.Options{Pins: opts.Pins, Threshold: opts.Threshold, Previous: prev, CertificatesFrom: &from})
		if err != nil {
			return recoverRefusal("recovery_fork", "the saved export does not extend the restored one (%v); the two logs are a fork: escalate, do not release the hold", err)
		}
		lost = ext.Certificates
	} else {
		prev, err := exportCheckpoint(savedData)
		if err != nil {
			return err
		}
		if _, err := audit.Verify(bytes.NewReader(restoredData), audit.Options{Pins: opts.Pins, Threshold: opts.Threshold, Previous: prev}); err != nil {
			return recoverRefusal("recovery_fork", "the restored export does not extend the saved one (%v); the two logs are a fork: escalate, do not release the hold", err)
		}
	}

	// 4. The installation ID, from all three inputs.
	installation := restored.Bundle.InstallationID
	if installation == "" {
		if saved.Bundle.InstallationID != "" || len(docs) > 0 {
			return recoverRefusal("recovery_installation_lost",
				"the restored trust bundle v%d has no installation ID, but the saved export's trust bundle has one or a server KRL copy was given: "+
					"a lost trust bundle added the installation ID and revocations may have followed, which the restored signer cannot publish. "+
					"Keep the hold and escalate", restored.Bundle.Version)
		}
		_, err := fmt.Fprintln(stdout, nothingToRecover)
		return err
	}

	// 5. Every import, under the restored bundle.
	var imports []recoverImport
	if saved.LastKRL != nil {
		m, err := krl.ParseManifest(saved.LastKRL.Manifest)
		if err != nil {
			return recoverRefusal("recovery_import_invalid", "the saved export's last KRL: %v", err)
		}
		imports = append(imports, recoverImport{source: fmt.Sprintf("saved export, log entry %d", m.LogIndex),
			im: wire.RecoveryImport{KRL: saved.LastKRL.KRL, Manifest: saved.LastKRL.Manifest, Sig: saved.LastKRL.Sig}, m: m})
	}
	for _, d := range docs {
		if !slices.ContainsFunc(imports, func(o recoverImport) bool { return bytes.Equal(o.im.Manifest, d.im.Manifest) }) {
			imports = append(imports, d)
		}
	}
	if len(imports) > wire.MaxRecoveryImports {
		return recoverRefusal("recovery_import_invalid", "%d distinct KRL versions to import, at most %d", len(imports), wire.MaxRecoveryImports)
	}
	var (
		parsed    []*krl.Parsed
		maxImport uint64
	)
	for i := range imports {
		im := &imports[i]
		if _, err := krl.VerifyManifest(im.im.Manifest, im.im.Sig, im.im.KRL, restored.Bundle, installation, 0); err != nil {
			return recoverRefusal("recovery_import_invalid", "%s: it is not a KRL version of the restored trust bundle v%d and installation %s: %v",
				im.source, restored.Bundle.Version, installation, err)
		}
		p, err := krl.Parse(im.im.KRL)
		if err != nil {
			return recoverRefusal("recovery_import_invalid", "%s: %v", im.source, err)
		}
		if p.Version != im.m.KRLVersion {
			return recoverRefusal("recovery_import_invalid", "%s: the KRL header says version %d, its manifest %d", im.source, p.Version, im.m.KRLVersion)
		}
		im.p = p
		parsed = append(parsed, p)
		maxImport = max(maxImport, im.m.KRLVersion)
	}

	// The lost certificates, one per serial, and the owner's answer, at
	// one clock reading: the request's CreatedAt.
	createdAt := uint64(max(recoverNow().Unix(), 0)) //nolint:gosec // G115: >= 0
	at := createdAt - min(createdAt, wire.MaxRequestSkewSeconds)
	var (
		certs   []lostCert
		expired int
	)
	seen := map[uint64]bool{}
	for _, lc := range lost {
		c, err := parseLostCert(lc.Cert)
		if err != nil {
			return fmt.Errorf("the saved export's entry %d: %w", lc.Index, err)
		}
		if seen[c.Serial] {
			continue // the first in log order
		}
		seen[c.Serial] = true
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil {
			return fmt.Errorf("the saved export's entry %d: key ID: %w", lc.Index, err)
		}
		user := kid.CA == trust.RoleUser
		revoke := user || named[c.Serial]
		if krl.CheckCarriedLost(c.ValidBefore, createdAt, user, revoke) != nil {
			expired++
			continue
		}
		certs = append(certs, lostCert{c: c, raw: lc.Cert, kid: kid, live: krl.EntryLive(c.ValidBefore, at), revoke: revoke})
	}
	for serial := range named {
		if !slices.ContainsFunc(certs, func(o lostCert) bool { return o.c.Serial == serial && o.kid.CA != trust.RoleUser }) {
			return recoverRefusal("recovery_revoke_lost_unknown", "--revoke-lost %d is not a lost host or machine certificate of the saved export", serial)
		}
	}
	slices.SortFunc(certs, func(a, b lostCert) int {
		switch {
		case a.c.Serial < b.c.Serial:
			return -1
		case a.c.Serial > b.c.Serial:
			return 1
		}
		return 0
	})

	// The entries, by the signer's rule, with the restored issuance as the
	// lookup (the signer's issuance table holds exactly those).
	issued := map[uint64]*ssh.Certificate{}
	for _, lc := range restored.Certificates {
		if lc.Kind == tlog.KindRevocationRecovery {
			continue
		}
		c, err := parseLostCert(lc.Cert)
		if err != nil {
			return fmt.Errorf("the restored export's entry %d: %w", lc.Index, err)
		}
		issued[c.Serial] = c
	}
	rcs := make([]krl.RecoveredCert, 0, len(certs))
	for _, lc := range certs {
		rcs = append(rcs, krl.RecoveredCert{CAKey: lc.c.SignatureKey.Marshal(), Serial: lc.c.Serial, KeyID: lc.c.KeyId, ValidBefore: lc.c.ValidBefore, Revoke: lc.revoke})
	}
	entries, err := krl.RecoveryEntries(parsed, rcs, func(serial uint64) ([]byte, string, uint64, bool) {
		c, ok := issued[serial]
		if !ok {
			return nil, "", 0, false
		}
		return c.SignatureKey.Marshal(), c.KeyId, c.ValidBefore, true
	})
	if errors.Is(err, krl.ErrRecoveryTooLarge) {
		return recoverRefusal("recovery_too_large", "%v", err)
	}
	if err != nil {
		return recoverRefusal("recovery_import_invalid", "%v", err)
	}

	req := &wire.RecoveryRequest{
		InstallationID: installation,
		CreatedAt:      createdAt,
		RestoredSize:   restored.Size,
	}
	copy(req.RestoredRoot[:], restored.Root)
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		return err
	}
	for _, im := range imports {
		req.Imports = append(req.Imports, im.im)
	}
	for _, lc := range certs {
		req.Certificates = append(req.Certificates, wire.RecoveredCertificate{Cert: lc.raw, Revoke: lc.revoke})
	}
	signing, err := req.SigningBytes()
	if err != nil {
		return recoverRefusal("recovery_too_large", "%v", err)
	}
	printRecoverySummary(stdout, restored, saved, imports, certs, expired, len(entries), maxImport)

	if err := confirmRecovery(*yes, stdout); err != nil {
		return err
	}
	fp := *adminKey
	if fp == "" {
		fp = cfg.AdminKey
	}
	if fp == "" {
		return errNoAdminKey
	}
	if err := trust.CheckPins([]string{fp}, 1); err != nil {
		return fmt.Errorf("--admin-key: %w", err)
	}
	signer, closeAgent, err := adminSigner(fp)
	if err != nil {
		return err
	}
	defer closeAgent()
	sig, err := sshsig.Sign(rand.Reader, signer, wire.RecoverySSHSIGNamespace, signing)
	if err != nil {
		return fmt.Errorf("sign the recovery with %s: %w", fp, err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	data, err := req.Marshal()
	if err != nil {
		return err
	}
	if err := writeExclusive(*outPath, data, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote the signed recovery request to %s; apply it on the signer host, under the hold, with: keyroster-signer recover-revocations --state-dir DIR < %s\n",
		*outPath, *outPath)
	return err
}

// printRecoverySummary prints what the recovery imports and carries, and
// how many lost certificates it leaves out as expired, for the admin to
// check before signing.
func printRecoverySummary(w io.Writer, restored, saved *audit.Report, imports []recoverImport, certs []lostCert, expired, entries int, maxImport uint64) {
	var b strings.Builder
	fmt.Fprintf(&b, "installation: %s\n", restored.Bundle.InstallationID)
	fmt.Fprintf(&b, "restored log: %d entries, root %s; saved log: %d entries\n",
		restored.Size, base64.StdEncoding.EncodeToString(restored.Root), saved.Size)
	for _, im := range imports {
		var serials, keyIDs uint64
		for _, sec := range im.p.Certs {
			for _, r := range sec.Serials {
				serials += r.Hi - r.Lo + 1
			}
			keyIDs += uint64(len(sec.KeyIDs))
		}
		fmt.Fprintf(&b, "import: %s: KRL v%d, issued at %s: %d serials, %d key IDs, %d keys\n",
			im.source, im.m.KRLVersion, im.m.IssuedAt, serials, keyIDs, len(im.p.Keys))
	}
	if len(certs) == 0 && expired == 0 {
		b.WriteString("lost certificates: none\n")
	}
	if expired > 0 {
		fmt.Fprintf(&b, "lost certificates expired before this request, not carried: %d\n", expired)
	}
	for _, lc := range certs {
		state := "expired"
		if lc.live {
			state = "live"
		}
		fmt.Fprintf(&b, "lost certificate: serial %d, %s, subject %s, key %s, valid before %d (%s): ",
			lc.c.Serial, lc.kid.CA, lc.kid.Subject, ssh.FingerprintSHA256(lc.c.Key), lc.c.ValidBefore, state)
		if lc.revoke {
			b.WriteString("revoke\n")
			continue
		}
		fmt.Fprintf(&b, "keep; public key %s; revoke later with: keyroster revoke key <file with this public key>\n",
			strings.TrimSpace(string(ssh.MarshalAuthorizedKey(lc.c.Key))))
	}
	fmt.Fprintf(&b, "entries: %d; the KRL the recovery publishes must be above v%d\n", entries, maxImport)
	_, _ = io.WriteString(w, b.String())
}

// confirmRecovery asks before the recovery is signed: with yes it reads
// nothing; on a terminal only y or yes is consent; with no terminal and no
// yes it refuses.
func confirmRecovery(yes bool, stdout io.Writer) error {
	if yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errors.New("refusing to sign without confirmation: stdin is not a terminal; check the summary and re-run with --yes")
	}
	if _, err := io.WriteString(stdout, "Sign this recovery? [y/N] "); err != nil {
		return err
	}
	line, _ := bufio.NewReader(ceremonyInput).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed; nothing was signed")
}

// parseLostCert parses a certificate a verified export holds.
func parseLostCert(raw []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("certificate does not parse: %w", err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("the logged key is not a certificate")
	}
	return c, nil
}

// readLimited reads path, refusing a file above limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// exportCheckpoint returns the signed checkpoint of an export: its final
// line's checkpoint note. audit.Verify checks it.
func exportCheckpoint(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	last := trimmed[bytes.LastIndexByte(trimmed, '\n')+1:]
	var line audit.ExportLine
	if err := json.Unmarshal(last, &line); err != nil || line.Checkpoint == "" {
		return nil, errors.New("the last line of the export is not a checkpoint line")
	}
	return []byte(line.Checkpoint), nil
}
