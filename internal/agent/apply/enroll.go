//go:build linux

package apply

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// The enrollment hand-over's files (enroll.RequestFile and friends).
const (
	EnrollRequestFile = enroll.RequestFile
	EnrollPoPFile     = enroll.AnswerFile
	IdentityFile      = enroll.IdentityFile
)

// Enrollment refusals.
var (
	ErrEnrollRequest     = errors.New("enroll_request_invalid")
	ErrHostKeyUnreadable = errors.New("host_key_unreadable")
)

// checkEnrollRequest is the applier's check of enroll-request.json:
// canonical JSON of enroll.Request, both hashes 64 lowercase hex digits,
// the host name in the directory's grammar and the installation ID the
// pinned one, byte for byte.
func checkEnrollRequest(b []byte, pins *state.Pins) (*enroll.Request, error) {
	var r enroll.Request
	if err := trust.DecodeStrict(b, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnrollRequest, err)
	}
	switch {
	case !enroll.IsSHA256Hex(r.IdentitySPKISHA256) || !enroll.IsSHA256Hex(r.TokenSHA256):
		return nil, fmt.Errorf("%w: identity_spki_sha256 and token_sha256 must be 64 lowercase hex digits", ErrEnrollRequest)
	case !directory.ValidUserName(r.ExpectedName):
		return nil, fmt.Errorf("%w: expected_name is not a directory host name", ErrEnrollRequest)
	case r.InstallationID != pins.InstallationID:
		return nil, fmt.Errorf("%w: installation_id is not the installation pinned in %s", ErrEnrollRequest, state.PinsFile)
	}
	return &r, nil
}

// Enroll answers one enrollment request (03-07, F2): when the spool holds
// enroll-request.json, read through spool.ReadFileAt (O_NOFOLLOW,
// O_NONBLOCK, a regular file of at most enroll.MaxRequestFile bytes), checked
// against pins.json (checkEnrollRequest), every host key sshd -T names of
// a type a directory host entry may name signs the enroll.PoP with the
// installation ID of pins.json, and enroll-pop.json is written into the
// outbox (spool.WriteFileAt, mode 0640). An answer already there for the
// same statement is kept. It reports whether it wrote one; no request
// means nothing to do. The state directory and the outbox must be the
// applier's own (state_dir_unsafe), as at the start of every apply.
func Enroll(ctx context.Context, cfg Config, l Layout) (bool, error) {
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	e := &engine{cfg: cfg, l: l, report: &Report{}, stateFd: -1}
	if err := CheckStateDirs(l); err != nil {
		return false, err
	}
	stateFd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	defer func() { _ = unix.Close(stateFd) }()
	pins, err := state.LoadPins(stateFd)
	if err != nil {
		return false, err
	}
	spoolFd, err := spool.OpenDir(cfg.Spool)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(spoolFd) }()
	b, err := spool.ReadFileAt(spoolFd, EnrollRequestFile, enroll.MaxRequestFile)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrEnrollRequest, err)
	}
	req, err := checkEnrollRequest(b, pins)
	if err != nil {
		return false, err
	}
	dump, err := e.sshdDump(ctx, "")
	if err != nil {
		return false, err
	}
	signers, err := hostSigners(dump)
	if err != nil {
		return false, err
	}
	facts := hostFacts(l)
	factsSum, err := enroll.FactsSHA256(facts)
	if err != nil {
		return false, err
	}
	pubs := make([]ssh.PublicKey, 0, len(signers))
	for _, s := range signers {
		pubs = append(pubs, s.PublicKey())
	}
	pop := enroll.PoP{
		Domain: enroll.Domain, InstallationID: pins.InstallationID, TokenSHA256: req.TokenSHA256,
		IdentitySPKISHA256: req.IdentitySPKISHA256, HostKeys: enroll.SortHostKeys(pubs), FactsSHA256: factsSum,
	}
	outFd, err := spool.OpenDir(l.Outbox())
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	defer func() { _ = unix.Close(outFd) }()
	if old, err := spool.ReadFileAt(outFd, EnrollPoPFile, enroll.MaxAnswerFile); err == nil {
		var a enroll.Answer
		if trust.DecodeStrict(old, &a) == nil && samePoP(a.PoP, pop) && a.Facts == facts {
			return false, nil
		}
	}
	ordered := make([]ssh.Signer, 0, len(signers))
	for _, k := range pop.HostKeys {
		for _, s := range signers {
			if trust.FormatKey(s.PublicKey()) == k {
				ordered = append(ordered, s)
				break
			}
		}
	}
	sigs, err := enroll.Sign(pop, ordered)
	if err != nil {
		return false, err
	}
	out, err := trust.CanonicalJSON(enroll.Answer{PoP: pop, Facts: facts, Sigs: sigs})
	if err != nil {
		return false, err
	}
	if err := paths.Allowed(l, filepath.Join(l.Outbox(), EnrollPoPFile)); err != nil {
		return false, err
	}
	if err := spool.WriteFileAt(outFd, EnrollPoPFile, out, 0o640); err != nil {
		return false, err
	}
	return true, nil
}

// samePoP reports whether a and b are one statement.
func samePoP(a, b enroll.PoP) bool {
	x, err1 := a.Canonical()
	y, err2 := b.Canonical()
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// hostSigners reads the private host keys sshd -T names (hostkey lines),
// keeping those of a type a directory host entry may name (Ed25519,
// ECDSA; an RSA key, which every stock Debian host also has, is skipped,
// since no host entry could name it). A host key held by an agent
// (HostKeyAgent) cannot be read: host_key_unreadable. So is a key of a
// kept type that is not an unencrypted OpenSSH or PEM private key, or
// whose public half does not match its .pub.
func hostSigners(d Dump) ([]ssh.Signer, error) {
	if a := d.One("hostkeyagent"); a != "" && a != "none" {
		return nil, fmt.Errorf("%w: sshd uses host keys held by an agent (HostKeyAgent %s), which keyroster-agent cannot sign with", ErrHostKeyUnreadable, a)
	}
	pubs, err := hostKeys(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHostKeyUnreadable, err)
	}
	var out []ssh.Signer
	for _, p := range d["hostkey"] {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		pubLine, err := readSmall(p+".pub", 16<<10)
		if err != nil {
			return nil, fmt.Errorf("%w: %s.pub: %w", ErrHostKeyUnreadable, p, err)
		}
		f := strings.Fields(string(pubLine))
		if len(f) == 0 || !directory.IsHostKeyType(f[0]) {
			continue
		}
		raw, err := readSmall(p, 64<<10)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrHostKeyUnreadable, p, err)
		}
		s, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrHostKeyUnreadable, p, err)
		}
		if !directory.IsHostKeyType(s.PublicKey().Type()) || !hasPubKey(pubs, s.PublicKey()) {
			return nil, fmt.Errorf("%w: %s does not match its .pub", ErrHostKeyUnreadable, p)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: sshd -T names no Ed25519 or ECDSA host key; a directory host entry can name only those", ErrHostKeyUnreadable)
	}
	if len(out) > directory.MaxHostKeys {
		return nil, fmt.Errorf("%w: sshd -T names %d Ed25519 or ECDSA host keys, above the %d a host entry holds", ErrHostKeyUnreadable, len(out), directory.MaxHostKeys)
	}
	return out, nil
}

func hasPubKey(keys []ssh.PublicKey, k ssh.PublicKey) bool {
	for _, x := range keys {
		if bytes.Equal(x.Marshal(), k.Marshal()) {
			return true
		}
	}
	return false
}

// hostFacts are the facts this host reports: ID and VERSION_ID from
// <root>/etc/os-release (else <root>/usr/lib/os-release) and the kernel's
// host name, each made printable (enroll.SanitizeFact). The sshd version
// is not collected: reading it means running sshd -V, an exec site the
// agent does not have, so it is reported unknown.
func hostFacts(l Layout) enroll.Facts {
	var f enroll.Facts
	for _, p := range []string{filepath.Join(l.Root, "etc", "os-release"), filepath.Join(l.Root, "usr", "lib", "os-release")} {
		b, err := readSmall(p, 64<<10)
		if err != nil {
			continue
		}
		f.OSID, f.OSVersionID = osRelease(b, "ID"), osRelease(b, "VERSION_ID")
		break
	}
	if h, err := os.Hostname(); err == nil {
		f.Hostname = h
	}
	f.OSID, f.OSVersionID, f.Hostname = enroll.SanitizeFact(f.OSID), enroll.SanitizeFact(f.OSVersionID), enroll.SanitizeFact(f.Hostname)
	return f
}

// osRelease returns the value of key in an os-release file, its quotes
// removed.
func osRelease(b []byte, key string) string {
	sc := bufio.NewScanner(io.LimitReader(bytes.NewReader(b), 64<<10))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if ok && k == key {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// CheckStateDirs is the state_dir_unsafe check of every applier start
// (03-05), extended to the outbox (03-07, F2): the state directory, and
// accepted/ and the outbox when they exist, must each be a directory (not
// a symlink) owned by the applier's uid and writable by neither group nor
// others. The outbox's group may read it (2750).
func CheckStateDirs(l Layout) error {
	if err := checkOwnDir(l.StateDir); err != nil {
		return err
	}
	for _, d := range []string{l.State(state.AcceptedDir), l.Outbox()} {
		if err := checkOwnDir(d); err != nil {
			var st unix.Stat_t
			if unix.Lstat(d, &st) != nil && errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
	}
	return nil
}

// Identity is what keyroster-agent identity prints for the approval
// comparison (03-07): the fetcher's TLS identity, as
// enroll.IdentityFingerprint of the SPKI in the spool's identity.pub, and
// the host keys an enrollment signs with (those of a type a directory host
// entry may name, sorted as the proof of possession lists them), each with
// its ssh.FingerprintSHA256. keyroster host approve prints the same
// strings for the pending host.
type Identity struct {
	Agent        string
	HostKeys     []string
	Fingerprints []string
}

// ReadIdentity reads Identity: identity.pub through spool.ReadFileAt
// (empty Agent when the fetcher has not written it yet) and the host keys
// sshd -T names.
func ReadIdentity(ctx context.Context, cfg Config, l Layout) (*Identity, error) {
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	e := &engine{cfg: cfg, l: l, report: &Report{}, stateFd: -1}
	id := &Identity{}
	fd, err := spool.OpenDir(cfg.Spool)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, IdentityFile, enroll.MaxRequestFile)
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, err
	default:
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%s: not one PEM PUBLIC KEY block", IdentityFile)
		}
		sum := sha256.Sum256(block.Bytes)
		id.Agent = enroll.IdentityFingerprint(sum[:])
	}
	dump, err := e.sshdDump(ctx, "")
	if err != nil {
		return nil, err
	}
	pubs, err := hostKeys(dump)
	if err != nil {
		return nil, err
	}
	var kept []ssh.PublicKey
	for _, p := range pubs {
		if directory.IsHostKeyType(p.Type()) {
			kept = append(kept, p)
		}
	}
	id.HostKeys = enroll.SortHostKeys(kept)
	for _, k := range id.HostKeys {
		pub, err := trust.ParseKey(k)
		if err != nil {
			return nil, err
		}
		id.Fingerprints = append(id.Fingerprints, ssh.FingerprintSHA256(pub))
	}
	return id, nil
}
