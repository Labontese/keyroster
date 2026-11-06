//go:build linux

package apply

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// HostCertReport is what one HostCerts run did (03-09).
type HostCertReport struct {
	// Hold is the host-level hold that stopped the step ("" for none),
	// Code the record code of wantDropIn ("" for none).
	Hold string `json:"hold,omitempty"`
	Code string `json:"code,omitempty"`
	// Installed, Removed and Requested are the KeySHA256 of the keys whose
	// certificate was installed, whose line was removed and for which a
	// request was written; Deferred maps a key to why it waits.
	Installed []string          `json:"installed,omitempty"`
	Removed   []string          `json:"removed,omitempty"`
	Requested []string          `json:"requested,omitempty"`
	Deferred  map[string]string `json:"deferred,omitempty"`
	// Skipped are the host key types the step does not certify (RSA).
	Skipped []string `json:"skipped,omitempty"`
	// Recovered is set when an unfinished install or a drop-in that
	// differed from the record was rendered again from the committed set.
	Recovered bool `json:"recovered,omitempty"`
	// Changed is set when the step wrote anything.
	Changed bool `json:"changed"`
	// Due is the earliest time the step has something to do again (the
	// zero time for none known).
	Due time.Time `json:"due"`
}

// HostCerts is the host-certificate step (03-09, AGENT-06, D-16, D1): its
// own entry point under apply.lock, as Enroll is. It reads time only
// through cfg.Clock. In order:
//
//  1. Under apply.lock it reads the marker, current and last-good and
//     applies stuck(). When last-good is not the agent's generation
//     (no_generation) or an apply is unfinished (a pending marker,
//     stuck(), or Apply's recover predicate: apply_unfinished), it writes
//     nothing at all, and returns sshd -T's error if sshd -T fails.
//     Otherwise a failing sshd -T gets Apply's pre-repair
//     (preRepairDropInLocked, sshd -T again, activatePreRepair).
//  2. The holds of hostcert.Decide, first. Under a host-level hold only
//     the migration and the recovery run.
//  3. A legacy host's record is created; an unfinished install, or a
//     drop-in that differs from wantDropIn, is rendered again from the
//     committed set (writeDropInSpec, activateDropIn) before anything else.
//  4. Answers bound to the applier's own recent request IDs are verified
//     (hostcert.VerifyAnswer) and kept as immutable certificate files.
//  5. Verified certificate files no answer named are adopted.
//  6. One install batch: the record's candidate, the drop-in, sshd -t,
//     the sshd -T checks, reload, the trust self-test and the
//     served-certificate self-test, then the commit; any failure renders
//     the committed set again.
//  7. Requests for the keys that are due, signed by their host keys.
//  8. GC of certificate files nothing names.
//
// It never writes current, last-good, a generation, accepted/ or a trust
// file, and none of its failures is an apply error.
func HostCerts(ctx context.Context, cfg Config, l Layout) (*HostCertReport, error) {
	if cfg.SelfTestTimeout <= 0 {
		cfg.SelfTestTimeout = 10 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	r := &HostCertReport{Deferred: map[string]string{}}
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: &Report{Errors: []string{}}, stateFd: -1}
	defer func() {
		if e.stateFd >= 0 {
			_ = unix.Close(e.stateFd)
		}
	}()
	err := e.hostCerts(ctx, r)
	return r, err
}

// hostCertState is what one HostCerts run reads before it decides.
type hostCertState struct {
	now      time.Time
	rec      *hostcert.Record
	code     string
	attempts *hostcert.Attempts
	in       hostcert.Input
	entry    *directory.Host
	pins     *state.Pins
	signers  map[string]ssh.Signer // by KeySHA256
	served   map[string]ssh.PublicKey
	certs    map[string]*ssh.Certificate // committed, file present and matching
	install  string                      // installation ID
	caKeys   []ssh.PublicKey
	krl      *krl.Parsed
}

func (e *engine) hostCerts(ctx context.Context, r *HostCertReport) error {
	for _, p := range []string{e.cfg.SSHD, e.cfg.SSHDConfig, e.cfg.SSHKeygen, e.l.Root, e.l.StateDir} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%w: %q is not an absolute path", ErrConfig, p)
		}
	}
	if err := CheckReload(e.cfg.Reload); err != nil {
		return err
	}
	if err := CheckStateDirs(e.l); err != nil {
		return err
	}
	// No outbox, no fetcher to post a request: a host applied by hand
	// without enrollment gets no host certificate, and nothing is written.
	if _, err := os.Lstat(e.l.Outbox()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	fd, err := spool.OpenDir(e.l.StateDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	e.stateFd = fd
	if e.pins, err = state.LoadPins(e.stateFd); err != nil {
		return err
	}
	unlock, err := e.lock()
	if err != nil {
		return err
	}
	defer unlock()
	e.locked = true

	// 1. The marker, current, last-good and stuck(), before any write or
	// pre-repair (Apply's order).
	m, err := e.loadMarker()
	if err != nil {
		return err
	}
	cur, err := e.resolveLink(e.l.Current())
	if err != nil {
		return err
	}
	lg, err := e.resolveLink(e.l.LastGood())
	if err != nil {
		return err
	}
	noGeneration := lg.kind != linkAgent
	unfinished := m != nil || stuck(m, cur, lg) != nil ||
		(cur.kind == linkAgent && lg.kind == linkAgent && cur.n != lg.n && !atRollbackTarget(cur, lg))
	if e.dump, err = e.sshdDump(ctx, ""); err != nil {
		if noGeneration || unfinished {
			return err
		}
		same, derr := e.dropInIsWanted()
		if derr != nil {
			return errors.Join(err, derr)
		}
		if same {
			return err
		}
		if perr := e.preRepairDropInLocked(); perr != nil {
			return errors.Join(err, perr)
		}
		r.Changed = true
		if e.dump, err = e.sshdDump(ctx, ""); err != nil {
			return err
		}
		if e.keys, err = hostKeys(e.dump); err != nil {
			return err
		}
		if err := e.activatePreRepair(ctx); err != nil {
			return err
		}
	}
	if e.keys, err = hostKeys(e.dump); err != nil {
		return err
	}
	if noGeneration || unfinished {
		r.Hold = hostcert.HoldNoGeneration
		if !noGeneration {
			r.Hold = hostcert.HoldApplyUnfinished
		}
		return nil
	}

	st, err := e.readHostCertState(ctx, lg)
	if err != nil {
		return err
	}
	r.Code = st.code
	actions := hostcert.Decide(st.in)
	hold := ""
	if len(actions) == 1 && actions[0].Kind == hostcert.Hold {
		hold = actions[0].Code
		r.Hold = hold
		if actions[0].WriteNothing {
			return nil
		}
	}
	for _, p := range e.keys {
		if hostcert.CertAlgorithm(p) == "" {
			r.Skipped = append(r.Skipped, p.Type())
		}
	}

	// 3. Migration, then recovery from the committed set.
	if st.rec == nil && st.code == "" {
		st.rec = &hostcert.Record{Version: hostcert.RecordVersion, Committed: []hostcert.Entry{}, Candidate: []hostcert.Entry{}}
		if err := e.saveHostCertRecord(st.rec); err != nil {
			return err
		}
		e.logf("hostcert_record_created: %s", e.l.State(hostcert.RecordFile))
		r.Changed = true
	}
	if err := e.recoverHostCerts(ctx, st, r); err != nil {
		return err
	}
	if hold != "" {
		return e.finishHostCerts(ctx, st, r)
	}

	now := uint64(max(st.now.Unix(), 0))
	defers := map[string]string{}
	for _, a := range actions {
		if a.Kind == hostcert.Defer {
			defers[a.Key] = a.Code
			r.Deferred[a.Key] = a.Code
		}
	}

	// 4. Answers, for every key the entry lists and sshd serves.
	changedAttempts := false
	for k, pub := range st.served {
		ch, err := e.readHostCertAnswer(st, k, pub, now)
		if err != nil {
			return err
		}
		changedAttempts = changedAttempts || ch
	}
	// Requests no answer came for in time are abandoned, as transient
	// failures (one whose outbox file was never written included).
	for i := range st.attempts.Keys {
		a := &st.attempts.Keys[i]
		if n, created := a.Abandoned(now); n > 0 {
			e.hostCertFailure(st, a, "no_answer", min(created, now))
			changedAttempts = true
		}
	}
	// 5. Adoption of verified files for keys with nothing installable.
	for k, pub := range st.served {
		a := st.attempts.Lookup(k)
		if a != nil && a.KeptFile != "" {
			continue
		}
		if f := e.adoptHostCert(st, k, pub); f != "" {
			st.attempts.Get(k).KeptFile = f
			changedAttempts = true
		}
	}
	if changedAttempts {
		if err := e.saveHostCertAttempts(st.attempts); err != nil {
			return err
		}
		r.Changed = true
	}

	// 6. One install batch.
	if err := e.installHostCerts(ctx, st, actions, defers, r); err != nil {
		if isCrash(err) {
			return err
		}
		e.logf("ERROR host certificates: install: %v", err)
	}

	// 7. Requests.
	actions = hostcert.Decide(e.refreshInput(st))
	for _, a := range actions {
		switch a.Kind {
		case hostcert.Request:
			if err := e.requestHostCert(st, a, r); err != nil {
				return err
			}
		case hostcert.Defer:
			r.Deferred[a.Key] = a.Code
		}
	}
	e.pruneOutbox(st)

	// 8. GC.
	if st.code == "" {
		if err := e.gcHostCerts(st); err != nil {
			return err
		}
	}
	r.Due = hostCertDue(st)
	return e.finishHostCerts(ctx, st, r)
}

// finishHostCerts records the skipped key types and the last code in the
// attempts file and, whenever the step changed something, writes
// status.json under the held lock (publishStatus, as publishPending does;
// never WriteStatus, which would take apply.lock again).
func (e *engine) finishHostCerts(ctx context.Context, st *hostCertState, r *HostCertReport) error {
	detail := r.Hold
	if detail == "" {
		detail = r.Code
	}
	if detail == "" {
		for _, k := range slices.Sorted(maps.Keys(r.Deferred)) {
			if c := r.Deferred[k]; c != hostcert.DeferPending {
				detail = c
				break
			}
		}
	}
	if detail != "" && !hostcert.CodeRE.MatchString(detail) {
		detail = ""
	}
	skipped := slices.Clone(r.Skipped)
	slices.Sort(skipped)
	skipped = slices.Compact(skipped)
	if len(skipped) > hostcert.MaxSkipped {
		skipped = skipped[:hostcert.MaxSkipped]
	}
	if st.attempts.Detail != detail || !slices.Equal(st.attempts.Skipped, skipped) {
		st.attempts.Detail, st.attempts.Skipped = detail, skipped
		if err := e.saveHostCertAttempts(st.attempts); err != nil {
			return err
		}
		r.Changed = true
	}
	if !r.Changed {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(e.l.Outbox())); err != nil {
		return nil
	}
	if _, err := e.publishStatus(ctx, StatusUpdate{}); err != nil {
		e.logf("WARNING host certificates: status: %v", err)
	}
	return nil
}

// readHostCertState reads the record, the attempts, the accepted state and
// the facts Decide needs.
func (e *engine) readHostCertState(ctx context.Context, lg link) (*hostCertState, error) {
	st := &hostCertState{now: e.clock.Now(), pins: e.pins, signers: map[string]ssh.Signer{}, served: map[string]ssh.PublicKey{}, certs: map[string]*ssh.Certificate{}}
	var err error
	if st.rec, st.code, err = e.readHostCertRecord(); err != nil {
		return nil, err
	}
	if st.attempts, err = e.readHostCertAttempts(); err != nil {
		return nil, err
	}
	stored, err := e.loadStored()
	if err != nil {
		return nil, err
	}
	in := hostcert.Input{Now: st.now, Attempts: st.attempts}
	if rec, err := e.readRecord(lg.n); err == nil && rec != nil {
		in.HostStatus = rec.HostStatus
	}
	var bundle *trust.Bundle
	if stored != nil && stored.Bundle != nil {
		if bundle, err = trust.ParseBundle(stored.Bundle); err != nil {
			return nil, err
		}
		in.Bundle = stored.BundleVersion
		st.install = bundle.InstallationID
		if pol, err := trust.ParsePolicy(stored.Policy); err == nil {
			in.Policy = pol.Version
		}
		if cas, err := krl.RoleCAKeys(bundle, trust.RoleHost); err == nil {
			for _, b := range cas {
				if pub, err := ssh.ParsePublicKey(b); err == nil {
					st.caKeys = append(st.caKeys, pub)
				}
			}
		}
	}
	in.CAKeys = st.caKeys
	if stored != nil && stored.Directory != nil {
		in.Directory = stored.DirectoryVersion
		in.Authorized = stored.DirectoryUnderPolicy() == nil
		if d, err := directory.Parse(stored.Directory); err == nil {
			for _, k := range e.keys {
				if h, ok := d.HostForKey(k); ok {
					st.entry = h
					break
				}
			}
		}
	}
	in.Entry = st.entry
	if g, curLink, err := e.readCurrent(); err == nil && curLink.kind == linkAgent && g != nil {
		if b := g.Files[KRLFile]; b != nil {
			if p, err := krl.Parse(b); err == nil {
				st.krl = p
			}
		}
	}
	in.KRL = st.krl
	signers, err := hostSigners(e.dump)
	if err == nil {
		for _, s := range signers {
			st.signers[hostcert.KeySHA256(s.PublicKey())] = s
		}
	}
	for _, p := range e.keys {
		if hostcert.CertAlgorithm(p) == "" {
			continue
		}
		in.Served = append(in.Served, p)
		if st.entry != nil && slices.Contains(st.entry.Keys, trust.FormatKey(p)) {
			st.served[hostcert.KeySHA256(p)] = p
		}
	}
	if algs := e.dump.One("hostkeyalgorithms"); algs != "" {
		in.HostKeyAlgorithms = strings.Split(algs, ",")
	}
	files, _ := configGraph(e.l, e.cfg.SSHDConfig, nil)
	in.InMatch = dropInInMatch(e.l, files) || st.code == CodeHostCertInMatch
	in.Foreign = foreignHostCertificate(e.l, files)
	if st.rec != nil {
		in.Committed = st.rec.Committed
		for _, en := range st.rec.Committed {
			if c := e.readCertFile(en.File, en.CertSHA256); c != nil {
				st.certs[en.KeySHA256] = c
			}
		}
	}
	in.Installed = st.certs
	st.in = in
	_ = ctx
	return st, nil
}

// refreshInput is st's Decide input after the install batch.
func (e *engine) refreshInput(st *hostCertState) hostcert.Input {
	in := st.in
	in.Attempts = st.attempts
	if st.rec != nil {
		in.Committed = st.rec.Committed
	}
	in.Installed = st.certs
	return in
}

// foreignHostCertificate reports a HostCertificate directive in any file
// sshd reads but the agent's drop-in (03-09, D1): reported, never edited,
// and it holds all host-certificate work.
func foreignHostCertificate(l Layout, files []configFile) bool {
	for _, f := range files {
		if f.path == l.DropIn() {
			continue
		}
		for _, ln := range f.lines {
			if ln.keyword == hostCertificateKeyword {
				return true
			}
		}
	}
	return false
}

// readCertFile reads a certificate file of the host-certificate directory
// whose SHA-256 must be sum, nil when it is missing, not a regular file,
// or differs.
func (e *engine) readCertFile(name, sum string) *ssh.Certificate {
	fd, err := spool.OpenDir(e.l.HostCertDir())
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, name, hostcert.MaxAnswer)
	if err != nil {
		return nil
	}
	c, raw, err := parseCertFile(b)
	if err != nil || (sum != "" && trust.SHA256Hex(raw) != sum) {
		return nil
	}
	return c
}

// parseCertFile parses a certificate file (one authorized_keys line) and
// returns the certificate and its SSH wire bytes.
func parseCertFile(b []byte) (*ssh.Certificate, []byte, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, nil, err
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, nil, errors.New("not a certificate")
	}
	return c, c.Marshal(), nil
}

// certFileBytes is the file a certificate is kept as: one
// authorized_keys line.
func certFileBytes(c *ssh.Certificate) []byte { return ssh.MarshalAuthorizedKey(c) }

// answerCheck is VerifyAnswer's input for key pub in st.
func (st *hostCertState) answerCheck(pub ssh.PublicKey) hostcert.AnswerCheck {
	committed := uint64(0)
	if en := hostcert.Find(st.in.Committed, hostcert.KeySHA256(pub)); en != nil {
		committed = en.Serial
	}
	name := ""
	var principals []string
	if st.entry != nil {
		name, principals = st.entry.Name, st.entry.Principals
	}
	return hostcert.AnswerCheck{Key: pub, HostName: name, Principals: principals, CAKeys: st.caKeys, KRL: st.krl, Committed: committed, Now: st.now}
}

// readHostCertAnswer reads key k's spool answer: one for an unconsumed,
// live request ID of k's is verified and its certificate kept as a file
// (write and fsync it and its directory, save the attempts with KeptFile
// and the request consumed, remove the outbox request), or its refusal
// recorded. Any other answer is ignored. It reports whether the attempts
// changed (the caller saves them).
func (e *engine) readHostCertAnswer(st *hostCertState, k string, pub ssh.PublicKey, now uint64) (bool, error) {
	sfd, err := spool.OpenDir(e.cfg.Spool)
	if err != nil {
		return false, nil
	}
	defer func() { _ = unix.Close(sfd) }()
	b, err := spool.ReadFileAt(sfd, hostcert.AnswerFileName(k), hostcert.MaxAnswer)
	if err != nil {
		return false, nil
	}
	ans, err := hostcert.ParseAnswer(b)
	if err != nil {
		return false, nil
	}
	a := st.attempts.Lookup(k)
	if a == nil {
		return false, nil
	}
	req := a.Answerable(ans.RequestID, now)
	if req == nil {
		return false, nil
	}
	if ans.Refused != "" {
		req.Consumed = true
		e.hostCertFailure(st, a, ans.Refused, now)
		return true, e.removeOutboxRequest(k)
	}
	c, err := hostcert.ParseCert(ans.Certificate)
	if err == nil {
		err = hostcert.VerifyAnswer(c, st.answerCheck(pub))
	}
	if err != nil {
		req.Consumed = true
		e.hostCertFailure(st, a, hostcert.Code(err), now)
		e.logf("WARNING host certificate answer for %s refused: %v", ssh.FingerprintSHA256(pub), err)
		return true, e.removeOutboxRequest(k)
	}
	name := hostcert.CertFileName(k, c.Serial)
	if err := e.writeCertFile(name, c); err != nil {
		return false, err
	}
	if err := e.fault("hostcert-answer-file"); err != nil {
		return false, err
	}
	req.Consumed = true
	a.KeptFile = name
	if err := e.saveHostCertAttempts(st.attempts); err != nil {
		return false, err
	}
	if err := e.fault("hostcert-answer-attempts"); err != nil {
		return false, err
	}
	if err := e.removeOutboxRequest(k); err != nil {
		return false, err
	}
	if err := e.fault("hostcert-answer-outbox"); err != nil {
		return false, err
	}
	return true, nil
}

// hostCertFailure records a failed attempt for a: a sticky hold for a
// detail on Q-09-7's closed list, else a transient failure with back-off.
func (e *engine) hostCertFailure(st *hostCertState, a *hostcert.Attempt, code string, now uint64) {
	a.LastCode = code
	if hostcert.IsSticky(code) {
		a.Sticky = &hostcert.StickyHold{Code: code, Bundle: st.in.Bundle, Policy: st.in.Policy, Directory: st.in.Directory, At: now}
		return
	}
	a.NextAt, a.Failures = hostcert.NextBackoff(now, a.Failures+1, st.certs[a.KeySHA256])
}

// writeCertFile writes a certificate file into the host-certificate
// directory (0755), mode 0644, and fsyncs it and the directory.
func (e *engine) writeCertFile(name string, c *ssh.Certificate) error {
	if err := e.mkdirMode(e.l.HostCertDir(), 0o755); err != nil {
		return err
	}
	return e.writeFile(e.l.HostCertDir(), name, certFileBytes(c), 0o644)
}

// adoptHostCert returns the best (highest serial) certificate file of key
// k above the committed serial that passes VerifyAnswer, "" for none.
func (e *engine) adoptHostCert(st *hostCertState, k string, pub ssh.PublicKey) string {
	ents, err := os.ReadDir(e.l.HostCertDir())
	if err != nil {
		return ""
	}
	best, bestSerial := "", uint64(0)
	check := st.answerCheck(pub)
	for _, d := range ents {
		m := hostcert.CertFileRE.FindStringSubmatch(d.Name())
		if m == nil || m[1] != k || !d.Type().IsRegular() {
			continue
		}
		c := e.readCertFile(d.Name(), "")
		if c == nil || hostcert.CertFileName(k, c.Serial) != d.Name() || hostcert.VerifyAnswer(c, check) != nil {
			continue
		}
		if c.Serial > bestSerial {
			best, bestSerial = d.Name(), c.Serial
		}
	}
	return best
}

// recoverHostCerts renders the committed set again (03-09, D1) when the
// record is InProgress or the drop-in differs from wantDropIn: it writes
// wantDropIn().Spec and runs activateDropIn with it (sshd -t, the sshd -T
// checks, reload), and only then clears InProgress.
func (e *engine) recoverHostCerts(ctx context.Context, st *hostCertState, r *HostCertReport) error {
	inProgress := st.rec != nil && st.rec.InProgress
	same, err := e.dropInIsWanted()
	if err != nil {
		return err
	}
	if !inProgress && same {
		return nil
	}
	w, err := e.wantDropIn()
	if err != nil {
		return err
	}
	if err := e.writeDropInSpec(w.Spec); err != nil {
		return err
	}
	if err := e.activateDropIn(ctx, w.Spec); err != nil {
		return err
	}
	r.Recovered, r.Changed = true, true
	if inProgress {
		st.rec.InProgress, st.rec.Candidate = false, []hostcert.Entry{}
		if err := e.saveHostCertRecord(st.rec); err != nil {
			return err
		}
	}
	e.logf("host certificates: rendered the committed set again (%d lines)", len(w.Spec.HostCertificates))
	return nil
}

// installHostCerts is the install batch (D1's order): every key with a
// kept, verified certificate that is not deferred by its algorithm, and
// every Remove action, in one candidate.
func (e *engine) installHostCerts(ctx context.Context, st *hostCertState, actions []hostcert.Action, defers map[string]string, r *HostCertReport) error {
	if st.rec == nil {
		if !e.refillHostCertRecord(st, defers) {
			return nil
		}
	}
	cand := slices.Clone(st.rec.Committed)
	var installed, removed []string
	var certs []*ssh.Certificate
	for _, a := range actions {
		if a.Kind == hostcert.Remove {
			cand = slices.DeleteFunc(cand, func(en hostcert.Entry) bool { return en.KeySHA256 == a.Key })
			removed = append(removed, a.Key)
		}
	}
	for k, pub := range st.served {
		at := st.attempts.Lookup(k)
		if at == nil || at.KeptFile == "" || defers[k] == hostcert.DeferAlgorithmDisabled {
			continue
		}
		c := e.readCertFile(at.KeptFile, "")
		if c == nil || hostcert.VerifyAnswer(c, st.answerCheck(pub)) != nil {
			at.KeptFile = ""
			continue
		}
		en, err := hostcert.NewEntry(pub, c, c.Marshal(), rand.Reader)
		if err != nil {
			return err
		}
		cand = slices.DeleteFunc(cand, func(x hostcert.Entry) bool { return x.KeySHA256 == k })
		cand = append(cand, en)
		installed = append(installed, k)
	}
	if len(installed) == 0 && len(removed) == 0 {
		return nil
	}
	hostcert.SortEntries(cand)
	for _, en := range cand {
		if c := e.readCertFile(en.File, ""); c != nil {
			certs = append(certs, c)
		}
	}
	st.rec.InProgress, st.rec.Candidate = true, cand
	if err := e.saveHostCertRecord(st.rec); err != nil {
		return err
	}
	r.Changed = true
	if err := e.fault("hostcert-candidate"); err != nil {
		return err
	}
	spec := specOf(e.l.HostCertDir(), cand)
	err := e.activateCandidate(ctx, spec, certs, cand, st)
	if err != nil {
		if isCrash(err) {
			return err
		}
		if rerr := e.rollbackHostCerts(ctx, st); rerr != nil {
			return errors.Join(err, rerr)
		}
		now := uint64(max(st.now.Unix(), 0))
		for _, k := range installed {
			e.hostCertFailure(st, st.attempts.Get(k), "install_failed", now)
		}
		_ = e.saveHostCertAttempts(st.attempts)
		return err
	}
	if err := e.fault("hostcert-commit"); err != nil {
		return err
	}
	for _, k := range installed {
		at := st.attempts.Get(k)
		at.KeptFile, at.Failures, at.NextAt, at.Sticky, at.LastCode = "", 0, 0, nil, ""
	}
	if err := e.saveHostCertAttempts(st.attempts); err != nil {
		return err
	}
	r.Installed, r.Removed = installed, removed
	st.certs = map[string]*ssh.Certificate{}
	for _, en := range st.rec.Committed {
		if c := e.readCertFile(en.File, en.CertSHA256); c != nil {
			st.certs[en.KeySHA256] = c
		}
	}
	return nil
}

// refillHostCertRecord starts a new, empty record under a record code
// (hostcert_record_missing or hostcert_record_invalid) when adoption found
// a verified file to install: the empty spec the code left is refilled
// from files that pass VerifyAnswer (03-09). An invalid record is set
// aside first, never followed or parsed again. With nothing to install it
// leaves the record as it is, so the code, and GC's skip, stay.
func (e *engine) refillHostCertRecord(st *hostCertState, defers map[string]string) bool {
	if st.code != CodeHostCertRecordMissing && st.code != CodeHostCertRecordInvalid {
		return false
	}
	installable := false
	for k := range st.served {
		if at := st.attempts.Lookup(k); at != nil && at.KeptFile != "" && defers[k] != hostcert.DeferAlgorithmDisabled {
			installable = true
		}
	}
	if !installable {
		return false
	}
	if st.code == CodeHostCertRecordInvalid {
		if err := e.setAsideHostCertRecord(); err != nil {
			e.logf("ERROR host certificates: set aside %s: %v", hostcert.RecordFile, err)
			return false
		}
	}
	st.rec = &hostcert.Record{Version: hostcert.RecordVersion, Committed: []hostcert.Entry{}, Candidate: []hostcert.Entry{}}
	e.logf("host certificates: %s: refilling the record from verified files", st.code)
	return true
}

// setAsideHostCertRecord renames an invalid record (whatever its type: a
// symlink is renamed, not followed) to hostcert.json.invalid in the state
// directory, replacing an earlier one.
func (e *engine) setAsideHostCertRecord() error {
	aside := hostcert.RecordFile + ".invalid"
	if err := unix.Unlinkat(e.stateFd, aside, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		if err := unix.Unlinkat(e.stateFd, aside, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	if err := unix.Renameat(e.stateFd, hostcert.RecordFile, e.stateFd, aside); err != nil {
		return err
	}
	return unix.Fsync(e.stateFd)
}

// activateCandidate writes the candidate drop-in, checks and reloads it,
// self-tests, and commits the record with Served from the
// served-certificate self-test.
func (e *engine) activateCandidate(ctx context.Context, spec DropInSpec, certs []*ssh.Certificate, cand []hostcert.Entry, st *hostCertState) error {
	if err := e.writeDropInSpec(spec); err != nil {
		return err
	}
	if err := e.fault("hostcert-dropin"); err != nil {
		return err
	}
	if err := e.activateDropIn(ctx, spec); err != nil {
		return err
	}
	if err := e.fault("hostcert-reload"); err != nil {
		return err
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		return err
	}
	served, err := e.hostCertSelfTest(ctx, e.dump, certs)
	if err != nil {
		return err
	}
	if err := e.fault("hostcert-selftest"); err != nil {
		return err
	}
	for i := range cand {
		cand[i].Served = served[cand[i].KeySHA256]
	}
	st.rec.Committed, st.rec.InProgress, st.rec.Candidate = cand, false, []hostcert.Entry{}
	return e.saveHostCertRecord(st.rec)
}

// rollbackHostCerts renders the committed set again after a failed
// install: writeDropInSpec and activateDropIn with wantDropIn().Spec (the
// record is still InProgress, so wantDropIn reads its committed set), then
// InProgress is cleared. It never touches current, last-good or a
// generation.
func (e *engine) rollbackHostCerts(ctx context.Context, st *hostCertState) error {
	w, err := e.wantDropIn()
	if err != nil {
		return err
	}
	if err := e.writeDropInSpec(w.Spec); err != nil {
		return err
	}
	if err := e.fault("hostcert-rollback-dropin"); err != nil {
		return err
	}
	if err := e.activateDropIn(ctx, w.Spec); err != nil {
		return err
	}
	if err := e.fault("hostcert-rollback-reload"); err != nil {
		return err
	}
	st.rec.InProgress, st.rec.Candidate = false, []hostcert.Entry{}
	return e.saveHostCertRecord(st.rec)
}

// requestHostCert builds and signs a request for a.Key and writes it: the
// attempts file with the new request ID first, then the outbox request.
func (e *engine) requestHostCert(st *hostCertState, a hostcert.Action, r *HostCertReport) error {
	s := st.signers[a.Key]
	if s == nil || st.entry == nil || st.install == "" {
		r.Deferred[a.Key] = "host_key_unreadable"
		return nil
	}
	req, err := hostcert.BuildRequest(s, st.install, st.entry.Name, st.now, rand.Reader)
	if err != nil {
		return err
	}
	body, err := req.Marshal()
	if err != nil {
		return err
	}
	at := st.attempts.Get(a.Key)
	at.AddRequest(fmt.Sprintf("%x", req.RequestID[:]), req.CreatedAt)
	if err := e.saveHostCertAttempts(st.attempts); err != nil {
		return err
	}
	if err := e.fault("hostcert-request"); err != nil {
		return err
	}
	out, err := trust.CanonicalJSON(hostcert.OutboxRequest{Request: body})
	if err != nil {
		return err
	}
	if err := e.writeFile(e.l.Outbox(), hostcert.RequestFileName(a.Key), out, 0o640); err != nil {
		return err
	}
	r.Requested = append(r.Requested, a.Key)
	r.Changed = true
	return nil
}

// removeOutboxRequest removes key k's outbox request.
func (e *engine) removeOutboxRequest(k string) error {
	return e.remove(filepath.Join(e.l.Outbox(), hostcert.RequestFileName(k)))
}

// pruneOutbox removes the outbox request of every key with no live,
// unconsumed request.
func (e *engine) pruneOutbox(st *hostCertState) {
	now := uint64(max(st.now.Unix(), 0))
	ents, err := os.ReadDir(e.l.Outbox())
	if err != nil {
		return
	}
	for _, d := range ents {
		m := hostcert.RequestFileRE.FindStringSubmatch(d.Name())
		if m == nil {
			continue
		}
		if a := st.attempts.Lookup(m[1]); a != nil && a.Pending(now) != nil {
			continue
		}
		_ = e.removeOutboxRequest(m[1])
	}
}

// gcHostCerts removes the regular certificate files of the host directory
// that nothing names: not the committed set, not a KeptFile and not the
// drop-in on disk. Symlinks are never followed.
func (e *engine) gcHostCerts(st *hostCertState) error {
	keep := map[string]bool{}
	if st.rec != nil {
		for _, en := range st.rec.Committed {
			keep[en.File] = true
		}
		for _, en := range st.rec.Candidate {
			keep[en.File] = true
		}
	}
	for _, a := range st.attempts.Keys {
		if a.KeptFile != "" {
			keep[a.KeptFile] = true
		}
	}
	if b, err := e.readDropIn(); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if p, ok := strings.CutPrefix(l, "HostCertificate "); ok && filepath.Dir(p) == e.l.HostCertDir() {
				keep[filepath.Base(p)] = true
			}
		}
	}
	ents, err := os.ReadDir(e.l.HostCertDir())
	if err != nil {
		return nil
	}
	for _, d := range ents {
		if !d.Type().IsRegular() || !hostcert.CertFileRE.MatchString(d.Name()) || keep[d.Name()] {
			continue
		}
		if err := e.fault("hostcert-gc"); err != nil {
			return err
		}
		if err := e.remove(filepath.Join(e.l.HostCertDir(), d.Name())); err != nil {
			return err
		}
	}
	return nil
}

// hostCertDue is the earliest time the step has something to do again:
// the next renewal or missing threshold, back-off, sticky release or
// request abandonment.
func hostCertDue(st *hostCertState) time.Time {
	var due uint64
	next := func(t uint64) {
		if t != 0 && (due == 0 || t < due) {
			due = t
		}
	}
	// A key that waits (a live request, a back-off or a sticky hold) is
	// due when its wait ends, not at a renewal threshold already passed:
	// otherwise the run loop would call the step every iteration while an
	// answer is outstanding.
	now := uint64(max(st.now.Unix(), 0))
	waiting := map[string]bool{}
	for _, a := range st.attempts.Keys {
		w := a.NextAt > now || (a.Sticky != nil && a.Sticky.At+hostcert.StickyRelease > now && a.Sticky.At <= now+3600)
		for _, p := range a.Requests {
			w = w || (!p.Consumed && p.CreatedAt+hostcert.RequestTTL > now)
		}
		waiting[a.KeySHA256] = w
	}
	if st.rec != nil {
		for _, en := range st.rec.Committed {
			threshold := func(t uint64) {
				if t > now || !waiting[en.KeySHA256] {
					next(t)
				}
			}
			threshold(en.RenewAt)
			if c := st.certs[en.KeySHA256]; c != nil {
				threshold(c.ValidBefore - hostcert.MissingMargin(hostcert.Lifetime(c)))
			}
		}
	}
	for _, a := range st.attempts.Keys {
		if a.NextAt > now || !waiting[a.KeySHA256] {
			next(a.NextAt)
		}
		if a.Sticky != nil {
			next(a.Sticky.At + hostcert.StickyRelease)
		}
		for _, p := range a.Requests {
			if !p.Consumed {
				next(p.CreatedAt + hostcert.RequestTTL)
			}
		}
	}
	if due == 0 {
		return time.Time{}
	}
	return time.Unix(int64(min(due, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped
}

// readHostCertAttempts reads <state>/hostcert-attempts.json; a missing or
// unreadable one starts empty.
func (e *engine) readHostCertAttempts() (*hostcert.Attempts, error) {
	b, err := e.readState(hostcert.AttemptsFile, hostcert.MaxAttempts)
	if err != nil || b == nil {
		return &hostcert.Attempts{Version: hostcert.AttemptsVersion, Keys: []hostcert.Attempt{}}, nil
	}
	a, err := hostcert.ParseAttempts(b)
	if err != nil {
		e.logf("WARNING %s does not parse (%v); starting with no attempts", e.l.State(hostcert.AttemptsFile), err)
		return &hostcert.Attempts{Version: hostcert.AttemptsVersion, Keys: []hostcert.Attempt{}}, nil
	}
	return a, nil
}

// saveHostCertAttempts writes the attempts file, 0600.
func (e *engine) saveHostCertAttempts(a *hostcert.Attempts) error {
	b, err := a.Encode()
	if err != nil {
		return err
	}
	return e.writeState(hostcert.AttemptsFile, b)
}

// saveHostCertRecord writes the record, 0600 (temp+rename under the lock).
func (e *engine) saveHostCertRecord(r *hostcert.Record) error {
	b, err := r.Encode()
	if err != nil {
		return err
	}
	return e.writeState(hostcert.RecordFile, b)
}
