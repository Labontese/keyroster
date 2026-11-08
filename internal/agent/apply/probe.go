//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	certpkg "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// ErrProbeAccountInvalid is a Config.ProbeAccount outside
// directory.ValidAccountName (03-10b).
var ErrProbeAccountInvalid = errors.New("probe_account_invalid")

// checkProbeAccountName refuses a probe account name that is not a valid
// account name ("" is the default, certpkg.ReservedAccountName).
func checkProbeAccountName(name string) error {
	if name != "" && !directory.ValidAccountName(name) {
		return fmt.Errorf("%w: %w: %q is not a valid account name", ErrConfig, ErrProbeAccountInvalid, name)
	}
	return nil
}

// probesOn reports whether the probe self-test is on: always, but in the
// unit-test harness and the e2e test build's --probe-self-test off.
func (e *engine) probesOn() bool { return !e.cfg.probeOff }

// probeAccount is the probe account's name.
func (e *engine) probeAccount() string {
	if e.cfg.ProbeAccount != "" {
		return e.cfg.ProbeAccount
	}
	return certpkg.ReservedAccountName
}

// fixedPrincipals is the path of the one principals file a generation may
// hold beyond maxAccounts (the probe account's, G21), "" while the probes
// are off.
func (e *engine) fixedPrincipals() string {
	if !e.probesOn() {
		return ""
	}
	return PrincipalsDir + "/" + e.probeAccount()
}

// The probe principals file (03-10b, 'Contracts frozen by this plan').
const (
	probeFileHeader = "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n"
	probeFileHost   = "# probe account, host "
)

// probeFileFor is the probe account's principals file for host: two
// comment lines and the one principal keyroster-probe:<host>.
func probeFileFor(host string) []byte {
	return []byte(probeFileHeader + probeFileHost + host + "\n" + certpkg.ReservedPrincipalPrefix + host + "\n")
}

// isProbeFile reports whether b is exactly a probeFileFor file: the three
// lines and nothing else, the name of line 3 equal to line 2's, and equal
// to host when host is not empty. A file with another principal line, or
// a directory-rendered file, is not one.
func isProbeFile(b []byte, host string) bool {
	rest, ok := bytes.CutPrefix(b, []byte(probeFileHeader+probeFileHost))
	if !ok {
		return false
	}
	name, rest, ok := bytes.Cut(rest, []byte("\n"))
	if !ok || len(name) == 0 || (host != "" && string(name) != host) {
		return false
	}
	return string(rest) == certpkg.ReservedPrincipalPrefix+string(name)+"\n"
}

// isCurProbeFile is isProbeFile for the generation current names, which a
// hold or a settle may have made from an intermediate: it also accepts
// the intermediate header alone and the intermediate header followed by
// exactly one line keyroster-probe:<name> (Intermediate writes its header
// into every principals file).
func isCurProbeFile(b []byte) bool {
	if isProbeFile(b, "") {
		return true
	}
	rest, ok := bytes.CutPrefix(b, []byte(intermediateHeader))
	if !ok {
		return false
	}
	if len(rest) == 0 {
		return true
	}
	line, ok := bytes.CutSuffix(rest, []byte("\n"))
	if !ok || bytes.Contains(line, []byte("\n")) {
		return false
	}
	name, ok := bytes.CutPrefix(line, []byte(certpkg.ReservedPrincipalPrefix))
	return ok && len(name) > 0
}

// addProbeFile adds the probe account's file to g, an active host's
// generation that Render made (03-10b, D4): only while the probes are on,
// never in a trust-only or fallback render (the caller's), and never over
// a file the host group rendered for that account (the gate then holds
// account_is_managed).
func (e *engine) addProbeFile(g *Generation) {
	if !e.probesOn() || g == nil || g.Host == "" {
		return
	}
	name := PrincipalsDir + "/" + e.probeAccount()
	if _, ok := g.Files[name]; ok {
		return
	}
	g.Files[name] = probeFileFor(g.Host)
}

// ProbeReport is what one ProbeCerts run did (03-10b).
type ProbeReport struct {
	// Off: the probe self-test is off; nothing was read or written.
	Off bool `json:"off,omitempty"`
	// Hold is the host-level hold that stopped the step ("" for none),
	// Detail the record's detail after the run.
	Hold   string `json:"hold,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Requested and Kept are the polarities requested and kept this run.
	Requested []string `json:"requested,omitempty"`
	Kept      []string `json:"kept,omitempty"`
	// PairChanged: the committed pair changed (a new pair is usable).
	PairChanged bool `json:"pair_changed,omitempty"`
	// Changed: the step wrote anything.
	Changed bool `json:"changed"`
	// Due is the earliest time the step has something to do again.
	Due time.Time `json:"due"`
}

// ProbeCerts is the probe-certificate issuance step (03-10b, D-06): its own
// entry point under apply.lock, built from HostCerts. After a first
// install it asks for one positive and one negative probe certificate for
// the host's own entry (a fresh Ed25519 key per request, its private half
// cleared once the request is signed and never written), verifies every
// answer field by field (probecert.VerifyCert) before it keeps it in
// <state>/probe.json, keeps the pair in use until a newer pair's negative
// is listed in the KRL in force, and renews at 2/3 of the lifetime. Only
// hostcert.HostHold's host-level holds apply: a pair is requested whatever
// the probe account's state (Planner decisions D5). It never writes
// current, last-good, a generation, accepted/, a trust file or the drop-in,
// and none of its failures is an apply error.
func ProbeCerts(ctx context.Context, cfg Config, l Layout) (*ProbeReport, error) {
	if cfg.probeOff {
		return &ProbeReport{Off: true}, nil
	}
	if err := checkProbeAccountName(cfg.ProbeAccount); err != nil {
		return &ProbeReport{}, err
	}
	if cfg.SelfTestTimeout <= 0 {
		cfg.SelfTestTimeout = 10 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	r := &ProbeReport{}
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: &Report{Errors: []string{}}, stateFd: -1}
	defer func() {
		if e.stateFd >= 0 {
			_ = unix.Close(e.stateFd)
		}
	}()
	err := e.probeCerts(ctx, r)
	return r, err
}

// probeFacts is what one ProbeCerts run reads before it decides.
type probeFacts struct {
	now     time.Time
	rec     *probecert.Record
	in      probecert.Input
	entry   *directory.Host
	signer  ssh.Signer
	install string
}

func (e *engine) probeCerts(ctx context.Context, r *ProbeReport) error {
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
	// No outbox, no fetcher to post a request: nothing to do.
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
	if noGeneration || unfinished {
		// No request before a first install, and nothing while an apply is
		// unfinished: write nothing at all.
		r.Hold = hostcert.HoldNoGeneration
		if !noGeneration {
			r.Hold = hostcert.HoldApplyUnfinished
		}
		return nil
	}
	if e.dump, err = e.sshdDump(ctx, ""); err != nil {
		return err
	}
	if e.keys, err = hostKeys(e.dump); err != nil {
		return err
	}
	st, err := e.readProbeFacts(lg)
	if err != nil {
		return err
	}
	pl := probecert.Decide(st.in)
	if pl.WriteNothing {
		r.Hold = pl.Hold
		return nil
	}
	if pl.Hold != "" {
		r.Hold = pl.Hold
		return e.finishProbeCerts(ctx, st, r, issueDetail(pl.Hold))
	}

	now := uint64(max(st.now.Unix(), 0))
	changed := e.reconcileProbeOutbox(st, now)
	// Answers bound to the applier's own live request IDs.
	for _, pol := range probecert.Polarities {
		ch, err := e.readProbeAnswer(st, pol, now, r)
		if err != nil {
			return err
		}
		changed = changed || ch
	}
	for _, pol := range probecert.Polarities {
		a := st.rec.Attempts.Get(pol)
		if n, _ := a.Abandoned(now); n > 0 {
			probecert.Fail(st.input(), pol, "no_answer")
			changed = true
		}
	}
	if changed {
		if err := e.saveProbeRecord(st.rec); err != nil {
			return err
		}
		if err := e.fault("probe-answer-record"); err != nil {
			return err
		}
		r.Changed = true
	}
	pl = probecert.Decide(st.input())
	switch {
	case pl.Switch:
		st.rec.Committed, st.rec.Next = st.rec.Next, probecert.Pair{}
		r.PairChanged = true
	case pl.DropNext:
		st.rec.Next = probecert.Pair{}
	}
	if pl.Switch || pl.DropNext {
		if err := e.saveProbeRecord(st.rec); err != nil {
			return err
		}
		if err := e.fault("probe-switch"); err != nil {
			return err
		}
		r.Changed = true
	}
	for _, q := range pl.Requests {
		if err := e.requestProbeCert(st, q.Polarity, r); err != nil {
			return err
		}
	}
	e.pruneProbeOutbox(st, now)
	detail := ""
	for _, pol := range probecert.Polarities {
		if d := pl.Defers[pol]; d != "" && d != probecert.DeferPending {
			detail = issueDetail(d)
			break
		}
	}
	r.Due = probeDue(st)
	return e.finishProbeCerts(ctx, st, r, detail)
}

// issueDetail is the record's detail for a hold or defer code:
// probe_issue:<code> with ':' replaced by '_'.
func issueDetail(code string) string {
	return "probe_issue:" + strings.ReplaceAll(code, ":", "_")
}

// finishProbeCerts records the detail and, when the step changed
// something, writes the status under the held lock.
func (e *engine) finishProbeCerts(ctx context.Context, st *probeFacts, r *ProbeReport, detail string) error {
	if detail != "" && !hostcert.CodeRE.MatchString(detail) {
		detail = ""
	}
	r.Detail = detail
	if st.rec.Detail != detail {
		st.rec.Detail = detail
		if err := e.saveProbeRecord(st.rec); err != nil {
			return err
		}
		r.Changed = true
	}
	if !r.Changed {
		return nil
	}
	if _, err := e.publishStatus(ctx, StatusUpdate{}); err != nil {
		e.logf("WARNING probe certificates: status: %v", err)
	}
	return nil
}

// input is st's Decide input with the record's current pairs.
func (st *probeFacts) input() probecert.Input {
	in := st.in
	in.Committed, in.Next, in.Attempts = st.rec.Committed, st.rec.Next, &st.rec.Attempts
	return in
}

// readProbeFacts reads the record and the facts Decide needs: the accepted
// state, the installation, the machine CA keys of the verified bundle, the
// directory entry the served keys name, whether the directory is
// authorized, the committed generation's host status and the KRL of the
// generation current names.
func (e *engine) readProbeFacts(lg link) (*probeFacts, error) {
	st := &probeFacts{now: e.clock.Now(), rec: e.readProbeRecord()}
	stored, err := e.loadStored()
	if err != nil {
		return nil, err
	}
	in := probecert.Input{Now: st.now}
	if rec, err := e.readRecord(lg.n); err == nil && rec != nil {
		in.HostStatus = rec.HostStatus
	}
	if stored != nil && stored.Bundle != nil {
		bundle, err := trust.ParseBundle(stored.Bundle)
		if err != nil {
			return nil, err
		}
		in.Bundle = stored.BundleVersion
		st.install = bundle.InstallationID
		if pol, err := trust.ParsePolicy(stored.Policy); err == nil {
			in.Policy = pol.Version
		}
		if cas, err := krl.RoleCAKeys(bundle, trust.RoleMachine); err == nil {
			for _, b := range cas {
				if pub, err := ssh.ParsePublicKey(b); err == nil {
					in.CAKeys = append(in.CAKeys, pub)
				}
			}
		}
	}
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
				in.KRL = p
			}
		}
	}
	// The host key that signs the requests: the first served key the entry
	// lists that has a signer, by lowest KeySHA256.
	if signers, err := hostSigners(e.dump); err == nil && st.entry != nil {
		slices.SortFunc(signers, func(a, b ssh.Signer) int {
			return strings.Compare(hostcert.KeySHA256(a.PublicKey()), hostcert.KeySHA256(b.PublicKey()))
		})
		for _, s := range signers {
			if slices.Contains(st.entry.Keys, trust.FormatKey(s.PublicKey())) {
				st.signer = s
				break
			}
		}
	}
	st.in = in
	st.in.Committed, st.in.Next, st.in.Attempts = st.rec.Committed, st.rec.Next, &st.rec.Attempts
	return st, nil
}

// readProbeRecord reads <state>/probe.json; a missing or unreadable one
// starts empty.
func (e *engine) readProbeRecord() *probecert.Record {
	b, err := e.readState(probecert.RecordFile, probecert.MaxRecord)
	if err != nil || b == nil {
		return probecert.NewRecord()
	}
	rec, err := probecert.ParseRecord(b)
	if err != nil {
		e.logf("WARNING %s does not parse (%v); starting with no probe certificates", e.l.State(probecert.RecordFile), err)
		return probecert.NewRecord()
	}
	return rec
}

// saveProbeRecord writes <state>/probe.json, 0600, under the lock.
func (e *engine) saveProbeRecord(r *probecert.Record) error {
	b, err := r.Encode()
	if err != nil {
		return err
	}
	return e.writeState(probecert.RecordFile, b)
}

// reconcileProbeOutbox marks consumed a live request whose outbox file is
// missing or names another request: a crash between the attempt and the
// outbox write left it, nothing can post it, and its probe key no longer
// exists, so it is requested again at once. It reports whether it
// changed the attempts.
func (e *engine) reconcileProbeOutbox(st *probeFacts, now uint64) bool {
	changed := false
	for _, pol := range probecert.Polarities {
		p := st.rec.Attempts.Get(pol).Pending(now)
		if p == nil {
			continue
		}
		if outboxProbeID(e.l.Outbox(), pol) != p.ID {
			p.Consumed = true
			changed = true
		}
	}
	return changed
}

// outboxProbeID is the request ID of polarity pol's outbox request, ""
// when there is none or it does not parse.
func outboxProbeID(dir string, pol probecert.Polarity) string {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return ""
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, probecert.RequestFileName(pol), hostcert.MaxOutboxRequest)
	if err != nil {
		return ""
	}
	o, err := hostcert.ParseOutboxRequest(b)
	if err != nil {
		return ""
	}
	req, err := wireProbeID(o.Request)
	if err != nil {
		return ""
	}
	return req
}

// readProbeAnswer reads polarity pol's spool answer: one for a live,
// unconsumed request ID of its attempt is verified (probecert.VerifyCert
// against that request's probe key and the machine CA keys) and kept as
// Next's member of that polarity, or its refusal recorded; the request is
// consumed and its outbox file removed (consumeProbeAnswer). Any other
// answer is ignored.
func (e *engine) readProbeAnswer(st *probeFacts, pol probecert.Polarity, now uint64, r *ProbeReport) (bool, error) {
	sfd, err := spool.OpenDir(e.cfg.Spool)
	if err != nil {
		return false, nil
	}
	defer func() { _ = unix.Close(sfd) }()
	b, err := spool.ReadFileAt(sfd, probecert.AnswerFileName(pol), hostcert.MaxAnswer)
	if err != nil {
		return false, nil
	}
	ans, err := hostcert.ParseAnswer(b)
	if err != nil {
		return false, nil
	}
	a := st.rec.Attempts.Get(pol)
	req := a.Answerable(ans.RequestID, now)
	if req == nil {
		return false, nil
	}
	req.Consumed = true
	if ans.Refused != "" {
		probecert.Fail(st.input(), pol, ans.Refused)
		return true, e.consumeProbeAnswer(st, pol)
	}
	c, err := hostcert.ParseCert(ans.Certificate)
	if err == nil {
		var key ssh.PublicKey
		if key, err = ssh.ParsePublicKey(req.ProbeKey); err == nil {
			name := ""
			if st.entry != nil {
				name = st.entry.Name
			}
			err = probecert.VerifyCert(c, probecert.CertCheck{HostName: name, ProbeKey: key, CAKeys: st.in.CAKeys, Now: st.now})
		}
	}
	if err != nil {
		probecert.Fail(st.input(), pol, probecert.ErrCode(err))
		e.logf("WARNING %s probe certificate answer refused: %v", pol, err)
		return true, e.consumeProbeAnswer(st, pol)
	}
	renew, err := hostcert.RenewAt(c, e.probeRandom())
	if err != nil {
		return false, err
	}
	st.rec.Next.Set(pol, probecert.NewCert(c, renew))
	a.Failures, a.NextAt, a.LastCode = 0, 0, ""
	r.Kept = append(r.Kept, string(pol))
	return true, e.consumeProbeAnswer(st, pol)
}

// consumeProbeAnswer saves probe.json, with the consumed request and the
// kept certificate or recorded refusal, before it removes polarity pol's
// outbox request. Removed first, a crash before the save would leave a
// live request with no outbox file, which reconcileProbeOutbox consumes
// unanswered: a verified certificate would be lost and issuance refused
// as probe_cert_recent for up to an hour, holding additions (PR #91
// review, F4).
func (e *engine) consumeProbeAnswer(st *probeFacts, pol probecert.Polarity) error {
	if err := e.saveProbeRecord(st.rec); err != nil {
		return err
	}
	if err := e.fault("probe-answer-save"); err != nil {
		return err
	}
	return e.removeProbeOutbox(pol)
}

// requestProbeCert builds and signs a request for polarity pol and writes
// it: the record with the new request ID and probe public key first, then
// the outbox request.
func (e *engine) requestProbeCert(st *probeFacts, pol probecert.Polarity, r *ProbeReport) error {
	if st.signer == nil || st.entry == nil || st.install == "" {
		return nil
	}
	keygen := e.cfg.probeKeygen
	if keygen == nil {
		keygen = ed25519.GenerateKey
	}
	req, pub, err := probecert.BuildRequest(st.signer, st.install, st.entry.Name, pol == probecert.Negative, st.now, e.probeRandom(), keygen)
	if err != nil {
		return err
	}
	body, err := req.Marshal()
	if err != nil {
		return err
	}
	st.rec.Attempts.Get(pol).AddRequest(fmt.Sprintf("%x", req.RequestID[:]), req.CreatedAt, pub.Marshal())
	if err := e.saveProbeRecord(st.rec); err != nil {
		return err
	}
	if err := e.fault("probe-request-attempt"); err != nil {
		return err
	}
	out, err := trust.CanonicalJSON(hostcert.OutboxRequest{Request: body})
	if err != nil {
		return err
	}
	if err := e.writeFile(e.l.Outbox(), probecert.RequestFileName(pol), out, 0o640); err != nil {
		return err
	}
	if err := e.fault("probe-request-outbox"); err != nil {
		return err
	}
	r.Requested = append(r.Requested, string(pol))
	r.Changed = true
	return nil
}

// probeRandom is the random source of probe requests.
func (e *engine) probeRandom() io.Reader {
	if e.cfg.probeRand != nil {
		return e.cfg.probeRand
	}
	return rand.Reader
}

// removeProbeOutbox removes polarity pol's outbox request.
func (e *engine) removeProbeOutbox(pol probecert.Polarity) error {
	return e.remove(filepath.Join(e.l.Outbox(), probecert.RequestFileName(pol)))
}

// pruneProbeOutbox removes the outbox request of every polarity with no
// live, unconsumed request.
func (e *engine) pruneProbeOutbox(st *probeFacts, now uint64) {
	for _, pol := range probecert.Polarities {
		if st.rec.Attempts.Get(pol).Pending(now) != nil {
			continue
		}
		if _, err := os.Lstat(filepath.Join(e.l.Outbox(), probecert.RequestFileName(pol))); err == nil {
			_ = e.removeProbeOutbox(pol)
		}
	}
}

// probeDue is the earliest time the step has something to do again: the
// committed pair's renewal or missing threshold, a back-off end, a sticky
// release or a request abandonment, never earlier than now +
// hostcert.BackoffMin.
func probeDue(st *probeFacts) time.Time {
	now := uint64(max(st.now.Unix(), 0))
	var due uint64
	next := func(t uint64) {
		if t > now && (due == 0 || t < due) {
			due = t
		}
	}
	for _, c := range []*probecert.Cert{st.rec.Committed.Positive, st.rec.Committed.Negative, st.rec.Next.Positive, st.rec.Next.Negative} {
		if c == nil {
			continue
		}
		next(c.RenewAt)
		if sc := c.Parse(); sc != nil {
			next(sc.ValidBefore - hostcert.MissingMargin(hostcert.Lifetime(sc)))
		}
	}
	for _, pol := range probecert.Polarities {
		a := st.rec.Attempts.Get(pol)
		next(a.NextAt)
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
	due = max(due, now+hostcert.BackoffMin)
	return time.Unix(int64(min(due, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped
}

// wireProbeID is the request ID of ProbeIssueRequest bytes, in hex.
func wireProbeID(b []byte) (string, error) {
	req, err := wire.ParseProbeIssueRequest(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(req.RequestID[:]), nil
}
