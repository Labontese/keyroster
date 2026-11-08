//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	certpkg "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// probeHost is a testHost with the probe self-test on and an outbox
// (03-10b), and a stand-in machine CA that answers probe requests.
type probeHost struct {
	*testHost
	serial   uint64
	lifetime uint64
}

func newProbeHost(t *testing.T) *probeHost {
	t.Helper()
	h := &probeHost{testHost: newTestHost(t, newFixture(t)), serial: 1_794_000_000_000_000, lifetime: 600}
	h.cfg.probeOff = false
	h.cfg.SelfTestTimeout = time.Second
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *probeHost) probeCerts() (*ProbeReport, error) {
	h.t.Helper()
	return ProbeCerts(context.Background(), h.cfg, h.l)
}

func (h *probeHost) mustProbeCerts() *ProbeReport {
	h.t.Helper()
	r, err := h.probeCerts()
	if err != nil {
		h.t.Fatalf("ProbeCerts: %v (report %+v)", err, r)
	}
	return r
}

// record reads <state>/probe.json (nil when absent).
func (h *probeHost) record() *probecert.Record {
	h.t.Helper()
	b, err := os.ReadFile(h.l.State(probecert.RecordFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	r, err := probecert.ParseRecord(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

// outbox reads the outbox probe requests by polarity.
func (h *probeHost) outbox() map[probecert.Polarity]*wire.ProbeIssueRequest {
	h.t.Helper()
	out := map[probecert.Polarity]*wire.ProbeIssueRequest{}
	for _, pol := range probecert.Polarities {
		b, err := os.ReadFile(filepath.Join(h.l.Outbox(), probecert.RequestFileName(pol)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			h.t.Fatal(err)
		}
		o, err := hostcert.ParseOutboxRequest(b)
		if err != nil {
			h.t.Fatal(err)
		}
		req, err := wire.ParseProbeIssueRequest(o.Request)
		if err != nil {
			h.t.Fatal(err)
		}
		out[pol] = req
	}
	return out
}

// issueFor is the probe certificate the machine CA would issue for req at
// the fake clock's time, with key and principal overridable.
func (h *probeHost) issueFor(req *wire.ProbeIssueRequest, key ssh.PublicKey) *ssh.Certificate {
	h.t.Helper()
	if key == nil {
		k, err := ssh.ParsePublicKey(req.ProbeKey)
		if err != nil {
			h.t.Fatal(err)
		}
		key = k
	}
	h.serial++
	c, err := certpkg.Build(certpkg.Request{
		Profile: certpkg.Profile{CertType: ssh.UserCert, MaxTTL: 7 * 24 * time.Hour, DefaultExtensions: map[string]string{},
			AllowedCriticalOptions: []string{"force-command", "source-address"}, ReservedPrincipals: true},
		Subject: key, Principals: []string{certpkg.ReservedPrincipalPrefix + "web1"}, Now: h.clock.Now(),
		ValidFor: time.Duration(h.lifetime) * time.Second, Serial: h.serial, //nolint:gosec // G115: a test lifetime
		KeyID:           certpkg.KeyID{V3: true, CA: "machine", Subject: "probe.web1", Request: strings.Repeat("cd", 16), Policy: 1, Directory: 1, Serial: h.serial},
		CriticalOptions: certprofile.ProbeCriticalOptions()}, h.f.mach, rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// writeProbeAnswer writes polarity pol's spool answer.
func (h *probeHost) writeProbeAnswer(pol probecert.Polarity, a hostcert.Answer) {
	h.t.Helper()
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.spool, probecert.AnswerFileName(pol)), b, 0o644); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
}

// answerAll answers every outbox request with a valid certificate and
// returns them.
func (h *probeHost) answerAll() map[probecert.Polarity]*ssh.Certificate {
	h.t.Helper()
	out := map[probecert.Polarity]*ssh.Certificate{}
	for pol, req := range h.outbox() {
		c := h.issueFor(req, nil)
		h.writeProbeAnswer(pol, hostcert.Answer{RequestID: hexOf(req.RequestID[:]), Certificate: c.Marshal()})
		out[pol] = c
	}
	return out
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// listNegative makes the next KRL list serial under the machine CA and
// applies it.
func (h *probeHost) listNegative(serial uint64) {
	h.t.Helper()
	h.f.krlMachSerials = append(h.f.krlMachSerials, serial)
	h.publishKRL()
	h.mustApply()
}

// probeCrashAt makes the fault point point crash.
func (h *probeHost) probeCrashAt(point string) {
	h.cfg.Fault = func(p string) error {
		if p == point {
			return errCrash
		}
		return nil
	}
}

// outboxCovered requires every outbox probe request to be a request the
// record knows: no request can be posted whose probe key the applier did
// not record first.
func (h *probeHost) outboxCovered(what string) {
	h.t.Helper()
	rec := h.record()
	for pol, req := range h.outbox() {
		id := hexOf(req.RequestID[:])
		if rec == nil || !slices.ContainsFunc(rec.Attempts.Get(pol).Requests, func(p probecert.Pending) bool {
			return p.ID == id && bytes.Equal(p.ProbeKey, req.ProbeKey)
		}) {
			h.t.Fatalf("%s: the %s outbox request %s is not in the record", what, pol, id)
		}
	}
}

func TestProbeStep(t *testing.T) {
	t.Run("requests_both_after_first_install", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		r := h.mustProbeCerts()
		if !slices.Equal(r.Requested, []string{"positive", "negative"}) || !r.Changed {
			t.Fatalf("report %+v", r)
		}
		out := h.outbox()
		if len(out) != 2 || out[probecert.Positive].Negative || !out[probecert.Negative].Negative {
			t.Fatalf("outbox %v", out)
		}
		h.outboxCovered("after the requests")
		for _, pol := range probecert.Polarities {
			fi, err := os.Stat(filepath.Join(h.l.Outbox(), probecert.RequestFileName(pol)))
			if err != nil || fi.Mode().Perm() != 0o640 {
				t.Fatalf("%s outbox mode: %v %v", pol, fi.Mode(), err)
			}
		}
		if fi, err := os.Stat(h.l.State(probecert.RecordFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("probe.json: %v %v", fi.Mode(), err)
		}
	})
	t.Run("no_request_before_first_install", func(t *testing.T) {
		h := newProbeHost(t)
		r := h.mustProbeCerts()
		if r.Hold != hostcert.HoldNoGeneration || len(h.outbox()) != 0 || h.record() != nil {
			t.Fatalf("before a first install: %+v", r)
		}
	})
	t.Run("off_requests_nothing", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.cfg.probeOff = true
		r := h.mustProbeCerts()
		if !r.Off || r.Changed || len(h.outbox()) != 0 || h.record() != nil {
			t.Fatalf("probes off: %+v", r)
		}
	})
	t.Run("host_holds_write_nothing_or_hold", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		// apply_unfinished: a crash during a two-step move leaves a marker.
		h.publishDir(h.spec("role:x"))
		h.cfg.Fault = func(p string) error {
			if p == "swap" {
				return errCrash
			}
			return nil
		}
		if _, err := h.apply(); !errors.Is(err, errCrash) {
			t.Fatalf("the crashed apply: %v", err)
		}
		h.cfg.Fault = nil
		if r := h.mustProbeCerts(); r.Hold != hostcert.HoldApplyUnfinished || h.record() != nil || len(h.outbox()) != 0 {
			t.Fatalf("an unfinished apply: %+v", r)
		}
		// The addition of role:x waits for the probe gate (Task 3); its
		// removal part lands.
		if _, err := h.apply(); err != nil && !errors.Is(err, ErrProbeHeld) {
			t.Fatalf("apply: %v", err)
		}
		// A disabled host holds and writes the hold's detail, no request.
		s := h.spec("role:ops")
		s.status = directory.StatusDisabled
		h.publishDir(s)
		h.mustApply()
		r := h.mustProbeCerts()
		if rec := h.record(); r.Hold != hostcert.HoldHostDisabled || rec == nil || rec.Detail != "probe_issue:host_disabled" || len(h.outbox()) != 0 {
			t.Fatalf("a disabled host: %+v, record %+v", r, rec)
		}
	})
	t.Run("answer_kept_after_verification", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		certs := h.answerAll()
		r := h.mustProbeCerts()
		rec := h.record()
		if len(r.Kept) != 2 || rec.Next.Positive == nil || rec.Next.Negative == nil || !rec.Committed.Empty() || len(h.outbox()) != 0 {
			t.Fatalf("report %+v, record %+v", r, rec)
		}
		if rec.Next.Negative.Serial != certs[probecert.Negative].Serial || !bytes.Equal(rec.Next.Positive.Cert, certs[probecert.Positive].Marshal()) {
			t.Fatal("the kept certificates differ from the answers")
		}
		h.listNegative(certs[probecert.Negative].Serial)
		if r := h.mustProbeCerts(); !r.PairChanged || h.record().Committed.Negative == nil || !h.record().Next.Empty() {
			t.Fatalf("after the negative is listed: %+v", r)
		}
	})
	t.Run("bad_answer_not_kept_transient", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		req := h.outbox()[probecert.Positive]
		c := h.issueFor(req, newTestSigner(t).PublicKey())
		h.writeProbeAnswer(probecert.Positive, hostcert.Answer{RequestID: hexOf(req.RequestID[:]), Certificate: c.Marshal()})
		h.mustProbeCerts()
		a := h.record().Attempts.Positive
		if h.record().Next.Positive != nil || a.LastCode != "other_key" || a.Sticky != nil || a.NextAt == 0 {
			t.Fatalf("attempt %+v", a)
		}
		if _, ok := h.outbox()[probecert.Positive]; ok {
			t.Fatal("the refused request's outbox file is still there")
		}
	})
	t.Run("refusal_sticky_and_transient", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		out := h.outbox()
		h.writeProbeAnswer(probecert.Positive, hostcert.Answer{RequestID: hexOf(out[probecert.Positive].RequestID[:]), Refused: "host_key_revoked"})
		h.writeProbeAnswer(probecert.Negative, hostcert.Answer{RequestID: hexOf(out[probecert.Negative].RequestID[:]), Refused: "probe_cert_recent"})
		h.mustProbeCerts()
		rec := h.record()
		if rec.Attempts.Positive.Sticky == nil || rec.Attempts.Positive.Sticky.Code != "host_key_revoked" {
			t.Fatalf("positive %+v, want a sticky hold", rec.Attempts.Positive)
		}
		if rec.Attempts.Negative.Sticky != nil || rec.Attempts.Negative.NextAt == 0 {
			t.Fatalf("negative %+v, want a transient back-off", rec.Attempts.Negative)
		}
		if r := h.mustProbeCerts(); len(r.Requested) != 0 || rec.Detail == "" && h.record().Detail == "" {
			t.Fatalf("while both wait: %+v, detail %q", r, h.record().Detail)
		}
	})
	t.Run("pending_request_not_duplicated", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		before := h.outbox()
		r := h.mustProbeCerts()
		after := h.outbox()
		if len(r.Requested) != 0 || before[probecert.Positive].RequestID != after[probecert.Positive].RequestID || before[probecert.Negative].RequestID != after[probecert.Negative].RequestID {
			t.Fatalf("a second run: %+v", r)
		}
	})
	t.Run("abandoned_request_backs_off", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		h.clock.advance(hostcert.RequestTTL * time.Second)
		r := h.mustProbeCerts()
		a := h.record().Attempts.Negative
		if len(r.Requested) != 0 || a.LastCode != "no_answer" || a.NextAt == 0 || len(h.outbox()) != 0 {
			t.Fatalf("abandoned: %+v, attempt %+v", r, a)
		}
		h.clock.advance(hostcert.BackoffMin * time.Second)
		if r := h.mustProbeCerts(); len(r.Requested) != 2 {
			t.Fatalf("after the back-off: %+v", r)
		}
	})
	t.Run("half_answer_kept_as_next_until_second_arrives", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		out := h.outbox()
		c := h.issueFor(out[probecert.Positive], nil)
		h.writeProbeAnswer(probecert.Positive, hostcert.Answer{RequestID: hexOf(out[probecert.Positive].RequestID[:]), Certificate: c.Marshal()})
		r := h.mustProbeCerts()
		rec := h.record()
		if rec.Next.Positive == nil || rec.Next.Negative != nil || len(r.Requested) != 0 || !rec.Committed.Empty() {
			t.Fatalf("half: %+v, %+v", r, rec)
		}
		n := h.issueFor(out[probecert.Negative], nil)
		h.writeProbeAnswer(probecert.Negative, hostcert.Answer{RequestID: hexOf(out[probecert.Negative].RequestID[:]), Certificate: n.Marshal()})
		h.mustProbeCerts()
		if rec := h.record(); !rec.Next.Complete() {
			t.Fatalf("both: %+v", rec)
		}
	})
	t.Run("private_key_never_on_disk", func(t *testing.T) {
		h := newProbeHost(t)
		var seeds [][]byte
		h.cfg.probeKeygen = func(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
			pub, priv, err := ed25519.GenerateKey(r)
			if err == nil {
				seeds = append(seeds, bytes.Clone(priv.Seed()))
			}
			return pub, priv, err
		}
		h.installed("role:ops")
		h.mustProbeCerts()
		h.answerAll()
		h.mustProbeCerts()
		if len(seeds) != 2 {
			t.Fatalf("%d keys generated, want 2", len(seeds))
		}
		for _, dir := range []string{h.l.StateDir, h.l.Root} {
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || !d.Type().IsRegular() {
					return nil
				}
				b, _ := os.ReadFile(p) //nolint:gosec // test fixture
				if bytes.Contains(b, []byte("PRIVATE KEY")) {
					t.Errorf("%s contains PRIVATE KEY", p)
				}
				for _, s := range seeds {
					if bytes.Contains(b, s) || bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString(s))) {
						t.Errorf("%s contains a probe key seed", p)
					}
				}
				return nil
			})
		}
	})
	t.Run("crash_points", func(t *testing.T) {
		for _, point := range []string{"probe-request-attempt", "probe-request-outbox"} {
			h := newProbeHost(t)
			h.installed("role:ops")
			h.probeCrashAt(point)
			if _, err := h.probeCerts(); !errors.Is(err, errCrash) {
				t.Fatalf("%s: %v", point, err)
			}
			h.outboxCovered(point)
			h.cfg.Fault = nil
			h.mustProbeCerts()
			h.outboxCovered(point + ", then a run")
			if len(h.outbox()) != 2 {
				t.Fatalf("%s: the next run left %d outbox requests, want 2", point, len(h.outbox()))
			}
		}
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		certs := h.answerAll()
		h.probeCrashAt("probe-answer-record")
		if _, err := h.probeCerts(); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		h.cfg.Fault = nil
		h.mustProbeCerts()
		if rec := h.record(); !rec.Next.Complete() || len(h.outbox()) != 0 {
			t.Fatalf("after a crash at probe-answer-record: %+v", rec)
		}
		h.listNegative(certs[probecert.Negative].Serial)
		h.probeCrashAt("probe-switch")
		if _, err := h.probeCerts(); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		h.cfg.Fault = nil
		h.mustProbeCerts()
		if rec := h.record(); !rec.Committed.Complete() || !rec.Next.Empty() {
			t.Fatalf("after a crash at probe-switch: %+v", rec)
		}
	})
	t.Run("outbox_pruned_without_pending", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		h.mustProbeCerts()
		out := h.outbox()
		h.writeProbeAnswer(probecert.Negative, hostcert.Answer{RequestID: hexOf(out[probecert.Negative].RequestID[:]), Refused: "host_key_revoked"})
		h.mustProbeCerts()
		stale, err := os.ReadFile(filepath.Join(h.l.Outbox(), probecert.RequestFileName(probecert.Positive)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(h.l.Outbox(), probecert.RequestFileName(probecert.Negative)), stale)
		h.mustProbeCerts()
		if _, ok := h.outbox()[probecert.Negative]; ok {
			t.Fatal("an outbox request with no pending attempt was kept")
		}
	})
}

func TestRenderProbeFile(t *testing.T) {
	probeFile := PrincipalsDir + "/" + certpkg.ReservedAccountName
	t.Run("only_with_probes_on", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		if got := h.file(probeFile); got != string(probeFileFor("web1")) {
			t.Fatalf("probe file %q", got)
		}
	})
	t.Run("only_active_host", func(t *testing.T) {
		h := newProbeHost(t)
		e := h.engine()
		g := &Generation{Files: map[string][]byte{}}
		e.addProbeFile(g)
		if len(g.Files) != 0 {
			t.Fatalf("a generation with no host gained %v", slices.Collect(mapKeys(g.Files)))
		}
	})
	t.Run("not_in_trust_only", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		h.cfg.probeOff = false
		spoolInState(t, h)
		h.installed("role:ops")
		h.publishDir(h.spec("role:evil"))
		// The addition of role:evil waits for the probe gate (Task 3); the
		// directory is accepted all the same.
		if _, err := h.apply(); err != nil && !errors.Is(err, ErrProbeHeld) {
			t.Fatalf("apply: %v", err)
		}
		bob, next := seedKey(t, 11), seedKey(t, 31)
		_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		h.publishKRL(4242)
		r, _ := h.apply()
		if !r.DirectoryUnauthorized {
			t.Fatalf("not unauthorized: %+v", r)
		}
		if _, err := os.Stat(filepath.Join(h.l.Current(), probeFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a trust-only generation holds the probe file: %v", err)
		}
	})
	t.Run("not_in_disabled_or_removed_fallback", func(t *testing.T) {
		for _, edit := range []func(s *dirSpec){func(s *dirSpec) { s.status = directory.StatusDisabled }, func(s *dirSpec) { s.noHost = true }} {
			h := newProbeHost(t)
			h.installed("role:ops")
			s := h.spec("role:ops")
			edit(&s)
			h.publishDir(s)
			h.mustApply()
			if _, err := os.Stat(filepath.Join(h.l.Current(), probeFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a fallback generation holds the probe file: %v", err)
			}
		}
	})
	t.Run("kept_in_rotated_fallback", func(t *testing.T) {
		h := newProbeHost(t)
		h.installed("role:ops")
		s := h.spec("role:ops", "role:x")
		s.hostKeys = []ssh.PublicKey{h.f.mach.PublicKey()}
		h.publishDir(s)
		if r := h.mustApply(); r.HostStatus != HostKeysRotated || h.file(probeFile) != string(probeFileFor("web1")) {
			t.Fatalf("rotated: %+v", r)
		}
	})
	t.Run("mapped_account_untouched", func(t *testing.T) {
		h := newProbeHost(t)
		s := h.spec("role:ops")
		s.accounts = append(s.accounts, certpkg.ReservedAccountName)
		h.publishDir(s)
		h.mustApply()
		if got := h.principals(certpkg.ReservedAccountName); !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("the mapped probe account's file: %v", got)
		}
		if strings.Contains(h.file(probeFile), certpkg.ReservedPrincipalPrefix) {
			t.Fatal("the probe principal was written over a mapped account's file")
		}
	})
	t.Run("bytes_identical_with_probes_off", func(t *testing.T) {
		on, off := newProbeHost(t), newTestHost(t, newFixture(t))
		off.installed("role:ops")
		if _, err := os.Stat(filepath.Join(off.l.Current(), probeFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("probes off: a probe file: %v", err)
		}
		on.f = off.f
		on.installed("role:ops")
		for _, name := range []string{CAFile, KRLFile} {
			if a, b := readOpt(t, filepath.Join(on.l.Current(), name)), readOpt(t, filepath.Join(off.l.Current(), name)); !bytes.Equal(a, b) {
				t.Fatalf("%s differs with probes on", name)
			}
		}
		if !slices.Equal(on.principals("deploy"), off.principals("deploy")) {
			t.Fatal("deploy's principals differ with probes on")
		}
		list := func(h *testHost) []string {
			ents, err := os.ReadDir(filepath.Join(h.l.Current(), PrincipalsDir))
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, e := range ents {
				out = append(out, e.Name())
			}
			return out
		}
		if got, want := list(on.testHost), append(list(off), certpkg.ReservedAccountName); !slices.Equal(got, want) {
			t.Fatalf("principals files with probes on %v, want %v", got, want)
		}
	})
	t.Run("file_content_exact", func(t *testing.T) {
		want := "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n# probe account, host web1\nkeyroster-probe:web1\n"
		if got := string(probeFileFor("web1")); got != want {
			t.Fatalf("%q", got)
		}
		if !isProbeFile([]byte(want), "web1") || isProbeFile([]byte(want), "web2") || !isCurProbeFile([]byte(want)) {
			t.Fatal("isProbeFile on the exact file")
		}
	})
}

func readOpt(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test fixture
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

func mapKeys(m map[string][]byte) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// fullGeneration is a generation of directory.MaxAccounts accounts, each
// with principal p, and the probe file.
func fullGeneration(p string, probe bool) *Generation {
	g := &Generation{Host: "web1", Files: map[string][]byte{CAFile: []byte("ssh-ed25519 AAAA\n"), KRLFile: {}}}
	for i := range directory.MaxAccounts {
		g.Files[PrincipalsDir+"/"+accountName(i)] = []byte("# x\n" + p + "\n")
	}
	if probe {
		g.Files[PrincipalsDir+"/"+certpkg.ReservedAccountName] = probeFileFor("web1")
	}
	return g
}

func accountName(i int) string {
	const digits = "0123456789"
	return "u" + string([]byte{digits[i/1000%10], digits[i/100%10], digits[i/10%10], digits[i%10]})
}

func TestCheckLimitsProbeFile(t *testing.T) {
	fixed := PrincipalsDir + "/" + certpkg.ReservedAccountName
	t.Run("two_full_groups_install_and_read_back", func(t *testing.T) {
		h := newProbeHost(t)
		e := h.engine()
		g := fullGeneration("role:ops", true)
		if err := checkLimitsFixed(g, fixed); err != nil {
			t.Fatalf("MaxAccounts accounts and the probe file: %v", err)
		}
		g.N = 900
		if err := e.installGeneration(g); err != nil {
			t.Fatalf("install: %v", err)
		}
		back, err := readGeneration(h.l.Gen(900))
		if err != nil || len(back.Files) != len(g.Files) {
			t.Fatalf("read back: %v (%d files)", err, len(back.Files))
		}
		over := fullGeneration("role:ops", true)
		over.Files[PrincipalsDir+"/extra"] = []byte("# x\n")
		if err := checkLimitsFixed(over, fixed); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("MaxAccounts plus two: %v", err)
		}
		if err := checkLimitsFixed(fullGeneration("role:ops", false), fixed); err != nil {
			t.Fatalf("MaxAccounts alone: %v", err)
		}
		plus := fullGeneration("role:ops", false)
		plus.Files[PrincipalsDir+"/extra"] = []byte("# x\n")
		if err := checkLimitsFixed(plus, fixed); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("MaxAccounts plus one that is not the probe file: %v", err)
		}
		// readGeneration refuses a directory of MaxAccounts plus two.
		dir := h.l.Gen(901)
		if err := os.MkdirAll(filepath.Join(dir, PrincipalsDir), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		for name, b := range over.Files {
			writeFile(t, filepath.Join(dir, name), b)
		}
		if _, err := readGeneration(dir); err == nil {
			t.Fatal("readGeneration read MaxAccounts plus two principals files")
		}
	})
	t.Run("intermediate_of_two_full_groups_fits", func(t *testing.T) {
		a, b := fullGeneration("role:ops", true), fullGeneration("role:dev", true)
		for name := range b.Files {
			if strings.HasPrefix(name, PrincipalsDir+"/u") {
				b.Files[name] = []byte("# x\nrole:ops\nrole:dev\n")
				break
			}
		}
		m, collapsed := Intermediate(a, b)
		if collapsed {
			t.Fatal("the intermediate collapsed")
		}
		if err := checkCandidate(b, a, link{kind: linkAgent, n: 1}, fixed); err != nil {
			t.Fatalf("the intermediate of two full groups: %v", err)
		}
		if err := checkLimitsFixed(m, fixed); err != nil {
			t.Fatal(err)
		}
	})
}

// TestDriftIncludesProbeAccount: the drift check evaluates every account
// with a principals file in the generation, so the probe account joins it
// (03-10b, Reconcile row 16); preflight evaluates the directory's own
// accounts only.
func TestDriftIncludesProbeAccount(t *testing.T) {
	h := newProbeHost(t)
	h.installed("role:ops")
	h.run.match = map[string]map[string]string{certpkg.ReservedAccountName: {"authorizedprincipalsfile": "none"}}
	r, err := h.check()
	if err != nil || !slices.ContainsFunc(r.Settings, func(s SettingDrift) bool { return s.Account == certpkg.ReservedAccountName }) {
		t.Fatalf("drift does not evaluate the probe account: %+v, %v", r, err)
	}
}
