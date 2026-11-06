//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	krcert "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// hostCertHost is a testHost set up for host certificates (03-09): the
// fake sshd also has a second Ed25519 key (ed2), an ECDSA P-256 key (ec)
// and an RSA key (rsaKey), listed after its first key; the outbox exists;
// the self-test waits at most 1 s; and serial counts the certificates
// the test's stand-in signer issued.
type hostCertHost struct {
	*testHost
	ed2, ec, rsaKey ssh.Signer
	serial          uint64
	// lifetime is the lifetime the stand-in signer gives (V, seconds).
	lifetime uint64
}

func newHostCertHost(t *testing.T) *hostCertHost {
	t.Helper()
	h := &hostCertHost{testHost: newTestHost(t, newFixture(t)), serial: 1_793_000_000_000_000, lifetime: 2592000}
	var paths []string
	for _, k := range []struct {
		kind string
		dst  *ssh.Signer
	}{{"ed25519", &h.ed2}, {"ecdsa", &h.ec}, {"rsa", &h.rsaKey}} {
		s, p := h.sshd.addHostKey(t, k.kind)
		*k.dst = s
		paths = append(paths, p)
	}
	h.run.extraHostKeys = paths
	h.cfg.SelfTestTimeout = time.Second
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil {
		t.Fatal(err)
	}
	return h
}

// hostSpec is the directory spec naming web1 by keys (sorted as the
// directory keeps them).
func (h *hostCertHost) hostSpec(keys ...ssh.PublicKey) dirSpec {
	return dirSpec{principals: []string{"role:ops"}, accounts: []string{"deploy"}, hostKeys: sortedKeys(keys)}
}

func sortedKeys(keys []ssh.PublicKey) []ssh.PublicKey {
	byFormat := map[string]ssh.PublicKey{}
	for _, k := range keys {
		byFormat[trust.FormatKey(k)] = k
	}
	var out []ssh.PublicKey
	for _, f := range enroll.SortHostKeys(keys) {
		out = append(out, byFormat[f])
	}
	return out
}

// issue is the stand-in signer: a kr3 host certificate for pub, for
// web1, from the fixture's host CA, issued now on the host's clock for
// h.lifetime, with the next serial.
func (h *hostCertHost) issue(pub ssh.PublicKey, req string) *ssh.Certificate {
	h.t.Helper()
	h.serial++
	c, err := krcert.Build(krcert.Request{
		Profile:    krcert.Profile{CertType: ssh.HostCert, MaxTTL: 30 * 24 * time.Hour},
		Subject:    pub,
		Principals: []string{"web1"},
		Now:        h.clock.Now(),
		ValidFor:   time.Duration(h.lifetime) * time.Second, //nolint:gosec // G115: test lifetimes
		KeyID:      krcert.KeyID{V3: true, CA: "host", Subject: "web1", Request: req, Policy: 1, Directory: 1, Serial: h.serial},
		Serial:     h.serial,
	}, h.f.host, rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// outboxRequests are the outbox's host certificate requests, by key.
func (h *hostCertHost) outboxRequests() map[string]*wire.HostIssueRequest {
	h.t.Helper()
	out := map[string]*wire.HostIssueRequest{}
	ents, err := os.ReadDir(h.l.Outbox())
	if err != nil {
		h.t.Fatal(err)
	}
	for _, d := range ents {
		m := hostcert.RequestFileRE.FindStringSubmatch(d.Name())
		if m == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(h.l.Outbox(), d.Name())) //nolint:gosec // test fixture
		if err != nil {
			h.t.Fatal(err)
		}
		r, err := hostcert.ParseOutboxRequest(b)
		if err != nil {
			h.t.Fatal(err)
		}
		req, err := wire.ParseHostIssueRequest(r.Request)
		if err != nil {
			h.t.Fatal(err)
		}
		out[m[1]] = req
	}
	return out
}

// answer is the fetcher's and the signer's part: every outbox request is
// answered with a certificate in the spool. It returns the certificates
// by key.
func (h *hostCertHost) answer() map[string]*ssh.Certificate {
	h.t.Helper()
	got := map[string]*ssh.Certificate{}
	for k, req := range h.outboxRequests() {
		pub, err := ssh.ParsePublicKey(req.HostKey)
		if err != nil {
			h.t.Fatal(err)
		}
		c := h.issue(pub, hex.EncodeToString(req.RequestID[:]))
		h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Certificate: c.Marshal()})
		got[k] = c
	}
	return got
}

func (h *hostCertHost) writeAnswer(k string, a hostcert.Answer) {
	h.t.Helper()
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.spool, hostcert.AnswerFileName(k)), b, 0o644); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
}

// hostCerts runs one HostCerts step.
func (h *hostCertHost) hostCerts() (*HostCertReport, error) {
	h.t.Helper()
	return HostCerts(context.Background(), h.cfg, h.l)
}

func (h *hostCertHost) mustHostCerts() *HostCertReport {
	h.t.Helper()
	r, err := h.hostCerts()
	if err != nil {
		h.t.Fatalf("HostCerts: %v (report %+v)", err, r)
	}
	return r
}

// dropInCerts are the HostCertificate paths of the drop-in on disk.
func (h *hostCertHost) dropInCerts() []string {
	h.t.Helper()
	b, err := os.ReadFile(h.l.DropIn())
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "HostCertificate "); ok {
			out = append(out, p)
		}
	}
	return out
}

// served is what the fake sshd serves for algorithm alg now.
func (h *hostCertHost) served(alg string) *ssh.Certificate {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	d := net.Dialer{Deadline: deadline}
	c, err := probeCert(context.Background(), d.DialContext, net.JoinHostPort("127.0.0.1", strconv.Itoa(h.sshd.port)), deadline, alg)
	if err != nil {
		return nil
	}
	return c
}

// certFile writes c as an authorized_keys line under dir and returns its
// path.
func certFile(t *testing.T, dir, name string, c *ssh.Certificate) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(c), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return p
}

// TestFakeSSHDHostCerts proves the fake sshd's own host-certificate
// contract (03-09), which every TestHostCertStep case relies on.
func TestFakeSSHDHostCerts(t *testing.T) {
	h := newHostCertHost(t)
	h.installed("role:ops")
	dir := t.TempDir()
	c1 := h.issue(h.sshd.pub, strings.Repeat("0", 32))
	c2 := h.issue(h.ed2.PublicKey(), strings.Repeat("1", 32))
	c3 := h.issue(h.ec.PublicKey(), strings.Repeat("2", 32))
	p1, p2, p3 := certFile(t, dir, "c1", c1), certFile(t, dir, "c2", c2), certFile(t, dir, "c3", c3)
	// ed2's certificate is named first: the order of the lines does not
	// matter, the HostKey order does.
	dropIn := string(DropIn(h.l, DropInSpec{})) + "HostCertificate " + p2 + "\nHostCertificate " + p1 + "\nHostCertificate " + p3 + "\n"
	if err := os.WriteFile(h.l.DropIn(), []byte(dropIn), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	t.Run("written_not_reloaded_serves_nothing_new", func(t *testing.T) {
		if c := h.served(ssh.CertAlgoED25519v01); c != nil {
			t.Fatalf("before a reload the fake serves certificate %q", c.KeyId)
		}
	})
	h.sshd.reload(h.l, false)
	t.Run("reload_serves_first_key_per_algorithm", func(t *testing.T) {
		if c := h.served(ssh.CertAlgoED25519v01); c == nil || !bytes.Equal(c.Marshal(), c1.Marshal()) {
			t.Fatalf("ed25519 certificate served %v, want the first host key's", c)
		}
		if c := h.served(ssh.CertAlgoECDSA256v01); c == nil || !bytes.Equal(c.Marshal(), c3.Marshal()) {
			t.Fatalf("ecdsa certificate served %v, want the ECDSA key's", c)
		}
	})
	t.Run("dump_lists_every_value_in_order", func(t *testing.T) {
		h.run.hostCertBefore, h.run.hostCertAfter = []string{"/etc/ssh/before-cert.pub"}, []string{"/etc/ssh/after-cert.pub"}
		defer func() { h.run.hostCertBefore, h.run.hostCertAfter = nil, nil }()
		d := ParseDump([]byte(h.run.dump()))
		want := []string{"/etc/ssh/before-cert.pub", p2, p1, p3, "/etc/ssh/after-cert.pub"}
		if !slices.Equal(d["hostcertificate"], want) {
			t.Fatalf("sshd -T hostcertificate %q, want %q", d["hostcertificate"], want)
		}
		if d.One("hostkeyalgorithms") == "" {
			t.Fatal("no hostkeyalgorithms line")
		}
	})
	t.Run("wrong_certificate_knob", func(t *testing.T) {
		wrong := h.issue(h.sshd.pub, strings.Repeat("3", 32))
		h.sshd.serveCert(wrong)
		defer h.sshd.serveCert(nil)
		if c := h.served(ssh.CertAlgoED25519v01); c == nil || !bytes.Equal(c.Marshal(), wrong.Marshal()) {
			t.Fatalf("the knob's certificate is not served: %v", c)
		}
	})
}

// TestDropInSpec: DropIn's empty spec renders 03-05's drop-in byte for
// byte; HostCertificate lines follow the trio, sorted.
func TestDropInSpec(t *testing.T) {
	l := Layout{Root: "/r", StateDir: "/s"}
	t.Run("empty_spec_is_todays_bytes", func(t *testing.T) {
		want := "# keyroster: managed by keyroster-agent; do not edit\n" +
			"TrustedUserCAKeys /r/etc/ssh/keyroster/current/user_ca_keys\n" +
			"RevokedKeys /r/etc/ssh/keyroster/current/revoked.krl\n" +
			"AuthorizedPrincipalsFile /r/etc/ssh/keyroster/current/principals/%u\n"
		if got := string(DropIn(l, DropInSpec{})); got != want {
			t.Fatalf("DropIn with the empty spec:\n%s\nwant:\n%s", got, want)
		}
	})
	dropInSpecSorted(t)
}

// TestHostCertStep is the host-certificate step on the fake sshd (03-09).
func TestHostCertStep(t *testing.T) {
	t.Run("install_serves_and_survives_next_apply", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		h.mustApply()
		r := h.mustHostCerts()
		reqs := h.outboxRequests()
		if len(reqs) != 2 || len(r.Requested) != 2 {
			t.Fatalf("after the first step %d outbox requests (report %+v), want one per listed Ed25519 and ECDSA key", len(reqs), r)
		}
		for _, req := range reqs {
			if req.ValidForSeconds != 0 || req.HostName != "web1" || req.InstallationID != testInstallation {
				t.Fatalf("request %+v, want valid_for 0 for web1 of the installation", req)
			}
		}
		issued := h.answer()
		r = h.mustHostCerts()
		if len(r.Installed) != 2 {
			t.Fatalf("the second step installed %v (report %+v), want both keys", r.Installed, r)
		}
		lines := h.dropInCerts()
		if len(lines) != 2 {
			t.Fatalf("the drop-in names %d host certificates, want 2", len(lines))
		}
		for k, c := range issued {
			got := h.served(c.Type())
			if got == nil || !bytes.Equal(got.Marshal(), c.Marshal()) {
				t.Fatalf("sshd serves %v for %s, want the installed certificate of key %s", got, c.Type(), k[:12])
			}
		}
		rec := h.record()
		if len(rec.Committed) != 2 || rec.InProgress || !rec.Committed[0].Served || !rec.Committed[1].Served {
			t.Fatalf("record %+v, want both committed and served", rec)
		}
		before, err := os.ReadFile(h.l.DropIn())
		if err != nil {
			t.Fatal(err)
		}
		// The next apply, of a new directory version, keeps the lines.
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		ar := h.mustApply()
		if ar.Generation == 0 {
			t.Fatalf("apply report %+v", ar)
		}
		after, err := os.ReadFile(h.l.DropIn())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("the next apply changed the drop-in:\n%s\nwant:\n%s", after, before)
		}
		if r := h.mustHostCerts(); len(r.Requested) != 0 || len(r.Installed) != 0 {
			t.Fatalf("a step with nothing due did %+v", r)
		}
	})
	hostCertStepCases(t)
	hostCertStepCases2(t)
}

// record reads the host-certificate record.
func (h *hostCertHost) record() *hostcert.Record {
	h.t.Helper()
	b, err := os.ReadFile(h.l.State(hostcert.RecordFile))
	if err != nil {
		h.t.Fatal(err)
	}
	r, err := hostcert.ParseRecord(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

// errCrash is the injected crash of the host-certificate fault points.
var errCrash error = &crash{point: "a host-certificate step"}

// crashAt makes the next HostCerts run stop at point.
func (h *hostCertHost) crashAt(point string) {
	h.cfg.Fault = func(p string) error {
		if p == point {
			return errCrash
		}
		return nil
	}
}

// crashed runs HostCerts with a crash at point and requires it.
func (h *hostCertHost) crashed(point string) {
	h.t.Helper()
	h.crashAt(point)
	_, err := h.hostCerts()
	h.cfg.Fault = nil
	if !errors.Is(err, errCrash) {
		h.t.Fatalf("HostCerts with a crash at %s: %v", point, err)
	}
}

// both installs web1's Ed25519 and ECDSA certificates and returns them.
func (h *hostCertHost) both() map[string]*ssh.Certificate {
	h.t.Helper()
	h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
	h.mustApply()
	h.mustHostCerts()
	got := h.answer()
	if r := h.mustHostCerts(); len(r.Installed) != 2 {
		h.t.Fatalf("installed %v", r)
	}
	return got
}

// one installs web1's Ed25519 certificate only (the directory lists one
// key).
func (h *hostCertHost) one() *ssh.Certificate {
	h.t.Helper()
	h.publishDir(h.hostSpec(h.sshd.pub))
	h.mustApply()
	h.mustHostCerts()
	var c *ssh.Certificate
	for _, x := range h.answer() {
		c = x
	}
	if r := h.mustHostCerts(); len(r.Installed) != 1 {
		h.t.Fatalf("installed %v", r)
	}
	return c
}

// requested runs to the point where web1's Ed25519 key has an answered
// request (one key, first install).
func (h *hostCertHost) requested() {
	h.t.Helper()
	h.publishDir(h.hostSpec(h.sshd.pub))
	h.mustApply()
	h.mustHostCerts()
	h.answer()
}

func (h *hostCertHost) reloadCount() int {
	h.run.mu.Lock()
	defer h.run.mu.Unlock()
	return h.run.reloads
}

func (h *hostCertHost) attempts() *hostcert.Attempts {
	h.t.Helper()
	b, err := os.ReadFile(h.l.State(hostcert.AttemptsFile))
	if err != nil {
		h.t.Fatal(err)
	}
	a, err := hostcert.ParseAttempts(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return a
}

func (h *hostCertHost) dropInBytes() []byte {
	h.t.Helper()
	b, _ := os.ReadFile(h.l.DropIn())
	return b
}

func (h *hostCertHost) committedRender() []byte {
	h.t.Helper()
	return DropIn(h.l, specOf(h.l.HostCertDir(), h.record().Committed))
}

func (h *hostCertHost) certFiles() []string {
	h.t.Helper()
	ents, _ := os.ReadDir(h.l.HostCertDir())
	var out []string
	for _, d := range ents {
		out = append(out, d.Name())
	}
	return out
}

// renewDue moves the clock past every installed certificate's RenewAt.
func (h *hostCertHost) renewDue() {
	h.t.Helper()
	var at uint64
	for _, en := range h.record().Committed {
		at = max(at, en.RenewAt)
	}
	h.clock.advance(time.Duration(int64(at)+1-h.clock.Now().Unix()) * time.Second) //nolint:gosec // G115: test times
}

func hostCertStepCases(t *testing.T) {
	t.Run("crash_after_attempts_before_outbox_abandons", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.crashed("hostcert-request")
		if len(h.outboxRequests()) != 0 || len(h.attempts().Keys) != 1 {
			t.Fatal("after the crash: an outbox file, or no pending request")
		}
		orphan := h.attempts().Keys[0].Requests[0].ID
		if r := h.mustHostCerts(); len(r.Requested) != 0 || len(h.outboxRequests()) != 0 {
			t.Fatal("the orphan request ID was posted or replaced within 330 s")
		}
		h.clock.advance(330 * time.Second)
		h.mustHostCerts()
		reqs := h.outboxRequests()
		if len(reqs) != 1 {
			t.Fatalf("after 330 s %d outbox requests, want a fresh one", len(reqs))
		}
		for _, r := range reqs {
			if hex.EncodeToString(r.RequestID[:]) == orphan {
				t.Fatal("the orphan request ID was posted")
			}
		}
	})
	t.Run("crash_after_cert_file_adopts", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-answer-file")
		if r := h.mustHostCerts(); len(r.Installed) != 1 || len(r.Requested) != 0 {
			t.Fatalf("after the crash: %+v, want the file installed and no new request", r)
		}
	})
	t.Run("crash_after_cert_file_adopts_first_install", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-answer-file")
		if r := h.mustHostCerts(); len(r.Installed) != 1 || r.Code != "" {
			t.Fatalf("after the crash: %+v, want the file installed and no record code", r)
		}
	})
	t.Run("crash_after_answer_consumed_installs_kept", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-answer-attempts")
		if len(h.outboxRequests()) != 1 {
			t.Fatal("the outbox request went before the crash point")
		}
		if r := h.mustHostCerts(); len(r.Installed) != 1 || len(r.Requested) != 0 || len(h.outboxRequests()) != 0 {
			t.Fatalf("after the crash: %+v", r)
		}
	})
	t.Run("crash_after_outbox_removed_installs_kept", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-answer-outbox")
		ents, _ := os.ReadDir(h.spool)
		for _, d := range ents {
			if hostcert.AnswerFileRE.MatchString(d.Name()) {
				_ = os.Remove(filepath.Join(h.spool, d.Name()))
			}
		}
		if r := h.mustHostCerts(); len(r.Installed) != 1 || len(r.Requested) != 0 {
			t.Fatalf("after the crash: %+v", r)
		}
	})
	for _, point := range []string{"hostcert-candidate", "hostcert-dropin", "hostcert-reload"} {
		name := map[string]string{"hostcert-candidate": "crash_after_candidate_rolls_back_then_installs",
			"hostcert-dropin": "crash_after_dropin_rolls_back", "hostcert-reload": "crash_after_reload_rolls_back"}[point]
		t.Run(name, func(t *testing.T) {
			h := newHostCertHost(t)
			h.requested()
			h.crashed(point)
			if rec := h.record(); !rec.InProgress || len(rec.Committed) != 0 {
				t.Fatalf("after the crash the record is %+v, want the candidate in progress and nothing committed", rec)
			}
			before := h.reloadCount()
			r := h.mustHostCerts()
			if !r.Recovered || h.reloadCount() <= before || len(r.Installed) != 1 || h.record().InProgress {
				t.Fatalf("the next run: %+v (reloads %d -> %d)", r, before, h.reloadCount())
			}
		})
	}
	t.Run("crash_after_selftest_rolls_back", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-selftest")
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		h.mustHostCerts()
		if rec := h.record(); rec.InProgress || len(rec.Committed) != 0 {
			t.Fatalf("record %+v, want the committed set (empty) kept: an unfinished candidate is never committed", rec)
		}
	})
	t.Run("crash_after_commit_gcs", func(t *testing.T) {
		h := newHostCertHost(t)
		old := h.one()
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.crashed("hostcert-commit")
		h.mustHostCerts()
		for _, f := range h.certFiles() {
			if f == hostcert.CertFileName(hostcert.KeySHA256(h.sshd.pub), old.Serial) {
				t.Fatal("the replaced certificate's file was not collected")
			}
		}
	})
	t.Run("crash_in_rollback_before_reload_reloads", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		h.crashed("hostcert-rollback-dropin")
		h.sshd.serveCert(nil)
		if !bytes.Equal(h.dropInBytes(), h.committedRender()) || !h.record().InProgress {
			t.Fatal("the rollback did not write the committed set before the crash point")
		}
		before := h.reloadCount()
		if r := h.mustHostCerts(); !r.Recovered || h.reloadCount() <= before {
			t.Fatalf("the next run did not reload although the drop-in equals the committed set: %+v", r)
		}
	})
	t.Run("crash_in_rollback_before_record_clears", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		h.crashed("hostcert-rollback-reload")
		h.sshd.serveCert(nil)
		if r := h.mustHostCerts(); !r.Recovered || h.record().InProgress {
			t.Fatalf("the next run: %+v, want a recovery that clears InProgress", r)
		}
	})
	t.Run("crash_during_gc_converges", func(t *testing.T) {
		h := newHostCertHost(t)
		old := h.one()
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.crashed("hostcert-gc")
		h.mustHostCerts()
		if slices.Contains(h.certFiles(), hostcert.CertFileName(hostcert.KeySHA256(h.sshd.pub), old.Serial)) {
			t.Fatal("the next GC did not finish")
		}
	})
	t.Run("crash_during_removal_converges", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		// A new version lists only the ECDSA key: the Ed25519 line goes.
		h.publishDir(h.hostSpec(h.ec.PublicKey()))
		h.mustApply()
		h.crashed("hostcert-dropin")
		if rec := h.record(); !rec.InProgress || len(rec.Candidate) != 0 || len(h.dropInCerts()) != 0 {
			t.Fatalf("after the crash: record %+v, drop-in lines %v; want an empty candidate in progress", rec, h.dropInCerts())
		}
		r := h.mustHostCerts()
		if !r.Recovered || len(h.record().Committed) != 0 || h.record().InProgress || len(h.dropInCerts()) != 0 {
			t.Fatalf("the next run: %+v, record %+v; want the committed set rendered, reloaded, then the empty set committed", r, h.record())
		}
	})
	for _, point := range []string{"hostcert-candidate", "hostcert-dropin", "hostcert-reload", "hostcert-selftest"} {
		t.Run("apply_after_crash_renders_committed", func(t *testing.T) {
			h := newHostCertHost(t)
			h.requested()
			h.crashed(point)
			h.mustApply()
			if !bytes.Equal(h.dropInBytes(), h.committedRender()) {
				t.Fatalf("after a crash at %s, Apply left %q, want the committed set's drop-in", point, h.dropInBytes())
			}
		})
	}
	t.Run("outbox_request_abandoned_after_330s", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		first := h.outboxRequests()
		b1, _ := os.ReadFile(filepath.Join(h.l.Outbox(), hostcert.RequestFileName(hostcert.KeySHA256(h.sshd.pub))))
		h.clock.advance(329 * time.Second)
		h.mustHostCerts()
		b2, _ := os.ReadFile(filepath.Join(h.l.Outbox(), hostcert.RequestFileName(hostcert.KeySHA256(h.sshd.pub))))
		if !bytes.Equal(b1, b2) || len(h.attempts().Keys[0].Requests) != 1 {
			t.Fatal("at 329 s the request was replaced")
		}
		h.clock.advance(time.Second)
		h.mustHostCerts()
		second := h.outboxRequests()
		for k := range first {
			if second[k] == nil || second[k].RequestID == first[k].RequestID {
				t.Fatal("at 330 s the request was not abandoned for a fresh one")
			}
		}
	})
}

// stateSnapshot hashes every managed path HostCerts may write: the drop-in,
// the record, the attempts file, the host-certificate directory, the
// outbox and status.json (apply.lock excluded).
func (h *hostCertHost) stateSnapshot() string {
	h.t.Helper()
	var b strings.Builder
	for _, p := range []string{h.l.DropIn(), h.l.State(hostcert.RecordFile), h.l.State(hostcert.AttemptsFile)} {
		x, err := os.ReadFile(p) //nolint:gosec // test fixture
		fmt.Fprintf(&b, "%s %v %x\n", p, err == nil, sha256.Sum256(x))
	}
	for _, d := range []string{h.l.HostCertDir(), h.l.Outbox()} {
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			x, _ := os.ReadFile(filepath.Join(d, e.Name())) //nolint:gosec // test fixture
			fmt.Fprintf(&b, "%s/%s %x\n", d, e.Name(), sha256.Sum256(x))
		}
	}
	return b.String()
}

// treeSnapshot hashes every file under dir (links by their target).
func treeSnapshot(t *testing.T, dirs ...string) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				tgt, _ := os.Readlink(p)
				fmt.Fprintf(&b, "%s -> %s\n", p, tgt)
				return nil
			}
			if d.Type().IsRegular() {
				x, _ := os.ReadFile(p) //nolint:gosec // test fixture
				fmt.Fprintf(&b, "%s %x\n", p, sha256.Sum256(x))
			}
			return nil
		})
	}
	return b.String()
}

// editDropInLines writes the drop-in without its HostCertificate lines.
func (h *hostCertHost) stripLines() {
	h.t.Helper()
	if err := os.WriteFile(h.l.DropIn(), DropIn(h.l, DropInSpec{}), 0o644); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
}

func (h *hostCertHost) writeRecord(b []byte, mode os.FileMode) {
	h.t.Helper()
	p := h.l.State(hostcert.RecordFile)
	_ = os.Remove(p)
	if err := os.WriteFile(p, b, mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hostCertHost) status() *heartbeat.Status {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
	if err != nil {
		h.t.Fatal(err)
	}
	s, err := heartbeat.ParseStatus(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

// setSSHDConfig replaces the host's sshd_config.
func (h *hostCertHost) setSSHDConfig(text string) {
	h.t.Helper()
	if err := os.WriteFile(h.cfg.SSHDConfig, []byte(text), 0o644); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
}

func (h *hostCertHost) include() string {
	return "Include " + filepath.Join(h.l.DropInDir(), "*.conf") + "\n"
}

func hostCertStepCases2(t *testing.T) {
	ed := func(h *hostCertHost) string { return hostcert.KeySHA256(h.sshd.pub) }
	t.Run("recovery_without_bundle", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		want := h.committedRender()
		h.run.rejectDropIn = func(b []byte) bool { return bytes.Contains(b, []byte("garbage")) }
		if err := os.WriteFile(h.l.DropIn(), []byte("garbage\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		_ = os.RemoveAll(h.l.State("accepted"))
		_, _ = h.apply()
		if !bytes.Equal(h.dropInBytes(), want) {
			t.Fatalf("with accepted/ removed the pre-repair wrote %q, want the record's lines", h.dropInBytes())
		}
	})
	t.Run("record_legacy_migrates", func(t *testing.T) {
		h := newHostCertHost(t)
		var log bytes.Buffer
		h.cfg.Log = &log
		h.mustHostCerts() // no generation: nothing
		if _, err := os.Stat(h.l.State(hostcert.RecordFile)); err == nil {
			t.Fatal("a record was written under no_generation")
		}
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		h.mustHostCerts()
		if rec := h.record(); len(rec.Committed) != 0 || rec.InProgress || strings.Count(log.String(), "hostcert_record_created") != 1 {
			t.Fatalf("record %+v, log %q; want the empty record created once", rec, log.String())
		}
	})
	t.Run("record_missing_reported_and_adopted", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		_ = os.Remove(h.l.State(hostcert.RecordFile))
		r := h.mustHostCerts()
		if r.Code != CodeHostCertRecordMissing || len(h.record().Committed) != 1 {
			t.Fatalf("report %+v, want hostcert_record_missing and the file adopted", r)
		}
	})
	t.Run("missing_detected_after_apply_first", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		_ = os.Remove(h.l.State(hostcert.RecordFile))
		h.mustApply()
		if r := h.mustHostCerts(); r.Code != CodeHostCertRecordMissing {
			t.Fatalf("after Apply rendered the empty spec: %+v, want hostcert_record_missing", r)
		}
	})
	t.Run("record_invalid_set_aside_and_adopted", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		h.writeRecord([]byte("garbage"), 0o600)
		r := h.mustHostCerts()
		if r.Code != CodeHostCertRecordInvalid || len(h.record().Committed) != 1 {
			t.Fatalf("report %+v, want hostcert_record_invalid and the file adopted", r)
		}
	})
	t.Run("krl_lands_with_bad_record", func(t *testing.T) {
		for name, bad := range map[string]func(h *hostCertHost){
			"symlink": func(h *hostCertHost) {
				_ = os.Remove(h.l.State(hostcert.RecordFile))
				_ = os.Symlink("/etc/passwd", h.l.State(hostcert.RecordFile))
			},
			"mode_0644": func(h *hostCertHost) { _ = os.Chmod(h.l.State(hostcert.RecordFile), 0o644) }, //nolint:gosec // the bad mode under test
			"oversize":  func(h *hostCertHost) { h.writeRecord(bytes.Repeat([]byte(" "), hostcert.MaxRecord+1), 0o600) },
			"directory": func(h *hostCertHost) {
				_ = os.Remove(h.l.State(hostcert.RecordFile))
				_ = os.Mkdir(h.l.State(hostcert.RecordFile), 0o700)
			},
		} {
			t.Run(name, func(t *testing.T) {
				h := newHostCertHost(t)
				h.one()
				bad(h)
				h.publishKRL(77)
				r := h.mustApply()
				if r.KRLVersion == 0 || !h.krlRevokes(h.l.Current(), 77) {
					t.Fatalf("the newer KRL did not commit: %+v", r)
				}
				h.mustHostCerts()
				if d := h.status().HostCertDetail; d != CodeHostCertRecordInvalid {
					t.Fatalf("host_cert_detail %q, want hostcert_record_invalid", d)
				}
			})
		}
	})
	t.Run("record_symlink_is_invalid_not_error", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		_ = os.Remove(h.l.State(hostcert.RecordFile))
		_ = os.Symlink("/etc/passwd", h.l.State(hostcert.RecordFile))
		if r, err := h.hostCerts(); err != nil || r.Code != CodeHostCertRecordInvalid {
			t.Fatalf("HostCerts = %+v, %v; want the code, not an error", r, err)
		}
	})
	t.Run("check_and_preflight_leave_record_untouched", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		before := h.stateSnapshot()
		_, _ = Check(context.Background(), h.cfg, h.l)
		_, _ = Preflight(context.Background(), h.cfg, h.l)
		dry := h.cfg
		dry.DryRun = true
		_, _ = Apply(context.Background(), dry, h.l)
		if after := h.stateSnapshot(); after != before {
			t.Fatalf("check, preflight or apply --dry-run changed the host-certificate state:\n%s\nwas:\n%s", after, before)
		}
	})
	t.Run("simultaneous_applies", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = Apply(context.Background(), h.cfg, h.l) }()
			go func() { defer wg.Done(); _, _ = HostCerts(context.Background(), h.cfg, h.l) }()
		}
		wg.Wait()
		if !bytes.Equal(h.dropInBytes(), h.committedRender()) || h.record().InProgress {
			t.Fatal("after simultaneous runs the drop-in and the record disagree")
		}
	})
	t.Run("renewal_replaces_file", func(t *testing.T) {
		h := newHostCertHost(t)
		old := h.one()
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.mustHostCerts()
		rec := h.record()
		if len(rec.Committed) != 1 || rec.Committed[0].Serial <= old.Serial || !strings.HasSuffix(h.dropInCerts()[0], rec.Committed[0].File) {
			t.Fatalf("after the renewal: %+v", rec)
		}
	})
	t.Run("removal_drops_line", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.publishDir(h.hostSpec(h.ec.PublicKey()))
		h.mustApply()
		h.mustHostCerts()
		if len(h.record().Committed) != 1 || len(h.dropInCerts()) != 1 {
			t.Fatalf("after the removal: %+v", h.record())
		}
	})
	t.Run("remove_last_key_commits_empty_set", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		h.publishDir(h.hostSpec(h.ec.PublicKey()))
		h.mustApply()
		h.mustHostCerts()
		if rec := h.record(); len(rec.Committed) != 0 || rec.InProgress || len(h.dropInCerts()) != 0 {
			t.Fatalf("after removing the last line: %+v", rec)
		}
	})
	t.Run("two_keys_one_algorithm", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub, h.ed2.PublicKey()))
		h.mustApply()
		h.mustHostCerts()
		h.answer()
		h.mustHostCerts()
		rec := h.record()
		served := map[string]bool{}
		for _, en := range rec.Committed {
			served[en.KeySHA256] = en.Served
		}
		if len(rec.Committed) != 2 || !served[ed(h)] || served[hostcert.KeySHA256(h.ed2.PublicKey())] {
			t.Fatalf("record %+v, want both certified, the first key served and the second not", rec)
		}
	})
	t.Run("two_algorithms_each_served", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		for _, en := range h.record().Committed {
			if !en.Served {
				t.Fatalf("entry %+v not served", en)
			}
		}
	})
	t.Run("reload_lag_does_not_roll_back", func(t *testing.T) {
		h := newHostCertHost(t)
		h.sshd.reloadDelay = 300 * time.Millisecond
		h.both()
		if rec := h.record(); len(rec.Committed) != 2 {
			t.Fatalf("with a 300 ms reload lag: %+v", rec)
		}
	})
	t.Run("repair_keeps_extensions", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.stripLines()
		h.mustApply()
		if !bytes.Equal(h.dropInBytes(), h.committedRender()) {
			t.Fatal("the no-op repair dropped the HostCertificate lines")
		}
		if err := os.WriteFile(h.l.DropIn(), trialDropIn(h.l), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		h.mustApply()
		if !bytes.Equal(h.dropInBytes(), h.committedRender()) {
			t.Fatal("repairDropIn after a trial dropped the HostCertificate lines")
		}
	})
	t.Run("first_install_rollback_no_lines", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		_, _ = h.hostCerts()
		if len(h.dropInCerts()) != 0 || len(h.record().Committed) != 0 || h.attempts().Keys[0].KeptFile == "" {
			t.Fatalf("after a failed first install: lines %v, record %+v", h.dropInCerts(), h.record())
		}
	})
	t.Run("generation_rollback_keeps_section", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		want := h.committedRender()
		h.stripLines()
		h.publishKRL(78)
		h.sshd.setStall(true)
		_, _ = h.apply()
		h.sshd.setStall(false)
		if !bytes.Equal(h.dropInBytes(), want) {
			t.Fatalf("after a generation rollback the drop-in is %q, want the HostCertificate section", h.dropInBytes())
		}
	})
	t.Run("hostcert_rollback_keeps_trust_files", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		// current is set apart from last-good: a failed apply with a newer
		// KRL leaves current at the rollback target (last-good's trust
		// with the newer KRL), which holds no host-certificate work.
		h.publishKRL(82)
		h.sshd.setStall(true)
		_, _ = h.apply()
		h.sshd.setStall(false)
		if c, lg := h.current(), h.lastGood(); c == 0 || c == lg {
			t.Fatalf("current %d, last-good %d: want current set apart", c, lg)
		}
		before := treeSnapshot(t, h.l.Current(), h.l.LastGood(), h.l.GenDir(), h.l.State("accepted"))
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		_, _ = h.hostCerts()
		if a := h.attempts(); len(a.Keys) == 0 || a.Keys[0].KeptFile == "" || a.Keys[0].LastCode == "" {
			t.Fatalf("attempts %+v: want a failed install that kept the certificate", a)
		}
		if after := treeSnapshot(t, h.l.Current(), h.l.LastGood(), h.l.GenDir(), h.l.State("accepted")); after != before {
			t.Fatal("a served_cert_mismatch rollback changed current, last-good, gen/ or accepted/")
		}
	})
	t.Run("foreign_cert_before_include", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.setSSHDConfig("HostCertificate /etc/ssh/other-cert.pub\n" + h.include())
		if r := h.mustHostCerts(); r.Hold != hostcert.HoldForeignHostCertificate || len(h.outboxRequests()) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("foreign_cert_after_include", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.setSSHDConfig(h.include() + "HostCertificate /etc/ssh/other-cert.pub\n")
		if r := h.mustHostCerts(); r.Hold != hostcert.HoldForeignHostCertificate || len(h.outboxRequests()) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("foreign_cert_blocks_adoption_and_answers", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.setSSHDConfig(h.include() + "HostCertificate /etc/ssh/other-cert.pub\n")
		h.mustHostCerts()
		if a := h.attempts(); a.Keys[0].KeptFile != "" || a.Keys[0].Requests[0].Consumed || len(h.record().Committed) != 0 {
			t.Fatalf("under a foreign certificate the answer was read: %+v", a)
		}
	})
	t.Run("include_inside_match", func(t *testing.T) {
		h := newHostCertHost(t)
		h.setSSHDConfig("Match User nobody\n\t" + h.include())
		// sshd reads the drop-in only for that user: the global sshd -T
		// shows none of its lines (the fake's noInclude).
		h.run.noInclude = true
		h.publishDir(h.hostSpec(h.sshd.pub))
		if _, err := h.apply(); err == nil {
			t.Fatal("the trust apply accepted a drop-in inside a Match block")
		}
	})
	t.Run("include_moved_into_match_after_install_krl_lands", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.setSSHDConfig("Match User nobody\n\t" + h.include())
		h.run.rejectDropIn = func(b []byte) bool { return bytes.Contains(b, []byte("HostCertificate")) }
		h.publishKRL(79)
		before := h.reloadCount()
		r, _ := h.apply()
		if r == nil || !h.krlRevokes(h.l.Current(), 79) || len(h.dropInCerts()) != 0 || h.reloadCount()-before != 1 {
			t.Fatalf("report %+v, lines %v, reloads %d; want the spec-less drop-in, one reload and the KRL", r, h.dropInCerts(), h.reloadCount()-before)
		}
	})
	t.Run("noop_repairs_section", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.stripLines()
		if r := h.mustApply(); r.NoOp || !bytes.Equal(h.dropInBytes(), h.committedRender()) {
			t.Fatalf("the no-op run: %+v", r)
		}
	})
	t.Run("unauthorized_noop_repairs_section", func(t *testing.T) {
		a := adminRemoved(t)
		h := &hostCertHost{testHost: a.testHost}
		_ = os.Mkdir(h.l.Outbox(), 0o750)
		before := h.dropInBytes()
		if err := os.WriteFile(h.l.DropIn(), append(bytes.Clone(before), []byte("# edited\n")...), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		_, _ = h.apply()
		if !bytes.Equal(h.dropInBytes(), before) {
			t.Fatal("the unauthorized no-op did not repair the drop-in")
		}
	})
	t.Run("versions_commit_repairs_section", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.stripLines()
		gen := h.current()
		// A policy rotation with the CA set and admins unchanged renders
		// the same bytes: the new versions are committed without a swap.
		_, b2, p2 := h.f.rotation(h.f.bundle, h.f.bundleDoc, h.f.policyDoc, h.f.policy, h.f.policy.Admins, "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = b2, p2
		r := h.mustApply()
		if h.current() != gen || r.BundleVersion != 2 {
			t.Fatalf("generation %d -> %d, bundle %d: want bundle 2 stored on the same generation", gen, h.current(), r.BundleVersion)
		}
		if !bytes.Equal(h.dropInBytes(), h.committedRender()) {
			t.Fatal("the commit of unchanged versions did not repair the section")
		}
	})
	t.Run("dry_run_noop_does_not_repair", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.stripLines()
		before := h.dropInBytes()
		dry := h.cfg
		dry.DryRun = true
		r, _ := Apply(context.Background(), dry, h.l)
		if !bytes.Equal(h.dropInBytes(), before) || r == nil || !slices.ContainsFunc(r.Diff, func(s string) bool { return strings.HasPrefix(s, "repair ") }) {
			t.Fatalf("dry run: %+v", r)
		}
	})
	t.Run("served_cert_mismatch_rolls_back", func(t *testing.T) {
		h := newHostCertHost(t)
		old := h.one()
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		if _, err := h.hostCerts(); err != nil {
			t.Fatal(err)
		}
		if rec := h.record(); rec.InProgress || rec.Committed[0].Serial != old.Serial {
			t.Fatalf("after served_cert_mismatch: %+v, want the committed set kept", rec)
		}
	})
	t.Run("algorithm_disabled_reported", func(t *testing.T) {
		h := newHostCertHost(t)
		h.run.hostKeyAlgorithms = ssh.CertAlgoED25519v01 + "," + ssh.KeyAlgoED25519 + "," + ssh.KeyAlgoECDSA256
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		h.mustApply()
		if r := h.mustHostCerts(); r.Deferred[hostcert.KeySHA256(h.ec.PublicKey())] != hostcert.DeferAlgorithmDisabled {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("algorithm_disabled_on_one_key_installs_other", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.run.hostKeyAlgorithms = ssh.CertAlgoED25519v01 + "," + ssh.KeyAlgoED25519 + "," + ssh.KeyAlgoECDSA256
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.mustHostCerts()
		served := map[string]bool{}
		var edSerial uint64
		for _, en := range h.record().Committed {
			served[en.KeySHA256] = en.Served
			if en.KeySHA256 == ed(h) {
				edSerial = en.Serial
			}
		}
		if served[hostcert.KeySHA256(h.ec.PublicKey())] || !served[ed(h)] || edSerial == 0 || h.record().InProgress {
			t.Fatalf("record %+v, want the Ed25519 renewal committed and the ECDSA key not served", h.record())
		}
	})
	t.Run("answer_for_unknown_request_ignored", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		c := h.issue(h.sshd.pub, strings.Repeat("d", 32))
		h.writeAnswer(ed(h), hostcert.Answer{RequestID: strings.Repeat("d", 32), Certificate: c.Marshal()})
		h.mustHostCerts()
		if len(h.record().Committed) != 0 {
			t.Fatal("an answer for a request ID the applier never issued was installed")
		}
	})
	t.Run("late_answer_within_330s_installed", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		h.clock.advance(300 * time.Second)
		h.answer()
		if r := h.mustHostCerts(); len(r.Installed) != 1 {
			t.Fatalf("a late answer: %+v", r)
		}
	})
	t.Run("redelivered_answer_installed", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		for k, req := range h.outboxRequests() {
			c := h.issue(h.sshd.pub, strings.Repeat("c", 32)) // its req names an earlier request
			h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Certificate: c.Marshal()})
		}
		if r := h.mustHostCerts(); len(r.Installed) != 1 {
			t.Fatalf("a re-delivered answer: %+v", r)
		}
	})
	t.Run("failed_install_keeps_cert_and_retries", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		_, _ = h.hostCerts()
		h.sshd.serveCert(nil)
		if r := h.mustHostCerts(); len(r.Installed) != 1 || len(r.Requested) != 0 {
			t.Fatalf("the retry: %+v, want the kept certificate installed without a new request", r)
		}
	})
	t.Run("kept_file_revoked_before_retry_not_installed", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		_, _ = h.hostCerts()
		h.sshd.serveCert(nil)
		kept := h.attempts().Keys[0].KeptFile
		m := hostcert.CertFileRE.FindStringSubmatch(kept)
		serial, _ := strconv.ParseUint(m[2], 10, 64)
		h.f.krlHostSerials = []uint64{serial}
		h.publishKRL()
		h.mustApply()
		h.mustHostCerts()
		if len(h.record().Committed) != 0 {
			t.Fatal("a kept certificate the KRL now revokes was installed")
		}
	})
	t.Run("adopted_file_survives_hold", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		_, _ = h.hostCerts()
		kept := h.attempts().Keys[0].KeptFile
		spec := h.hostSpec(h.sshd.pub)
		spec.status = "disabled"
		h.publishDir(spec)
		_, _ = h.apply()
		h.mustHostCerts()
		if !slices.Contains(h.certFiles(), kept) {
			t.Fatal("GC removed a kept file under a hold")
		}
	})
	t.Run("gc_keeps_files_when_record_missing_under_hold", func(t *testing.T) {
		for _, variant := range []string{"host_disabled", "no_hold_unadoptable"} {
			t.Run(variant, func(t *testing.T) {
				h := newHostCertHost(t)
				h.one()
				files := h.certFiles()
				if variant == "host_disabled" {
					spec := h.hostSpec(h.sshd.pub)
					spec.status = "disabled"
					h.publishDir(spec)
				} else {
					// Files that fail VerifyAnswer: signed by a CA nobody pins.
					other := h.issueBy(seedKey(t, 99), h.sshd.pub)
					name := hostcert.CertFileName(ed(h), other.Serial)
					if err := os.WriteFile(filepath.Join(h.l.HostCertDir(), name), ssh.MarshalAuthorizedKey(other), 0o644); err != nil { //nolint:gosec // test fixture
						t.Fatal(err)
					}
					files = h.certFiles()
					for _, f := range files {
						if f != name {
							_ = os.Remove(filepath.Join(h.l.HostCertDir(), f))
						}
					}
					files = h.certFiles()
					a := h.attempts()
					a.Keys = []hostcert.Attempt{{KeySHA256: ed(h), Requests: []hostcert.PendingRequest{}, NextAt: uint64(h.clock.Now().Unix()) + 3000}} //nolint:gosec // G115
					b, _ := a.Encode()
					_ = os.WriteFile(h.l.State(hostcert.AttemptsFile), b, 0o600)
				}
				_ = os.Remove(h.l.State(hostcert.RecordFile))
				_, _ = h.apply()
				for range 2 {
					r, _ := h.hostCerts()
					if r.Code != CodeHostCertRecordMissing {
						t.Fatalf("report %+v, want hostcert_record_missing", r)
					}
				}
				if got := h.certFiles(); !slices.Equal(got, files) {
					t.Fatalf("files %v, want %v kept", got, files)
				}
			})
		}
	})
	t.Run("gc_leaves_unrelated_files", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		dir := h.l.HostCertDir()
		_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644) //nolint:gosec // test fixture
		_ = os.WriteFile(filepath.Join(dir, "other.pub"), []byte("x"), 0o644) //nolint:gosec // test fixture
		_ = os.Symlink("/etc/passwd", filepath.Join(dir, hostcert.CertFileName(strings.Repeat("a", 64), 7)))
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.mustHostCerts()
		for _, f := range []string{"notes.txt", "other.pub", hostcert.CertFileName(strings.Repeat("a", 64), 7)} {
			if _, err := os.Lstat(filepath.Join(dir, f)); err != nil {
				t.Fatalf("GC removed %s", f)
			}
		}
	})
	t.Run("gc_never_removes_file_named_by_dropin", func(t *testing.T) {
		h := newHostCertHost(t)
		c := h.one()
		stray := hostcert.CertFileName(strings.Repeat("b", 64), 5)
		_ = os.WriteFile(filepath.Join(h.l.HostCertDir(), stray), ssh.MarshalAuthorizedKey(c), 0o644) //nolint:gosec // test fixture
		b := append(h.dropInBytes(), []byte("HostCertificate "+filepath.Join(h.l.HostCertDir(), stray)+"\n")...)
		_ = os.WriteFile(h.l.DropIn(), b, 0o644) //nolint:gosec // test fixture
		e := &engine{cfg: h.cfg, l: h.l, clock: h.cfg.Clock, report: &Report{}, stateFd: -1}
		st := &hostCertState{rec: h.record(), attempts: h.attempts()}
		if err := e.gcHostCerts(st); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(h.certFiles(), stray) {
			t.Fatal("GC removed a file the drop-in names")
		}
	})
	t.Run("cert_file_edited_is_drift", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		en := h.record().Committed[0]
		other := h.issue(h.sshd.pub, strings.Repeat("f", 32))
		_ = os.WriteFile(filepath.Join(h.l.HostCertDir(), en.File), ssh.MarshalAuthorizedKey(other), 0o644) //nolint:gosec // test fixture
		d, err := Check(context.Background(), h.cfg, h.l)
		if err != nil || !slices.ContainsFunc(d.Files, func(f FileDrift) bool { return strings.HasSuffix(f.File, en.File) }) {
			t.Fatalf("check %+v, %v: want a FileDrift", d, err)
		}
		if r := h.mustHostCerts(); !slices.Contains(r.Requested, en.KeySHA256) {
			t.Fatalf("%+v: the edited file was treated as installed", r)
		}
	})
	t.Run("check_during_install_not_drift", func(t *testing.T) {
		h := newHostCertHost(t)
		h.requested()
		h.crashed("hostcert-reload")
		d, err := Check(context.Background(), h.cfg, h.l)
		if err != nil || slices.ContainsFunc(d.Files, func(f FileDrift) bool { return f.File == h.l.DropIn() }) {
			t.Fatalf("check during an install: %+v, %v", d, err)
		}
	})
	t.Run("rsa_skipped_reported", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		if r := h.mustHostCerts(); !slices.Contains(r.Skipped, ssh.KeyAlgoRSA) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("no_request_while_directory_unauthorized", func(t *testing.T) {
		a := adminRemoved(t)
		h := &hostCertHost{testHost: a.testHost}
		_ = os.Mkdir(h.l.Outbox(), 0o750)
		if r := h.mustHostCerts(); r.Hold != hostcert.HoldDirectoryUnauthorized || len(h.outboxRequests()) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("no_request_when_host_keys_rotated", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		spec := h.hostSpec(seedKey(t, 98).PublicKey())
		h.publishDir(spec)
		_, _ = h.apply()
		if r := h.mustHostCerts(); r.Hold == "" || len(r.Requested) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("no_request_when_entry_disabled", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		spec := h.hostSpec(h.sshd.pub)
		spec.status = "disabled"
		h.publishDir(spec)
		_, _ = h.apply()
		if r := h.mustHostCerts(); r.Hold != hostcert.HoldHostDisabled || len(r.Requested) != 0 {
			t.Fatalf("%+v", r)
		}
	})
	writeNothing := func(t *testing.T, h *hostCertHost, prep func()) {
		t.Helper()
		prep()
		before, reloads := h.stateSnapshot(), h.reloadCount()
		_, _ = h.hostCerts()
		if after := h.stateSnapshot(); after != before || h.reloadCount() != reloads {
			t.Fatalf("HostCerts wrote:\n%s\nwas:\n%s\n(reloads %d -> %d)", after, before, reloads, h.reloadCount())
		}
	}
	pendingMarker := func(h *hostCertHost) {
		h.t.Helper()
		h.cfg.Fault = func(p string) error {
			if p == "swap" {
				return errCrash
			}
			return nil
		}
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		_, _ = h.apply()
		h.cfg.Fault = nil
	}
	t.Run("no_install_while_marker_pending", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		writeNothing(t, h, func() { h.renewDue(); h.mustHostCerts(); h.answer(); pendingMarker(h) })
	})
	t.Run("no_install_before_first_lastgood", func(t *testing.T) {
		h := newHostCertHost(t)
		writeNothing(t, h, func() {})
	})
	t.Run("hold_no_generation_writes_nothing", func(t *testing.T) {
		for _, foreign := range []bool{false, true} {
			h := newHostCertHost(t)
			if foreign {
				_ = os.WriteFile(h.l.DropIn(), []byte("HostCertificate /etc/ssh/x-cert.pub\n"), 0o644) //nolint:gosec // test fixture
			}
			writeNothing(t, h, func() {})
			if r, _ := h.hostCerts(); r.Hold != hostcert.HoldNoGeneration {
				t.Fatalf("%+v, want no_generation", r)
			}
		}
	})
	sshdTFails := func(h *hostCertHost) {
		h.t.Helper()
		h.run.rejectDropIn = func(b []byte) bool { return bytes.Contains(b, []byte("# edited")) }
		b := append(h.dropInBytes(), []byte("# edited\n")...)
		_ = os.WriteFile(h.l.DropIn(), b, 0o644) //nolint:gosec // test fixture
	}
	t.Run("no_install_while_marker_pending_sshd_t_fails", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		pendingMarker(h)
		writeNothing(t, h, func() { sshdTFails(h) })
		if _, err := h.hostCerts(); err == nil {
			t.Fatal("HostCerts did not return sshd -T's error")
		}
	})
	t.Run("no_install_while_stuck_sshd_t_fails", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		// A dangling current with no marker: stuck() is set.
		older, err := os.Readlink(h.l.Current())
		if err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(h.l.Current())
		if err := os.Symlink(filepath.Join(filepath.Dir(older), "999999"), h.l.Current()); err != nil {
			t.Fatal(err)
		}
		writeNothing(t, h, func() { sshdTFails(h) })
		if r, err := h.hostCerts(); err == nil {
			t.Fatalf("HostCerts = %+v, want sshd -T's error", r)
		}
	})
	t.Run("no_install_while_recover_due_sshd_t_fails", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		older, err := os.Readlink(h.l.Current())
		if err != nil {
			t.Fatal(err)
		}
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		h.mustApply()
		// current goes back to the older generation, which is not the
		// rollback target of the newer last-good: Apply's no-marker
		// recover predicate (apply.go:453) holds.
		_ = os.Remove(h.l.Current())
		if err := os.Symlink(older, h.l.Current()); err != nil {
			t.Fatal(err)
		}
		if c, lg := h.current(), h.lastGood(); c == 0 || lg == 0 || c == lg {
			t.Fatalf("current %d, last-good %d: want both the agent's at different numbers", c, lg)
		}
		writeNothing(t, h, func() { sshdTFails(h) })
		if r, err := h.hostCerts(); err == nil {
			t.Fatalf("HostCerts = %+v, want sshd -T's error", r)
		}
	})
	t.Run("request_valid_for_is_zero", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		for _, r := range h.outboxRequests() {
			if r.ValidForSeconds != 0 {
				t.Fatalf("valid_for %d", r.ValidForSeconds)
			}
		}
	})
	t.Run("backoff_on_one_key_installs_other", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		h.mustApply()
		h.mustHostCerts()
		for k, req := range h.outboxRequests() {
			if k == hostcert.KeySHA256(h.ec.PublicKey()) {
				h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Refused: "cert_revoked"})
				continue
			}
			c := h.issue(h.sshd.pub, hex.EncodeToString(req.RequestID[:]))
			h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Certificate: c.Marshal()})
		}
		r := h.mustHostCerts()
		if len(r.Installed) != 1 || r.Installed[0] != ed(h) || !strings.HasPrefix(r.Deferred[hostcert.KeySHA256(h.ec.PublicKey())], hostcert.DeferRefusedPrefix) {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("krl_lands_while_hostcert_fails", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		h.sshd.serveCert(h.issue(h.sshd.pub, strings.Repeat("e", 32)))
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		_, _ = h.hostCerts()
		h.publishKRL(80)
		h.mustApply()
		if !h.krlRevokes(h.l.Current(), 80) {
			t.Fatal("the KRL did not land while the host-certificate step failed")
		}
	})
}

// issueBy is issue with another CA.
func (h *hostCertHost) issueBy(ca ssh.Signer, pub ssh.PublicKey) *ssh.Certificate {
	h.t.Helper()
	h.serial++
	c, err := krcert.Build(krcert.Request{
		Profile: krcert.Profile{CertType: ssh.HostCert, MaxTTL: 30 * 24 * time.Hour}, Subject: pub, Principals: []string{"web1"}, Now: h.clock.Now(),
		ValidFor: time.Duration(h.lifetime) * time.Second, Serial: h.serial, //nolint:gosec // G115: test lifetimes
		KeyID: krcert.KeyID{V3: true, CA: "host", Subject: "web1", Request: strings.Repeat("9", 32), Policy: 1, Directory: 1, Serial: h.serial},
	}, ca, rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// dropInSpecSorted: the HostCertificate lines follow the trio, sorted,
// whatever order the spec lists them in (03-09, D1).
func dropInSpecSorted(t *testing.T) {
	t.Run("spec_lines_sorted_after_trio", func(t *testing.T) {
		l := Layout{Root: "/r", StateDir: "/s"}
		got := string(DropIn(l, DropInSpec{HostCertificates: []string{"/r/c/b.pub", "/r/c/a.pub"}}))
		want := string(DropIn(l, DropInSpec{})) + "HostCertificate /r/c/a.pub\nHostCertificate /r/c/b.pub\n"
		if got != want {
			t.Fatalf("DropIn:\n%s\nwant:\n%s", got, want)
		}
	})
}

// TestHostCertConfigGraph: a sibling file of the drop-in that ends inside
// a Match block does not put the next sibling's lines inside Match (sshd
// ends a Match block at the end of an included file).
func TestHostCertConfigGraph(t *testing.T) {
	t.Run("sibling_match_isolated", func(t *testing.T) {
		h := newHostCertHost(t)
		rel, err := filepath.Rel(h.l.Root, filepath.Join(filepath.Dir(h.l.DropIn()), "00-a.conf"))
		if err != nil {
			t.Fatal(err)
		}
		writeRootFile(t, h.testHost, rel, "Match User nobody\n\tPasswordAuthentication no\n")
		if err := os.WriteFile(h.l.DropIn(), DropIn(h.l, DropInSpec{}), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		files, _ := configGraph(h.l, h.cfg.SSHDConfig, nil)
		seen := false
		for _, f := range files {
			seen = seen || f.path == h.l.DropIn()
		}
		if !seen || dropInInMatch(h.l, files) {
			t.Fatalf("drop-in read %t, in Match %t: want read outside Match", seen, dropInInMatch(h.l, files))
		}
	})
}

// TestHostCertDrift is check's host-certificate part (03-09).
func TestHostCertDrift(t *testing.T) {
	check := func(t *testing.T, h *hostCertHost) *DriftReport {
		t.Helper()
		d, err := Check(context.Background(), h.cfg, h.l)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Run("spec_line_missing_in_sshd_T", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		want := h.dropInCerts()[0]
		// sshd -T reads no drop-in: none of the spec's lines is in force.
		h.run.noInclude = true
		d := check(t, h)
		if !slices.ContainsFunc(d.Settings, func(s SettingDrift) bool { return s.Keyword == hostCertificateKeyword && s.Want == want }) {
			t.Fatalf("settings %+v, want %s missing from sshd -T", d.Settings, want)
		}
	})
	t.Run("foreign_hostcertificate_value_reported", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.run.hostCertAfter = []string{"/etc/ssh/other-cert.pub"}
		d := check(t, h)
		if !slices.ContainsFunc(d.Settings, func(s SettingDrift) bool {
			return s.Keyword == hostCertificateKeyword && s.Got == "/etc/ssh/other-cert.pub" && s.Want == ""
		}) {
			t.Fatalf("settings %+v, want the foreign value", d.Settings)
		}
	})
	t.Run("renewal_candidate_not_drift", func(t *testing.T) {
		h := newHostCertHost(t)
		h.one()
		h.renewDue()
		h.mustHostCerts()
		h.answer()
		h.crashed("hostcert-reload")
		d := check(t, h)
		if slices.ContainsFunc(d.Settings, func(s SettingDrift) bool { return s.Keyword == hostCertificateKeyword }) {
			t.Fatalf("settings %+v: the renewal's candidate in force is reported as drift", d.Settings)
		}
	})
	t.Run("committed_file_missing_reported", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		en := h.record().Committed[0]
		if err := os.Remove(filepath.Join(h.l.HostCertDir(), en.File)); err != nil {
			t.Fatal(err)
		}
		d := check(t, h)
		if !slices.ContainsFunc(d.Files, func(f FileDrift) bool {
			return strings.HasSuffix(f.File, en.File) && f.GotSHA256 == "" && f.WantSHA256 == en.CertSHA256
		}) {
			t.Fatalf("files %+v, want the missing certificate file", d.Files)
		}
	})
}

// TestHostCertPreflight is preflight's host-certificate part (03-09).
func TestHostCertPreflight(t *testing.T) {
	preflight := func(t *testing.T, h *hostCertHost) *PreflightReport {
		t.Helper()
		r, err := Preflight(context.Background(), h.cfg, h.l)
		if err != nil {
			t.Fatalf("Preflight: %v", err)
		}
		return r
	}
	hasNote := func(r *PreflightReport, code string) bool {
		return slices.ContainsFunc(r.Notes, func(n string) bool { return strings.HasPrefix(n, code+":") })
	}
	t.Run("foreign_host_certificate_is_a_note", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		appendFile(t, h.cfg.SSHDConfig, "HostCertificate /etc/ssh/other-cert.pub\n")
		r := preflight(t, h)
		if !hasNote(r, CodeForeignHostCertificate) || r.Refused() {
			t.Fatalf("report %+v, want a foreign_host_certificate note and no refusal", r)
		}
	})
	t.Run("invalid_record_is_a_note", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.writeRecord([]byte("garbage"), 0o600)
		r := preflight(t, h)
		if !hasNote(r, CodeHostCertRecordInvalid) || r.Refused() {
			t.Fatalf("report %+v, want a hostcert_record_invalid note and no refusal", r)
		}
	})
	t.Run("installed_with_lines_no_drift", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		r := preflight(t, h)
		if finding(r, CodeDropInDrift) != nil || finding(r, CodeForeignTrust) != nil {
			t.Fatalf("findings %+v, want neither dropin_drift nor foreign_trust_setting", r.Findings)
		}
	})
	t.Run("preflightApply_skipped_when_equal", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		// A missing ssh-keygen is a refusal of preflightApply: with the
		// drop-in equal to wantDropIn it is never reached.
		h.cfg.SSHKeygen = filepath.Join(h.l.Root, "no-ssh-keygen")
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		if _, err := h.apply(); err != nil {
			t.Fatalf("an apply with the drop-in as wanted ran preflightApply: %v", err)
		}
		h.stripLines()
		h.publishDir(h.hostSpec(h.sshd.pub, h.ec.PublicKey()))
		if _, err := h.apply(); err == nil || !strings.Contains(err.Error(), CodeSSHKeygenMissing) {
			t.Fatalf("an apply with a differing drop-in: %v, want preflightApply's ssh_keygen_missing", err)
		}
	})
	t.Run("preflight_no_state_dir_foreign_dropin", func(t *testing.T) {
		h := newHostCertHost(t)
		dropIn := "TrustedUserCAKeys /etc/ssh/other_ca.pub\nHostCertificate /etc/ssh/x-cert.pub\n"
		if err := os.WriteFile(h.l.DropIn(), []byte(dropIn), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if err := os.RemoveAll(h.l.StateDir); err != nil {
			t.Fatal(err)
		}
		r := preflight(t, h)
		if finding(r, CodeForeignTrust) == nil {
			t.Fatalf("findings %+v, want foreign_trust_setting", r.Findings)
		}
	})
}

// TestHostCertStatus: status.json carries the host-certificate fields
// (03-09).
func TestHostCertStatus(t *testing.T) {
	t.Run("fields_from_record_and_attempts", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		s := h.status()
		if len(s.HostCerts) != 2 || len(s.HostKeysSkipped) != 1 || s.HostKeysSkipped[0] != (heartbeat.SkippedKey{Type: ssh.KeyAlgoRSA, Reason: "rsa_host_key_skipped"}) {
			t.Fatalf("status %+v %+v, want both certificates and the RSA key skipped", s.HostCerts, s.HostKeysSkipped)
		}
		for _, c := range s.HostCerts {
			i := slices.IndexFunc(h.record().Committed, func(e hostcert.Entry) bool { return e.KeySHA256 == c.KeySHA256 })
			if i < 0 || c.Serial == 0 || c.ValidBefore == 0 || len(c.CASHA256) != 64 || !c.Served || c.Type == "" {
				t.Fatalf("host_certs entry %+v", c)
			}
		}
	})
	t.Run("served_false_encoded", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub, h.ed2.PublicKey()))
		h.mustApply()
		h.mustHostCerts()
		h.answer()
		h.mustHostCerts()
		b, err := os.ReadFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(`"served":false`)) || !bytes.Contains(b, []byte(`"served":true`)) {
			t.Fatalf("status.json %s, want served true and false encoded", b)
		}
	})
	t.Run("status_written_after_install", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		h.mustHostCerts()
		h.answer()
		_ = os.Remove(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = HostCerts(context.Background(), h.cfg, h.l)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("HostCerts did not return: a self-deadlock on apply.lock")
		}
		if s := h.status(); len(s.HostCerts) != 1 {
			t.Fatalf("status %+v, want the installed certificate", s.HostCerts)
		}
	})
	t.Run("no_certificates_no_fields", func(t *testing.T) {
		h := newHostCertHost(t)
		h.installed("role:ops")
		b, err := os.ReadFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"host_certs", "host_keys_skipped", "host_cert_detail"} {
			if bytes.Contains(b, []byte(`"`+f+`"`)) {
				t.Fatalf("a host without host certificates writes %s: %s", f, b)
			}
		}
	})
}

// TestHostCertAttemptsPruned: the attempts of keys sshd no longer serves
// or the entry no longer lists are dropped, so retired keys never use up
// the file's room of directory.MaxHostKeys keys (03-09).
func TestHostCertAttemptsPruned(t *testing.T) {
	t.Run("ninth_key_requested", func(t *testing.T) {
		h := newHostCertHost(t)
		h.publishDir(h.hostSpec(h.sshd.pub))
		h.mustApply()
		// Eight keys this host served and listed once, all retired now.
		a := &hostcert.Attempts{Version: hostcert.AttemptsVersion, Keys: []hostcert.Attempt{}, Skipped: []string{}}
		for i := range 8 {
			a.Keys = append(a.Keys, hostcert.Attempt{KeySHA256: hostcert.KeySHA256(seedKey(t, byte(40+i)).PublicKey()), Requests: []hostcert.PendingRequest{}})
		}
		slices.SortFunc(a.Keys, func(x, y hostcert.Attempt) int { return strings.Compare(x.KeySHA256, y.KeySHA256) })
		b, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.l.State(hostcert.AttemptsFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		r := h.mustHostCerts()
		got := h.attempts()
		if len(r.Requested) != 1 || len(got.Keys) != 1 || got.Keys[0].KeySHA256 != hostcert.KeySHA256(h.sshd.pub) {
			t.Fatalf("report %+v, attempts %+v: want the served key requested and only its attempt kept", r, got.Keys)
		}
	})
}

// TestHostCertDueNotPast: the due time HostCerts returns is never one it
// reached already, so the run loop does not call it on every iteration
// for a key it cannot act on (03-09).
func TestHostCertDueNotPast(t *testing.T) {
	t.Run("algorithm_disabled_past_renew_at", func(t *testing.T) {
		h := newHostCertHost(t)
		h.both()
		h.run.hostKeyAlgorithms = ssh.CertAlgoED25519v01 + "," + ssh.KeyAlgoED25519 + "," + ssh.KeyAlgoECDSA256
		h.renewDue()
		for i := range 2 {
			r := h.mustHostCerts()
			if !r.Due.After(h.clock.Now()) {
				t.Fatalf("run %d: due %v at %v (report %+v), want a time after now", i, r.Due, h.clock.Now(), r)
			}
		}
	})
}

// TestHostCertLostFileHealed: a committed certificate file that is lost
// or edited inside the signer's window is healed by the re-delivered
// certificate, which carries the same serial (03-09).
func TestHostCertLostFileHealed(t *testing.T) {
	for _, damage := range []string{"removed", "edited"} {
		t.Run(damage, func(t *testing.T) {
			h := newHostCertHost(t)
			c := h.one()
			en := h.record().Committed[0]
			p := filepath.Join(h.l.HostCertDir(), en.File)
			if damage == "removed" {
				_ = os.Remove(p)
			} else {
				_ = os.WriteFile(p, []byte("garbage\n"), 0o644) //nolint:gosec // test fixture
			}
			if r := h.mustHostCerts(); len(r.Requested) != 1 {
				t.Fatalf("report %+v, want a request for the damaged key", r)
			}
			// The signer re-delivers the certificate it issued in its window.
			for k, req := range h.outboxRequests() {
				h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Certificate: c.Marshal()})
			}
			r := h.mustHostCerts()
			rec := h.record()
			if len(r.Installed) != 1 || len(rec.Committed) != 1 || rec.Committed[0].Serial != c.Serial || !rec.Committed[0].Served {
				t.Fatalf("report %+v, record %+v: want the re-delivered certificate installed and served", r, rec)
			}
			if got := h.served(c.Type()); got == nil || !bytes.Equal(got.Marshal(), c.Marshal()) {
				t.Fatal("sshd does not serve the healed certificate")
			}
		})
	}
	t.Run("intact_file_same_serial_refused", func(t *testing.T) {
		h := newHostCertHost(t)
		c := h.one()
		h.renewDue()
		h.mustHostCerts()
		for k, req := range h.outboxRequests() {
			h.writeAnswer(k, hostcert.Answer{RequestID: hex.EncodeToString(req.RequestID[:]), Certificate: c.Marshal()})
		}
		if r := h.mustHostCerts(); len(r.Installed) != 0 || h.attempts().Keys[0].LastCode != "answer_not_newer" {
			t.Fatalf("report %+v, attempts %+v: want the same serial refused while the file is intact", r, h.attempts())
		}
	})
}

// TestHostCertSelfTestFamilies: the served-certificate self-test skips an
// IPv6 loopback address that is off or unreachable, as selfTest does, and
// probes the next one sshd listens on (03-09).
func TestHostCertSelfTestFamilies(t *testing.T) {
	h := newHostCertHost(t)
	c := h.one()
	port := strconv.Itoa(h.sshd.port)
	dump := ParseDump([]byte("listenaddress [::]:" + port + "\nlistenaddress " + net.JoinHostPort(net.IPv4zero.String(), port) + "\n"))
	for _, tc := range []struct {
		name  string
		errno syscall.Errno
		v6off bool
	}{{"eaddrnotavail", syscall.EADDRNOTAVAIL, false}, {"eafnosupport", syscall.EAFNOSUPPORT, false}, {"ipv6_off_on_lo", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			e := h.engine()
			e.cfg.SelfTestTimeout = 500 * time.Millisecond
			e.ipv6Off = func() bool { return tc.v6off }
			e.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, "[::1]") {
					if tc.errno == 0 {
						t.Fatalf("dialled %s with IPv6 off on lo", addr)
					}
					return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", tc.errno)}
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			served, err := e.hostCertSelfTest(context.Background(), dump, []*ssh.Certificate{c})
			if err != nil || !served[hostcert.KeySHA256(c.Key)] {
				t.Fatalf("hostCertSelfTest = %v, %v; want the certificate served on 127.0.0.1", served, err)
			}
		})
	}
}
