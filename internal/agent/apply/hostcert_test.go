//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
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
