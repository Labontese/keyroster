//go:build linux

package apply

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/trust"
)

// enrollHost is a test host with an outbox (root 0750, as install makes it
// apart from the group) and pins.json.
func enrollHost(t *testing.T) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil {
		t.Fatal(err)
	}
	return h
}

// request is a valid enroll-request.json for h.
func request(h *testHost) enroll.Request {
	return enroll.Request{IdentitySPKISHA256: strings.Repeat("ab", 32), TokenSHA256: strings.Repeat("cd", 32), ExpectedName: "web1",
		InstallationID: h.f.pins().InstallationID}
}

// writeRequest writes r into h's spool as the fetcher would.
func writeRequest(t *testing.T, h *testHost, r enroll.Request) {
	t.Helper()
	b, err := trust.CanonicalJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.spool, EnrollRequestFile), b, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// answer reads and decodes h's outbox answer.
func answer(t *testing.T, h *testHost) *enroll.Answer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), EnrollPoPFile))
	if err != nil {
		t.Fatal(err)
	}
	var a enroll.Answer
	if err := trust.DecodeStrict(b, &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

func (h *testHost) enroll() (bool, error) {
	return Enroll(context.Background(), h.cfg, h.l)
}

func (h *testHost) noAnswer(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(h.l.Outbox(), EnrollPoPFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an answer was written: %v", err)
	}
}

// TestEnroll pins the applier's side of the enrollment hand-over (F2,
// T-03-225): the fetcher-written request is read through the open
// contract, checked against pins.json, and answered with every Ed25519 or
// ECDSA host key's proof of possession, written into the outbox only.
func TestEnroll(t *testing.T) {
	t.Run("valid_request_answered", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		if wrote, err := h.enroll(); wrote || err != nil {
			t.Fatalf("no request: %t, %v", wrote, err)
		}
		h.noAnswer(t)
		writeRequest(t, h, request(h))
		if wrote, err := h.enroll(); !wrote || err != nil {
			t.Fatalf("a valid request: %t, %v", wrote, err)
		}
		a := answer(t, h)
		if err := enroll.Verify(a.PoP, nil, a.Sigs); err != nil {
			t.Fatalf("the answer does not verify: %v", err)
		}
		if len(a.PoP.HostKeys) != 1 || a.PoP.HostKeys[0] != trust.FormatKey(h.sshd.pub) || a.PoP.IdentitySPKISHA256 != request(h).IdentitySPKISHA256 {
			t.Fatalf("PoP %+v", a.PoP)
		}
		st, err := os.Stat(filepath.Join(h.l.Outbox(), EnrollPoPFile))
		if err != nil || st.Mode().Perm() != 0o640 {
			t.Fatalf("enroll-pop.json mode %v (%v), want 0640", st.Mode(), err)
		}
		if wrote, err := h.enroll(); wrote || err != nil {
			t.Fatalf("the same request again: %t, %v (the answer is kept)", wrote, err)
		}
	})
	t.Run("pop_uses_pinned_installation", func(t *testing.T) {
		t.Parallel()
		// The applier signs only with pins.json's installation ID; a
		// request naming another is refused before anything is signed
		// (enroll_request_other_installation_refused).
		h := enrollHost(t)
		writeRequest(t, h, request(h))
		if _, err := h.enroll(); err != nil {
			t.Fatal(err)
		}
		if a := answer(t, h); a.PoP.InstallationID != h.f.pins().InstallationID {
			t.Fatalf("the PoP names installation %s, pins.json %s", a.PoP.InstallationID, h.f.pins().InstallationID)
		}
	})
	for name, edit := range map[string]func(r *enroll.Request){
		"enroll_request_other_installation_refused": func(r *enroll.Request) { r.InstallationID = "fedcba9876543210fedcba9876543210" },
		"installation_case_differs_refused":         func(r *enroll.Request) { r.InstallationID = strings.ToUpper(r.InstallationID) },
		"identity_not_hex_refused":                  func(r *enroll.Request) { r.IdentitySPKISHA256 = strings.Repeat("AB", 32) },
		"token_hash_short_refused":                  func(r *enroll.Request) { r.TokenSHA256 = "cd" },
		"bad_host_name_refused":                     func(r *enroll.Request) { r.ExpectedName = "../web1" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := enrollHost(t)
			r := request(h)
			edit(&r)
			writeRequest(t, h, r)
			if _, err := h.enroll(); !errors.Is(err, ErrEnrollRequest) {
				t.Fatalf("Enroll = %v, want enroll_request_invalid", err)
			}
			h.noAnswer(t)
		})
	}
	t.Run("enroll_request_not_canonical_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		b, _ := trust.CanonicalJSON(request(h))
		if err := os.WriteFile(filepath.Join(h.spool, EnrollRequestFile), append([]byte(" "), b...), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := h.enroll(); !errors.Is(err, ErrEnrollRequest) {
			t.Fatalf("Enroll = %v", err)
		}
	})
	t.Run("enroll_request_symlink_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		b, _ := trust.CanonicalJSON(request(h))
		if err := os.WriteFile(target, b, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(h.spool, EnrollRequestFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := h.enroll(); !errors.Is(err, ErrEnrollRequest) || !errors.Is(err, spool.ErrSymlink) {
			t.Fatalf("a symlinked request: %v", err)
		}
		h.noAnswer(t)
	})
	t.Run("enroll_request_fifo_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		if err := unix.Mkfifo(filepath.Join(h.spool, EnrollRequestFile), 0o644); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := h.enroll(); done <- err }()
		select {
		case err := <-done:
			if !errors.Is(err, spool.ErrNotRegular) {
				t.Fatalf("a FIFO request: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Enroll blocked on a FIFO")
		}
		h.noAnswer(t)
	})
	t.Run("enroll_request_oversize_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		p := filepath.Join(h.spool, EnrollRequestFile)
		if err := os.WriteFile(p, []byte(strings.Repeat(" ", enroll.MaxRequestFile)), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		// 4 KiB passes the size check (and then fails as JSON).
		if _, err := h.enroll(); !errors.Is(err, ErrEnrollRequest) || errors.Is(err, spool.ErrOversize) {
			t.Fatalf("a 4 KiB request: %v, want enroll_request_invalid but not spool_oversize", err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat(" ", enroll.MaxRequestFile+1)), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := h.enroll(); !errors.Is(err, spool.ErrOversize) {
			t.Fatalf("a 4 KiB + 1 request: %v, want spool_oversize", err)
		}
		h.noAnswer(t)
	})
	t.Run("outbox_write_ignores_planted_symlink", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("keep me\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(h.l.Outbox(), EnrollPoPFile)); err != nil {
			t.Fatal(err)
		}
		writeRequest(t, h, request(h))
		if wrote, err := h.enroll(); !wrote || err != nil {
			t.Fatalf("Enroll over a planted symlink: %t, %v", wrote, err)
		}
		if got := readFile(t, victim); got != "keep me\n" {
			t.Fatalf("the symlink's target was written: %q", got)
		}
		if st, err := os.Lstat(filepath.Join(h.l.Outbox(), EnrollPoPFile)); err != nil || !st.Mode().IsRegular() {
			t.Fatalf("enroll-pop.json is not a regular file: %v", err)
		}
	})
	t.Run("state_dir_unsafe_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		writeRequest(t, h, request(h))
		chmod(t, h.l.Outbox(), 0o770)
		if _, err := h.enroll(); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("a group-writable outbox: %v", err)
		}
		if _, err := Apply(context.Background(), h.cfg, h.l); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("apply with a group-writable outbox: %v", err)
		}
		chmod(t, h.l.Outbox(), 0o750)
		if err := os.Rename(h.l.Outbox(), h.l.Outbox()+".real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(h.l.Outbox()+".real", h.l.Outbox()); err != nil {
			t.Fatal(err)
		}
		if _, err := h.enroll(); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("an outbox replaced by a symlink: %v", err)
		}
		if _, err := Apply(context.Background(), h.cfg, h.l); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("apply with an outbox replaced by a symlink: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(h.l.Outbox()+".real", EnrollPoPFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("an answer was written through the symlink")
		}
	})
	t.Run("rsa_host_key_skipped", func(t *testing.T) {
		t.Parallel()
		// Stock Debian and Ubuntu hosts also have an RSA host key, which no
		// directory host entry may name: it is not in the proof.
		h := enrollHost(t)
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(rk, "")
		if err != nil {
			t.Fatal(err)
		}
		rsaPath := filepath.Join(t.TempDir(), "ssh_host_rsa_key")
		if err := os.WriteFile(rsaPath, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&rk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rsaPath+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		h.run.extraHostKeys = []string{rsaPath}
		writeRequest(t, h, request(h))
		if _, err := h.enroll(); err != nil {
			t.Fatal(err)
		}
		if a := answer(t, h); len(a.PoP.HostKeys) != 1 || !strings.HasPrefix(a.PoP.HostKeys[0], ssh.KeyAlgoED25519+" ") || len(a.Sigs) != 1 {
			t.Fatalf("PoP host keys %q", a.PoP.HostKeys)
		}
	})
	t.Run("host_key_agent_refused", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		h.run.extra = "hostkeyagent /run/sshd-agent.sock\n"
		writeRequest(t, h, request(h))
		if _, err := h.enroll(); !errors.Is(err, ErrHostKeyUnreadable) {
			t.Fatalf("host keys in an agent: %v", err)
		}
		h.noAnswer(t)
	})
	t.Run("encrypted_host_key_unreadable", func(t *testing.T) {
		t.Parallel()
		h := enrollHost(t)
		if err := os.WriteFile(h.sshd.keyPath, []byte("not a key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeRequest(t, h, request(h))
		if _, err := h.enroll(); !errors.Is(err, ErrHostKeyUnreadable) {
			t.Fatalf("an unreadable host key: %v", err)
		}
	})
}

// TestReadIdentity (TestIdentityCommand's library half): the identity is
// the fingerprint of the fetcher's SPKI, and the host keys are those an
// enrollment signs with.
func TestReadIdentity(t *testing.T) {
	h := enrollHost(t)
	id, err := ReadIdentity(context.Background(), h.cfg, h.l)
	if err != nil || id.Agent != "" || len(id.HostKeys) != 1 || id.Fingerprints[0] != ssh.FingerprintSHA256(h.sshd.pub) {
		t.Fatalf("before identity.pub: %+v, %v", id, err)
	}
}
