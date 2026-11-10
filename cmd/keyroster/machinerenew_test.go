package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// newRenewEnv is a dirEnv whose root-signed policy has pop.machines on
// (03-11b).
func newRenewEnv(t *testing.T) *dirEnv {
	t.Helper()
	return newDirEnvPolicy(t, 1, 1, func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Machines: true} })
}

// machineKeyFile writes a fresh unencrypted Ed25519 private key to a file
// of its own directory and returns the path and the key.
func machineKeyFile(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ci")
	writeTestFile(t, path, pem.EncodeToMemory(block))
	return path, priv
}

// renewOpts break one thing at a time in the certificate the stub returns.
type renewOpts struct {
	ca         ssh.Signer        // the signing key; nil: the bundle's machine CA key
	claimCA    ssh.Signer        // SignatureKey written after signing (bad signature); nil: ca
	key        ssh.PublicKey     // the certified key; nil: the request's key
	certType   uint32            // 0: a user certificate
	request    string            // req= of the key ID; "": the request's ID
	subject    string            // sub= of the key ID; "": the request's name
	principals []string          // nil: deploy
	lifetime   uint64            // seconds; 0: 24 h
	policy     uint64            // pol= of the key ID; 0: the verified policy's version
	shift      int64             // seconds added to ValidAfter and ValidBefore
	critical   map[string]string // critical options
	extensions map[string]string // nil: permit-pty
}

// machineCASigner is the bundle's machine CA key as a signer.
func machineCASigner(t *testing.T, e *dirEnv) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(e.caKeys["machine"])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// lastRenew returns the request of the last body posted to the renew
// route.
func (e *dirEnv) lastRenew(t *testing.T) *wire.MachineIssueRequest {
	t.Helper()
	e.mu.Lock()
	body := e.renewBodies[len(e.renewBodies)-1]
	e.mu.Unlock()
	var in serverclient.MachineRenewRequest
	if err := json.Unmarshal(body, &in); err != nil {
		t.Errorf("renew body: %v", err)
		return nil
	}
	req, err := wire.ParseMachineIssueRequest(in.Request)
	if err != nil {
		t.Errorf("renew request: %v", err)
		return nil
	}
	return req
}

// machineCertFor builds the certificate the stub answers for req.
func machineCertFor(t *testing.T, e *dirEnv, req *wire.MachineIssueRequest, o renewOpts) *ssh.Certificate {
	t.Helper()
	key, err := ssh.ParsePublicKey(req.MachineKey)
	if err != nil {
		t.Fatal(err)
	}
	if o.key != nil {
		key = o.key
	}
	ca := o.ca
	if ca == nil {
		ca = machineCASigner(t, e)
	}
	kid := cert.KeyID{V3: true, CA: "machine", Subject: req.MachineName, Request: hex.EncodeToString(req.RequestID[:]), Policy: e.pol.Version, Directory: 1, Serial: 4242}
	if o.request != "" {
		kid.Request = o.request
	}
	if o.subject != "" {
		kid.Subject = o.subject
	}
	if o.policy != 0 {
		kid.Policy = o.policy
	}
	principals := o.principals
	if principals == nil {
		principals = []string{"deploy"}
	}
	lifetime := o.lifetime
	if lifetime == 0 {
		lifetime = 24 * 3600
	}
	certType := o.certType
	if certType == 0 {
		certType = ssh.UserCert
	}
	now := uint64(time.Now().Unix() + o.shift) //nolint:gosec // G115: the test's clock
	ext := o.extensions
	if ext == nil {
		ext = map[string]string{"permit-pty": ""}
	}
	c := &ssh.Certificate{
		Key: key, Serial: 4242, CertType: certType, KeyId: kid.String(), ValidPrincipals: principals,
		ValidAfter: now - 300, ValidBefore: now + lifetime,
		Permissions: ssh.Permissions{Extensions: ext, CriticalOptions: o.critical},
	}
	if err := c.SignCert(rand.Reader, ca); err != nil { //nolint:forbidigo // a test double of the signer whose answers break one check at a time (03-11b)
		t.Fatal(err)
	}
	if o.claimCA != nil {
		c.SignatureKey = o.claimCA.PublicKey()
	}
	return c
}

// renewAnswer makes the stub answer every renewal with the certificate
// machineCertFor builds from the posted request.
func renewAnswer(t *testing.T, e *dirEnv, o renewOpts) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.override["POST "+serverclient.MachineRenewPath] = func(w http.ResponseWriter) {
		req := e.lastRenew(t)
		if req == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c := machineCertFor(t, e, req, o)
		_ = json.NewEncoder(w).Encode(serverclient.MachineRenewAnswer{Certificate: c.Marshal()})
	}
}

// renewCount is how many renew requests the stub received.
func (e *dirEnv) renewCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.renewBodies)
}

// otherEd is a fresh Ed25519 signer.
func otherEd(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestMachineRenew pins keyroster machine renew's first slice (03-11b,
// D-15): the certificate alone is written, atomically; --out naming the
// key file is refused; a policy without pop.machines sends nothing.
func TestMachineRenew(t *testing.T) {
	t.Run("issued_writes_cert_only", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		key, _ := machineKeyFile(t)
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		code, stdout, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(readTestFile(t, out))
		if err != nil {
			t.Fatalf("CERTFILE: %v", err)
		}
		if c, ok := pk.(*ssh.Certificate); !ok || c.Serial != 4242 {
			t.Fatalf("CERTFILE holds %T, want the certificate", pk)
		}
		if runtime.GOOS != "windows" { // Windows has no Unix mode bits to check
			if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o644 {
				t.Fatalf("CERTFILE mode %v (%v), want 0644", fi.Mode().Perm(), err)
			}
		}
		for _, want := range []string{"machine certificate for ci written to " + out, "serial:      4242", "lifetime:    24h0m0s",
			"principals:  deploy", "CA:          SHA256:", "key:         SHA256:",
			"they are not checked against the directory except by --expect-principal"} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, stdout)
			}
		}
	})
	t.Run("out_written_atomically", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		key, _ := machineKeyFile(t)
		dir := t.TempDir()
		out := filepath.Join(dir, "ci-cert.pub")
		writeTestFile(t, out, []byte("the old certificate\n"))
		prev := machineRenewBeforeRename
		machineRenewBeforeRename = func() error { return errors.New("injected fault before the rename") }
		t.Cleanup(func() { machineRenewBeforeRename = prev })
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
		if code != 1 || !strings.Contains(stderr, "injected fault before the rename") {
			t.Fatalf("exit %d: %s; want 1 with the fault", code, stderr)
		}
		if got := string(readTestFile(t, out)); got != "the old certificate\n" {
			t.Fatalf("CERTFILE after the fault: %q, want the old certificate", got)
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("the directory holds %v (%v), want only CERTFILE", entries, err)
		}
	})
	t.Run("out_is_key_file_refused", func(t *testing.T) {
		const want = "--out names the key file; refusing to overwrite a private key"
		t.Run("same_path", func(t *testing.T) {
			e := newRenewEnv(t)
			renewAnswer(t, e, renewOpts{})
			key, _ := machineKeyFile(t)
			before := readTestFile(t, key)
			code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", filepath.Join(filepath.Dir(key), ".", filepath.Base(key)))
			if code != 1 || !strings.Contains(stderr, want) || e.renewCount() != 0 || !bytes.Equal(readTestFile(t, key), before) {
				t.Fatalf("exit %d, %d requests sent: %s; want 1, none, and %q", code, e.renewCount(), stderr, want)
			}
		})
		t.Run("hard_link", func(t *testing.T) {
			e := newRenewEnv(t)
			renewAnswer(t, e, renewOpts{})
			key, _ := machineKeyFile(t)
			link := filepath.Join(t.TempDir(), "ci-cert.pub")
			if err := os.Link(key, link); err != nil {
				t.Skipf("os.Link is not available here (%v), so a second name for the key file cannot be made", err)
			}
			code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", link)
			if code != 1 || !strings.Contains(stderr, want) || e.renewCount() != 0 {
				t.Fatalf("exit %d, %d requests sent: %s; want 1, none, and %q", code, e.renewCount(), stderr, want)
			}
		})
	})
	t.Run("pop_off_refused_before_send", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		renewAnswer(t, e, renewOpts{})
		key, _ := machineKeyFile(t)
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
		if code != 1 || !strings.Contains(stderr, "the root-signed policy does not allow machine renewal (pop.machines); nothing was sent") || e.renewCount() != 0 {
			t.Fatalf("exit %d, %d requests sent: %s", code, e.renewCount(), stderr)
		}
	})
	t.Run("no_installation_id_refused", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		e.resignBundle(t, func(b *trust.Bundle) { b.InstallationID = "" })
		key, _ := machineKeyFile(t)
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 1 || !strings.Contains(stderr, "the trust bundle has no installation ID; machine renewal needs one") || e.renewCount() != 0 {
			t.Fatalf("exit %d, %d sent: %s", code, e.renewCount(), stderr)
		}
	})
	t.Run("agent_key_signs", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		k1, k2 := newEd(t), newEd(t)
		useCountingKeyring(t, k1, k2)
		pub2, err := ssh.NewPublicKey(k2.Public())
		if err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "machine", "renew", "ci", "--agent-key", ssh.FingerprintSHA256(pub2), "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		req := e.lastRenew(t)
		if !bytes.Equal(req.MachineKey, pub2.Marshal()) {
			t.Fatal("the request's key is not the agent key named")
		}
		sig, err := sshsig.Parse(req.Evidence[0].Blob)
		if err != nil || !bytes.Equal(sig.PublicKey().Marshal(), pub2.Marshal()) || sig.Verify(wire.MachinePoPNamespace, req.SigningBytes()) != nil {
			t.Fatalf("the proof of possession does not verify under the agent key (%v)", err)
		}
	})
	t.Run("agent_key_missing", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		useCountingKeyring(t, newEd(t))
		pub, err := ssh.NewPublicKey(newEd(t).Public())
		if err != nil {
			t.Fatal(err)
		}
		fp := ssh.FingerprintSHA256(pub)
		code, _, stderr := run(t, "machine", "renew", "ci", "--agent-key", fp, "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 1 || !strings.Contains(stderr, "ssh-agent does not hold the machine key "+fp+"; load it with ssh-add") || e.renewCount() != 0 {
			t.Fatalf("exit %d, %d sent: %s", code, e.renewCount(), stderr)
		}
	})
	t.Run("usage", func(t *testing.T) {
		for name, args := range map[string][]string{
			"both_key_flags":            {"ci", "--key", "k", "--agent-key", "SHA256:x", "--out", "o"},
			"no_key_flag":               {"ci", "--out", "o"},
			"passphrase_fd_without_key": {"ci", "--agent-key", "SHA256:x", "--passphrase-fd", "3", "--out", "o"},
			"no_out":                    {"ci", "--key", "k"},
		} {
			t.Run(name, func(t *testing.T) {
				e := newRenewEnv(t)
				code, _, stderr := run(t, append([]string{"machine", "renew"}, args...)...)
				if code != 2 || !strings.Contains(stderr, "machine renew: ") || e.renewCount() != 0 {
					t.Fatalf("exit %d: %s; want 2 with a message", code, stderr)
				}
			})
		}
		t.Run("bad_name", func(t *testing.T) {
			newRenewEnv(t)
			code, _, stderr := run(t, "machine", "renew", "Bad/Name", "--key", "k", "--out", "o")
			if code != 1 || !strings.Contains(stderr, errHostName("machine", "Bad/Name").Error()) {
				t.Fatalf("exit %d: %s", code, stderr)
			}
		})
	})
	t.Run("refusal_texts", func(t *testing.T) {
		for _, tc := range []struct{ detail, want string }{
			{"machine_not_authenticated", "the server does not authenticate this renewal (machine_not_authenticated): the machine name is unknown, the key is not the one the directory lists for it, or the signature did not verify; the server does not say which, and its log does; nothing was issued"},
			{"machine_pop_not_enabled", "the policy in force does not allow machine renewal (machine_pop_not_enabled, pop.machines is off); nothing was issued"},
			{"request_time_skew", "this host's clock differs from the signer's by more than 5 minutes (request_time_skew); fix the clock and run again; nothing was issued"},
			{"machine_issue_installation_mismatch", "the server's signer belongs to another installation than the trust bundle your root pins verify (machine_issue_installation_mismatch); check the server URL and the root pins that keyroster init saved; nothing was issued"},
			{"machine_issue_no_installation_id", "the signer's trust bundle has no installation ID, or the request lost its own (machine_issue_no_installation_id); check the server URL and the root pins that keyroster init saved; nothing was issued"},
			{"directory_not_installed", "the signer holds no usable directory (directory_not_installed); ask an admin to install one; nothing was issued"},
			{"directory_not_authorized", "the signer holds no usable directory (directory_not_authorized); ask an admin to install one; nothing was issued"},
			{"machine_name_reserved", "machine names starting with probe. are reserved (machine_name_reserved); nothing was issued"},
			{"machine_key_revoked", "this key is revoked for good (machine_key_revoked); an admin must list a new key under a new name; nothing was issued"},
			{"cert_revoked", "a revocation holds this machine until the admins install a newer directory version (cert_revoked); ask an admin; nothing was issued"},
			{"machine_disabled", "the directory lists this machine as disabled (machine_disabled); ask an admin; nothing was issued"},
			{"machine_key_unusable", "the key listed for this machine is a key of this installation's trust bundle and never gets a machine certificate (machine_key_unusable); nothing was issued"},
			{"machine_issue_valid_for_not_zero", "the request did not reach the signer unchanged (machine_issue_valid_for_not_zero): this CLI always sends 0; nothing was issued"},
			{"bad_principal", "the installation cannot issue this certificate (bad_principal); ask an admin; nothing was issued"},
			{"ca_not_configured", "the installation cannot issue this certificate (ca_not_configured); ask an admin; nothing was issued"},
			{"duplicate_request", "the signer already accepted a request with this ID (duplicate_request); run the command again"},
			{"machine_renew_too_often", "12 certificates were issued for this key in the last hour (machine_renew_too_often); refused attempts do not count; wait and run again"},
			{"signer_too_old", "the signer predates machine certificates (signer_too_old); upgrade keyroster-signer, then keyroster-server; nothing was issued"},
			{"rate_limited", "the server rate limited this renewal; run it again after 7 seconds"},
			{"unavailable_503", "the server cannot reach its signer (HTTP 503); the outcome is unknown: if the certificate was issued, a retry costs one of the 12 per hour for this key"},
		} {
			t.Run(tc.detail, func(t *testing.T) {
				e := newRenewEnv(t)
				switch tc.detail {
				case "rate_limited":
					answerWith(e, http.StatusTooManyRequests, "rate limited", map[string]string{"Retry-After": "7"})
				case "unavailable_503":
					answerWith(e, http.StatusServiceUnavailable, "signer unavailable", nil)
				case "machine_issue_valid_for_not_zero", "duplicate_request":
					// Matched by detail whatever the status.
					answerWith(e, http.StatusBadRequest, tc.detail, nil)
				default:
					answerWith(e, http.StatusForbidden, tc.detail, nil)
				}
				key, _ := machineKeyFile(t)
				out := filepath.Join(t.TempDir(), "c.pub")
				code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
				if code != 1 || !strings.Contains(stderr, tc.want) {
					t.Fatalf("exit %d: %s\nwant %q", code, stderr, tc.want)
				}
				if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("CERTFILE written after a refusal")
				}
			})
		}
	})
	t.Run("unknown_detail_is_peer_text", func(t *testing.T) {
		e := newRenewEnv(t)
		answerWith(e, http.StatusForbidden, "a_detail_this_cli_does_not_know", nil)
		key, _ := machineKeyFile(t)
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", filepath.Join(t.TempDir(), "c.pub"))
		if code != 1 || !strings.Contains(stderr, "the server refused the renewal") || !strings.Contains(stderr, "a_detail_this_cli_does_not_know") ||
			strings.Contains(stderr, "ask an admin") || strings.Contains(stderr, "run again") {
			t.Fatalf("exit %d: %s; want the detail as peer text with no advice", code, stderr)
		}
	})
	t.Run("answer_refused_text", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{key: otherEd(t).PublicKey()})
		key, _ := machineKeyFile(t)
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", filepath.Join(t.TempDir(), "c.pub"))
		want := "the server's answer was issued but refused by this CLI's check (it is for another key); nothing was written. " +
			"The signer logged the issuance (serial 4242) and it counts toward the 12 per hour for this key"
		if code != 1 || !strings.Contains(stderr, want) {
			t.Fatalf("exit %d: %s\nwant %q", code, stderr, want)
		}
	})
}

// TestMachineRenewNeverWritesKey pins the prohibition of 03-11b: the
// machine's private key is never sent and never written. The key bytes
// come from the test's own source, never from the code under test.
func TestMachineRenewNeverWritesKey(t *testing.T) {
	e := newRenewEnv(t)
	renewAnswer(t, e, renewOpts{})
	key, priv := machineKeyFile(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "ci-cert.pub")
	if code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	needles := map[string][]byte{"seed": priv.Seed(), "private key": priv}
	// The base64 body lines of the key file that carry seed bytes; the
	// others hold only the public key and the format's framing, which the
	// request carries legitimately.
	var lines []string
	for _, line := range strings.Split(string(readTestFile(t, key)), "\n") {
		if line != "" && !strings.HasPrefix(line, "-----") {
			lines = append(lines, line)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	seedAt := bytes.Index(decoded, priv.Seed())
	if err != nil || seedAt < 0 {
		t.Fatalf("the key file body does not decode to the seed (%v)", err)
	}
	at := 0
	for i, line := range lines {
		n := len(line) / 4 * 3
		if at < seedAt+ed25519.SeedSize && seedAt < at+n {
			needles[fmt.Sprintf("key file line %d", i+1)] = []byte(line)
		}
		at += n
	}
	check := func(where string, data []byte) {
		for name, n := range needles {
			if bytes.Contains(data, n) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(n))) {
				t.Fatalf("%s holds the %s", where, name)
			}
		}
	}
	cfgPath, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{outDir, filepath.Dir(key), filepath.Dir(cfgPath)} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || p == key {
				return err
			}
			check(p, readTestFile(t, p))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	e.mu.Lock()
	bodies := e.renewBodies
	e.mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("%d renew bodies, want 1", len(bodies))
	}
	check("the request body", bodies[0])
	var in serverclient.MachineRenewRequest
	if err := json.Unmarshal(bodies[0], &in); err != nil {
		t.Fatal(err)
	}
	check("the request bytes", in.Request)
}

// TestMachineRenewChecksAnswer pins the answer check of machine renew
// (03-11b): each broken certificate is refused, nothing is written, and
// the text says the certificate was issued and counts toward the rate.
func TestMachineRenewChecksAnswer(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts func(t *testing.T, e *dirEnv) renewOpts
		why  string
	}{
		{"wrong_ca", func(t *testing.T, _ *dirEnv) renewOpts { return renewOpts{ca: otherEd(t)} },
			"it is not signed by an active or next machine CA key of your root-signed trust bundle"},
		{"retired_ca_refused", func(t *testing.T, e *dirEnv) renewOpts {
			old := otherEd(t)
			e.resignBundle(t, func(b *trust.Bundle) {
				// The bundle lists entries by role, then by increasing
				// generation; machine is the last role.
				last := b.CAs[len(b.CAs)-1]
				b.CAs = append(b.CAs, trust.CAEntry{Role: trust.RoleMachine, Key: trust.FormatKey(old.PublicKey()), Alg: old.PublicKey().Type(),
					Custody: last.Custody, State: "retired", Generation: last.Generation + 1})
			})
			return renewOpts{ca: old}
		}, "it is not signed by an active or next machine CA key of your root-signed trust bundle"},
		{"bad_signature", func(t *testing.T, e *dirEnv) renewOpts {
			return renewOpts{ca: otherEd(t), claimCA: machineCASigner(t, e)}
		}, "its CA signature or validity does not verify"},
		{"wrong_key", func(t *testing.T, _ *dirEnv) renewOpts { return renewOpts{key: otherEd(t).PublicKey()} },
			"it is for another key"},
		{"host_cert_type_refused", func(*testing.T, *dirEnv) renewOpts { return renewOpts{certType: ssh.HostCert} },
			"it is not a user certificate"},
		{"replayed_older_cert_refused", func(*testing.T, *dirEnv) renewOpts {
			return renewOpts{request: hex.EncodeToString(bytes.Repeat([]byte{7}, 16))}
		}, "its key ID does not name this machine and request"},
		{"wrong_keyid_subject", func(*testing.T, *dirEnv) renewOpts { return renewOpts{subject: "other"} },
			"its key ID does not name this machine and request"},
		{"no_principals_refused", func(*testing.T, *dirEnv) renewOpts { return renewOpts{principals: []string{}} },
			"it has no principals"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newRenewEnv(t)
			renewAnswer(t, e, tc.opts(t, e))
			key, _ := machineKeyFile(t)
			out := filepath.Join(t.TempDir(), "ci-cert.pub")
			code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
			if code != 1 {
				t.Fatalf("exit %d: %s; want 1", code, stderr)
			}
			for _, want := range []string{"the server's answer was issued but refused by this CLI's check (" + tc.why + ")",
				"; nothing was written. The signer logged the issuance (serial 4242) and it counts toward the 12 per hour for this key"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr lacks %q:\n%s", want, stderr)
				}
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("CERTFILE exists after a refused answer (%v)", err)
			}
		})
	}
	// refused runs one renewal against the stub's answer o with the extra
	// arguments and requires the refusal text why and no CERTFILE.
	refused := func(t *testing.T, o renewOpts, why string, extra ...string) {
		t.Helper()
		e := newRenewEnv(t)
		renewAnswer(t, e, o)
		key, _ := machineKeyFile(t)
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		code, _, stderr := run(t, append([]string{"machine", "renew", "ci", "--key", key, "--out", out}, extra...)...)
		if code != 1 || !strings.Contains(stderr, "refused by this CLI's check ("+why+")") {
			t.Fatalf("exit %d: %s\nwant the refusal %q", code, stderr, why)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("CERTFILE exists after a refused answer")
		}
	}
	t.Run("wrong_policy_version", func(t *testing.T) {
		refused(t, renewOpts{policy: 99}, "its key ID names policy v99, but the verified policy is v1: the policy changed while renewing; run again")
	})
	t.Run("valid_after_out_of_window", func(t *testing.T) {
		refused(t, renewOpts{shift: -3600}, "its validity does not start at this request's time")
	})
	t.Run("lifetime_above_cap", func(t *testing.T) {
		refused(t, renewOpts{lifetime: 24*3600 + 1}, "its lifetime of 86401 s is outside 60 s to the machine cap of 86400 s")
	})
	t.Run("lifetime_below_60", func(t *testing.T) {
		refused(t, renewOpts{lifetime: 59}, "its lifetime of 59 s is outside 60 s to the machine cap of 86400 s")
	})
	t.Run("critical_option_refused", func(t *testing.T) {
		for _, opt := range []map[string]string{{"source-address": "127.0.0.1/32"}, {"force-command": "/bin/true"}} {
			refused(t, renewOpts{critical: opt}, "it carries critical options, which a machine certificate never has")
		}
	})
	t.Run("extension_outside_profile_refused", func(t *testing.T) {
		refused(t, renewOpts{extensions: map[string]string{"permit-pty": "", "no-such-extension@example.com": ""}},
			`it carries the extension "no-such-extension@example.com", which the machine profile does not allow`)
	})
	t.Run("missing_expected_principal", func(t *testing.T) {
		refused(t, renewOpts{}, `it lacks the expected principal "release"`, "--expect-principal", "deploy", "--expect-principal", "release")
	})
	t.Run("expected_principal_present_passes", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{principals: []string{"deploy", "release"}})
		key, _ := machineKeyFile(t)
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", filepath.Join(t.TempDir(), "c.pub"),
			"--expect-principal", "deploy", "--expect-principal", "release")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})
}

// answerWith makes the stub answer every renewal with status code and the
// JSON error detail, plus the headers.
func answerWith(e *dirEnv, code int, detail string, hdr map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.override["POST "+serverclient.MachineRenewPath] = func(w http.ResponseWriter) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(serverclient.APIError{Error: detail})
	}
}

// buildMachineCert builds a machine certificate with cert.Build, as the
// signer does: issued at now, for pub and name, under ca, for lifetime.
func buildMachineCert(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, name string, now time.Time, lifetime time.Duration, rnd io.Reader) *ssh.Certificate {
	t.Helper()
	c, err := cert.Build(cert.Request{
		Profile:    cert.Profile{CertType: ssh.UserCert, MaxTTL: 30 * 24 * time.Hour, DefaultExtensions: map[string]string{"permit-pty": ""}},
		Subject:    pub,
		Principals: []string{"deploy"},
		Now:        now,
		ValidFor:   lifetime,
		KeyID:      cert.KeyID{V3: true, CA: "machine", Subject: name, Request: hex.EncodeToString(bytes.Repeat([]byte{9}, 16)), Policy: 1, Directory: 1, Serial: 7},
		Serial:     7,
	}, ca, rnd)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// useRenewClock sets machine renew's clock to now.
func useRenewClock(t *testing.T, now time.Time) {
	t.Helper()
	prev := machineRenewTimeNow
	machineRenewTimeNow = func() time.Time { return now }
	t.Cleanup(func() { machineRenewTimeNow = prev })
}

// TestMachineRenewIfDue pins --if-due (03-11b, b-C5, PD7): deterministic,
// stateless, and a renewal for any certificate that is not this key's,
// name's and CA's current one.
func TestMachineRenewIfDue(t *testing.T) {
	// ifDue writes c (nil: nothing) to CERTFILE and runs machine renew
	// --if-due with the key flags; it returns the exit code, the output and
	// how many requests the stub received.
	ifDue := func(t *testing.T, e *dirEnv, c *ssh.Certificate, keyArgs ...string) (int, string, int) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		if c != nil {
			writeTestFile(t, out, ssh.MarshalAuthorizedKey(c))
		}
		code, stdout, stderr := run(t, append([]string{"machine", "renew", "ci", "--out", out, "--if-due"}, keyArgs...)...)
		return code, stdout + stderr, e.renewCount()
	}
	keyed := func(t *testing.T) (*dirEnv, string, ssh.PublicKey) {
		t.Helper()
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		path, priv := machineKeyFile(t)
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		return e, path, pub
	}
	now := time.Now().Truncate(time.Second)
	t.Run("not_due_sends_nothing", func(t *testing.T) {
		e, path, pub := keyed(t)
		c := buildMachineCert(t, machineCASigner(t, e), pub, "ci", now, 24*time.Hour, rand.Reader)
		code, out, sent := ifDue(t, e, c, "--key", path)
		due := time.Unix(int64(machineCertDue(c)), 0).UTC().Format(time.RFC3339) //nolint:gosec // G115: a test time
		if code != 0 || !strings.HasPrefix(out, "not due: ") || !strings.Contains(out, "renews from "+due+"; nothing was sent") || sent != 0 {
			t.Fatalf("exit %d, %d sent: %s", code, sent, out)
		}
	})
	t.Run("due_at_threshold", func(t *testing.T) {
		e, path, pub := keyed(t)
		c := buildMachineCert(t, machineCASigner(t, e), pub, "ci", now, 24*time.Hour, rand.Reader)
		due := int64(machineCertDue(c)) //nolint:gosec // G115: a test time
		useRenewClock(t, time.Unix(due-1, 0))
		if code, out, sent := ifDue(t, e, c, "--key", path); code != 0 || sent != 0 || !strings.HasPrefix(out, "not due: ") {
			t.Fatalf("one second before the due time: exit %d, %d sent: %s", code, sent, out)
		}
		useRenewClock(t, time.Unix(due, 0))
		if _, out, sent := ifDue(t, e, c, "--key", path); sent != 1 || strings.Contains(out, "not due") {
			t.Fatalf("at the due time: %d sent: %s; want a renewal", sent, out)
		}
	})
	t.Run("threshold_is_deterministic", func(t *testing.T) {
		digest := func(v uint64) [32]byte {
			var d [32]byte
			binary.BigEndian.PutUint64(d[:8], v)
			d[31] = 0xAB // bytes past the first 8 do not count
			return d
		}
		for _, tc := range []struct {
			lifetime, first8, want uint64
		}{
			{86400, 0xE11, 1800057599},
			{86400, 0xE10, 1800057600},
			{86400, 0xFFFFFFFFFFFFFFFF, 1800057585},
			{60, 0x0D, 1800000039},
			{9, 0xFFFF, 1800000006},
			{2592000, 0x01, 1801727999},
		} {
			if got := machineDue(1800000000, tc.lifetime, digest(tc.first8)); got != tc.want {
				t.Fatalf("machineDue(1800000000, %d, %#x) = %d, want %d", tc.lifetime, tc.first8, got, tc.want)
			}
		}
		ca, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public())
		if err != nil {
			t.Fatal(err)
		}
		c := buildMachineCert(t, ca, pub, "ci", time.Unix(1800000000, 0), 24*time.Hour, bytes.NewReader(make([]byte, 1024)))
		if got, want := machineCertDue(c), machineDue(c.ValidAfter+300, 86400, sha256.Sum256(c.Marshal())); got != want {
			t.Fatalf("the wrapper gives %d, machineDue of the certificate's SHA-256 %d", got, want)
		}
	})
	t.Run("jitter_below_cap", func(t *testing.T) {
		for _, l := range []uint64{60, 3600, 86400, 30 * 86400} {
			m := min(3600, l/10)
			for range 200 {
				var d [32]byte
				if _, err := rand.Read(d[:]); err != nil {
					t.Fatal(err)
				}
				if j := 1800000000 + 2*l/3 - machineDue(1800000000, l, d); j >= m {
					t.Fatalf("lifetime %d: jitter %d, want below %d", l, j, m)
				}
			}
		}
	})
	t.Run("expired_is_due", func(t *testing.T) {
		e, path, pub := keyed(t)
		c := buildMachineCert(t, machineCASigner(t, e), pub, "ci", now.Add(-48*time.Hour), 24*time.Hour, rand.Reader)
		if code, out, sent := ifDue(t, e, c, "--key", path); code != 0 || sent != 1 {
			t.Fatalf("exit %d, %d sent: %s; want a renewal", code, sent, out)
		}
	})
	t.Run("missing_is_due", func(t *testing.T) {
		e, path, _ := keyed(t)
		if code, out, sent := ifDue(t, e, nil, "--key", path); code != 0 || sent != 1 {
			t.Fatalf("exit %d, %d sent: %s; want a renewal", code, sent, out)
		}
	})
	t.Run("unparsable_is_due", func(t *testing.T) {
		e, path, _ := keyed(t)
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		writeTestFile(t, out, []byte("not a certificate\n"))
		code, stdout, stderr := run(t, "machine", "renew", "ci", "--out", out, "--if-due", "--key", path)
		if code != 0 || e.renewCount() != 1 {
			t.Fatalf("exit %d, %d sent: %s%s; want a renewal", code, e.renewCount(), stdout, stderr)
		}
	})
	t.Run("other_key_is_due", func(t *testing.T) {
		e, path, _ := keyed(t)
		c := buildMachineCert(t, machineCASigner(t, e), otherEd(t).PublicKey(), "ci", now, 24*time.Hour, rand.Reader)
		if code, out, sent := ifDue(t, e, c, "--key", path); code != 0 || sent != 1 {
			t.Fatalf("exit %d, %d sent: %s; want a renewal", code, sent, out)
		}
	})
	t.Run("other_name_is_due", func(t *testing.T) {
		e, path, pub := keyed(t)
		c := buildMachineCert(t, machineCASigner(t, e), pub, "other", now, 24*time.Hour, rand.Reader)
		if code, out, sent := ifDue(t, e, c, "--key", path); code != 0 || sent != 1 {
			t.Fatalf("exit %d, %d sent: %s; want a renewal", code, sent, out)
		}
	})
	t.Run("other_ca_is_due", func(t *testing.T) {
		e, path, pub := keyed(t)
		c := buildMachineCert(t, otherEd(t), pub, "ci", now, 24*time.Hour, rand.Reader)
		if code, out, sent := ifDue(t, e, c, "--key", path); code != 0 || sent != 1 {
			t.Fatalf("exit %d, %d sent: %s; want a renewal", code, sent, out)
		}
	})
	t.Run("encrypted_key_not_due_asks_no_passphrase", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		priv := newEd(t)
		path, _ := writeKeyPEM(t, priv, machineKeyPass)
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		fd, r := passPipe(t, machineKeyPass)
		c := buildMachineCert(t, machineCASigner(t, e), pub, "ci", now, 24*time.Hour, rand.Reader)
		code, out, sent := ifDue(t, e, c, "--key", path, "--passphrase-fd", strconv.Itoa(fd))
		if code != 0 || sent != 0 || !strings.HasPrefix(out, "not due: ") || !unread(t, r, machineKeyPass) {
			t.Fatalf("exit %d, %d sent: %s; want not due with the passphrase unread", code, sent, out)
		}
	})
	t.Run("agent_key_not_due_sends_nothing", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		priv := newEd(t)
		useCountingKeyring(t, priv)
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		c := buildMachineCert(t, machineCASigner(t, e), pub, "ci", now, 24*time.Hour, rand.Reader)
		code, out, sent := ifDue(t, e, c, "--agent-key", ssh.FingerprintSHA256(pub))
		if code != 0 || sent != 0 || !strings.HasPrefix(out, "not due: ") {
			t.Fatalf("exit %d, %d sent: %s", code, sent, out)
		}
	})
}

// FuzzMachineRenewAnswer: checkMachineCertificate never accepts a
// certificate that the fixture bundle's active machine CA key did not
// sign, nor one for another key or another req=.
func FuzzMachineRenewAnswer(f *testing.F) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		f.Fatal(err)
	}
	_, keyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	key, err := ssh.NewPublicKey(keyPriv.Public())
	if err != nil {
		f.Fatal(err)
	}
	b := &trust.Bundle{CAs: []trust.CAEntry{{Role: trust.RoleMachine, Key: trust.FormatKey(ca.PublicKey()), State: "active", Generation: 1}}}
	pol := &trust.Policy{Version: 1, CAProfiles: []trust.CAProfile{{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}}}}
	now := time.Now()
	req := &wire.MachineIssueRequest{MachineName: "ci", MachineKey: key.Marshal(), RequestID: [16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
		CreatedAt: uint64(now.Unix())} //nolint:gosec // G115: the test's clock
	seed := func(principals []string) []byte {
		c, err := cert.Build(cert.Request{
			Profile: cert.Profile{CertType: ssh.UserCert, MaxTTL: 24 * time.Hour, DefaultExtensions: map[string]string{"permit-pty": ""}},
			Subject: key, Principals: principals, Now: now, ValidFor: time.Hour,
			KeyID:  cert.KeyID{V3: true, CA: "machine", Subject: "ci", Request: hex.EncodeToString(req.RequestID[:]), Policy: 1, Directory: 1, Serial: 3},
			Serial: 3,
		}, ca, rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		return c.Marshal()
	}
	f.Add(seed([]string{"deploy"}))
	if raw := seed([]string{"deploy"}); len(raw) > 0 {
		pk, _ := ssh.ParsePublicKey(raw)
		c := pk.(*ssh.Certificate)
		c.ValidPrincipals = nil
		f.Add(c.Marshal())
	}
	f.Fuzz(func(t *testing.T, blob []byte) {
		c, err := checkMachineCertificate(blob, req, b, pol, "ci", nil)
		if err != nil {
			return
		}
		if !bytes.Equal(c.SignatureKey.Marshal(), ca.PublicKey().Marshal()) || !bytes.Equal(c.Key.Marshal(), key.Marshal()) {
			t.Fatal("accepted a certificate of another CA or key")
		}
		issued := time.Unix(int64(min(c.ValidAfter, 1<<62))+300, 0) //nolint:gosec // G115: bounded
		if err := (&ssh.CertChecker{Clock: func() time.Time { return issued }}).CheckCert(c.ValidPrincipals[0], c); err != nil {
			t.Fatalf("accepted a certificate whose signature does not verify: %v", err)
		}
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil || kid.Request != hex.EncodeToString(req.RequestID[:]) {
			t.Fatal("accepted a certificate for another request")
		}
	})
}
