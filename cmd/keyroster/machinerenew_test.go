package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/serverclient"
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
	ca         ssh.Signer    // the signing key; nil: the bundle's machine CA key
	claimCA    ssh.Signer    // SignatureKey written after signing (bad signature); nil: ca
	key        ssh.PublicKey // the certified key; nil: the request's key
	certType   uint32        // 0: a user certificate
	request    string        // req= of the key ID; "": the request's ID
	subject    string        // sub= of the key ID; "": the request's name
	principals []string      // nil: deploy
	lifetime   uint64        // seconds; 0: 24 h
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
	now := uint64(time.Now().Unix()) //nolint:gosec // G115: the test's clock
	c := &ssh.Certificate{
		Key: key, Serial: 4242, CertType: certType, KeyId: kid.String(), ValidPrincipals: principals,
		ValidAfter: now - 300, ValidBefore: now + lifetime,
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
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
			for _, want := range []string{"the signer issued a certificate (serial 4242), but this CLI refused it: " + tc.why,
				"nothing was written", "counts toward the machine's 12 renewals per hour"} {
				if !strings.Contains(stderr, want) {
					t.Fatalf("stderr lacks %q:\n%s", want, stderr)
				}
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("CERTFILE exists after a refused answer (%v)", err)
			}
		})
	}
}
