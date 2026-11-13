//go:build e2e

package e2e

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/agent/fetch"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// agentGate is a gated proxy in front of the signer's agent backend
// (03-08i): every agent call is forwarded to the role agent, except that
// once armed, the first signature with the armed key's fingerprint signals
// entered and waits until release. The signer is started on the proxy's
// socket (--backend-opt socket=), so its keys and custody are the role
// agent's and match the bundle.
type agentGate struct {
	sock string

	mu       sync.Mutex
	armed    string // SHA256 fingerprint; "" when not armed
	fired    bool
	entered  chan struct{}
	released chan struct{}
	once     sync.Once
}

// serve is a serverOpts.SignerServe: it starts the proxy on a socket in a
// short temporary directory and then keyroster-signer serve on sg's state
// with the proxy as its agent socket, as signerEnv.serve starts it.
func (g *agentGate) serve(t *testing.T, sg *signerEnv) {
	t.Helper()
	g.entered, g.released = make(chan struct{}), make(chan struct{})
	g.sock = filepath.Join(shortTempDir(t), "gate.sock")
	l, err := net.Listen("unix", g.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go g.proxy(c, sg.RoleAgent)
		}
	}()
	_, log, done := startDaemon(t, "keyroster-signer", envWithout("SSH_AUTH_SOCK"), signerBin,
		"serve", "--state-dir", sg.StateDir, "--socket", sg.Socket, "--allow-uid", strconv.Itoa(os.Getuid()),
		"--backend-opt", "socket="+g.sock)
	waitFor(t, "signer socket", done, log, func() bool { return isSocket(sg.Socket) })
}

// proxy serves one signer connection: agent.ServeAgent over a gated
// client of a fresh connection to the role agent.
func (g *agentGate) proxy(c net.Conn, upstream string) {
	defer func() { _ = c.Close() }()
	u, err := net.Dial("unix", upstream)
	if err != nil {
		return
	}
	defer func() { _ = u.Close() }()
	_ = agent.ServeAgent(gatedAgent{ExtendedAgent: agent.NewClient(u), g: g}, c)
}

// arm makes the first later signature with the key fp wait at the gate,
// and returns its Once-guarded release.
func (g *agentGate) arm(fp string) func() {
	g.mu.Lock()
	g.armed = fp
	g.mu.Unlock()
	return func() { g.once.Do(func() { close(g.released) }) }
}

// wait holds a signature with key at the gate when it is the first one
// with the armed fingerprint.
func (g *agentGate) wait(key ssh.PublicKey) {
	g.mu.Lock()
	hold := !g.fired && g.armed != "" && ssh.FingerprintSHA256(key) == g.armed
	if hold {
		g.fired = true
	}
	g.mu.Unlock()
	if hold {
		close(g.entered)
		<-g.released
	}
}

// gatedAgent forwards every call to the role agent, holding signatures at
// the gate.
type gatedAgent struct {
	agent.ExtendedAgent
	g *agentGate
}

func (a gatedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.g.wait(key)
	return a.ExtendedAgent.Sign(key, data)
}

func (a gatedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.g.wait(key)
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

// fetcherRefusals are the fetcher log phrases of a state request the
// server did not answer: rate limited, or not approved.
var fetcherRefusals = []string{"rate limiting", "waiting for an admin's approval"}

func refusedInLog(log string) string {
	for _, p := range fetcherRefusals {
		if strings.Contains(log, p) {
			return p
		}
	}
	return ""
}

// TestDeliveryDuringHeldSignature (03-08i): a real keyroster-server in front
// of the real signer keeps answering GET /api/v1/krl and an approved
// agent's state with 200 while one CA signature holds the signer's lock
// past statusTTL and krlTTL (5 s each), because the signer answers Status
// from its snapshot without waiting for the lock. The signature is held
// behind a gated proxy of the agent backend. The hold is anchored to t0,
// the return of a control state request: every server cache entry was
// fetched at or before t0. The held issue's connection is bounded by the
// signer's connDeadline and the CLI's defaultTimeout (10 s each), so the
// gate must open within 7 s of the issue's start.
func TestDeliveryDuringHeldSignature(t *testing.T) {
	gate := &agentGate{}
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true, SignerServe: gate.serve})
	login := currentUser(t)
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}
	eh := enrollApproved(t, env, kr, "web1")
	h := eh.agentHost

	// 2. Controls, before anything is held.
	krl := env.mustGet(t, serverclient.KRLPath)
	if krl.code != http.StatusOK {
		t.Fatalf("control GET krl = %d %s", krl.code, krl.body)
	}
	eh.stopFetch(t)
	time.Sleep(4 * time.Second) // the agent's token bucket refills
	flog := &syncBuffer{}
	f, err := fetch.New(fetch.Config{
		ConfigFile: filepath.Join(h.root, "etc", "keyroster-agent", "fetch.json"),
		Dir:        filepath.Join(h.root, "var", "lib", "keyroster-agent-fetch"),
		Spool:      filepath.Join(h.state, "spool"),
		Outbox:     filepath.Join(h.state, "outbox"),
		Log:        flog,
	})
	if err != nil {
		t.Fatalf("fetch.New: %v", err)
	}
	octx, ocancel := context.WithTimeout(context.Background(), 10*time.Second)
	err = f.Once(octx)
	ocancel()
	if p := refusedInLog(flog.String()); err != nil || p != "" {
		t.Fatalf("control state request: %v (log %q):\n%s", err, p, flog.String())
	}
	t0 := time.Now()

	// 3. Arm the gate on the user CA key and start an issue.
	time.Sleep(time.Until(t0.Add(4 * time.Second)))
	release := gate.arm(fingerprint(t, env.Signer.UserCAPub))
	t.Cleanup(release)
	keyDir := t.TempDir()
	userKey := filepath.Join(keyDir, "user")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "held", "-f", userKey)
	type issued struct {
		code int
		out  string
	}
	issueDone := make(chan issued, 1)
	issueStart := time.Now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, keyrosterBin, "ca", "issue", "--socket", env.Signer.Socket, "--admin-key", env.Signer.AdminFingerprint, //nolint:gosec // G204: the binary under test
			"--installation-id", env.Signer.InstallationID, // (03-14d, F15)
			"--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+env.Signer.AdminAgent)
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			code = -1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
		}
		issueDone <- issued{code, string(out)}
	}()

	// 4. The issue reaches the CA signature: the signer holds s.mu in
	// cert.Build.
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("the issue never reached the user CA signature within 10 s")
	}

	// 5. Both caches are stale: statusTTL and krlTTL are 5 s.
	time.Sleep(time.Until(t0.Add(6 * time.Second)))

	// 6. The KRL route.
	ok := true
	r, err := env.get(serverclient.KRLPath)
	switch {
	case err != nil:
		ok = false
		t.Errorf("held-signature krl: got no answer: %v", err)
	case r.code != http.StatusOK:
		ok = false
		t.Errorf("held-signature krl: got %d", r.code)
	case r.body != krl.body:
		ok = false
		t.Errorf("held-signature krl: got %d with another body than the control's", r.code)
	}

	// 7. The approved agent's state.
	mark := len(flog.String())
	octx, ocancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = f.Once(octx)
	ocancel()
	if p := refusedInLog(flog.String()[mark:]); err != nil || p != "" {
		ok = false
		t.Errorf("held-signature state: %v (log %q)", err, p)
	}

	// 8. Release the gate.
	release()
	held := time.Since(issueStart)
	if ok {
		if held > 7*time.Second {
			t.Errorf("held-signature hold: released %v after the issue started, budget 7s", held)
		}
		select {
		case i := <-issueDone:
			if i.code != 0 {
				t.Errorf("the held issue exited %d:\n%s", i.code, i.out)
			}
		case <-time.After(15 * time.Second):
			t.Errorf("the held issue did not exit within 15 s of the release")
		}
	} else {
		select {
		case i := <-issueDone:
			t.Logf("the held issue exited %d after the release (it may fail at its 10 s deadline once the routes failed):\n%s", i.code, i.out)
		case <-time.After(15 * time.Second):
			t.Logf("the held issue did not exit within 15 s of the release")
		}
	}
	t.Logf("the signature was held for %v", held)

	// 9. The host's fetcher again.
	eh.startFetch(t)
}
