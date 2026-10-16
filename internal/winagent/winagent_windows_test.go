//go:build windows

package winagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"

	"github.com/Labontese/keyroster/internal/cert"
)

// keyrosterExe is a keyroster.exe built from this tree by TestMain, for the
// two tests that run the real binary on the account's own agent pipe.
var keyrosterExe string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "winagent-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keyrosterExe = filepath.Join(dir, "keyroster.exe")
	out, err := exec.Command("go", "build", "-trimpath", "-o", keyrosterExe, "github.com/Labontese/keyroster/cmd/keyroster").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build keyroster.exe: %v\n%s", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// testPipe returns a fresh random pipe path that is not the account's agent
// pipe, for the in-process cases.
func testPipe(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\keyroster-agent-test-` + hex.EncodeToString(b[:])
}

// startServe runs Serve on path in the background. The returned channel
// receives Serve's result. Serve is cancelled at test end if still running.
func startServe(t *testing.T, path string, opts Options) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, path, opts) }()
	waitForPipe(t, path)
	return done
}

// waitForPipe waits up to 5 s until path exists.
func waitForPipe(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		inUse, err := pipeInUse(path)
		if err != nil {
			t.Fatal(err)
		}
		if inUse {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within 5 s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pipeInUse dials path once with a 1 s timeout, sends nothing and closes at
// once. It returns false only when the pipe does not exist. A dial that
// succeeds, is refused with access denied, or times out on a busy pipe
// returns true; any other error is returned.
func pipeInUse(path string) (bool, error) {
	timeout := time.Second
	conn, err := winio.DialPipe(path, &timeout)
	switch {
	case err == nil:
		_ = conn.Close()
		return true, nil
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return false, nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, winio.ErrTimeout):
		return true, nil
	default:
		return false, err
	}
}

// requireAccountPipeFree fails the test when a keyroster agent already
// serves the account's pipe. The test never adds a key to, or stops, an
// agent it did not start.
func requireAccountPipeFree(t *testing.T) string {
	t.Helper()
	path, err := PipePath()
	if err != nil {
		t.Fatal(err)
	}
	inUse, err := pipeInUse(path)
	if err != nil {
		t.Fatal(err)
	}
	if inUse {
		t.Fatalf("a keyroster agent already serves %s: stop that agent or wait until it exits (when its last key expires, or 5 minutes after start without a key), then run the test again", path)
	}
	return path
}

// testKey returns a fresh Ed25519 key and a user certificate for it, issued
// by a throwaway CA through internal/cert.Build (the module's only signing
// call site) with key ID subject u:<name>.
func testKey(t *testing.T, name string) (ed25519.PrivateKey, *ssh.Certificate) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cert.Build(cert.Request{
		Profile:    cert.DefaultUserProfile(),
		Subject:    sshPub,
		Principals: []string{"probe"},
		Now:        time.Now(),
		ValidFor:   10 * time.Minute,
		KeyID:      cert.KeyID{CA: "user", Subject: "u:" + name, Request: "0123456789abcdef0123456789abcdef", Serial: 1},
		Serial:     1,
	}, caSigner, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, c
}

// addKeyAndCert adds priv and its certificate, both with lifetime secs.
func addKeyAndCert(c agent.Agent, priv ed25519.PrivateKey, cert *ssh.Certificate, secs uint32) error {
	if err := c.Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: secs}); err != nil {
		return err
	}
	return c.Add(agent.AddedKey{PrivateKey: priv, Certificate: cert, LifetimeSecs: secs})
}

// dialTest dials a test pipe directly.
func dialTest(t *testing.T, path string) net.Conn {
	t.Helper()
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// waitDone waits up to d for Serve's result.
func waitDone(t *testing.T, done <-chan error, d time.Duration, what string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil", err)
		}
	case <-time.After(d):
		t.Fatalf("Serve did not return within %s %s", d, what)
	}
}

func noStart(t *testing.T) func() error {
	return func() error {
		t.Error("ensure called start although the agent was running")
		return errors.New("start not expected")
	}
}

// schedSlack absorbs Windows timer granularity (15.6 ms) and goroutine
// scheduling on loaded CI runners in the "within N polls" deadlines.
const schedSlack = 250 * time.Millisecond

func TestAgent(t *testing.T) {
	t.Run("lifetime_expiry_exit", func(t *testing.T) {
		path := testPipe(t)
		opts := Options{Poll: 200 * time.Millisecond, IdleExit: 2 * time.Second}
		done := startServe(t, path, opts)
		conn := dialTest(t, path)
		c := agent.NewClient(conn)
		priv, cert := testKey(t, "lifetime")
		if err := addKeyAndCert(c, priv, cert, 2); err != nil {
			t.Fatal(err)
		}
		keys, err := c.List()
		if err != nil || len(keys) != 2 {
			t.Fatalf("List after add = %d keys, %v; want 2", len(keys), err)
		}
		time.Sleep(3 * time.Second)
		keys, err = c.List()
		if err != nil || len(keys) != 0 {
			t.Fatalf("List after 3 s = %d keys, %v; want 0", len(keys), err)
		}
		select {
		case err := <-done:
			t.Fatalf("Serve returned %v while a connection was open", err)
		default:
		}
		_ = conn.Close()
		waitDone(t, done, 3*opts.Poll+schedSlack, "after the last connection closed (3 polls)")
	})

	t.Run("idle_exit", func(t *testing.T) {
		path := testPipe(t)
		opts := Options{Poll: 50 * time.Millisecond, IdleExit: time.Second}
		start := time.Now()
		done := startServe(t, path, opts)
		waitDone(t, done, opts.IdleExit+3*opts.Poll+schedSlack, "without a key")
		if el := time.Since(start); el < opts.IdleExit {
			t.Fatalf("Serve returned after %s, before IdleExit %s", el, opts.IdleExit)
		}
		if inUse, err := pipeInUse(path); err != nil || inUse {
			t.Fatalf("pipe still present after exit (%v, %v)", inUse, err)
		}
	})

	t.Run("second_serve_refused", func(t *testing.T) {
		path := testPipe(t)
		startServe(t, path, Options{Poll: 50 * time.Millisecond, IdleExit: 10 * time.Second})
		err := Serve(context.Background(), path, Options{})
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("second Serve on the same pipe = %v, want a refusal saying the pipe already exists", err)
		}
	})

	t.Run("verify_own_pipe", func(t *testing.T) {
		path := testPipe(t)
		startServe(t, path, Options{Poll: 50 * time.Millisecond, IdleExit: 10 * time.Second})
		conn := dialTest(t, path)
		defer func() { _ = conn.Close() }()
		if err := VerifyServerOwner(conn); err != nil {
			t.Fatalf("VerifyServerOwner on our own pipe: %v", err)
		}
	})

	t.Run("sddl_single_allow", func(t *testing.T) {
		me, err := currentSID()
		if err != nil {
			t.Fatal(err)
		}
		sddl := SDDL(me.String())
		if n := strings.Count(sddl, "(A;"); n != 1 || !strings.Contains(sddl, "(A;;GA;;;"+me.String()+")") {
			t.Fatalf("SDDL %q: want exactly one allow ACE, for %s", sddl, me)
		}
		if !strings.HasPrefix(sddl, "D:P(D;;GA;;;NU)") {
			t.Fatalf("SDDL %q: want a protected DACL that first denies network logons", sddl)
		}
		// The live pipe carries that DACL.
		path := testPipe(t)
		startServe(t, path, Options{Poll: 50 * time.Millisecond, IdleExit: 10 * time.Second})
		conn := dialTest(t, path)
		defer func() { _ = conn.Close() }()
		fd := conn.(interface{ Fd() uintptr }).Fd()
		sd, err := windows.GetSecurityInfo(windows.Handle(fd), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		live := sd.String()
		t.Logf("live pipe DACL: %s", strings.ReplaceAll(live, me.String(), "<SID>"))
		if strings.Count(live, "(A;") != 1 || !strings.Contains(live, ";;;"+me.String()+")") ||
			!strings.Contains(live, "(D;") || !strings.Contains(live, ";;;NU)") || !strings.HasPrefix(live, "D:P") {
			t.Fatalf("live pipe DACL does not match SDDL %q", sddl)
		}
	})

	t.Run("openssh_spelling_dials", func(t *testing.T) {
		// keyroster agent prints the //./pipe/ spelling; go-winio (admin
		// signing via SSH_AUTH_SOCK) must reach the pipe with it as well.
		path := testPipe(t)
		startServe(t, path, Options{Poll: 50 * time.Millisecond, IdleExit: 10 * time.Second})
		spelled := OpenSSHSpelling(path)
		if !strings.HasPrefix(spelled, "//./pipe/keyroster-agent-test-") {
			t.Fatalf("OpenSSHSpelling(%q) = %q", path, spelled)
		}
		conn := dialTest(t, spelled)
		defer func() { _ = conn.Close() }()
		if _, err := agent.NewClient(conn).List(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("owner_mismatch_refused", func(t *testing.T) {
		system, err := windows.StringToSid("S-1-5-18")
		if err != nil {
			t.Fatal(err)
		}
		me, err := currentSID()
		if err != nil {
			t.Fatal(err)
		}
		err = checkOwner(system, me)
		if err == nil {
			t.Fatal("checkOwner accepted a pipe served by LocalSystem")
		}
		if !strings.Contains(err.Error(), "S-1-5-18") || !strings.Contains(err.Error(), me.String()) {
			t.Fatalf("checkOwner error %q does not name both SIDs", err)
		}
		if err := checkOwner(me, me); err != nil {
			t.Fatalf("control: checkOwner with our own SID: %v", err)
		}
	})

	t.Run("owner_access_denied_names_elevation", func(t *testing.T) {
		err := unverifiable("open server process 4", windows.ERROR_ACCESS_DENIED)
		if !errors.Is(err, ErrOwnerUnverifiable) || !strings.Contains(err.Error(), "elevated") {
			t.Fatalf("access denied mapped to %q; want ErrOwnerUnverifiable naming elevation", err)
		}
		other := unverifiable("open server process 4", windows.ERROR_INVALID_PARAMETER)
		if errors.Is(other, ErrOwnerUnverifiable) || !errors.Is(other, windows.ERROR_INVALID_PARAMETER) {
			t.Fatalf("other error mapped to %q; want it returned as is", other)
		}
	})

	t.Run("ensure_fails_closed", func(t *testing.T) {
		path := testPipe(t)
		opts := Options{Poll: 50 * time.Millisecond, IdleExit: time.Second}
		start := time.Now()
		done := startServe(t, path, opts)
		errReject := errors.New("test verifier rejects")
		conn, err := ensure(context.Background(), path, noStart(t), func(net.Conn) error { return errReject })
		if conn != nil || !errors.Is(err, errReject) {
			t.Fatalf("ensure with a rejecting verifier = %v, %v; want nil and the verifier's error", conn, err)
		}
		// A rejected connection left open would hold the agent alive.
		waitDone(t, done, opts.IdleExit+3*opts.Poll+schedSlack-time.Since(start), "after the rejected connection (1 s plus 3 polls)")

		// Control: the real verifier accepts our own agent.
		path2 := testPipe(t)
		startServe(t, path2, Options{Poll: 50 * time.Millisecond, IdleExit: 10 * time.Second})
		conn, err = ensure(context.Background(), path2, noStart(t), VerifyServerOwner)
		if err != nil || conn == nil {
			t.Fatalf("control: ensure with VerifyServerOwner = %v, %v", conn, err)
		}
		_ = conn.Close()
	})

	t.Run("exit_waits_for_open_connection", func(t *testing.T) {
		path := testPipe(t)
		opts := Options{Poll: 50 * time.Millisecond, IdleExit: 2 * time.Second}
		done := startServe(t, path, opts)
		a := dialTest(t, path)
		priv, _ := testKey(t, "unused")
		if err := agent.NewClient(a).Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: 1}); err != nil {
			t.Fatal(err)
		}
		_ = a.Close()
		b, err := ensure(context.Background(), path, noStart(t), VerifyServerOwner)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		select {
		case err := <-done:
			t.Fatalf("Serve returned %v while connection B was open", err)
		default:
		}
		keys, err := agent.NewClient(b).List()
		if err != nil || len(keys) != 0 {
			t.Fatalf("List on B after 2 s = %d keys, %v; want 0 (expired)", len(keys), err)
		}
		_ = b.Close()
		waitDone(t, done, 3*opts.Poll+schedSlack, "after B closed (3 polls)")
	})

	t.Run("ensure_retries_once_on_closing_agent", func(t *testing.T) {
		// A server that closes its first `drop` connections at once, as Serve
		// does after its exit decision, then serves a keyring.
		serveDropping := func(t *testing.T, drop int) string {
			path := testPipe(t)
			me, err := currentSID()
			if err != nil {
				t.Fatal(err)
			}
			l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: SDDL(me.String())})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			keyring := agent.NewKeyring()
			go func() {
				for n := 0; ; n++ {
					c, err := l.Accept()
					if err != nil {
						return
					}
					if n < drop {
						_ = c.Close()
						continue
					}
					go func() { _ = agent.ServeAgent(keyring, c); _ = c.Close() }()
				}
			}()
			return path
		}
		conn, err := ensure(context.Background(), serveDropping(t, 1), noStart(t), VerifyServerOwner)
		if err != nil {
			t.Fatalf("ensure after one closed connection: %v", err)
		}
		_ = conn.Close()
		conn, err = ensure(context.Background(), serveDropping(t, 2), noStart(t), VerifyServerOwner)
		if err == nil {
			_ = conn.Close()
			t.Fatal("ensure succeeded although both attempts were closed; want one retry only")
		}
	})

	t.Run("add_races_expiry_exit", func(t *testing.T) {
		// Each loop adds a 1 s key, waits about 1 s (swept a little around
		// the expiry) and connects again, so its next ensure lands close to
		// the agent's expiry exit: on a live agent, on one that is exiting
		// (ensure retries and starts a new one), or on none. Several loops
		// on their own pipes run side by side to collect more such races.
		const loops = 8
		opts := Options{Poll: 5 * time.Millisecond}
		var (
			mu     sync.Mutex
			serves []<-chan error
		)
		end := time.Now().Add(3 * time.Second)
		var wg sync.WaitGroup
		for l := range loops {
			path := testPipe(t)
			priv, _ := testKey(t, "race")
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := func() error {
					ctx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)
					done := make(chan error, 1)
					go func() { done <- Serve(ctx, path, opts) }()
					mu.Lock()
					serves = append(serves, done)
					mu.Unlock()
					return nil
				}
				for i := 0; time.Now().Before(end); i++ {
					conn, err := ensure(context.Background(), path, start, VerifyServerOwner)
					if err != nil {
						t.Errorf("loop %d iteration %d: ensure: %v", l, i, err)
						return
					}
					c := agent.NewClient(conn)
					if err := c.Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: 1}); err != nil {
						t.Errorf("loop %d iteration %d: Add after ensure succeeded: %v", l, i, err)
					} else if keys, err := c.List(); err != nil || len(keys) == 0 {
						t.Errorf("loop %d iteration %d: List after Add = %d keys, %v", l, i, len(keys), err)
					}
					_ = conn.Close()
					sweep := time.Duration((i*7+l*3)%21-10) * time.Millisecond
					time.Sleep(time.Second + sweep)
				}
			}()
		}
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(serves) <= loops {
			t.Fatalf("only %d agents started for %d loops; the loops never outlived an agent", len(serves), loops)
		}
		t.Logf("%d loops started %d agents in 3 s", loops, len(serves))
		for i, done := range serves {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve %d returned %v, want nil", i, err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("Serve %d did not return", i)
			}
		}
	})

	t.Run("ensure_starts_real_agent", func(t *testing.T) {
		path := requireAccountPipeFree(t)
		conn, err := Ensure(context.Background(), keyrosterExe)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		inUse, err := pipeInUse(path)
		if err != nil || !inUse {
			_ = conn.Close()
			t.Fatalf("pipeInUse(PipePath()) while our agent serves it = %v, %v; want true", inUse, err)
		}
		priv, _ := testKey(t, "real")
		if err := agent.NewClient(conn).Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: 1}); err != nil {
			_ = conn.Close()
			t.Fatalf("Add: %v", err)
		}
		added := time.Now()
		_ = conn.Close()
		// 1 s lifetime + two default 5 s polls + 5 s slack.
		deadline := added.Add(16 * time.Second)
		for {
			inUse, err := pipeInUse(path)
			if err != nil {
				t.Fatal(err)
			}
			if !inUse {
				t.Logf("agent exited %s after the add", time.Since(added).Round(time.Millisecond))
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the agent Ensure started still serves %s 16 s after its only key (1 s lifetime) was added", path)
			}
			time.Sleep(500 * time.Millisecond)
		}
	})
}
