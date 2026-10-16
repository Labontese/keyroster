//go:build windows

package winagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

const inboxOpenSSH = `C:\Windows\System32\OpenSSH\`

// TestInboxSSHOffersAgentCert runs the real keyroster.exe agent on the
// account's own pipe, loads a key and certificate with the inbox ssh-add.exe
// and a 4 s lifetime, checks that the inbox ssh.exe offers the certificate to
// an SSH server, and that key, certificate and agent are gone afterwards.
// It skips without the inbox client unless KEYROSTER_REQUIRE_INBOX_SSH=1.
func TestInboxSSHOffersAgentCert(t *testing.T) {
	if _, err := os.Stat(inboxOpenSSH + "ssh.exe"); err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_INBOX_SSH") == "1" {
			t.Fatalf("inbox ssh.exe not found and KEYROSTER_REQUIRE_INBOX_SSH=1: %v", err)
		}
		t.Skipf("inbox ssh.exe not found (set KEYROSTER_REQUIRE_INBOX_SSH=1 to fail instead): %v", err)
	}

	// 1. The account's pipe must be free; then start our own agent on it.
	path := requireAccountPipeFree(t)
	sockPath := OpenSSHSpelling(path)
	var agentOut lockedBuffer
	cmd := exec.Command(keyrosterExe, "agent")
	cmd.Stdout, cmd.Stderr = &agentOut, &agentOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// exited is closed once the agent process has ended; waitErr is then set.
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		select {
		case <-exited:
		default:
			_ = cmd.Process.Kill()
			<-exited
		}
	})
	for deadline := time.Now().Add(5 * time.Second); ; {
		inUse, err := pipeInUse(path)
		if err != nil {
			t.Fatal(err)
		}
		if inUse {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("keyroster agent did not create %s within 5 s; output:\n%s", path, agentOut.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// An idle connection, held until the listing after expiry, keeps the agent
	// from exiting before that listing runs: it exits at its first poll after
	// the last key expired with no connection open, which can come before
	// add+5 s.
	hold := dialTest(t, path)
	defer func() { _ = hold.Close() }()

	// 2. Load key and certificate with the inbox ssh-add.exe.
	dir := t.TempDir()
	keyPath := writeKeyFiles(t, dir)
	env := envWithAgent("SSH_AUTH_SOCK=" + sockPath)
	out := inbox(t, env, "ssh-add.exe", "-t", "4", keyPath)
	added := time.Now()
	if !strings.Contains(out, "Certificate added") || !strings.Contains(out, "Lifetime set to 4 seconds") {
		t.Fatalf("ssh-add.exe -t 4 output:\n%s", out)
	}
	if out := inbox(t, env, "ssh-add.exe", "-l"); !strings.Contains(out, "ED25519-CERT") {
		t.Fatalf("ssh-add.exe -l after add, want the certificate:\n%s", out)
	}

	// 3. The inbox ssh.exe, pointed at the agent with IdentityAgent only,
	// offers the certificate.
	offers := offeredKeys(t, func(port string) {
		inbox(t, envWithAgent("SSH_AUTH_SOCK="), "ssh.exe", "-n", "-F", "none",
			"-o", "IdentityAgent="+sockPath, "-o", "IdentitiesOnly=no", "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"),
			"-p", port, "probe@127.0.0.1", "exit")
	})
	if !containsOffer(offers, "ssh-ed25519-cert-v01@openssh.com keyid=offer-test") {
		t.Fatalf("server saw offers %q, want the agent's certificate", offers)
	}

	// 4. After the 4 s lifetime both entries are gone, and the agent exits.
	time.Sleep(time.Until(added.Add(5 * time.Second)))
	if out := inbox(t, env, "ssh-add.exe", "-l"); !strings.Contains(out, "The agent has no identities") {
		t.Fatalf("ssh-add.exe -l 5 s after the add:\n%s", out)
	}
	_ = hold.Close()
	// 4 s lifetime + two default 5 s polls + 5 s slack.
	select {
	case <-exited:
		if waitErr != nil {
			t.Fatalf("keyroster agent exited with %v; output:\n%s", waitErr, agentOut.String())
		}
		t.Logf("agent exited %s after the add", time.Since(added).Round(time.Millisecond))
	case <-time.After(time.Until(added.Add(19 * time.Second))):
		t.Fatalf("keyroster agent still running 19 s after the add; output:\n%s", agentOut.String())
	}
	if !strings.Contains(agentOut.String(), "IdentityAgent "+sockPath) {
		t.Fatalf("agent output does not print the IdentityAgent line:\n%s", agentOut.String())
	}
}

// writeKeyFiles writes a fresh key, its public key and a user certificate
// (key ID offer-test) as OpenSSH files and returns the private key path. The
// files get an owner-only protected DACL: Windows OpenSSH refuses a private
// key file that inherits wider access ("UNPROTECTED PRIVATE KEY FILE").
func writeKeyFiles(t *testing.T, dir string) string {
	t.Helper()
	priv, cert := testKey(t, "offer-test")
	keyPath := filepath.Join(dir, "id_test")
	blk, err := ssh.MarshalPrivateKey(priv, "offer-test-key")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		keyPath:               pem.EncodeToMemory(blk),
		keyPath + ".pub":      ssh.MarshalAuthorizedKey(cert.Key),
		keyPath + "-cert.pub": ssh.MarshalAuthorizedKey(cert),
	}
	me, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + me.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	for p, data := range files {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	return keyPath
}

// envWithAgent returns the environment with SSH_AUTH_SOCK replaced by kv.
func envWithAgent(kv string) []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "SSH_AUTH_SOCK=") {
			env = append(env, e)
		}
	}
	return append(env, kv)
}

// inbox runs an inbox OpenSSH tool and returns its combined output. Exit
// status is not checked: ssh.exe exits 255 against the refusing server and
// ssh-add.exe -l exits 1 on an empty agent; callers check the output.
func inbox(t *testing.T, env []string, tool string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, inboxOpenSSH+tool, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	t.Logf("%s %s: %v\n%s", tool, strings.Join(args, " "), err, out)
	return string(out)
}

// offeredKeys runs an SSH server on 127.0.0.1 that records each offered
// public key (type, plus the key ID for certificates) and refuses all, calls
// client with its port, and returns the offers.
func offeredKeys(t *testing.T, client func(port string)) []string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu     sync.Mutex
		offers []string
	)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		s := k.Type()
		if c, ok := k.(*ssh.Certificate); ok {
			s += " keyid=" + c.KeyId
		}
		mu.Lock()
		offers = append(offers, s)
		mu.Unlock()
		return nil, fmt.Errorf("refused")
	}}
	cfg.AddHostKey(host)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _, _, _ = ssh.NewServerConn(c, cfg)
			_ = c.Close()
		}
	}()
	client(strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
	_ = l.Close()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), offers...)
}

func containsOffer(offers []string, want string) bool {
	for _, o := range offers {
		if o == want {
			return true
		}
	}
	return false
}

// lockedBuffer is a bytes.Buffer safe for the agent process's output copier
// and the test reading it at the same time.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
