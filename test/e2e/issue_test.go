//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestIssueAcceptedBySSHD is the Walking Skeleton: keyroster ca issue ->
// keyroster-signer (CA key in ssh-agent, pinned by fingerprint) -> a
// certificate that real sshd accepts. A decoy key is loaded into the agent
// before the CA key, so a signer that picked "the first key" would sign
// with the decoy and the Signing CA assertion would fail.
func TestIssueAcceptedBySSHD(t *testing.T) {
	dir := t.TempDir()
	login := currentUser(t)

	decoy := filepath.Join(dir, "decoy")
	caKey := filepath.Join(dir, "user_ca")
	userKey := filepath.Join(dir, "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "decoy", "-f", decoy)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user-ca", "-f", caKey)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", userKey)
	caFP := fingerprint(t, caKey+".pub")
	decoyFP := fingerprint(t, decoy+".pub")

	agentSock := startAgent(t)
	sshAdd(t, agentSock, decoy) // first in the agent's list
	sshAdd(t, agentSock, caKey)

	signerSock := startSigner(t,
		"--allow-uid", strconv.Itoa(os.Getuid()),
		"--backend", "agent",
		"--backend-opt", "socket="+agentSock,
		"--user-ca-fp", caFP)

	out := issue(t, signerSock,
		"--pubkey", userKey+".pub",
		"--principal", login,
		"--subject", "u:"+login,
		"--ttl", "10m")
	t.Logf("keyroster ca issue:\n%s", out)
	certFile := userKey + "-cert.pub"

	port := startSSHD(t, sshdOptions{
		UserCAPub:  caKey + ".pub",
		Principals: map[string][]string{login: {login}},
	})
	code, output := sshLogin(t, loginOptions{
		Port: port, Key: userKey, Cert: certFile, User: login, Command: "true",
	})
	if code != 0 {
		t.Fatalf("ssh login with the issued certificate exited %d:\n%s", code, output)
	}

	// Oracle: ssh-keygen -L on the issued certificate.
	info := sshKeygen(t, "-L", "-f", certFile)
	t.Logf("ssh-keygen -L:\n%s", info)
	fields := parseCertInfo(t, info)

	serial, err := strconv.ParseUint(fields.serial, 10, 64)
	if err != nil || serial == 0 {
		t.Errorf("Serial = %q, want a decimal above 0", fields.serial)
	}
	if !strings.HasPrefix(fields.keyID, "kr1/ca=user/") {
		t.Errorf("Key ID = %q, want prefix kr1/ca=user/", fields.keyID)
	}
	if want := "/ser=" + fields.serial; !strings.HasSuffix(fields.keyID, want) {
		t.Errorf("Key ID = %q, want suffix %q", fields.keyID, want)
	}
	if len(fields.extensions) != 1 || fields.extensions[0] != "permit-pty" {
		t.Errorf("Extensions = %q, want exactly [permit-pty]", fields.extensions)
	}
	if len(fields.critical) != 0 {
		t.Errorf("Critical Options = %q, want none", fields.critical)
	}
	if len(fields.principals) != 1 || fields.principals[0] != login {
		t.Errorf("Principals = %q, want [%s]", fields.principals, login)
	}
	if fields.signingCAFP != caFP {
		t.Errorf("Signing CA fingerprint = %q, want the pinned CA %q", fields.signingCAFP, caFP)
	}
	if fields.signingCAFP == decoyFP {
		t.Errorf("certificate was signed by the decoy key %s (selection by agent position)", decoyFP)
	}
}

func fingerprint(t *testing.T, pubFile string) string {
	t.Helper()
	data, err := os.ReadFile(pubFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub)
}

type certInfo struct {
	serial      string
	keyID       string
	signingCAFP string
	principals  []string
	critical    []string
	extensions  []string
}

var signingCARE = regexp.MustCompile(`^Signing CA: \S+ (SHA256:\S+)`)

// parseCertInfo reads the fields of ssh-keygen -L output that the test
// asserts on.
func parseCertInfo(t *testing.T, out string) certInfo {
	t.Helper()
	var ci certInfo
	var list *[]string
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// List items (16 spaces) are indented deeper than field names (8).
		if list != nil && strings.HasPrefix(raw, strings.Repeat(" ", 16)) {
			*list = append(*list, line)
			continue
		}
		list = nil
		switch {
		case strings.HasPrefix(line, "Serial: "):
			ci.serial = strings.TrimPrefix(line, "Serial: ")
		case strings.HasPrefix(line, "Key ID: "):
			ci.keyID = strings.Trim(strings.TrimPrefix(line, "Key ID: "), `"`)
		case signingCARE.MatchString(line):
			ci.signingCAFP = signingCARE.FindStringSubmatch(line)[1]
		case strings.HasPrefix(line, "Principals:"):
			list = &ci.principals
		case strings.HasPrefix(line, "Critical Options:"):
			if !strings.Contains(line, "(none)") {
				list = &ci.critical
			}
		case strings.HasPrefix(line, "Extensions:"):
			if !strings.Contains(line, "(none)") {
				list = &ci.extensions
			}
		}
	}
	if ci.serial == "" || ci.keyID == "" || ci.signingCAFP == "" {
		t.Fatalf("could not parse ssh-keygen -L output:\n%s", out)
	}
	return ci
}
