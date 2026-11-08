//go:build e2e && e2eprobe

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// The agent's probe self-test end to end (03-10b, D-06, AGENT-04's agent
// half). Both tests are parallel (Planner decisions D12): Go starts them
// only after every serial test of the package finished, so the machine
// cap global is read and cleared by TestProbeSelfTestEndToEnd alone, while
// TestProbePairSpacing starts no server.

// requireNonRoot fails when the test runs as root: the probe account is
// the test user, and its uid must not be 0.
func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("the probe self-test e2e needs a non-root user: the probe account's uid must not be 0")
	}
}

// waitUntil polls cond every 500 ms until it holds or d passes; a timeout
// fails the test with logs() (the run, fetch and sshd logs).
func waitUntil(t *testing.T, what string, d time.Duration, logs func() string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s\n%s", what, d, logs())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// e2eProbeCert and e2eProbeRecord read <state>/probe.json by the format
// 'Contracts frozen by this plan' fixes, independently of the agent's own
// decoder.
type e2eProbeCert struct {
	Serial      uint64 `json:"serial"`
	IssuedAt    uint64 `json:"issued_at"`
	ValidBefore uint64 `json:"valid_before"`
	Cert        []byte `json:"cert"`
}

type e2eProbePair struct {
	Positive *e2eProbeCert `json:"positive"`
	Negative *e2eProbeCert `json:"negative"`
}

type e2eProbeRecord struct {
	Version   int          `json:"version"`
	Committed e2eProbePair `json:"committed"`
	Next      e2eProbePair `json:"next"`
}

// e2eProbeState reads <state>/probe-state.json's budget and hold.
type e2eProbeState struct {
	Negatives []uint64 `json:"negatives"`
	Held      *struct {
		Reason string `json:"reason"`
	} `json:"held"`
	Failure *struct {
		Code string `json:"code"`
	} `json:"failure"`
}

// probeLastApply is what these tests read of status.json's last_apply.
type probeLastApply struct {
	Generation       uint64   `json:"generation"`
	DirectoryVersion uint64   `json:"directory_version"`
	SelfTest         string   `json:"self_test"`
	Rollback         bool     `json:"rollback"`
	RollbackSelfTest string   `json:"rollback_self_test"`
	Detail           string   `json:"detail"`
	ProbePositive    string   `json:"probe_positive"`
	ProbeNegative    string   `json:"probe_negative"`
	Errors           []string `json:"errors"`
}

// joinProbeHost is joinHostCert with the probe self-test on: the host group
// maps krmanaged (no real user) to role ops, so the probe account, the test
// user (the only account the unprivileged test sshd can authenticate), is
// never a mapped account; the root's /etc/passwd names the probe account
// with the shell /usr/sbin/nologin, an executable regular file under the
// root; and the applier runs with --probe-self-test required and
// --probe-account <login>.
func joinProbeHost(t *testing.T, env *serverEnv, kr func(args ...string) string, name string) *enrolledHost {
	t.Helper()
	login := currentUser(t)
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", "krmanaged", "ops", "--yes")
	joinFile := filepath.Join(t.TempDir(), "join.txt")
	kr("host", "join-token", name, "--out", joinFile)
	h := newEnrolledHostLayout(t, env.Signer)
	writeProbePasswd(t, h, "/usr/sbin/nologin")
	if code, out := runBin(t, agentBin(t), "", "install", "--root", h.root, "--state-dir", h.state, "--join-file", joinFile, "--fetch-user", login); code != 0 {
		t.Fatalf("keyroster-agent install exited %d:\n%s", code, out)
	}
	h.probeSelfTest = "required"
	h.probeAccount = login
	eh := &enrolledHost{agentHost: h}
	eh.startRun(t)
	eh.startFetch(t, hostCertPoll)
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(kr("host", "pending"), "Pending host "+name); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("host pending never listed %s\nfetch log:\n%s", name, eh.fetch.String())
		}
	}
	code, ident := runBin(t, agentBin(t), "", "identity", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(opensshPrefix(t), "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
	if code != 0 {
		t.Fatalf("keyroster-agent identity exited %d:\n%s", code, ident)
	}
	args := []string{"host", "approve", name, "--group", "lab", "--principal", name, "--yes"}
	for _, l := range strings.Split(strings.TrimSpace(ident), "\n") {
		if fp, ok := strings.CutPrefix(l, "host key: "); ok {
			args = append(args, "--host-key", strings.Fields(fp)[0])
		}
	}
	kr(args...)
	waitUntil(t, "the first apply", 60*time.Second, func() string { return probeLogs(eh) }, func() bool {
		r := h.lastApply(t)
		return r != nil && r.Generation > 0 && r.SelfTest == "pass" && len(r.Errors) == 0
	})
	return eh
}

// writeProbePasswd writes <root>/etc/passwd with the one line of the
// probe account (the test user) and makes shell an executable regular
// file under the root.
func writeProbePasswd(t *testing.T, h *agentHost, shell string) {
	t.Helper()
	sh := filepath.Join(h.root, shell)
	if err := os.MkdirAll(filepath.Dir(sh), 0o755); err != nil { //nolint:gosec // G301: a host directory such as /usr/sbin, 0755 as packaged
		t.Fatal(err)
	}
	if err := os.WriteFile(sh, []byte("#!/bin/false\n"), 0o755); err != nil { //nolint:gosec // an executable shell fixture
		t.Fatal(err)
	}
	line := fmt.Sprintf("%s:x:%d:%d::/nonexistent:%s\n", currentUser(t), os.Getuid(), os.Getgid(), shell)
	if err := os.WriteFile(filepath.Join(h.root, "etc", "passwd"), []byte(line), 0o644); err != nil { //nolint:gosec // passwd's packaged mode
		t.Fatal(err)
	}
}

// probeLogs is what a failing wait prints: the run log, the fetch log and
// the sshd log.
func probeLogs(eh *enrolledHost) string {
	return "run log:\n" + eh.run.String() + "\nfetch log:\n" + eh.fetch.String() + "\nsshd log:\n" + eh.sshd.log.String()
}

// probeStatus reads status.json's last_apply (nil when absent).
func probeStatus(h *agentHost) *probeLastApply {
	b, err := os.ReadFile(filepath.Join(h.state, "status.json")) //nolint:gosec // test fixture
	if err != nil {
		return nil
	}
	var s struct {
		LastApply *probeLastApply `json:"last_apply"`
	}
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return s.LastApply
}

// readProbeRecord reads <state>/probe.json (nil when absent or malformed).
func readProbeRecord(h *agentHost) *e2eProbeRecord {
	b, err := os.ReadFile(filepath.Join(h.state, "probe.json")) //nolint:gosec // test fixture
	if err != nil {
		return nil
	}
	var r e2eProbeRecord
	if json.Unmarshal(b, &r) != nil || r.Version != 1 {
		return nil
	}
	return &r
}

// readProbeState reads <state>/probe-state.json (the zero state when
// absent or malformed).
func readProbeState(h *agentHost) e2eProbeState {
	var s e2eProbeState
	if b, err := os.ReadFile(filepath.Join(h.state, "probe-state.json")); err == nil { //nolint:gosec // test fixture
		_ = json.Unmarshal(b, &s)
	}
	return s
}

// negativesInHour counts the negative probes of the sliding hour.
func (s e2eProbeState) negativesInHour() int {
	now := uint64(time.Now().Unix()) //nolint:gosec // G115: after 1970
	n := 0
	for _, at := range s.Negatives {
		if at+3600 > now {
			n++
		}
	}
	return n
}

// currentFile reads a file of the generation current names ("" when
// absent).
func currentFile(h *agentHost, name string) string {
	b, _ := os.ReadFile(filepath.Join(h.root, "etc", "ssh", "keyroster", "current", name)) //nolint:gosec // test fixture
	return string(b)
}

// currentKRL parses the KRL of the generation current names (nil when it
// does not parse).
func currentKRL(h *agentHost) *krl.Parsed {
	k, err := krl.Parse([]byte(currentFile(h, "revoked.krl")))
	if err != nil {
		return nil
	}
	return k
}

// roleCAKeys returns the CA keys of role in the signer's bundle in force.
func roleCAKeys(t *testing.T, env *signerEnv, role string) [][]byte {
	t.Helper()
	st, err := signerclient.Status(context.Background(), env.Socket)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(st.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := krl.RoleCAKeys(b, role)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// hostDirectoryVersion is the directory version the server's host status
// shows for the one host, and the server's current one.
func hostDirectoryVersion(t *testing.T, kr func(args ...string) string) (host, current uint64) {
	t.Helper()
	var a serverclient.HostsStatusAnswer
	if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Hosts) != 1 || a.Hosts[0].Heartbeat == nil {
		return 0, a.Current.Directory
	}
	return a.Hosts[0].Heartbeat.Status.Directory.Version, a.Current.Directory
}

// linkTarget is the generation a link of the keyroster directory names.
func linkTarget(t *testing.T, h *agentHost, name string) string {
	t.Helper()
	s, err := os.Readlink(filepath.Join(h.root, "etc", "ssh", "keyroster", name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// noPrivateKey fails when a file under dir contains PRIVATE KEY. The
// fetcher's own TLS identity (identity.key and identity.next in its
// directory) is the one private key the layout root holds by design; it
// is no probe key and is skipped.
func noPrivateKey(t *testing.T, dir, fetchDir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		if filepath.Dir(p) == fetchDir && (d.Name() == "identity.key" || d.Name() == "identity.next") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // test fixture
		if err != nil {
			return nil
		}
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			return fmt.Errorf("%s contains PRIVATE KEY", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// probeCertOf parses a kept probe certificate.
func probeCertOf(t *testing.T, c *e2eProbeCert) *ssh.Certificate {
	t.Helper()
	pub, err := ssh.ParsePublicKey(c.Cert)
	if err != nil {
		t.Fatal(err)
	}
	sc, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("a kept probe certificate is not a certificate")
	}
	return sc
}

// sshdHUP makes the host's sshd re-read its configuration.
func sshdHUP(t *testing.T, h *agentHost) {
	t.Helper()
	if err := syscall.Kill(h.sshd.pid(t), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
}

// TestProbeSelfTestEndToEnd (03-10b): a host's applier gets a verified,
// restricted probe pair from the real signer through the fetcher and the
// server; the production PK_OK query separates the two certificates on
// real sshd; a widening passes both probes; a mixed change whose positive
// is refused keeps its removal and loses its addition; an unusable probe
// account holds a widening while the KRL and the narrowing part land, and
// fixing the account lands the held addition; no probe private key is on
// disk.
func TestProbeSelfTestEndToEnd(t *testing.T) {
	t.Parallel()
	requireNonRoot(t)
	// Planner decisions D6: a 600 s machine cap leaves a pair usable for
	// the test's three widenings with no renewal.
	withGenesisMachineMaxTTL(t, 600*time.Second)
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	kr := hostCertKR(t, env)
	login := currentUser(t)
	eh := joinProbeHost(t, env, kr, "web1")
	h := eh.agentHost
	logs := func() string { return probeLogs(eh) }
	hostKey := pubKey(t, readPub(t, h.sshd.hostKey))
	query := func(c *ssh.Certificate) (apply.ProbeOutcome, error) {
		return apply.ProbeQuery(context.Background(), apply.ProbeTarget{
			Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(h.sshd.port)), Source: "127.0.0.2", Account: login,
			HostKeys: []ssh.PublicKey{hostKey},
		}, c, time.Now().Add(10*time.Second))
	}
	// budgetAtMost fails a step whose negative probes in the hour exceed
	// its cumulative share plus the optional opportunistic pair.
	budgetAtMost := func(t *testing.T, n int) {
		t.Helper()
		if got := readProbeState(h).negativesInHour(); got > n+1 || got > 5 {
			t.Fatalf("%d negative probes in the hour, want at most %d (and never above 5)\n%s", got, n+1, logs())
		}
	}

	if !t.Run("pair_issued_and_enforced", func(t *testing.T) {
		var rec *e2eProbeRecord
		var pair e2eProbePair
		waitUntil(t, "a probe pair in probe.json", 120*time.Second, logs, func() bool {
			rec = readProbeRecord(h)
			if rec == nil {
				return false
			}
			if rec.Committed.Positive != nil && rec.Committed.Negative != nil {
				pair = rec.Committed
				return true
			}
			if rec.Next.Positive != nil && rec.Next.Negative != nil {
				if k := currentKRL(h); k != nil {
					neg := probeCertOf(t, rec.Next.Negative)
					if k.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial) {
						pair = rec.Next
						return true
					}
				}
			}
			return false
		})
		machine := roleCAKeys(t, env.Signer, trust.RoleMachine)
		pos, neg := probeCertOf(t, pair.Positive), probeCertOf(t, pair.Negative)
		for _, c := range []*ssh.Certificate{pos, neg} {
			if c.CertType != ssh.UserCert {
				t.Fatalf("serial %d: certificate type %d, want user", c.Serial, c.CertType)
			}
			if !slices.Equal(c.ValidPrincipals, []string{cert.ReservedPrincipalPrefix + "web1"}) {
				t.Fatalf("serial %d: principals %q", c.Serial, c.ValidPrincipals)
			}
			if len(c.Extensions) != 0 {
				t.Fatalf("serial %d: extensions %v", c.Serial, c.Extensions)
			}
			if len(c.CriticalOptions) != 2 || c.CriticalOptions["force-command"] != "/bin/false" || c.CriticalOptions["source-address"] != "127.0.0.0/8,::1/128" {
				t.Fatalf("serial %d: critical options %v", c.Serial, c.CriticalOptions)
			}
			if !slices.ContainsFunc(machine, func(k []byte) bool { return bytes.Equal(k, c.SignatureKey.Marshal()) }) {
				t.Fatalf("serial %d: not signed by a machine CA key of the served bundle", c.Serial)
			}
			kid, err := cert.ParseKeyID(c.KeyId)
			if err != nil || !kid.V3 || kid.CA != wire.CARoleMachine.String() || kid.Subject != "probe.web1" || kid.Serial != c.Serial {
				t.Fatalf("serial %d: key ID %q (%v)", c.Serial, c.KeyId, err)
			}
			if v := c.ValidBefore - c.ValidAfter - 300; v != 600 {
				t.Fatalf("serial %d: lifetime %d s, want 600 (the machine cap)", c.Serial, v)
			}
		}
		k, err := signerclient.GetKRL(context.Background(), env.Signer.Socket)
		if err != nil {
			t.Fatal(err)
		}
		sk, err := krl.Parse(k.KRL)
		if err != nil {
			t.Fatal(err)
		}
		if !sk.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial) || sk.RevokesSerial(pos.SignatureKey.Marshal(), pos.Serial) {
			t.Fatalf("the signer's KRL: negative %d listed %t, positive %d listed %t", neg.Serial,
				sk.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial), pos.Serial, sk.RevokesSerial(pos.SignatureKey.Marshal(), pos.Serial))
		}
		waitUntil(t, "the host's KRL lists the negative", 60*time.Second, logs, func() bool {
			hk := currentKRL(h)
			return hk != nil && hk.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial)
		})
		if r, err := query(pos); r != apply.ProbeAccepted {
			t.Fatalf("the positive: %s (%v)\n%s", r, err, logs())
		}
		if r, err := query(neg); r != apply.ProbeRefused {
			t.Fatalf("the negative: %s (%v)\n%s", r, err, logs())
		}
		noPrivateKey(t, h.state, "")
	}) {
		t.FailNow()
	}

	if !t.Run("widening_passes_probes", func(t *testing.T) {
		kr("role", "add", "dev", "--max-ttl", "1h", "--yes")
		kr("host-group", "map", "lab", "krmanaged", "ops", "dev", "--yes")
		waitUntil(t, "the widening lands with both probes passing", 240*time.Second, logs, func() bool {
			la := probeStatus(h)
			return la != nil && la.ProbePositive == "pass" && la.ProbeNegative == "pass" && !la.Rollback && len(la.Errors) == 0 &&
				la.Detail == "" && strings.Contains(currentFile(h, "principals/krmanaged"), "role:dev")
		})
		if s := readProbeState(h); len(s.Negatives) == 0 {
			t.Fatalf("probe-state.json lists no negative probe\n%s", logs())
		}
		budgetAtMost(t, 1)
	}) {
		t.FailNow()
	}

	if !t.Run("positive_refused_rolls_back", func(t *testing.T) {
		// A mixed change: dev is removed and qa added in one directory
		// version, and DenyUsers makes sshd refuse the probe account, so the
		// positive is refused once the change is live.
		cfg, err := os.ReadFile(h.sshd.cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.sshd.cfg, append(slices.Clone(cfg), []byte("DenyUsers "+login+"\n")...), 0o644); err != nil { //nolint:gosec // sshd_config's packaged mode
			t.Fatal(err)
		}
		sshdHUP(t, h)
		kr("role", "add", "qa", "--max-ttl", "1h", "--yes")
		done := make(chan struct{})
		regranted := make(chan string, 1)
		go func() {
			gone := false
			for {
				select {
				case <-done:
					return
				case <-time.After(200 * time.Millisecond):
				}
				has := strings.Contains(currentFile(h, "principals/krmanaged"), "role:dev")
				if !has {
					gone = true
				} else if gone {
					select {
					case regranted <- currentLink(h):
					default:
					}
				}
			}
		}()
		kr("host-group", "map", "lab", "krmanaged", "ops", "qa", "--yes")
		waitUntil(t, "the failed addition is rolled back", 300*time.Second, logs, func() bool {
			la := probeStatus(h)
			return la != nil && la.Rollback && la.Detail == "probe_positive_refused" && la.ProbePositive == "fail" && la.RollbackSelfTest == "pass"
		})
		close(done)
		p := currentFile(h, "principals/krmanaged")
		if strings.Contains(p, "role:dev") || strings.Contains(p, "role:qa") {
			t.Fatalf("current/principals/krmanaged after the failed mixed change:\n%s", p)
		}
		select {
		case g := <-regranted:
			t.Fatalf("role:dev was granted again after its removal (current named %s)", g)
		default:
		}
		if c, lg := linkTarget(t, h, "current"), linkTarget(t, h, "last-good"); c != lg {
			t.Fatalf("current names %s and last-good %s", c, lg)
		}
		waitUntil(t, "the host reports the new directory version", 20*time.Second, logs, func() bool {
			host, current := hostDirectoryVersion(t, kr)
			return host == current
		})
		budgetAtMost(t, 2)
		// The re-map to ops alone removes nothing current grants and adds
		// nothing: same classified content as the settled generation, other
		// bytes, so the same apply commits it and clears the held record.
		kr("host-group", "map", "lab", "krmanaged", "ops", "--yes")
		waitUntil(t, "the held record clears", 60*time.Second, logs, func() bool {
			la := probeStatus(h)
			return readProbeState(h).Held == nil && la != nil && !strings.HasPrefix(la.Detail, "probe_held")
		})
		waitUntil(t, "the probe alert", 60*time.Second, logs, func() bool {
			text := kr("host", "status")
			return strings.Contains(text, "probe: probe_positive_refused") || strings.Contains(text, "probe: probe_held:failure_backoff")
		})
		if err := os.WriteFile(h.sshd.cfg, cfg, 0o644); err != nil { //nolint:gosec // sshd_config's packaged mode
			t.Fatal(err)
		}
		sshdHUP(t, h)
	}) {
		t.FailNow()
	}

	if !t.Run("unusable_account_holds_widening_krl_and_narrowing_land", func(t *testing.T) {
		writeProbePasswd(t, h, "/bin/sh")
		before := readProbeState(h).Negatives
		c := issueAgentCert(t, env.Signer, "held", "role:ops")
		revokeSerial(t, env.Signer, c.serial)
		serial, err := strconv.ParseUint(c.serial, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		users := roleCAKeys(t, env.Signer, trust.RoleUser)
		kr("role", "update", "ops", "--principal", "role:ops2", "--yes")
		waitUntil(t, "the KRL and the narrowing part land, the addition is held", 240*time.Second, logs, func() bool {
			k := currentKRL(h)
			if k == nil || !slices.ContainsFunc(users, func(ca []byte) bool { return k.RevokesSerial(ca, serial) }) {
				return false
			}
			p := currentFile(h, "principals/krmanaged")
			la := probeStatus(h)
			return !strings.Contains(p, "role:ops") && la != nil && la.Detail == "probe_held:shell_not_nologin"
		})
		waitUntil(t, "the host reports the new directory version", 20*time.Second, logs, func() bool {
			host, current := hostDirectoryVersion(t, kr)
			return host == current
		})
		if after := readProbeState(h).Negatives; !slices.Equal(before, after) {
			t.Fatalf("negative probes %v, were %v: a held addition spent a pair", after, before)
		}
	}) {
		t.FailNow()
	}

	if !t.Run("fixing_the_account_lands_the_held_addition", func(t *testing.T) {
		writeProbePasswd(t, h, "/usr/sbin/nologin")
		waitUntil(t, "the held addition lands", 300*time.Second, logs, func() bool {
			la := probeStatus(h)
			return strings.Contains(currentFile(h, "principals/krmanaged"), "role:ops2") && la != nil &&
				la.ProbePositive == "pass" && la.ProbeNegative == "pass" && la.Detail == "" && readProbeState(h).Held == nil
		})
		waitUntil(t, "no probe alert", 60*time.Second, logs, func() bool {
			return !strings.Contains(kr("host", "status"), "probe: ")
		})
		budgetAtMost(t, 3)
	}) {
		t.FailNow()
	}

	t.Run("private_key_never_on_disk", func(t *testing.T) {
		noPrivateKey(t, h.state, "")
		noPrivateKey(t, h.root, filepath.Join(h.root, "var", "lib", "keyroster-agent-fetch"))
	})
}

// hostKeySeen makes the applier's listener-test handshake from src (a host
// key callback that records the key and stops, no authentication) and
// reports whether sshd presented hostKey.
func hostKeySeen(port int, src string, hostKey ssh.PublicKey) (bool, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	errSeen := errors.New("host key seen")
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{User: "probe", HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		seen = k
		return errSeen
	}}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if seen == nil {
		return false, err
	}
	return bytes.Equal(seen.Marshal(), hostKey.Marshal()), nil
}

// TestProbePairSpacing (03-10b, A9, P7, T-03-67) measures the per-source
// penalty at the production spacing: pairs of the production query (a
// PK_OK-then-abort positive, then a refused negative) from 127.0.0.2, 60 s
// apart, must never get 127.0.0.2 dropped, and after each pair 127.0.0.1
// is answered (an accepted query and the listener test's host-key
// handshake). On a build that penalises sources a control at a 2 s spacing
// must drop 127.0.0.2 first, so the measurement can fail.
func TestProbePairSpacing(t *testing.T) {
	t.Parallel()
	version := sshdVersion(t)
	user := currentUser(t)
	ca := newUserKey(t, "spacing_ca")
	certFor := func(name, principal string) *ssh.Certificate {
		key := newUserKey(t, name)
		sshKeygen(t, "-q", "-s", ca, "-I", name, "-n", principal, "-O", "force-command=/bin/false",
			"-O", "source-address=127.0.0.0/8,::1/128", key+".pub")
		c, ok := pubKey(t, readPub(t, key+"-cert.pub")).(*ssh.Certificate)
		if !ok {
			t.Fatal("ssh-keygen wrote no certificate")
		}
		return c
	}
	accepted := certFor("id_spacing_accepted", "keyroster-probe:web1")
	refused := certFor("id_spacing_refused", "keyroster-probe:web9")
	start := func() *sshdRun {
		return startSSHDWithLog(t, sshdOptions{UserCAPub: ca + ".pub", Principals: map[string][]string{user: {"keyroster-probe:web1"}}})
	}
	query := func(s *sshdRun, key ssh.PublicKey, src string, c *ssh.Certificate) (apply.ProbeOutcome, error) {
		return apply.ProbeQuery(context.Background(), apply.ProbeTarget{
			Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port)), Source: src, Account: user, HostKeys: []ssh.PublicKey{key},
		}, c, time.Now().Add(5*time.Second))
	}
	penalised := atLeast98(version)

	control := "not exercised"
	if penalised {
		ok := t.Run("control_drops_at_short_spacing", func(t *testing.T) {
			s := start()
			key := sshdHostKey(t, s)
			for i := 1; i <= 6; i++ {
				p, _ := query(s, key, "127.0.0.2", accepted)
				n, _ := query(s, key, "127.0.0.2", refused)
				if p == apply.ProbeInconclusive || n == apply.ProbeInconclusive {
					control = fmt.Sprintf("%d pairs", i)
					return
				}
				time.Sleep(2 * time.Second)
			}
			t.Fatalf("%s penalises sources, but 127.0.0.2 was not dropped within six pairs at a 2 s spacing: the spacing measurement could not fail\nsshd log:\n%s", version, s.log.String())
		})
		if !ok {
			t.FailNow()
		}
	}

	s := start()
	key := sshdHostKey(t, s)
	var odd []string
	answered := 0
	const pairs = 3
	for i := 0; i < pairs; i++ {
		if i > 0 {
			time.Sleep(apply.ProbePairSpacing)
		}
		if p, err := query(s, key, "127.0.0.2", accepted); p != apply.ProbeAccepted {
			odd = append(odd, fmt.Sprintf("pair %d positive: %s (%v)", i+1, p, err))
		}
		if n, err := query(s, key, "127.0.0.2", refused); n != apply.ProbeRefused {
			odd = append(odd, fmt.Sprintf("pair %d negative: %s (%v)", i+1, n, err))
		}
		l, lerr := query(s, key, "127.0.0.1", accepted)
		seen, herr := hostKeySeen(s.port, "127.0.0.1", key)
		if l == apply.ProbeAccepted && seen {
			answered++
		} else {
			odd = append(odd, fmt.Sprintf("pair %d listener source: query %s (%v), host key seen %t (%v)", i+1, l, lerr, seen, herr))
		}
	}
	penaltyLines := 0
	for _, l := range strings.Split(s.log.String(), "\n") {
		if strings.Contains(strings.ToLower(l), "penalt") {
			penaltyLines++
		}
	}
	dropped := "none"
	if len(odd) > 0 {
		dropped = strconv.Itoa(len(odd))
	}
	t.Logf("FACT A9 spacing %s: pairs=%d spacing=%s dropped=%s penalty_lines=%d listener_answered=%d/%d control_dropped_after=%s",
		version, pairs, strconv.Itoa(int(apply.ProbePairSpacing/time.Second))+"s", dropped, penaltyLines, answered, pairs, control)
	if !penalised {
		t.Logf("FACT P7 spacing %s: not exercised, no PerSourcePenalties", version)
	}
	t.Run("pairs_at_production_spacing_never_dropped", func(t *testing.T) {
		if len(odd) != 0 {
			t.Fatalf("at the production spacing: %v\nsshd log:\n%s", odd, s.log.String())
		}
	})
}

// currentLink is the generation current names ("" when it does not read),
// for the watcher goroutine, which must not fail the test itself.
func currentLink(h *agentHost) string {
	s, _ := os.Readlink(filepath.Join(h.root, "etc", "ssh", "keyroster", "current"))
	return s
}
