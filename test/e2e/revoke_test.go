//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestRevokeSerialEndToEnd is the Phase 3 tracer (03-01, REVOKE-01..03):
// certificates A and B log in to real sshd whose RevokedKeys points at
// <dir>/current/revoked.krl (a zero-byte file, which revokes nothing);
// keyroster revoke serial A goes through keyroster-server to the signer,
// which publishes the next KRL version (above the empty KRL its first
// start published, 03-03) written by our own encoder with an ops-signed,
// installation-bound manifest; the test fetches it through
// serverclient.Client.GetKRL, verifies it with krl.VerifyManifest against
// the root-pinned bundle, checks the candidate file with ssh-keygen -Q
// (A revoked, B not) and swaps current with rename(2). With no signal sent
// and the same sshd PID, A is refused with sshd's revoked-key log line and
// B still logs in. A restarted signer serves the same KRL, and keyroster
// audit verify accepts the exported log with its revoke and krl_publish
// entries (03-03). Versions are compared, never pinned: krl_version is
// max(previous + 1, issued_at) (owner decision 2026-10-25, Q1).
//
// The direct rename is test harness, not the agent: only the KRL changes
// between gen/1 and gen/2, so 03-05's intermediate generation would equal
// gen/2 and its first step is the whole swap.
func TestRevokeSerialEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{StoppableSigner: true})
	login := currentUser(t)
	keys := t.TempDir()

	// 1. Certificates A and B for principal role:t through the admin path.
	type subject struct{ key, cert, serial string }
	subjects := map[string]*subject{}
	for _, name := range []string{"a", "b"} {
		key := filepath.Join(keys, "id_"+name)
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
		env.Signer.issue(t, "--pubkey", key+".pub", "--principal", "role:t", "--subject", "u:"+name, "--ttl", "10m")
		cert := key + "-cert.pub"
		subjects[name] = &subject{key: key, cert: cert, serial: parseCertInfo(t, sshKeygen(t, "-L", "-f", cert)).serial}
	}
	a, b := subjects["a"], subjects["b"]
	if a.serial == b.serial {
		t.Fatalf("A and B share serial %s", a.serial)
	}

	// 2. gen/1 holds a zero-byte KRL; current -> gen/1 (relative).
	d := t.TempDir()
	for _, g := range []string{"gen/1", "gen/2"} {
		if err := os.MkdirAll(filepath.Join(d, g), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "gen/1/revoked.krl"), nil, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.Symlink("gen/1", filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	sshd := startSSHDWithLog(t, sshdOptions{
		UserCAPub:  env.Signer.UserCAPub,
		Principals: map[string][]string{login: {"role:t"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(d, "current", "revoked.krl")},
	})
	pid := sshd.pid(t)

	// 3. Controls: both log in under the zero-byte KRL.
	for name, s := range subjects {
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: s.key, Cert: s.cert, User: login, Command: "true"}); code != 0 {
			t.Fatalf("login with %s before the revocation exited %d:\n%s", name, code, out)
		}
	}

	// The empty KRL serve published at its first start (03-03).
	client, bundle := revokeClient(t, env)
	doc0, err := client.GetKRL(context.Background())
	if err != nil || doc0 == nil {
		t.Fatalf("GetKRL before the revocation = %v, %v", doc0, err)
	}
	m0, err := krl.VerifyManifest(doc0.Manifest, doc0.Sig, doc0.KRL, bundle, env.Signer.InstallationID, 0)
	if err != nil {
		t.Fatalf("VerifyManifest of the start-up KRL: %v", err)
	}
	if code, out := keygenQuery(t, writeKRL(t, doc0.KRL), a.cert); code != 0 {
		t.Fatalf("the start-up KRL revokes A (ssh-keygen -Q exited %d):\n%s", code, out)
	}

	// 4. keyroster revoke serial A through keyroster-server.
	admin := newCLIEnv(t)
	if code, out, errOut := runCLIIn(t, admin, "", "", keyrosterBin, append(env.initArgs(), "--admin-key", env.Signer.AdminFingerprint)...); code != 0 {
		t.Fatalf("keyroster init exited %d:\n%s%s", code, out, errOut)
	}
	code, out, errOut := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, "revoke", "serial", a.serial, "--reason", "e2e tracer")
	if code != 0 {
		t.Fatalf("keyroster revoke serial exited %d:\n%s%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster revoke serial:\n%s", out)
	match := regexp.MustCompile(`The server reports serial ` + a.serial + ` \(user\) revoked: KRL v([0-9]+) published`).FindStringSubmatch(out)
	if match == nil ||
		!strings.Contains(out, "Checked: the server serves KRL v"+match[1]+", signed by the ops key of your root-pinned trust bundle") ||
		!strings.Contains(out, "Checked: KRL v"+match[1]+" lists serial "+a.serial+" under a user CA key of your trust bundle") ||
		!strings.Contains(out, "Hosts enforce it once their keyroster agent applies this KRL.") {
		t.Fatalf("keyroster revoke serial output:\n%s", out)
	}
	reported, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	// 5. GET /api/v1/krl through the pinned client; verify against the
	// root-pinned bundle and the installation ID.
	doc, err := client.GetKRL(context.Background())
	if err != nil || doc == nil {
		t.Fatalf("GetKRL = %v, %v", doc, err)
	}
	m, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, m0.KRLVersion)
	if err != nil {
		t.Fatalf("VerifyManifest (strictly above the start-up KRL v%d): %v", m0.KRLVersion, err)
	}
	if m.KRLVersion != reported || m.InstallationID != env.Signer.InstallationID || m.BundleVersion != 1 {
		t.Fatalf("manifest = %+v, want the version the CLI reported (%d)", m, reported)
	}
	t.Logf("manifest: %s", doc.Manifest)

	// 6. Candidate file, the oracle on the same bytes, then the swap.
	cand := filepath.Join(d, "gen/2/revoked.krl")
	if err := os.WriteFile(cand, doc.KRL, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if code, out := keygenQuery(t, cand, b.cert); code != 0 {
		t.Fatalf("ssh-keygen -Q on B's certificate exited %d (B is not revoked):\n%s", code, out)
	}
	if code, out := keygenQuery(t, cand, a.cert); code == 0 {
		t.Fatalf("ssh-keygen -Q on A's certificate exited 0, want non-zero (A is revoked):\n%s", out)
	} else {
		t.Logf("ssh-keygen -Q on A (exit %d): %s", code, strings.TrimSpace(out))
	}
	tmp := filepath.Join(d, "current.tmp")
	if err := os.Symlink("gen/2", tmp); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, filepath.Join(d, "gen/2"))
	fsyncDir(t, d)
	if err := os.Rename(tmp, filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, d)

	// 7. A is refused with the revoked-key log line; B still logs in; same
	// sshd PID, no signal sent.
	before := sshd.log.String()
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: a.key, Cert: a.cert, User: login, Command: "true"}); code == 0 {
		t.Fatalf("login with A after the swap succeeded; want a refusal:\n%s", out)
	}
	waitForLog(t, sshd, before, "revoked")
	t.Logf("sshd after A: %s", strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: b.key, Cert: b.cert, User: login, Command: "true"}); code != 0 {
		t.Fatalf("login with B after the swap exited %d:\n%s", code, out)
	}
	if got := sshd.pid(t); got != pid {
		t.Fatalf("sshd PID changed from %d to %d", pid, got)
	}
	t.Logf("sshd PID %d unchanged; no signal was sent", pid)

	// 8. A restarted signer serves the same KRL.
	env.StopSigner()
	serveStoppable(t, env.Signer)
	// keyroster-server serves its copy of the KRL for up to
	// serverclient.KRLMaxStale; wait it out so this read reaches the
	// restarted signer instead of the cache.
	time.Sleep(serverclient.KRLMaxStale + time.Second)
	doc2, err := client.GetKRL(context.Background())
	if err != nil || doc2 == nil {
		t.Fatalf("GetKRL after the signer restart = %v, %v\nserver log:\n%s", doc2, err, env.Stderr.String())
	}
	if !bytes.Equal(doc2.KRL, doc.KRL) || !bytes.Equal(doc2.Manifest, doc.Manifest) || !bytes.Equal(doc2.Sig, doc.Sig) {
		t.Fatal("the restarted signer serves another KRL")
	}
	if m2, err := krl.ParseManifest(doc2.Manifest); err != nil || m2.KRLVersion != m.KRLVersion {
		t.Fatalf("manifest after the restart = %+v, %v; want version %d again", m2, err, m.KRLVersion)
	}

	// 9. keyroster audit verify checks the revoke entry and both
	// krl_publish entries (the start-up publish and the revocation's) of
	// the exported log; the restart published nothing.
	code, out = auditVerify(t, env.Signer, env.Signer.exportLog(t), "--json")
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, out)
	}
	var res struct {
		Kinds map[string]uint64 `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("audit verify --json: %v\n%s", err, out)
	}
	if res.Kinds["revoke"] != 1 || res.Kinds["krl_publish"] != 2 {
		t.Fatalf("audit verify kinds = %v, want 1 revoke and 2 krl_publish entries", res.Kinds)
	}
	t.Logf("keyroster audit verify: %s", strings.TrimSpace(out))
}

// TestRevokeUserEndToEnd (03-03b, D-09, REVOKE-01): alice and bob are
// enrolled and approved through the CLI and granted role ops; alice gets
// two passkey login certificates and bob one, and real sshd (the 03-01
// KRL layout) accepts all three. keyroster revoke user alice (admin quorum
// 1) revokes, disables alice and sweeps again; each answer reports both of
// alice's serials (the second sweep re-lists live certificates, and
// nothing is issued in between here), and the CLI says the KRL it checked
// lists them. The served KRL lists each serial once under the user CA key
// and nothing of bob's; after the swap sshd refuses both of alice's
// certificates and accepts bob's, a new login for alice is refused
// user_disabled, and keyroster audit verify passes the exported log with
// exactly two revoke entries of the same two entries, each followed by
// its krl_publish entry.
func TestRevokeUserEndToEnd(t *testing.T) {
	ctx := context.Background()
	login := currentUser(t)
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := revokeCLIRetry(t, env, admin, args...)
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}

	// 1. alice and bob enrolled, approved and granted role ops.
	alice, fpAlice := enroll(t, env, admin, "alice", webauthn.AlgEdDSA)
	kr("user", "approve", "alice", "--fingerprint", fpAlice, "--yes")
	bob, fpBob := enroll(t, env, admin, "bob", webauthn.AlgEdDSA)
	kr("user", "approve", "bob", "--fingerprint", fpBob, "--yes")
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("role", "grant", "ops", "--user", "alice", "--user", "bob", "--yes")

	// 2. Two login certificates for alice, one for bob.
	type holder struct {
		key, cert string
		serial    uint64
	}
	var alices []holder
	for range 2 {
		key, cert, c, err := revokeLogin(t, env, alice, "alice")
		if err != nil {
			t.Fatalf("alice's login: %v", err)
		}
		alices = append(alices, holder{key, cert, c.Serial})
	}
	bobKey, bobCert, bc, err := revokeLogin(t, env, bob, "bob")
	if err != nil {
		t.Fatalf("bob's login: %v", err)
	}
	want := []uint64{alices[0].serial, alices[1].serial}
	slices.Sort(want)
	if want[0] == want[1] || slices.Contains(want, bc.Serial) {
		t.Fatalf("serials alice %v, bob %d are not distinct", want, bc.Serial)
	}

	// 3. sshd with the 03-01 KRL layout accepts all three.
	d := krlLayout(t)
	sshd := startSSHDWithLog(t, sshdOptions{
		UserCAPub:  env.Signer.UserCAPub,
		Principals: map[string][]string{login: {"role:ops"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(d, "current", "revoked.krl")},
	})
	for i, h := range append(slices.Clone(alices), holder{bobKey, bobCert, bc.Serial}) {
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: h.key, Cert: h.cert, User: login, Command: "true"}); code != 0 {
			t.Fatalf("login %d before the revocation exited %d:\n%s", i, code, out)
		}
	}

	// 4. keyroster revoke user alice. The admin requests before used much
	// of the server's admin burst (20 at 60 a minute); a rate-limited step
	// here would end the command half-way (exit 3), so let it refill.
	time.Sleep(8 * time.Second)
	code, out, errOut := env.keyroster(t, admin, "", "revoke", "user", "alice", "--yes", "--reason", "e2e revoke user")
	if code != 0 {
		t.Fatalf("keyroster revoke user alice exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster revoke user alice:\n%s", out)
	wantLine := fmt.Sprintf("Serials: %d %d\n", want[0], want[1])
	for _, label := range []string{"First revocation of alice: the server reports 2 certificate(s) revoked", "Second revocation (after the disable) of alice: the server reports 2 certificate(s) revoked"} {
		i := strings.Index(out, label)
		if i < 0 || !strings.HasPrefix(out[i+strings.Index(out[i:], "\n")+1:], wantLine) {
			t.Fatalf("revoke user output lacks %q followed by %q:\n%s", label, wantLine, out)
		}
	}
	if n := strings.Count(out, "lists each of the 2 serial(s) the server's answer reports, under a user CA key of your trust bundle"); n != 2 {
		t.Fatalf("revoke user output says %d times that the KRL lists the reported serials, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "The server reports directory version") || !strings.Contains(out, "alice is disabled, and the KRL lists every certificate of alice the server reported.") {
		t.Fatalf("revoke user output lacks the install or the summary:\n%s", out)
	}

	// 5. The served KRL lists each of alice's serials once under the user
	// CA key (the second sweep's rows merge with the first's) and nothing
	// of bob's.
	client, bundle := revokeClient(t, env)
	doc, err := client.GetKRL(ctx)
	if err != nil || doc == nil {
		t.Fatalf("GetKRL = %v, %v", doc, err)
	}
	if _, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, 0); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	p, err := krl.Parse(doc.KRL)
	if err != nil {
		t.Fatalf("krl.Parse of the served KRL: %v", err)
	}
	userCA := pubKey(t, readPub(t, env.Signer.UserCAPub)).Marshal()
	var listed uint64
	for _, sec := range p.Certs {
		for _, r := range sec.Serials {
			listed += r.Hi - r.Lo + 1
		}
	}
	if listed != 2 || len(p.Certs) != 1 || !p.RevokesSerial(userCA, want[0]) || !p.RevokesSerial(userCA, want[1]) || p.RevokesSerial(userCA, bc.Serial) {
		t.Fatalf("the served KRL lists %d serials in %d sections, want exactly alice's %v under the user CA key", listed, len(p.Certs), want)
	}

	// 6. The swap; bob's certificate works and both of alice's are refused.
	// bob goes first: from OpenSSH 9.8, sshd's PerSourcePenalties (authfail
	// 5 s, applied from 15 s) would refuse 127.0.0.1 after enough failures.
	swapKRL(t, d, doc.KRL)
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: bobKey, Cert: bobCert, User: login, Command: "true"}); code != 0 {
		t.Fatalf("bob's login after the revocation exited %d:\n%s", code, out)
	}
	t.Log("sshd accepted bob's certificate after the swap")
	for i, h := range alices {
		before := sshd.log.String()
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: h.key, Cert: h.cert, User: login, Command: "true"}); code == 0 {
			t.Fatalf("alice's certificate %d logged in after the revocation:\n%s", i, out)
		}
		waitForLog(t, sshd, before, "revoked")
		t.Logf("sshd refused alice's certificate %d (serial %d): %s", i, h.serial, strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	}

	// 7. The signer refuses a new login for alice.
	if _, _, _, err := revokeLogin(t, env, alice, "alice"); !refusedWith(err, "user_disabled") {
		t.Fatalf("alice's login after revoke user = %v, want refused user_disabled", err)
	}

	// 8. audit verify: two revoke entries of alice's two serials, each
	// followed by its krl_publish entry, on top of the start-up publish.
	export := env.Signer.exportLog(t)
	code, vout := auditVerify(t, env.Signer, export, "--json")
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, vout)
	}
	var res struct {
		Kinds map[string]uint64 `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(vout), &res); err != nil {
		t.Fatalf("audit verify --json: %v\n%s", err, vout)
	}
	if res.Kinds["revoke"] != 2 || res.Kinds["krl_publish"] != 3 {
		t.Fatalf("audit verify kinds = %v, want 2 revoke and 3 krl_publish entries", res.Kinds)
	}
	lines := exportLines(t, export)
	revokes := 0
	for i, l := range lines {
		if l.Kind != "revoke" {
			continue
		}
		revokes++
		var got []uint64
		for _, e := range l.Entries {
			if e.EntryKind != "serial" {
				t.Fatalf("revoke entry %d has a %s entry", l.Index, e.EntryKind)
			}
			got = append(got, e.Serial)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("revoke entry %d lists serials %v, want alice's %v", l.Index, got, want)
		}
		if i+1 >= len(lines) || lines[i+1].Kind != "krl_publish" {
			t.Fatalf("revoke entry %d is not followed by a krl_publish entry", l.Index)
		}
	}
	if revokes != 2 {
		t.Fatalf("the export holds %d revoke entries, want 2", revokes)
	}
	t.Logf("keyroster audit verify: %s", strings.TrimSpace(vout))
}

// TestRevokeKeyEndToEnd (03-03b, REVOKE-01): keyroster revoke key with a
// user's plain key, then keyroster revoke key-id with a third
// certificate's key ID under the user CA. After the KRL swap sshd refuses
// a plain authorized_keys login with that key, a certificate for that
// key and the certificate with that key ID, and still accepts a control
// certificate.
func TestRevokeKeyEndToEnd(t *testing.T) {
	ctx := context.Background()
	login := currentUser(t)
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	keys := t.TempDir()

	// 1. Key k (plain, in authorized_keys, and with a certificate), and
	// certificates for keys c (revoked by key ID) and d (the control).
	type subject struct{ key, cert string }
	subjects := map[string]*subject{}
	for _, name := range []string{"k", "c", "d"} {
		key := filepath.Join(keys, "id_"+name)
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
		env.Signer.issue(t, "--pubkey", key+".pub", "--principal", "role:t", "--subject", "u:"+name, "--ttl", "10m")
		subjects[name] = &subject{key: key, cert: key + "-cert.pub"}
	}
	keyID := parseCertInfo(t, sshKeygen(t, "-L", "-f", subjects["c"].cert)).keyID
	if keyID == "" {
		t.Fatal("no key ID on c's certificate")
	}
	// The plain key alone, in a directory without its certificate (ssh
	// would load id_k-cert.pub next to id_k by itself).
	plain := filepath.Join(t.TempDir(), "id_k")
	copyFile(t, subjects["k"].key, plain, 0o600)
	ak := filepath.Join(t.TempDir(), "authorized_keys")
	copyFile(t, subjects["k"].key+".pub", ak, 0o644)

	d := krlLayout(t)
	sshd := startSSHDWithKeys(t, sshdOptions{
		UserCAPub:  env.Signer.UserCAPub,
		Principals: map[string][]string{login: {"role:t"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(d, "current", "revoked.krl")},
	}, ak)
	plainLogin := func() (int, string) {
		return sshLogin(t, loginOptions{Port: sshd.port, Key: plain, Cert: plain + "-cert.pub", User: login, Command: "true"})
	}

	// 2. Controls: every login works under the zero-byte KRL.
	if code, out := plainLogin(); code != 0 {
		t.Fatalf("plain key login before the revocation exited %d:\n%s", code, out)
	}
	for name, s := range subjects {
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: s.key, Cert: s.cert, User: login, Command: "true"}); code != 0 {
			t.Fatalf("login with %s's certificate before the revocation exited %d:\n%s", name, code, out)
		}
	}

	// 3. keyroster revoke key and keyroster revoke key-id.
	code, out, errOut := env.keyroster(t, admin, "", "revoke", "key", subjects["k"].key+".pub", "--reason", "e2e revoke key")
	if code != 0 {
		t.Fatalf("keyroster revoke key exited %d:\n%s%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster revoke key:\n%s", out)
	kPub := pubKey(t, readPub(t, subjects["k"].key+".pub"))
	if fp := ssh.FingerprintSHA256(kPub); !strings.Contains(out, "The server reports key "+fp+" revoked") ||
		!strings.Contains(out, "lists key "+fp+" as an explicit key") {
		t.Fatalf("keyroster revoke key output:\n%s", out)
	}
	code, out, errOut = env.keyroster(t, admin, "", "revoke", "key-id", keyID, "--ca", "user", "--reason", "e2e revoke key-id")
	if code != 0 {
		t.Fatalf("keyroster revoke key-id exited %d:\n%s%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster revoke key-id:\n%s", out)
	if !strings.Contains(out, fmt.Sprintf("lists key ID %q under a user CA key of your trust bundle", keyID)) {
		t.Fatalf("keyroster revoke key-id output:\n%s", out)
	}

	// 4. The served KRL lists the key and the key ID; the swap.
	client, bundle := revokeClient(t, env)
	doc, err := client.GetKRL(ctx)
	if err != nil || doc == nil {
		t.Fatalf("GetKRL = %v, %v", doc, err)
	}
	if _, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, 0); err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	p, err := krl.Parse(doc.KRL)
	if err != nil {
		t.Fatalf("krl.Parse of the served KRL: %v", err)
	}
	userCA := pubKey(t, readPub(t, env.Signer.UserCAPub)).Marshal()
	if !p.RevokesKey(kPub.Marshal()) || !p.RevokesKeyID(userCA, keyID) {
		t.Fatalf("the served KRL does not list key k and key ID %q", keyID)
	}
	swapKRL(t, d, doc.KRL)

	// 5. The control still logs in under the new KRL, and the plain key,
	// its certificate and the key ID's certificate are refused. The control
	// goes first: from OpenSSH 9.8, sshd's PerSourcePenalties (authfail 5 s,
	// applied from 15 s) refuses every connection from 127.0.0.1 after the
	// third failed authentication.
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: subjects["d"].key, Cert: subjects["d"].cert, User: login, Command: "true"}); code != 0 {
		t.Fatalf("login with the control certificate after the swap exited %d:\n%s", code, out)
	}
	before := sshd.log.String()
	if code, out := plainLogin(); code == 0 {
		t.Fatalf("plain key login after the revocation succeeded:\n%s", out)
	}
	waitForLog(t, sshd, before, "revoked")
	t.Logf("sshd refused the plain key: %s", strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	for _, name := range []string{"k", "c"} {
		before := sshd.log.String()
		s := subjects[name]
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: s.key, Cert: s.cert, User: login, Command: "true"}); code == 0 {
			t.Fatalf("login with %s's certificate after the revocation succeeded:\n%s", name, out)
		}
		waitForLog(t, sshd, before, "revoked")
		t.Logf("sshd refused %s's certificate: %s", name, strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	}
}

// revokeCLIRetry runs one admin CLI command; a command the server
// rate-limited (refused before any handler ran, so nothing changed) runs
// again after the limiter refills, as in TestRolesHostPrincipalsEndToEnd.
func revokeCLIRetry(t *testing.T, env *serverEnv, admin *cliEnv, args ...string) (int, string, string) {
	t.Helper()
	code, out, errOut := env.keyroster(t, admin, "", args...)
	for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
		t.Logf("keyroster %s was rate-limited; running it again in 2 s", strings.Join(args, " "))
		time.Sleep(2 * time.Second)
		code, out, errOut = env.keyroster(t, admin, "", args...)
	}
	return code, out, errOut
}

// revokeLogin logs user in on env's signer socket with a new ephemeral
// key, principals [role:ops] for 600 s, approved by auth's assertion for
// env's origin, and returns the key and certificate files and the
// certificate.
func revokeLogin(t *testing.T, env *serverEnv, auth *webauthntest.Authenticator, user string) (keyFile, certFile string, c *ssh.Certificate, err error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.LoginIssueRequest{
		SubjectKey:      sshPub.Marshal(),
		Subject:         user,
		Principals:      []string{"role:ops"},
		ValidForSeconds: 600,
		CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: test clock after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	a := auth.Assert(serverRPID, env.URL, req.Digest())
	blob, err := (&wire.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}}
	resp, err := signerclient.Login(context.Background(), env.Signer.Socket, req)
	if err != nil {
		return "", "", nil, err
	}
	keyFile, certFile = writeLoginKey(t, priv, resp.Cert)
	return keyFile, certFile, parseCert(t, resp.Cert), nil
}

// refusedWith reports whether err is the signer's refusal detail.
func refusedWith(err error, detail string) bool {
	var e *wire.ErrorResponse
	return errors.As(err, &e) && e.Message == detail
}

// krlLayout makes the 03-01 KRL layout in a new directory: gen/1 holds a
// zero-byte KRL (which revokes nothing), gen/2 is empty, and current ->
// gen/1 (relative).
func krlLayout(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, g := range []string{"gen/1", "gen/2"} {
		if err := os.MkdirAll(filepath.Join(d, g), 0o755); err != nil { //nolint:gosec // G301: test fixture, read by sshd
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "gen/1/revoked.krl"), nil, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.Symlink("gen/1", filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	return d
}

// swapKRL writes data as gen/2's KRL in the layout d and points current
// at gen/2 with rename(2).
func swapKRL(t *testing.T, d string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d, "gen/2/revoked.krl"), data, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	tmp := filepath.Join(d, "current.tmp")
	if err := os.Symlink("gen/2", tmp); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, filepath.Join(d, "gen/2"))
	fsyncDir(t, d)
	if err := os.Rename(tmp, filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, d)
}

// pubKey parses one authorized_keys line.
func pubKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// copyFile copies src to dst with mode perm.
func copyFile(t *testing.T, src, dst string, perm os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(src) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, perm); err != nil { //nolint:gosec // G703: test fixture paths
		t.Fatal(err)
	}
}

// exportLine is the part of one exported leaf the revoke tests read: its
// index and the kind and revoked entries of its decoded rendering.
type exportLine struct {
	Index   uint64
	Kind    string
	Entries []exportEntry
}

type exportEntry struct {
	EntryKind string `json:"entry_kind"`
	Serial    uint64 `json:"serial"`
}

// exportLines reads the leaf lines of a keyroster-signer export, in
// order (the closing checkpoint line carries no index and is skipped).
func exportLines(t *testing.T, export string) []exportLine {
	t.Helper()
	data, err := os.ReadFile(export) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	var out []exportLine
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e struct {
			Index   *uint64 `json:"index"`
			Decoded struct {
				Kind    string        `json:"kind"`
				Entries []exportEntry `json:"entries"`
			} `json:"decoded"`
		}
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("export line %q: %v", l, err)
		}
		if e.Index == nil {
			continue
		}
		out = append(out, exportLine{Index: *e.Index, Kind: e.Decoded.Kind, Entries: e.Decoded.Entries})
	}
	return out
}

// writeKRL writes data to a fresh file and returns its path.
func writeKRL(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "revoked.krl")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// revokeClient builds the pinned TLS client for env's server and returns
// it with the trust bundle verified against the root pins.
func revokeClient(t *testing.T, env *serverEnv) (*serverclient.Client, *trust.Bundle) {
	t.Helper()
	root, err := os.ReadFile(env.CA.RootPEM)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	c, err := serverclient.New(serverclient.Config{Server: env.URL, RootsPEM: []string{string(root)}, Pins: []string{env.CA.RootPin}, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := c.Trust(context.Background(), env.Signer.RootFingerprints, 1)
	if err != nil {
		t.Fatalf("Trust: %v", err)
	}
	return c, b
}

// keygenQuery runs ssh-keygen -Q -f krlFile certFile and returns its exit
// code and output (0: not revoked).
func keygenQuery(t *testing.T, krlFile, certFile string) (int, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keygen"), "-Q", "-f", krlFile, certFile)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	return 0, string(out)
}

func fsyncDir(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Open(dir) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

// sshdRun is an sshd started by startSSHDWithLog.
type sshdRun struct {
	port    int
	pidFile string
	log     *syncBuffer
}

// pid reads sshd's PidFile.
func (s *sshdRun) pid(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(s.pidFile)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("sshd PidFile %q: %v", data, err)
	}
	return n
}

// startSSHDWithLog is startSSHD (harness_test.go) that also returns the
// PidFile path and the daemon's log, which the tracer needs to show that
// the same sshd process refused a revoked key. It builds the same
// configuration from sshdConfigTemplate.
func startSSHDWithLog(t *testing.T, opts sshdOptions) *sshdRun {
	t.Helper()
	return startSSHDWithKeys(t, opts, "")
}

// startSSHDWithKeys is startSSHDWithLog with AuthorizedKeysFile set to
// authorizedKeys (sshd tokens such as %u allowed) instead of none, so a
// plain key can log in; "" keeps none. The template's line is replaced,
// not followed by another: sshd keeps the first value it reads.
func startSSHDWithKeys(t *testing.T, opts sshdOptions, authorizedKeys string) *sshdRun {
	t.Helper()
	prefix := opensshPrefix(t)
	dir := t.TempDir()
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ssh_host_ed25519_key"))
	if err := os.Mkdir(filepath.Join(dir, "principals"), 0o755); err != nil {
		t.Fatal(err)
	}
	for u, ps := range opts.Principals {
		if err := os.WriteFile(filepath.Join(dir, "principals", u), []byte(strings.Join(ps, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	port := freePort(t)
	cfg := fmt.Sprintf(sshdConfigTemplate, port, dir, dir, opts.UserCAPub, dir)
	if authorizedKeys != "" {
		if !strings.Contains(cfg, "\nAuthorizedKeysFile none\n") {
			t.Fatal("sshdConfigTemplate has no AuthorizedKeysFile none line to replace")
		}
		cfg = strings.Replace(cfg, "\nAuthorizedKeysFile none\n", "\nAuthorizedKeysFile "+authorizedKeys+"\n", 1)
	}
	for _, l := range opts.Extra {
		cfg += l + "\n"
	}
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	sshd := filepath.Join(prefix, "sbin", "sshd") // absolute: sshd re-execs itself
	if out, err := exec.Command(sshd, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd -t: %v\n%s\n%s", err, out, cfg)
	}
	_, log, done := startDaemon(t, "sshd", envWithout("SSH_AUTH_SOCK"), sshd, "-D", "-e", "-f", cfgPath)
	pidFile := filepath.Join(dir, "sshd.pid")
	waitFor(t, "sshd port", done, log, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		_, err = os.Stat(pidFile)
		return err == nil
	})
	return &sshdRun{port: port, pidFile: pidFile, log: log}
}

// waitForLog waits up to 5 s for sshd's log, after the prefix before, to
// contain want.
func waitForLog(t *testing.T, s *sshdRun, before, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(strings.TrimPrefix(s.log.String(), before), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd log has no %q after the refusal:\n%s", want, strings.TrimPrefix(s.log.String(), before))
		}
		time.Sleep(50 * time.Millisecond)
	}
}
