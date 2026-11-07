//go:build e2e && e2eprobe

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/wire"
)

// errProbeSentinel is what the PK_OK client's signer returns: sshd only
// asks for a signature after it accepted the certificate in the unsigned
// query (PK_OK), so seeing it means "accepted" (03-10, C21).
var errProbeSentinel = errors.New("probe e2e: PK_OK reached, no signature made")

// pkResult is the outcome of one unsigned publickey query.
type pkResult string

const (
	pkAccepted     pkResult = "accepted"
	pkRefused      pkResult = "refused"
	pkInconclusive pkResult = "inconclusive"
)

// sentinelSigner offers a certificate as its public key and never signs.
type sentinelSigner struct{ pub ssh.PublicKey }

func (s sentinelSigner) PublicKey() ssh.PublicKey { return s.pub }
func (sentinelSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errProbeSentinel
}

// sshdHostKey is the host key of an sshd the harness started.
func sshdHostKey(t *testing.T, s *sshdRun) ssh.PublicKey {
	t.Helper()
	return pubKey(t, readPub(t, filepath.Join(filepath.Dir(s.pidFile), "ssh_host_ed25519_key.pub")))
}

// pkQueryErr runs the unsigned publickey query of c for user against the
// sshd on port from the local address src, checking the host key, and
// never completes an authentication. It returns accepted for PK_OK,
// refused for "unable to authenticate", and inconclusive with the error
// for anything else (a dial error, a closed connection).
func pkQueryErr(port int, hostKey ssh.PublicKey, src, user string, c ssh.PublicKey) (pkResult, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return pkInconclusive, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(sentinelSigner{pub: c})},
		HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 10 * time.Second}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	switch {
	case err == nil:
		_ = ssh.NewClient(cc, chans, reqs).Close()
		return pkInconclusive, errors.New("authenticated without a signature")
	case errors.Is(err, errProbeSentinel):
		return pkAccepted, nil
	case strings.Contains(err.Error(), "unable to authenticate"):
		return pkRefused, nil
	}
	return pkInconclusive, err
}

// pkQuery is pkQueryErr that fails the test on an inconclusive result.
func pkQuery(t *testing.T, s *sshdRun, src, user string, c ssh.PublicKey) pkResult {
	t.Helper()
	r, err := pkQueryErr(s.port, sshdHostKey(t, s), src, user, c)
	if r == pkInconclusive {
		t.Fatalf("PK_OK query from %s: inconclusive: %v\nsshd log:\n%s", src, err, s.log.String())
	}
	return r
}

// probePair is one probe issuance through the signer socket: the request,
// the probe key and the certificate.
type probePair struct {
	req   *wire.ProbeIssueRequest
	probe ssh.Signer
	cert  *ssh.Certificate
}

// issueProbe asks the signer for a probe certificate for host name by the
// host key in hostKeyFile, with a fresh Ed25519 probe key.
func issueProbe(t *testing.T, env *serverEnv, name, hostKeyFile string, negative bool) probePair {
	t.Helper()
	raw, err := os.ReadFile(hostKeyFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.ProbeIssueRequest{InstallationID: env.Signer.InstallationID, HostName: name, HostKey: host.PublicKey().Marshal(),
		ProbeKey: probe.PublicKey().Marshal(), Negative: negative, CreatedAt: uint64(time.Now().Unix())} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	hs, err := sshsig.Sign(rand.Reader, host, wire.ProbePoPNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	ps, err := sshsig.Sign(rand.Reader, probe, wire.ProbePoPNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: hs}, {Type: wire.EvidenceProbePoP, Blob: ps}}
	resp, err := signerclient.ProbeIssue(context.Background(), env.Signer.Socket, req)
	if err != nil {
		t.Fatalf("ProbeIssue %s (negative %t): %v", name, negative, err)
	}
	pub, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("the answer is not a certificate")
	}
	return probePair{req: req, probe: probe, cert: c}
}

// signerKRL is the KRL the signer publishes now.
func signerKRL(t *testing.T, env *serverEnv) []byte {
	t.Helper()
	resp, err := signerclient.GetKRL(context.Background(), env.Signer.Socket)
	if err != nil {
		t.Fatal(err)
	}
	return resp.KRL
}

// writeFile writes data to a new file in a fresh directory and returns
// its path.
func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return p
}

// probeSSHD starts an sshd that trusts caPub only and maps the current
// user to the four probe principals, with RevokedKeys krlFile ("" for
// none).
func probeSSHD(t *testing.T, caPub, krlFile string) *sshdRun {
	t.Helper()
	var extra []string
	if krlFile != "" {
		extra = append(extra, "RevokedKeys "+krlFile)
	}
	return startSSHDWithLog(t, sshdOptions{UserCAPub: caPub, Extra: extra,
		Principals: map[string][]string{currentUser(t): {"keyroster-probe:web1", "keyroster-probe:web2", "keyroster-probe:web3", "keyroster-probe:web4"}}})
}

// TestProbeCertsAgainstSSHD (03-10, D-06, T-03-64, T-03-68): a probe pair
// issued by the signer from two proofs of possession is accepted by real
// sshd as the agent's self-test needs: the positive certificate gets
// PK_OK, the negative one is refused because its own serial is in the
// published KRL (in list and range encodings, as ssh-keygen -Q agrees), a
// corrupt KRL that keeps its magic refuses the positive one, the source
// address is checked in the unsigned query, and the probe key opens no
// session. Every issuance, KRL capture, sshd start and query happens in
// the parent body; each subtest asserts on what the parent recorded, so
// any subtest passes or fails alone.
func TestProbeCertsAgainstSSHD(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPHosts: true})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, out, errOut)
		}
		return out
	}
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", "deploy", "ops", "--yes")
	hostKeys := map[string]string{}
	for _, n := range []string{"web1", "web2", "web3", "web4"} {
		hostKeys[n] = newUserKey(t, "ssh_host_ed25519_key")
		kr("host", "add", n, "--group", "lab", "--key", hostKeys[n]+".pub", "--principal", n, "--yes")
	}
	user := currentUser(t)
	machineCA := env.Signer.MachineCAPub
	machineCAKey := pubKey(t, readPub(t, machineCA))

	// The sources of the refusing queries: at most two refusals each, and
	// no address twice (C20: 9.8 and later penalize a source after about
	// three failed authentications).
	sources := map[string]string{
		"positive_ok_negative_refused":    "127.0.0.2",
		"wrong_ca_pair_refused":           "127.0.0.3",
		"source_address_checked_in_query": "127.0.0.4",
		"serial_list":                     "127.0.0.5",
		"serial_range":                    "127.0.0.6",
		"corrupt_cut_after_12":            "127.0.0.7",
		"corrupt_last_byte_dropped":       "127.0.0.8",
		"garbage_krl_recorded":            "127.0.0.9",
	}
	if vals := slices.Collect(maps.Values(sources)); len(slices.Compact(slices.Sorted(slices.Values(vals)))) != len(vals) {
		t.Fatalf("the source table repeats an address: %v", sources)
	}

	// web1's pair; the negative one is the first of the test, so the
	// signer publishes it at once.
	neg1 := issueProbe(t, env, "web1", hostKeys["web1"], true)
	pos1 := issueProbe(t, env, "web1", hostKeys["web1"], false)
	published := signerKRL(t, env)
	publishedFile := writeFile(t, "published.krl", published)
	// web2: positive, the KRL captured, then the negative.
	pos2 := issueProbe(t, env, "web2", hostKeys["web2"], false)
	before := signerKRL(t, env)
	neg2 := issueProbe(t, env, "web2", hostKeys["web2"], true)
	_ = pos2

	// positive_ok_negative_refused.
	sshdKRL := probeSSHD(t, machineCA, publishedFile)
	okPos1 := pkQuery(t, sshdKRL, "127.0.0.1", user, pos1.cert)
	logBefore := sshdKRL.log.String()
	negRefused := pkQuery(t, sshdKRL, sources["positive_ok_negative_refused"], user, neg1.cert)
	time.Sleep(200 * time.Millisecond)
	revokedLogged := strings.Contains(strings.TrimPrefix(sshdKRL.log.String(), logBefore), "revoked")

	// control_no_revoked_keys_negative_accepted.
	sshdNone := probeSSHD(t, machineCA, "")
	controlNeg := pkQuery(t, sshdNone, "127.0.0.1", user, neg1.cert)

	// krl_before_negative_accepts_it.
	sshdBefore := probeSSHD(t, machineCA, writeFile(t, "before.krl", before))
	beforeNeg2 := pkQuery(t, sshdBefore, "127.0.0.1", user, neg2.cert)

	// corrupt_krl_refuses_positive: two corrupt files that keep the magic.
	corrupt := map[string][]byte{
		"corrupt_cut_after_12":      published[:12],
		"corrupt_last_byte_dropped": published[:len(published)-1],
	}
	corruptParse := map[string]error{}
	corruptResult := map[string]pkResult{}
	for name, data := range corrupt {
		_, corruptParse[name] = krl.Parse(data)
		if !strings.HasPrefix(string(data), krl.Magic) || corruptParse[name] == nil {
			t.Fatalf("%s: the corrupt KRL must keep the magic and fail krl.Parse (parse error %v)", name, corruptParse[name])
		}
		s := probeSSHD(t, machineCA, writeFile(t, name+".krl", data))
		corruptResult[name] = pkQuery(t, s, sources[name], user, pos1.cert)
	}

	// garbage_krl_recorded: no magic; recorded, never asserted.
	garbage := map[string][]byte{"garbage file": []byte("this is not a key revocation list\n"), "empty file": {}}
	garbageResult := map[string]pkResult{}
	for _, name := range []string{"garbage file", "empty file"} {
		s := probeSSHD(t, machineCA, writeFile(t, strings.ReplaceAll(name, " ", "_")+".krl", garbage[name]))
		r, err := pkQueryErr(s.port, sshdHostKey(t, s), sources["garbage_krl_recorded"], user, pos1.cert)
		if r == pkInconclusive {
			r = pkResult(fmt.Sprintf("inconclusive (%v)", err))
		}
		garbageResult[name] = r
	}

	// wrong_ca_pair_refused: the same principal under the user CA.
	wrongCAKey := newUserKey(t, "id_wrong_ca")
	sshKeygen(t, "-q", "-s", env.Signer.RoleKeyFiles["user"], "-I", "wrong-ca", "-n", "keyroster-probe:web1", wrongCAKey+".pub")
	wrongCA := pubKey(t, readPub(t, wrongCAKey+"-cert.pub"))
	sshdWrongCA := probeSSHD(t, machineCA, publishedFile)
	wrongCAResult := pkQuery(t, sshdWrongCA, sources["wrong_ca_pair_refused"], user, wrongCA)

	// serial_list_and_range_encodings: the negative serial in a serial list
	// with other serials, and inside a serial range.
	if pos1.cert.Serial >= neg1.cert.Serial-1 && pos1.cert.Serial <= neg1.cert.Serial+1 {
		t.Fatalf("the positive serial %d is next to the negative %d; the range case would revoke it", pos1.cert.Serial, neg1.cert.Serial)
	}
	encodings := map[string][]uint64{
		"serial_list":  {neg1.cert.Serial - 1000, neg1.cert.Serial, neg1.cert.Serial + 1000},
		"serial_range": {neg1.cert.Serial - 1, neg1.cert.Serial, neg1.cert.Serial + 1},
	}
	encodingNeg, encodingPos := map[string]pkResult{}, map[string]pkResult{}
	encodingShape := map[string]string{}
	for _, name := range []string{"serial_list", "serial_range"} {
		data, err := krl.Encode(krl.Set{Certs: []krl.CertSection{{CAKey: machineCAKey, Serials: encodings[name]}}}, 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := krl.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, sec := range p.Certs {
			encodingShape[name] = fmt.Sprintf("%v", sec.Serials)
		}
		s := probeSSHD(t, machineCA, writeFile(t, name+".krl", data))
		encodingPos[name] = pkQuery(t, s, "127.0.0.1", user, pos1.cert)
		encodingNeg[name] = pkQuery(t, s, sources[name], user, neg1.cert)
	}

	// ssh_keygen_Q_agrees.
	certFile := func(name string, c *ssh.Certificate) string {
		return writeFile(t, name+"-cert.pub", ssh.MarshalAuthorizedKey(c))
	}
	qNegCode, qNegOut := sshKeygenQ(t, publishedFile, certFile("neg1", neg1.cert))
	qPosCode, qPosOut := sshKeygenQ(t, publishedFile, certFile("pos1", pos1.cert))

	// source_address_checked_in_query: two machine-CA certificates for the
	// same principal and user, from the same source 127.0.0.4.
	src := sources["source_address_checked_in_query"]
	okKey, badKey := newUserKey(t, "id_src_ok"), newUserKey(t, "id_src_bad")
	sshKeygen(t, "-q", "-s", env.Signer.RoleKeyFiles["machine"], "-I", "src-ok", "-n", "keyroster-probe:web1", "-z", "11",
		"-O", "source-address="+src+"/32", okKey+".pub")
	sshKeygen(t, "-q", "-s", env.Signer.RoleKeyFiles["machine"], "-I", "src-bad", "-n", "keyroster-probe:web1", "-z", "12",
		"-O", "source-address=::1/128", badKey+".pub")
	sshdSrc := probeSSHD(t, machineCA, publishedFile)
	srcOK := pkQuery(t, sshdSrc, src, user, pubKey(t, readPub(t, okKey+"-cert.pub")))
	srcBad := pkQuery(t, sshdSrc, src, user, pubKey(t, readPub(t, badKey+"-cert.pub")))

	// probe_key_opens_no_session: a full authentication with the positive
	// probe certificate and its key from 127.0.0.1.
	sshdSession := probeSSHD(t, machineCA, publishedFile)
	session := probeSession(t, sshdSession, user, pos1)

	t.Run("pair_issued_and_restricted", func(t *testing.T) {
		for name, p := range map[string]probePair{"negative": neg1, "positive": pos1} {
			c := p.cert
			kid, err := cert.ParseKeyID(c.KeyId)
			if err != nil {
				t.Fatal(err)
			}
			if c.CertType != ssh.UserCert || !slices.Equal(c.ValidPrincipals, []string{"keyroster-probe:web1"}) || kid.CA != "machine" ||
				kid.Subject != "probe.web1" || c.ValidBefore-c.ValidAfter-300 != 86400 || len(c.Extensions) != 0 ||
				!maps.Equal(c.CriticalOptions, map[string]string{"force-command": "/bin/false", "source-address": "127.0.0.0/8,::1/128"}) ||
				!slices.Equal(c.SignatureKey.Marshal(), machineCAKey.Marshal()) {
				t.Fatalf("%s: type %d, principals %v, key ID %q, lifetime %d s, extensions %v, options %v", name, c.CertType,
					c.ValidPrincipals, c.KeyId, c.ValidBefore-c.ValidAfter-300, c.Extensions, c.CriticalOptions)
			}
		}
		p, err := krl.Parse(published)
		if err != nil {
			t.Fatal(err)
		}
		if !p.RevokesSerial(machineCAKey.Marshal(), neg1.cert.Serial) || p.RevokesSerial(machineCAKey.Marshal(), pos1.cert.Serial) {
			t.Fatal("the published KRL does not revoke exactly the negative serial under the machine CA key")
		}
	})
	t.Run("positive_ok_negative_refused", func(t *testing.T) {
		if okPos1 != pkAccepted || negRefused != pkRefused || !revokedLogged {
			t.Fatalf("positive %s, negative %s (want accepted, refused), sshd logged revoked: %t\n%s", okPos1, negRefused, revokedLogged, sshdKRL.log.String())
		}
	})
	t.Run("control_no_revoked_keys_negative_accepted", func(t *testing.T) {
		if controlNeg != pkAccepted {
			t.Fatalf("without RevokedKeys the negative certificate is %s, want accepted", controlNeg)
		}
	})
	t.Run("krl_before_negative_accepts_it", func(t *testing.T) {
		if beforeNeg2 != pkAccepted {
			t.Fatalf("under the KRL captured before it was issued, web2's negative certificate is %s, want accepted", beforeNeg2)
		}
	})
	t.Run("corrupt_krl_refuses_positive", func(t *testing.T) {
		for name, r := range corruptResult {
			if r != pkRefused {
				t.Errorf("%s: the positive certificate is %s under a corrupt KRL that keeps the magic, want refused (stop and report)", name, r)
			}
		}
	})
	t.Run("garbage_krl_recorded", func(t *testing.T) {
		t.Logf("FACT KRL %s: garbage file: positive %s; empty file: positive %s", sshdVersion(t), garbageResult["garbage file"], garbageResult["empty file"])
	})
	t.Run("wrong_ca_pair_refused", func(t *testing.T) {
		if wrongCAResult != pkRefused {
			t.Fatalf("a user-CA certificate for the probe principal is %s, want refused", wrongCAResult)
		}
	})
	t.Run("serial_list_and_range_encodings", func(t *testing.T) {
		if !strings.Contains(encodingShape["serial_list"], fmt.Sprintf("{%d %d}", neg1.cert.Serial, neg1.cert.Serial)) ||
			!strings.Contains(encodingShape["serial_range"], fmt.Sprintf("{%d %d}", neg1.cert.Serial-1, neg1.cert.Serial+1)) {
			t.Fatalf("the KRLs are not the list and range encodings: %v", encodingShape)
		}
		for _, name := range []string{"serial_list", "serial_range"} {
			if encodingNeg[name] != pkRefused || encodingPos[name] != pkAccepted {
				t.Errorf("%s: negative %s, positive %s; want refused, accepted", name, encodingNeg[name], encodingPos[name])
			}
		}
	})
	t.Run("ssh_keygen_Q_agrees", func(t *testing.T) {
		if qNegCode == 0 || !strings.Contains(qNegOut, "REVOKED") || qPosCode != 0 || !strings.Contains(qPosOut, ": ok") {
			t.Fatalf("ssh-keygen -Q: negative exit %d %q, positive exit %d %q", qNegCode, qNegOut, qPosCode, qPosOut)
		}
	})
	t.Run("source_address_checked_in_query", func(t *testing.T) {
		if srcOK != pkAccepted || srcBad != pkRefused {
			t.Fatalf("from %s: the certificate for %s/32 is %s (want accepted), the one for ::1/128 is %s (want refused)", src, src, srcOK, srcBad)
		}
	})
	t.Run("probe_key_opens_no_session", func(t *testing.T) {
		if session.authErr != nil {
			t.Fatalf("the full authentication with the probe key failed: %v\n%s", session.authErr, sshdSession.log.String())
		}
		if session.idErr == nil || len(session.idOut) != 0 || session.idExit == 0 {
			t.Errorf("id: output %q, exit %d, error %v; want no output and a non-zero exit (force-command /bin/false)", session.idOut, session.idExit, session.idErr)
		}
		if session.ptyErr == nil {
			t.Error("a pty was granted")
		}
		if session.tcpErr == nil {
			t.Error("a direct-tcpip channel was opened")
		}
		if session.agentErr == nil {
			t.Error("agent forwarding was granted")
		}
	})
}

// sessionFacts is what a full authentication with a probe key could do.
type sessionFacts struct {
	authErr, idErr, ptyErr, tcpErr, agentErr error
	idOut                                    []byte
	idExit                                   int
}

// probeSession authenticates fully with p's certificate and probe key
// from 127.0.0.1 and tries a command, a pty, a direct-tcpip channel to the
// sshd's own port and agent forwarding.
func probeSession(t *testing.T, s *sshdRun, user string, p probePair) sessionFacts {
	t.Helper()
	var f sessionFacts
	signer, err := ssh.NewCertSigner(p.cert, p.probe)
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.port))
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(sshdHostKey(t, s)), Timeout: 10 * time.Second})
	if err != nil {
		f.authErr = err
		return f
	}
	defer func() { _ = client.Close() }()
	if sess, err := client.NewSession(); err != nil {
		f.idErr = err
	} else {
		f.idOut, f.idErr = sess.Output("id")
		var ee *ssh.ExitError
		if errors.As(f.idErr, &ee) {
			f.idExit = ee.ExitStatus()
		}
		_ = sess.Close()
	}
	if sess, err := client.NewSession(); err != nil {
		f.ptyErr = err
	} else {
		f.ptyErr = sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
		_ = sess.Close()
	}
	if c, err := client.Dial("tcp", addr); err != nil {
		f.tcpErr = err
	} else {
		_ = c.Close()
	}
	if sess, err := client.NewSession(); err != nil {
		f.agentErr = err
	} else {
		f.agentErr = agent.RequestAgentForwarding(sess)
		_ = sess.Close()
	}
	return f
}

// sshdVersion is the OpenSSH version of the harness build, from ssh -V.
func sshdVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh"), "-V").CombinedOutput() //nolint:gosec // the harness build
	if err != nil {
		t.Fatalf("ssh -V: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
