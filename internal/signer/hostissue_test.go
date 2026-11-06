//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// hostEnv is a logEnv for host certificates (03-09): three admins at
// quorum 2, an installation ID, pop.hosts and a host cap of hostTTL, on a
// clock the test sets, with directory version 1 installed: web1 (active,
// keys ed and ec, principals web1 and web1.lab), web2 (disabled, key off)
// and web3 (active, key other).
type hostEnv struct {
	*revokeEnv
	ed, ec, off, other ssh.Signer
	hosts              []directory.Host
	docs               [][]byte
}

// newECDSAKey is a fresh ECDSA P-256 signer.
func newECDSAKey(t testing.TB) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newHostEnv(t *testing.T, hostTTL uint64) *hostEnv {
	t.Helper()
	return newHostEnvOpts(t, hostTTL, testInstallationID, true)
}

// newHostEnvBare is newHostEnv with no directory installed.
func newHostEnvBare(t *testing.T, hostTTL uint64) *hostEnv {
	t.Helper()
	return newHostEnvWith(t, hostTTL, testInstallationID, true, false)
}

// newHostEnvOpts is newHostEnv with the bundle's installation ID (""
// for none) and pop.hosts as given.
func newHostEnvOpts(t *testing.T, hostTTL uint64, install string, pop bool) *hostEnv {
	t.Helper()
	return newHostEnvWith(t, hostTTL, install, pop, true)
}

func newHostEnvWith(t *testing.T, hostTTL uint64, install string, pop, withDir bool) *hostEnv {
	t.Helper()
	fx := NewFixture(t, 2, 1)
	fx.InstallationID = install
	fx.PolicyEdit = func(p *trust.Policy) {
		if pop {
			p.PoP = &trust.PoPPolicy{Hosts: true}
		}
		for i := range p.CAProfiles {
			if p.CAProfiles[i].Role == trust.RoleHost {
				p.CAProfiles[i].MaxTTLSeconds = hostTTL
			}
		}
	}
	clock := &revokeClock{now: time.Now().Truncate(time.Second).Add(500 * time.Millisecond)}
	e := &hostEnv{revokeEnv: &revokeEnv{logEnv: newLogEnvClock(t, fx, clock.Now), clock: clock}}
	_, ed := NewEd25519Key(t)
	_, off := NewEd25519Key(t)
	_, other := NewEd25519Key(t)
	e.ed, e.ec, e.off, e.other = ed, newECDSAKey(t), off, other
	e.hosts = []directory.Host{
		{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(e.ed.PublicKey()), trust.FormatKey(e.ec.PublicKey())}, Principals: []string{"web1", "web1.lab"}, Status: directory.StatusActive},
		{Name: "web2", HostGroup: "lab", Keys: []string{trust.FormatKey(e.off.PublicKey())}, Principals: []string{"web2"}, Status: directory.StatusDisabled},
		{Name: "web3", HostGroup: "lab", Keys: []string{trust.FormatKey(e.other.PublicKey())}, Principals: []string{"web3"}, Status: directory.StatusActive},
	}
	if withDir {
		e.publish(t)
	}
	return e
}

// publish signs and installs the next directory version with e.hosts.
func (e *hostEnv) publish(t *testing.T) {
	t.Helper()
	prev := trust.GenesisPrev
	if n := len(e.docs); n > 0 {
		prev = trust.SHA256Hex(e.docs[n-1])
	}
	hosts := slices.Clone(e.hosts)
	for i := range hosts {
		hosts[i].Keys = slices.Sorted(slices.Values(hosts[i].Keys))
	}
	d := &directory.Directory{
		Version: uint64(len(e.docs) + 1), Prev: prev, InstallationID: e.fx.InstallationID,
		Roles:      []directory.Role{{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600}},
		HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
		Hosts:      hosts,
	}
	d.Sort()
	doc, sigs := signDirectory(t, d, e.fx.Admins[0])
	e.installDirectory(t, doc, sigs)
	e.docs = append(e.docs, doc)
}

// hostReq is a host request by key for name, valid_for 0, created now on
// the env's clock, signed by key under the host namespace.
func (e *hostEnv) hostReq(key ssh.Signer, name string) *wire.HostIssueRequest {
	e.t.Helper()
	install := e.fx.InstallationID
	if install == "" {
		install = testInstallationID
	}
	req := &wire.HostIssueRequest{InstallationID: install, HostName: name, HostKey: key.PublicKey().Marshal(),
		CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	return e.popSign(req, key, wire.HostPoPNamespace)
}

// popSign replaces req's evidence with a host-pop/v1 SSHSIG by key under
// ns over its signing bytes.
func (e *hostEnv) popSign(req *wire.HostIssueRequest, key ssh.Signer, ns string) *wire.HostIssueRequest {
	e.t.Helper()
	sig, err := sshsig.Sign(rand.Reader, key, ns, req.SigningBytes())
	if err != nil {
		e.t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: sig}}
	return req
}

// hostIssues are the host_issue leaves of the log.
func (e *hostEnv) hostIssues() []*tlog.HostIssueBody {
	e.t.Helper()
	var out []*tlog.HostIssueBody
	for _, l := range e.leavesOf() {
		if l.Kind != tlog.KindHostIssue {
			continue
		}
		b, err := tlog.DecodeHostIssueBody(l.Body)
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// mustHost requires req to be answered with a certificate and returns it.
// The clock moves on a millisecond first, so serials never wait for it.
func (e *hostEnv) mustHost(req *wire.HostIssueRequest) (*ssh.Certificate, *wire.IssueResponse) {
	e.t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.hostIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		e.t.Fatalf("HostIssue refused: %s", er.Message)
	}
	return parseIssued(e.t, resp.Cert), resp
}

func parseIssued(t *testing.T, b []byte) *ssh.Certificate {
	t.Helper()
	pub, err := ssh.ParsePublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	return c
}

// serveHostSigner closes e's signer and serves the same state on a socket
// with e's clock, for a peer of this process's uid, until the test ends.
func serveHostSigner(t *testing.T, e *hostEnv) (sock string, db *signerdb.DB) {
	t.Helper()
	e.close()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sdb, err := signerdb.OpenReadOnly(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	s, err := New(Config{Backend: e.backend, Clock: e.clock.Now, DB: db, StatusDB: sdb, AllowUIDs: []uint32{uint32(os.Getuid())}, Logger: slog.New(slog.DiscardHandler)}) //nolint:gosec // G115: a uid fits uint32
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "krhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "s.sock")
	l, err := Listen(sock, -1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return sock, db
}

// sshsigSign is an SSHSIG by s under ns over msg.
func sshsigSign(s ssh.Signer, ns string, msg []byte) ([]byte, error) {
	return sshsig.Sign(rand.Reader, s, ns, msg)
}

func TestHostIssue(t *testing.T) {
	hostIssueCases(t)
	t.Run("issued_entries_verify", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.mustHost(e.hostReq(e.ed, "web1"))
		e.mustHost(e.hostReq(e.ec, "web1"))
		e.mustHost(e.hostReq(e.other, "web3"))
		if rep := e.verifyExport(); rep.Counts[tlog.KindHostIssue] != 3 {
			t.Fatalf("audit verify counts %d host_issue entries, want 3", rep.Counts[tlog.KindHostIssue])
		}
	})
	t.Run("issues_kr3_for_listed_key", func(t *testing.T) {
		e := newHostEnv(t, 90)
		req := e.hostReq(e.ed, "web1")
		sock, db := serveHostSigner(t, e)
		resp, err := signerclient.HostIssue(context.Background(), sock, req)
		if err != nil {
			t.Fatalf("HostIssue over the socket: %v", err)
		}
		c := parseIssued(t, resp.Cert)
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil || !kid.V3 || kid.CA != "host" || kid.Subject != "web1" || kid.Serial != c.Serial || kid.Directory != 1 || kid.Policy != 1 {
			t.Fatalf("key ID %q (%v), want kr3/ca=host/sub=web1/.../pol=1/dir=1/ser=<serial>", c.KeyId, err)
		}
		if !strings.HasPrefix(c.KeyId, "kr3/ca=host/sub=web1/req=") {
			t.Fatalf("key ID %q", c.KeyId)
		}
		if c.CertType != ssh.HostCert || !slices.Equal(c.ValidPrincipals, []string{"web1", "web1.lab"}) ||
			string(c.Key.Marshal()) != string(e.ed.PublicKey().Marshal()) {
			t.Fatalf("certificate type %d, principals %v, key %s", c.CertType, c.ValidPrincipals, ssh.FingerprintSHA256(c.Key))
		}
		if v := c.ValidBefore - c.ValidAfter - 300; v != 90 {
			t.Fatalf("lifetime %d, want the 90 s cap", v)
		}
		if string(c.SignatureKey.Marshal()) != string(e.fx.Roles["host"].PublicKey().Marshal()) {
			t.Fatal("not signed by the host CA")
		}
		var leaves []tlog.Leaf
		if _, _, err := db.ReadLog(context.Background(), func(_ uint64, leaf []byte) error {
			l, err := tlog.DecodeLeaf(leaf)
			if err == nil && l.Kind == tlog.KindHostIssue {
				leaves = append(leaves, l)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(leaves) != 1 {
			t.Fatalf("%d host_issue leaves, want 1", len(leaves))
		}
		b, err := tlog.DecodeHostIssueBody(leaves[0].Body)
		if err != nil || b.Serial != c.Serial || b.CapSeconds != 90 || b.KeyID != c.KeyId || string(b.Request) != string(req.SigningBytes()) {
			t.Fatalf("host_issue body %+v (%v)", b, err)
		}
	})
}

// refusedHost requires req to be refused with detail and wire code code.
func (e *hostEnv) refusedHost(t *testing.T, req *wire.HostIssueRequest, detail string, code wire.ErrorCode) {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.hostIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er == nil {
		t.Fatalf("issued serial %d, want the refusal %s", resp.Serial, detail)
	}
	if er.Message != detail || er.Code != code {
		t.Fatalf("refused %s (%s), want %s (%s)", er.Message, er.Code, detail, code)
	}
}

// leafCount is the number of leaves of kind k.
func (e *hostEnv) leafCount(k tlog.Kind) int {
	e.t.Helper()
	n := 0
	for _, l := range e.leavesOf() {
		if l.Kind == k {
			n++
		}
	}
	return n
}

// liveHosts reads and, with set, replaces the signer's live host index
// (the one helper the index cases go through).
func liveHosts(e *hostEnv, set *hostIndex) hostIndex {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	if set != nil {
		e.s.loaded.hosts = set.clone()
	}
	return e.s.loaded.hosts.clone()
}

// rebuiltHosts is the host index a fresh rebuildLogFrom derives from the
// database.
func rebuiltHosts(t *testing.T, e *hostEnv) hostIndex {
	t.Helper()
	e.s.mu.Lock()
	v := e.s.cpVerifier
	e.s.mu.Unlock()
	_, _, installs, err := rebuildLogFrom(context.Background(), e.db, v)
	if err != nil {
		t.Fatal(err)
	}
	return installs.hosts.clone()
}

// sameIndex compares two host indexes by what HostIssue reads.
func sameIndex(a, b hostIndex) bool {
	if a.curDir != b.curDir || !reflect.DeepEqual(a.bySerial, b.bySerial) || !reflect.DeepEqual(a.byKeyID, b.byKeyID) ||
		!reflect.DeepEqual(a.revokedKeys, b.revokedKeys) || len(a.latest) != len(b.latest) {
		return false
	}
	for k, x := range a.latest {
		y, ok := b.latest[k]
		if !ok || x.serial != y.serial || x.leaf != y.leaf || x.capSeconds != y.capSeconds || x.issuedUnderDir != y.issuedUnderDir ||
			x.reqSHA256 != y.reqSHA256 || x.revoked != y.revoked || x.revokedAtDir != y.revokedAtDir || !bytes.Equal(x.certBytes, y.certBytes) ||
			!slices.Equal(x.principals, y.principals) || x.issued != y.issued {
			return false
		}
	}
	return true
}

// setHostCap installs a successor bundle whose policy sets the host cap to
// capSeconds (and edit, when set), and restarts the signer on it, as an
// operator's install-bundle and restart would.
func (e *hostEnv) setHostCap(t *testing.T, capSeconds uint64, edit func(*trust.Policy)) {
	t.Helper()
	e.close()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev, err := trust.ParseBundle(sb.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := trust.ParsePolicy(sb.Policy)
	if err != nil {
		t.Fatal(err)
	}
	pol.Version, pol.Prev = pol.Version+1, trust.SHA256Hex(sb.Policy)
	for i := range pol.CAProfiles {
		if pol.CAProfiles[i].Role == trust.RoleHost {
			pol.CAProfiles[i].MaxTTLSeconds = capSeconds
		}
	}
	if edit != nil {
		edit(pol)
	}
	d := docs4(t, successor(t, prev, pol), pol, e.fx.Root)
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	if _, err := InstallBundle(context.Background(), db, e.backend, nil, 0, d[0], d[1], d[2], d[3], e.clock.Now); err != nil {
		t.Fatalf("install the successor bundle: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.open(); err != nil {
		t.Fatal(err)
	}
}

// restart closes the signer and opens it again on the same state.
func (e *hostEnv) restart(t *testing.T) {
	t.Helper()
	e.close()
	if err := e.open(); err != nil {
		t.Fatalf("New after the restart: %v", err)
	}
}

// revokeHost revokes req (signed by the fixture's first admin) and
// requires success.
func (e *hostEnv) revokeHost(t *testing.T, req *wire.RevokeRequest) {
	t.Helper()
	req.InstallationID, req.CreatedAt, req.Reason = testInstallationID, uint64(e.clock.Now().Unix()), "test" //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, e.fx.Admins[0], wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	if _, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, req); er != nil {
		t.Fatalf("revoke refused: %s", er.Message)
	}
}

// tickTo sets the clock to t plus half a second (whole seconds decide).
func (e *hostEnv) tickTo(secs uint64) {
	e.clock.set(time.Unix(int64(secs), 500_000_000)) //nolint:gosec // G115: test times
}

// issuedSecs is a certificate's issuance second.
func issuedSecs(c *ssh.Certificate) uint64 { return c.ValidAfter + 300 }

// TestHostIssueBounds is TestHostIssue's refusal, re-delivery, bound,
// hold and index cases (03-09, Task 3); they run as subtests of
// TestHostIssue.
func hostIssueCases(t *testing.T) {
	refused := func(t *testing.T, edit func(e *hostEnv) *wire.HostIssueRequest, detail string, code wire.ErrorCode) {
		t.Helper()
		e := newHostEnv(t, 90)
		e.refusedHost(t, edit(e), detail, code)
	}
	t.Run("malformed_request", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.HostIssueRequest {
			r := e.hostReq(e.ed, "web1")
			r.HostName = "Web1!"
			return r
		}, "malformed_request", wire.CodeMalformed)
	})
	t.Run("request_time_skew", func(t *testing.T) {
		for _, d := range []int64{301, -301} {
			refused(t, func(e *hostEnv) *wire.HostIssueRequest {
				r := e.hostReq(e.ed, "web1")
				r.CreatedAt = uint64(e.clock.Now().Unix() + d) //nolint:gosec // G115: after 1970
				return e.popSign(r, e.ed, wire.HostPoPNamespace)
			}, "request_time_skew", wire.CodeRefused)
		}
	})
	t.Run("host_issue_no_installation_id", func(t *testing.T) {
		e := newHostEnvOpts(t, 90, "", true)
		r := e.hostReq(e.ed, "web1")
		r.InstallationID = testInstallationID
		e.refusedHost(t, e.popSign(r, e.ed, wire.HostPoPNamespace), "host_issue_no_installation_id", wire.CodeRefused)
	})
	t.Run("host_issue_installation_mismatch", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.HostIssueRequest {
			r := e.hostReq(e.ed, "web1")
			r.InstallationID = "fedcba9876543210fedcba9876543210"
			return e.popSign(r, e.ed, wire.HostPoPNamespace)
		}, "host_issue_installation_mismatch", wire.CodeRefused)
	})
	t.Run("host_pop_not_enabled", func(t *testing.T) {
		e := newHostEnvOpts(t, 90, testInstallationID, false)
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "host_pop_not_enabled", wire.CodeRefused)
	})
	t.Run("directory_not_installed", func(t *testing.T) {
		e := newHostEnvBare(t, 90)
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "directory_not_installed", wire.CodeRefused)
	})
	t.Run("directory_not_authorized", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setHostCap(t, 90, func(p *trust.Policy) { p.AdminQuorum = 2 })
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "directory_not_authorized", wire.CodeRefused)
	})
	t.Run("unknown_host", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.HostIssueRequest { return e.hostReq(e.ed, "web9") }, "unknown_host", wire.CodeRefused)
	})
	t.Run("host_key_not_listed", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.HostIssueRequest { return e.hostReq(e.other, "web1") }, "host_key_not_listed", wire.CodeRefused)
	})
	t.Run("host_key_revoked", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.off.PublicKey().Marshal()})
		// web2 is disabled too: the revoked key wins.
		e.refusedHost(t, e.hostReq(e.off, "web2"), "host_key_revoked", wire.CodeRefused)
	})
	t.Run("host_disabled", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.HostIssueRequest { return e.hostReq(e.off, "web2") }, "host_disabled", wire.CodeRefused)
	})
	t.Run("host_pop_invalid", func(t *testing.T) {
		for name, edit := range map[string]func(e *hostEnv, r *wire.HostIssueRequest) *wire.HostIssueRequest{
			"another_listed_key": func(e *hostEnv, r *wire.HostIssueRequest) *wire.HostIssueRequest {
				return e.popSign(r, e.ec, wire.HostPoPNamespace)
			},
			"wrong_namespace": func(e *hostEnv, r *wire.HostIssueRequest) *wire.HostIssueRequest {
				return e.popSign(r, e.ed, wire.ForgetSSHSIGNamespace)
			},
			"other_bytes": func(e *hostEnv, r *wire.HostIssueRequest) *wire.HostIssueRequest {
				sig, err := sshsigSign(e.ed, wire.HostPoPNamespace, []byte("other bytes"))
				if err != nil {
					t.Fatal(err)
				}
				r.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: sig}}
				return r
			},
		} {
			t.Run(name, func(t *testing.T) {
				refused(t, func(e *hostEnv) *wire.HostIssueRequest { return edit(e, e.hostReq(e.ed, "web1")) }, "host_pop_invalid", wire.CodeRefused)
			})
		}
	})
	t.Run("host_issue_valid_for_not_zero", func(t *testing.T) {
		for _, v := range []uint32{1, 90, 91} {
			refused(t, func(e *hostEnv) *wire.HostIssueRequest {
				r := e.hostReq(e.ed, "web1")
				r.ValidForSeconds = v
				return e.popSign(r, e.ed, wire.HostPoPNamespace)
			}, "host_issue_valid_for_not_zero", wire.CodeRefused)
		}
	})
	t.Run("duplicate_request", func(t *testing.T) {
		e := newHostEnv(t, 90)
		adm := e.request()
		if _, err := e.s.Issue(context.Background(), Peer{UID: 1000}, adm); err != nil {
			t.Fatal(err)
		}
		r := e.hostReq(e.ed, "web1")
		r.RequestID = adm.RequestID
		e.refusedHost(t, e.popSign(r, e.ed, wire.HostPoPNamespace), "duplicate_request", wire.CodeRefused)
	})
	t.Run("field_changed_after_signing_refused", func(t *testing.T) {
		for name, change := range map[string]func(e *hostEnv, r *wire.HostIssueRequest){
			"installation_id": func(e *hostEnv, r *wire.HostIssueRequest) {
				r.InstallationID = "fedcba9876543210fedcba9876543210"
				e.popSign(r, e.ed, wire.HostPoPNamespace)
				r.InstallationID = testInstallationID
			},
			"host_name": func(e *hostEnv, r *wire.HostIssueRequest) {
				r.HostName = "nohost"
				e.popSign(r, e.ed, wire.HostPoPNamespace)
				r.HostName = "web1"
			},
			"valid_for":  func(_ *hostEnv, r *wire.HostIssueRequest) { r.ValidForSeconds = 1 },
			"request_id": func(_ *hostEnv, r *wire.HostIssueRequest) { r.RequestID[0] ^= 1 },
			"created_at": func(_ *hostEnv, r *wire.HostIssueRequest) { r.CreatedAt-- },
		} {
			t.Run(name, func(t *testing.T) {
				refused(t, func(e *hostEnv) *wire.HostIssueRequest {
					r := e.hostReq(e.ed, "web1")
					change(e, r)
					return r
				}, "host_pop_invalid", wire.CodeRefused)
			})
		}
	})

	t.Run("exact_retry_redelivers_without_new_leaf", func(t *testing.T) {
		e := newHostEnv(t, 90)
		req := e.hostReq(e.ed, "web1")
		c1, r1 := e.mustHost(req)
		leaves, issued, _ := e.counts()
		c2, r2 := e.mustHost(req)
		if !bytes.Equal(c1.Marshal(), c2.Marshal()) || r1.Serial != r2.Serial {
			t.Fatalf("the retry got serial %d, want the same certificate as serial %d", r2.Serial, r1.Serial)
		}
		if l, i, _ := e.counts(); l != leaves || i != issued {
			t.Fatalf("the retry wrote %d leaves and %d issuances", l-leaves, i-issued)
		}
	})
	t.Run("recent_redelivers_latest", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		before := e.leafCount(tlog.KindHostIssue)
		e.tickTo(issuedSecs(c1) + 10)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if !bytes.Equal(c1.Marshal(), c2.Marshal()) || e.leafCount(tlog.KindHostIssue) != before {
			t.Fatal("a fresh request inside the window was not answered with the latest certificate, or it wrote a leaf")
		}
	})
	t.Run("recent_expired_or_revoked_refused", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 29)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); !bytes.Equal(c1.Marshal(), c2.Marshal()) {
			t.Fatal("at the window's last second the latest certificate is not re-delivered")
		}
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: c1.Serial})
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "cert_revoked", wire.CodeRefused)
	})
	t.Run("short_valid_for_still_bounded", func(t *testing.T) {
		e := newHostEnv(t, 90)
		for _, v := range []uint32{1, 90} {
			r := e.hostReq(e.ed, "web1")
			r.ValidForSeconds = v
			e.refusedHost(t, e.popSign(r, e.ed, wire.HostPoPNamespace), "host_issue_valid_for_not_zero", wire.CodeRefused)
		}
		before := e.leafCount(tlog.KindHostIssue)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 1)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if !bytes.Equal(c1.Marshal(), c2.Marshal()) || e.leafCount(tlog.KindHostIssue) != before+1 {
			t.Fatalf("two requests one second apart: %d new leaves, want one issuance and one re-delivery", e.leafCount(tlog.KindHostIssue)-before)
		}
	})
	t.Run("lifetime_is_cap_in_force", func(t *testing.T) {
		for _, c := range []uint64{90, 2592000} {
			e := newHostEnv(t, c)
			cert, _ := e.mustHost(e.hostReq(e.ed, "web1"))
			b := e.hostIssues()
			if v := cert.ValidBefore - cert.ValidAfter - 300; v != c || len(b) != 1 || b[0].CapSeconds != c {
				t.Fatalf("cap %d: lifetime %d, CapSeconds %v", c, v, b)
			}
		}
	})

	t.Run("recent_window_passes", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 30)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); c2.Serial <= c1.Serial {
			t.Fatal("at issued + cap/3 the request was not issued")
		}
	})
	t.Run("principals_change_bypasses_recent", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.hosts[0].Principals = []string{"web1", "web1.lab", "www"}
		e.publish(t)
		e.tickTo(issuedSecs(c1) + 1)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if c2.Serial <= c1.Serial || !slices.Equal(c2.ValidPrincipals, []string{"web1", "web1.lab", "www"}) {
			t.Fatalf("after a principal change: serial %d principals %v, want a new certificate", c2.Serial, c2.ValidPrincipals)
		}
	})
	t.Run("principals_exception_once_per_version", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.hosts[0].Principals = []string{"web1", "www"}
		e.publish(t)
		e.tickTo(issuedSecs(c1) + 1)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 2)
		before := e.leafCount(tlog.KindHostIssue)
		c3, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if !bytes.Equal(c2.Marshal(), c3.Marshal()) || e.leafCount(tlog.KindHostIssue) != before {
			t.Fatal("a second request under the same directory version was issued, not re-delivered")
		}
	})
	t.Run("rename_entry_still_recent", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.hosts[0].Name = "web1b"
		e.publish(t)
		e.tickTo(issuedSecs(c1) + 1)
		before := e.leafCount(tlog.KindHostIssue)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1b"))
		if !bytes.Equal(c1.Marshal(), c2.Marshal()) || e.leafCount(tlog.KindHostIssue) != before {
			t.Fatal("a rename reset the window")
		}
	})
	t.Run("other_key_not_recent", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 1)
		if c2, _ := e.mustHost(e.hostReq(e.ec, "web1")); c2.Serial <= c1.Serial || !bytes.Equal(c2.Key.Marshal(), e.ec.PublicKey().Marshal()) {
			t.Fatal("the second key inside the first key's window was not issued")
		}
	})
	t.Run("raised_cap_does_not_extend_window", func(t *testing.T) {
		e := newHostEnv(t, 86400)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.setHostCap(t, 2592000, nil)
		e.tickTo(issuedSecs(c1) + 16*3600)
		before := e.leafCount(tlog.KindHostIssue)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if c2.Serial <= c1.Serial || e.leafCount(tlog.KindHostIssue) != before+1 || c2.ValidBefore-c2.ValidAfter-300 != 2592000 {
			t.Fatalf("at 16 h after a raise: serial %d (was %d), %d new leaves, lifetime %d", c2.Serial, c1.Serial, e.leafCount(tlog.KindHostIssue)-before, c2.ValidBefore-c2.ValidAfter-300)
		}
	})
	t.Run("stale_agent_cap_not_stranded", func(t *testing.T) {
		e := newHostEnv(t, 86400)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.setHostCap(t, 2592000, nil)
		e.tickTo(issuedSecs(c1) + 16*3600)
		c2, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if c2.Serial <= c1.Serial || c2.ValidBefore-c2.ValidAfter-300 != 2592000 {
			t.Fatal("the renewal after a raise was not issued at 30 days")
		}
		e.setHostCap(t, 86400, nil)
		e.tickTo(issuedSecs(c2) + 20*86400)
		c3, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if c3.Serial <= c2.Serial || c3.ValidBefore-c3.ValidAfter-300 != 86400 {
			t.Fatal("the renewal after a lowering was not issued at 1 day")
		}
	})

	t.Run("revoke_serial_of_host_cert", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: c1.Serial})
		if !e.parsedKRL(t).RevokesSerial(c1.SignatureKey.Marshal(), c1.Serial) {
			t.Fatal("the published KRL does not revoke the host certificate's serial")
		}
	})
	t.Run("cert_revoked_until_new_directory", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: c1.Serial})
		e.tickTo(issuedSecs(c1) + 3600)
		e.refusedHost(t, e.hostReq(e.ed, "web1"), "cert_revoked", wire.CodeRefused)
		e.publish(t)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); c2.Serial <= c1.Serial {
			t.Fatal("after a new directory version the key was not issued")
		}
	})

	t.Run("many_user_rows_still_decided", func(t *testing.T) {
		e := newHostEnv(t, 90)
		if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
			for i := range 10000 {
				var id [16]byte
				id[0], id[1], id[2] = 0xee, byte(i>>8), byte(i)
				if err := e.db.InsertIssuance(tx, signerdb.Issuance{Serial: uint64(i + 1), RequestID: id, CARole: "user", //nolint:gosec // G115: small
					KeyID: "seed", Cert: []byte("seed"), IssuedAt: e.clock.Now()}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.tickTo(issuedSecs(c1) + 1)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); !bytes.Equal(c1.Marshal(), c2.Marshal()) {
			t.Fatal("with 10,000 user rows the recent request was not re-delivered")
		}
	})
	t.Run("principals_from_entry_only", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.hosts[0].Principals = []string{"a.example", "b.example"}
		e.publish(t)
		c, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if !slices.Equal(c.ValidPrincipals, []string{"a.example", "b.example"}) {
			t.Fatalf("principals %v, want exactly the entry's", c.ValidPrincipals)
		}
	})
	t.Run("nothing_released_before_commit", func(t *testing.T) {
		e := newHostEnv(t, 90)
		leaves, issued, last := e.counts()
		index := liveHosts(e, nil)
		e.s.mu.Lock()
		orig := e.s.cpSigner
		e.s.cpSigner = failingSigner{orig}
		e.s.mu.Unlock()
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		resp, er := e.s.hostIssueOrRefuse(context.Background(), Peer{UID: 1000}, e.hostReq(e.ed, "web1"))
		e.s.mu.Lock()
		e.s.cpSigner = orig
		e.s.mu.Unlock()
		if resp != nil || er == nil {
			t.Fatal("a certificate was answered although the checkpoint was not signed")
		}
		if l, i, s := e.counts(); l != leaves || i != issued || s != last || !sameIndex(index, liveHosts(e, nil)) {
			t.Fatal("the failed issuance left a leaf, a row, a serial or an index change")
		}
	})
	t.Run("index_matches_rebuild", func(t *testing.T) {
		e := newHostEnv(t, 90)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.mustHost(e.hostReq(e.ec, "web1"))
		e.hosts[0].Principals = []string{"web1", "www"}
		e.publish(t)
		e.tickTo(issuedSecs(c1) + 1)
		c3, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: c3.Serial})
		e.publish(t)
		e.mustHost(e.hostReq(e.other, "web3"))
		e.tickTo(issuedSecs(c1) + 2)
		e.mustHost(e.hostReq(e.other, "web3"))
		if !sameIndex(liveHosts(e, nil), rebuiltHosts(t, e)) {
			t.Fatal("the live host index differs from a fresh rebuild")
		}
	})
	t.Run("index_matches_rebuild_after_failed_commit", func(t *testing.T) {
		e := newHostEnv(t, 90)
		earlier := liveHosts(e, nil)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		// A COMMIT that reached the disk but reported an error: the live
		// index is the one before it.
		liveHosts(e, &earlier)
		body, err := (&tlog.RefusalBody{PeerUID: 1000, Reason: tlog.ReasonMalformed, Detail: "test"}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected failure after the append")
		ctx := context.Background()
		e.s.mu.Lock()
		err = e.s.logTx(ctx, func(tx *sql.Tx) error {
			if _, err := e.s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(e.clock.Now()), Kind: tlog.KindRefusal, Body: body}); err != nil {
				return err
			}
			return injected
		})
		e.s.mu.Unlock()
		if !errors.Is(err, injected) {
			t.Fatalf("logTx: %v", err)
		}
		if !sameIndex(liveHosts(e, nil), rebuiltHosts(t, e)) {
			t.Fatal("after the failed transaction the live index differs from a fresh rebuild")
		}
		e.tickTo(issuedSecs(c1) + 1)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); !bytes.Equal(c1.Marshal(), c2.Marshal()) {
			t.Fatal("after the reload the request inside the window was issued, not re-delivered")
		}
	})
}

// TestHostIssueRestart: the start-up log check counts host_issue leaves
// and rebuilds the host index (T-02-116, T-03-63).
func TestHostIssueRestart(t *testing.T) {
	e := newHostEnv(t, 90)
	c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
	c2, _ := e.mustHost(e.hostReq(e.other, "web3"))
	e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: c2.Serial})
	e.restart(t)
	e.tickTo(issuedSecs(c1) + 1)
	if c, _ := e.mustHost(e.hostReq(e.ed, "web1")); !bytes.Equal(c.Marshal(), c1.Marshal()) {
		t.Fatal("after the restart a request inside the window was issued: the index was not rebuilt")
	}
	e.refusedHost(t, e.hostReq(e.other, "web3"), "cert_revoked", wire.CodeRefused)

	t.Run("raised_cap_survives_restart", func(t *testing.T) {
		e := newHostEnv(t, 86400)
		c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		e.setHostCap(t, 2592000, nil) // restarts the signer
		e.tickTo(issuedSecs(c1) + 16*3600)
		before := e.leafCount(tlog.KindHostIssue)
		if c2, _ := e.mustHost(e.hostReq(e.ed, "web1")); c2.Serial <= c1.Serial || e.leafCount(tlog.KindHostIssue) != before+1 {
			t.Fatal("after a raise and a restart the request at 16 h was not issued")
		}
	})
	t.Run("restored_lost_revoked_cert_holds", func(t *testing.T) {
		for _, variant := range []string{"revoke_flag", "krl_entry"} {
			t.Run(variant, func(t *testing.T) {
				e := newHostEnv(t, 90)
				c1, _ := e.mustHost(e.hostReq(e.ed, "web1"))
				var imp []wire.RecoveryImport
				snapshot := e.snapshotDB(t)
				e.tickTo(issuedSecs(c1) + 30)
				lost, _ := e.mustHost(e.hostReq(e.ed, "web1"))
				if lost.Serial <= c1.Serial {
					t.Fatal("the lost certificate was not issued")
				}
				revoke := variant == "revoke_flag"
				if !revoke {
					e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: lost.Serial})
					imp = []wire.RecoveryImport{e.served(t)}
				}
				r := &hostEnv{revokeEnv: e.restored(t, snapshot), ed: e.ed, ec: e.ec, off: e.off, other: e.other, hosts: e.hosts, docs: e.docs}
				// The recovery's KRL version must lie above the imported one.
				r.tick(2 * time.Second)
				r.recover(t, r.recoveryRequest(t, imp, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: revoke}}, nil))
				r.tickTo(issuedSecs(lost) + 31)
				r.refusedHost(t, r.hostReq(r.ed, "web1"), "cert_revoked", wire.CodeRefused)
				r.restart(t)
				r.refusedHost(t, r.hostReq(r.ed, "web1"), "cert_revoked", wire.CodeRefused)
				r.publish(t)
				if c, _ := r.mustHost(r.hostReq(r.ed, "web1")); c.Serial <= lost.Serial {
					t.Fatal("after a newer directory version the key was not issued")
				}
			})
		}
	})
}

// TestHostIssueRefusalClasses: every new detail has its class, and none is
// internal (03-09).
func TestHostIssueRefusalClasses(t *testing.T) {
	for d, want := range map[string]uint8{
		"host_issue_no_installation_id": tlog.ReasonUnauthorized, "host_issue_installation_mismatch": tlog.ReasonUnauthorized,
		"host_pop_not_enabled": tlog.ReasonUnauthorized, "unknown_host": tlog.ReasonUnauthorized, "host_key_not_listed": tlog.ReasonUnauthorized,
		"host_disabled": tlog.ReasonUnauthorized, "host_pop_invalid": tlog.ReasonUnauthorized, "host_key_revoked": tlog.ReasonUnauthorized,
		"cert_revoked": tlog.ReasonUnauthorized, "host_issue_valid_for_not_zero": tlog.ReasonTTLExceeded, "host_cert_recent": tlog.ReasonDuplicateRequest,
	} {
		if got := classify(d); got != want || codeFor(got) != wire.CodeRefused || got == tlog.ReasonInternal {
			t.Errorf("classify(%q) = %d (%s), want %d and a refusal", d, got, codeFor(got), want)
		}
	}
}

// TestHostRefusalBucket: host refusals log on their own bucket (03-09), as
// directory installs do (TestDirectoryRefusalBudget's leaf-count method).
func TestHostRefusalBucket(t *testing.T) {
	t.Run("shared_bucket_drained", func(t *testing.T) {
		e := newHostEnv(t, 90)
		for range 1000 {
			before := e.leafCount(tlog.KindRefusal)
			_ = e.s.refuse(context.Background(), Peer{UID: 1000}, [32]byte{}, tlog.ReasonMalformed, "malformed_frame")
			if e.leafCount(tlog.KindRefusal) == before {
				break
			}
		}
		before := e.leafCount(tlog.KindRefusal)
		e.refusedHost(t, e.hostReq(e.ed, "web9"), "unknown_host", wire.CodeRefused)
		if e.leafCount(tlog.KindRefusal) != before+1 {
			t.Fatal("with the shared bucket drained a host refusal was not logged")
		}
	})
	t.Run("host_burst_leaves_shared_bucket", func(t *testing.T) {
		e := newHostEnv(t, 90)
		for range 1000 {
			before := e.leafCount(tlog.KindRefusal)
			e.refusedHost(t, e.hostReq(e.ed, "web9"), "unknown_host", wire.CodeRefused)
			if e.leafCount(tlog.KindRefusal) == before {
				break
			}
		}
		before := e.leafCount(tlog.KindRefusal)
		_ = e.s.refuse(context.Background(), Peer{UID: 1000}, [32]byte{}, tlog.ReasonMalformed, "malformed_frame")
		if e.leafCount(tlog.KindRefusal) != before+1 {
			t.Fatal("host refusals beyond their burst drained the shared bucket")
		}
	})
}
