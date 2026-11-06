package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
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
	fx := NewFixture(t, 3, 2)
	fx.InstallationID = testInstallationID
	fx.PolicyEdit = func(p *trust.Policy) {
		p.PoP = &trust.PoPPolicy{Hosts: true}
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
	e.publish(t)
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
		Version: uint64(len(e.docs) + 1), Prev: prev, InstallationID: testInstallationID,
		Roles:      []directory.Role{{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600}},
		HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
		Hosts:      hosts,
	}
	d.Sort()
	doc, sigs := signDirectory(t, d, e.fx.Admins[0], e.fx.Admins[1])
	e.installDirectory(t, doc, sigs)
	e.docs = append(e.docs, doc)
}

// hostReq is a host request by key for name, valid_for 0, created now on
// the env's clock, signed by key under the host namespace.
func (e *hostEnv) hostReq(key ssh.Signer, name string) *wire.HostIssueRequest {
	e.t.Helper()
	req := &wire.HostIssueRequest{InstallationID: testInstallationID, HostName: name, HostKey: key.PublicKey().Marshal(),
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

func TestHostIssue(t *testing.T) {
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
