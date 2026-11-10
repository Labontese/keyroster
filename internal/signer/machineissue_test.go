//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// machineEnv is a hostEnv for machine certificates (03-11): a successor
// policy with pop.hosts and pop.machines (unless the constructor says
// otherwise) and a machine cap of 24 h, and a directory with the
// machine-only roles deploy (app, deploy; 7200 s; permit-pty) and build
// (build, deploy; 5400 s) and the machines ci (k1, both roles, 3600 s,
// active) and ci2 (k2, deploy, 3600 s, disabled).
type machineEnv struct {
	*hostEnv
	k1, k2   ssh.Signer
	roles    []directory.Role
	machines []directory.Machine
}

func newMachineEnv(t *testing.T) *machineEnv {
	t.Helper()
	return newMachineEnvWith(t, testInstallationID, true, true, nil)
}

// newMachineEnvWith builds a machineEnv with the bundle's installation ID
// (""), pop.machines and a published directory as given; edit changes the
// successor policy.
func newMachineEnvWith(t *testing.T, install string, popMachines, withDir bool, edit func(*trust.Policy)) *machineEnv {
	t.Helper()
	var he *hostEnv
	if withDir {
		he = newHostEnvOpts(t, 3600, install, true)
	} else {
		he = newHostEnvWith(t, 3600, install, true, false)
	}
	he.setMachineCap(t, 24*3600, func(p *trust.Policy) {
		p.PoP = &trust.PoPPolicy{Hosts: true, Machines: popMachines}
		if edit != nil {
			edit(p)
		}
	})
	e := &machineEnv{hostEnv: he, k1: newEd25519(t), k2: newEd25519(t)}
	e.roles = []directory.Role{
		{Name: "deploy", Principals: []string{"app", "deploy"}, MaxTTLSeconds: 7200, Extensions: []string{"permit-pty"}},
		{Name: "build", Principals: []string{"build", "deploy"}, MaxTTLSeconds: 5400},
	}
	e.machines = []directory.Machine{
		{Name: "ci", Key: trust.FormatKey(e.k1.PublicKey()), Roles: []string{"build", "deploy"}, MaxTTLSeconds: 3600, Status: directory.StatusActive},
		{Name: "ci2", Key: trust.FormatKey(e.k2.PublicKey()), Roles: []string{"deploy"}, MaxTTLSeconds: 3600, Status: directory.StatusDisabled},
	}
	if withDir {
		e.publishMachines(t)
	}
	return e
}

// machineDirectory is the next directory version with e's hosts, roles and
// machines, edited by edit (nil: none), signed.
func (e *machineEnv) machineDirectory(t *testing.T, edit func(*directory.Directory)) (doc, sigs []byte) {
	t.Helper()
	return e.nextDirectory(t, func(d *directory.Directory) {
		for _, r := range e.roles {
			r.Principals, r.Extensions = slices.Clone(r.Principals), slices.Clone(r.Extensions)
			d.Roles = append(d.Roles, r)
		}
		for _, m := range e.machines {
			m.Roles = slices.Clone(m.Roles)
			d.Machines = append(d.Machines, m)
		}
		if edit != nil {
			edit(d)
		}
	})
}

// publishMachines installs the next directory version with e's machines.
func (e *machineEnv) publishMachines(t *testing.T) {
	t.Helper()
	doc, sigs := e.machineDirectory(t, nil)
	e.installDirectory(t, doc, sigs)
	e.docs = append(e.docs, doc)
}

// machineReq is a request by key for name, valid_for 0, a fresh request ID,
// created now on the env's clock, signed by key under the machine
// namespace.
func (e *machineEnv) machineReq(key ssh.Signer, name string) *wire.MachineIssueRequest {
	e.t.Helper()
	install := e.fx.InstallationID
	if install == "" {
		install = testInstallationID
	}
	req := &wire.MachineIssueRequest{InstallationID: install, MachineName: name, MachineKey: key.PublicKey().Marshal(),
		CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	return e.machineSign(req, key, wire.MachinePoPNamespace)
}

// machineSign replaces req's evidence with a machine-pop/v1 SSHSIG by key
// under ns over its signing bytes.
func (e *machineEnv) machineSign(req *wire.MachineIssueRequest, key ssh.Signer, ns string) *wire.MachineIssueRequest {
	e.t.Helper()
	sig, err := sshsig.Sign(rand.Reader, key, ns, req.SigningBytes())
	if err != nil {
		e.t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: sig}}
	return req
}

// badPoP replaces req's evidence with a signature by key over other bytes.
func (e *machineEnv) badPoP(req *wire.MachineIssueRequest, key ssh.Signer) *wire.MachineIssueRequest {
	e.t.Helper()
	sig, err := sshsig.Sign(rand.Reader, key, wire.MachinePoPNamespace, []byte("other bytes"))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: sig}}
	return req
}

// mustMachine issues req through the dispatch path and requires success.
func (e *machineEnv) mustMachine(t *testing.T, req *wire.MachineIssueRequest) (*ssh.Certificate, *wire.IssueResponse) {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.machineIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		t.Fatalf("MachineIssue refused: %s", er.Message)
	}
	return parseIssued(t, resp.Cert), resp
}

// refusedMachine requires req to be refused with detail and wire code
// code, with no machine_issue leaf and no serial drawn.
func (e *machineEnv) refusedMachine(t *testing.T, req *wire.MachineIssueRequest, detail string, code wire.ErrorCode) {
	t.Helper()
	before := e.leafCount(tlog.KindMachineIssue)
	_, _, serialBefore := e.counts()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.machineIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er == nil {
		t.Fatalf("issued serial %d, want the refusal %s", resp.Serial, detail)
	}
	if er.Message != detail || er.Code != code {
		t.Fatalf("refused %s (%s), want %s (%s)", er.Message, er.Code, detail, code)
	}
	if _, _, s := e.counts(); s != serialBefore || e.leafCount(tlog.KindMachineIssue) != before {
		t.Fatalf("the refusal %s drew a serial or wrote a machine_issue leaf", detail)
	}
}

// machineLeaves are the machine_issue leaves of the log.
func (e *machineEnv) machineLeaves(t *testing.T) []*tlog.MachineIssueBody {
	t.Helper()
	var out []*tlog.MachineIssueBody
	for _, l := range e.leavesOf() {
		if l.Kind != tlog.KindMachineIssue {
			continue
		}
		b, err := tlog.DecodeMachineIssueBody(l.Body)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// revokeKey revokes key explicitly (a TargetKey revoke by the first
// admin).
func (e *machineEnv) revokeKey(t *testing.T, key ssh.PublicKey) {
	t.Helper()
	e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: key.Marshal()})
}

// liveMachines is a clone of the signer's live machine index.
func liveMachines(e *machineEnv) machineIndex {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	return e.s.loaded.machines.clone()
}

// rebuiltMachines is the machine index a fresh rebuildLogFrom derives.
func rebuiltMachines(t *testing.T, e *machineEnv) machineIndex {
	t.Helper()
	e.s.mu.Lock()
	v := e.s.cpVerifier
	e.s.mu.Unlock()
	_, _, installs, err := rebuildLogFrom(context.Background(), e.db, v)
	if err != nil {
		t.Fatal(err)
	}
	return installs.machines.clone()
}

// sameMachineIndex compares two machine indexes by what MachineIssue
// reads.
func sameMachineIndex(a, b machineIndex) bool {
	if a.curDir != b.curDir || !reflect.DeepEqual(a.bySerial, b.bySerial) || !reflect.DeepEqual(a.byKeyID, b.byKeyID) ||
		!reflect.DeepEqual(a.recent, b.recent) || len(a.latest) != len(b.latest) {
		return false
	}
	for k, x := range a.latest {
		y, ok := b.latest[k]
		if !ok || x.serial != y.serial || x.leaf != y.leaf || x.capSeconds != y.capSeconds || x.issuedUnderDir != y.issuedUnderDir ||
			!bytes.Equal(x.certBytes, y.certBytes) ||
			!slices.Equal(x.principals, y.principals) || x.issued != y.issued {
			return false
		}
	}
	return true
}

// serveMachineSigner closes e's signer and serves the same state on a
// socket with e's clock, for a peer of this process's uid. stop ends the
// server and closes its handles, so e can open the state again.
func serveMachineSigner(t *testing.T, e *machineEnv) (sock string, stop func()) {
	t.Helper()
	e.close()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sdb, err := signerdb.OpenReadOnly(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Backend: e.backend, Clock: e.clock.Now, DB: db, StatusDB: sdb, AllowUIDs: []uint32{uint32(os.Getuid())}, Logger: slog.New(slog.DiscardHandler)}) //nolint:gosec // G115: a uid fits uint32
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "krmach")
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
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			<-served
			_ = sdb.Close()
			_ = db.Close()
		})
	}
	t.Cleanup(stop)
	return sock, stop
}

func (e *machineEnv) machineCAKey() []byte {
	return e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()
}

// TestMachineIssue: the signer issues a machine certificate by proof of
// possession of the listed key (03-11, AUTH-06, D-15), identity first
// (T-03-397), logged before the answer, re-verified by audit.
func TestMachineIssue(t *testing.T) {
	ctx := context.Background()
	// ready is shared by the refusal subtests that change no state but
	// refusal leaves; each one builds its own request, so it passes alone.
	var ready *machineEnv
	readyEnv := func() *machineEnv {
		if ready == nil {
			ready = newMachineEnv(t)
		}
		return ready
	}
	t.Run("tracer_issue_logged_restart_audit", func(t *testing.T) {
		e := newMachineEnv(t)
		req := e.machineReq(e.k1, "ci")
		sock, stop := serveMachineSigner(t, e)
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		resp, err := signerclient.MachineIssue(ctx, sock, req)
		if err != nil {
			t.Fatalf("MachineIssue over the socket: %v", err)
		}
		stop()
		if err := e.open(); err != nil {
			t.Fatal(err)
		}
		c := parseIssued(t, resp.Cert)
		checker := ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), e.machineCAKey()) }}
		if err := checker.CheckCert("app", c); err != nil {
			t.Fatalf("the certificate does not verify against the machine CA: %v", err)
		}
		leaves := e.machineLeaves(t)
		if len(leaves) != 1 || leaves[0].CapSeconds != c.ValidBefore-c.ValidAfter-300 || !bytes.Equal(leaves[0].Request, req.SigningBytes()) ||
			leaves[0].Serial != resp.Serial || !bytes.Equal(leaves[0].Cert, resp.Cert) {
			t.Fatalf("machine_issue leaves %+v", leaves)
		}
		if _, issued, _ := e.counts(); issued != 1 {
			t.Fatalf("%d issuance rows, want 1", issued)
		}
		e.restart(t)
		e.clock.set(e.clock.Now().Add(time.Minute))
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if rep := e.verifyExport(); rep.Counts[tlog.KindMachineIssue] != 2 {
			t.Fatalf("audit counts %d machine_issue entries, want 2", rep.Counts[tlog.KindMachineIssue])
		}
	})
	t.Run("certificate_exact", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		c, resp := e.mustMachine(t, req)
		e.s.mu.Lock()
		pol, dir := e.s.policy.Version, e.s.directoryVersion
		e.s.mu.Unlock()
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil || !kid.V3 || kid.CA != "machine" || kid.Subject != "ci" || kid.Request != hexID(req.RequestID) ||
			kid.Policy != pol || kid.Directory != dir || kid.Serial != c.Serial || c.Serial != resp.Serial {
			t.Fatalf("key ID %q (%v)", c.KeyId, err)
		}
		if c.CertType != ssh.UserCert || !bytes.Equal(c.SignatureKey.Marshal(), e.machineCAKey()) || !bytes.Equal(c.Key.Marshal(), e.k1.PublicKey().Marshal()) {
			t.Fatalf("type %d, CA %s, key %s", c.CertType, ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(c.Key))
		}
		if !slices.Equal(c.ValidPrincipals, []string{"app", "build", "deploy"}) || !maps.Equal(c.Extensions, map[string]string{"permit-pty": ""}) ||
			len(c.CriticalOptions) != 0 {
			t.Fatalf("principals %v, extensions %v, options %v", c.ValidPrincipals, c.Extensions, c.CriticalOptions)
		}
		if c.ValidAfter+300 != resp.Serial/1_000_000 || c.ValidBefore-c.ValidAfter-300 != 3600 {
			t.Fatalf("valid %d..%d for serial %d", c.ValidAfter, c.ValidBefore, resp.Serial)
		}
		leaves := e.leavesOf()
		if last := leaves[len(leaves)-1]; last.Kind != tlog.KindMachineIssue || last.Index != resp.LeafIndex {
			t.Fatalf("the answer names leaf %d, the last leaf is %d (%s)", resp.LeafIndex, last.Index, last.Kind)
		}
	})
	t.Run("principals_sorted_union", func(t *testing.T) {
		e := readyEnv()
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if !slices.Equal(c.ValidPrincipals, []string{"app", "build", "deploy"}) {
			t.Fatalf("principals %v, want the sorted union of deploy's and build's", c.ValidPrincipals)
		}
	})
	t.Run("role_extension_default_not_duplicated", func(t *testing.T) {
		e := readyEnv()
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if !maps.Equal(c.Extensions, map[string]string{"permit-pty": ""}) {
			t.Fatalf("extensions %v", c.Extensions)
		}
	})
	t.Run("role_extension_granted", func(t *testing.T) {
		e := newMachineEnvWith(t, testInstallationID, true, true, func(p *trust.Policy) {
			for i := range p.CAProfiles {
				if p.CAProfiles[i].Role == trust.RoleMachine {
					p.CAProfiles[i].AllowedExtensions = []string{"permit-port-forwarding"}
				}
			}
		})
		e.roles[1].Extensions = []string{"permit-port-forwarding"}
		e.publishMachines(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if !maps.Equal(c.Extensions, map[string]string{"permit-pty": "", "permit-port-forwarding": ""}) {
			t.Fatalf("extensions %v", c.Extensions)
		}
	})
	t.Run("lifetime_is_min_of_entry_and_roles", func(t *testing.T) {
		life := func(c *ssh.Certificate) uint64 { return c.ValidBefore - c.ValidAfter - 300 }
		e := newMachineEnv(t)
		if c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci")); life(c) != 3600 {
			t.Fatalf("entry smallest: lifetime %d, want 3600", life(c))
		}
		e.machines[0].MaxTTLSeconds = 9000
		e.publishMachines(t)
		if c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci")); life(c) != 5400 {
			t.Fatalf("role smallest: lifetime %d, want build's 5400", life(c))
		}
		e.setMachineCap(t, 4000, func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true, Machines: true} })
		e.machines[0].MaxTTLSeconds, e.roles[0].MaxTTLSeconds, e.roles[1].MaxTTLSeconds = 4000, 4000, 4000
		e.publishMachines(t)
		if c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci")); life(c) != 4000 {
			t.Fatalf("cap equal: lifetime %d, want 4000", life(c))
		}
		e.verifyExport()
	})
	t.Run("unknown_machine", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineReq(e.k1, "nope"), "unknown_machine", wire.CodeRefused)
	})
	t.Run("pop_by_request_key_not_listed_key_is_key_mismatch", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineReq(newEd25519(t), "ci"), "machine_key_mismatch", wire.CodeRefused)
	})
	t.Run("key_mismatch_other_listed_machine_key", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineReq(e.k2, "ci"), "machine_key_mismatch", wire.CodeRefused)
	})
	t.Run("pop_invalid_wrong_signature", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("pop_wrong_namespace_host_pop", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineSign(e.machineReq(e.k1, "ci"), e.k1, wire.HostPoPNamespace), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("pop_wrong_namespace_probe_pop", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineSign(e.machineReq(e.k1, "ci"), e.k1, wire.ProbePoPNamespace), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("pop_signature_by_other_key_than_listed", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineSign(e.machineReq(e.k1, "ci"), newEd25519(t), wire.MachinePoPNamespace), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("disabled_entry_refused", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.machineReq(e.k2, "ci2"), "machine_disabled", wire.CodeRefused)
	})
	t.Run("disabled_entry_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := readyEnv()
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k2, "ci2"), e.k2), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("key_revoked_before_disabled", func(t *testing.T) {
		e := newMachineEnv(t)
		e.revokeKey(t, e.k2.PublicKey())
		e.refusedMachine(t, e.machineReq(e.k2, "ci2"), "machine_key_revoked", wire.CodeRefused)
	})
	t.Run("revoked_key_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := newMachineEnv(t)
		e.revokeKey(t, e.k1.PublicKey())
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("valid_for_nonzero_refused", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		req.ValidForSeconds = 600
		e.refusedMachine(t, e.machineSign(req, e.k1, wire.MachinePoPNamespace), "machine_issue_valid_for_not_zero", wire.CodeRefused)
	})
	t.Run("installation_mismatch", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		req.InstallationID = "fedcba9876543210fedcba9876543210"
		e.refusedMachine(t, e.machineSign(req, e.k1, wire.MachinePoPNamespace), "machine_issue_installation_mismatch", wire.CodeRefused)
	})
	t.Run("installation_missing", func(t *testing.T) {
		e := newMachineEnvWith(t, "", true, true, nil)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_issue_no_installation_id", wire.CodeRefused)
	})
	t.Run("pop_not_enabled", func(t *testing.T) {
		e := newMachineEnvWith(t, testInstallationID, false, true, nil)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_pop_not_enabled", wire.CodeRefused)
	})
	t.Run("directory_not_installed", func(t *testing.T) {
		e := newMachineEnvWith(t, testInstallationID, true, false, nil)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "directory_not_installed", wire.CodeRefused)
	})
	t.Run("request_time_skew", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		req.CreatedAt -= 301
		e.refusedMachine(t, e.machineSign(req, e.k1, wire.MachinePoPNamespace), "request_time_skew", wire.CodeRefused)
	})
	t.Run("malformed_request", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		req.Evidence = nil
		e.refusedMachine(t, req, "malformed_request", wire.CodeMalformed)
	})
	t.Run("probe_prefixed_name_refused_at_issuance", func(t *testing.T) {
		e := newMachineEnv(t)
		k3 := newEd25519(t)
		doc, sigs := e.machineDirectory(t, func(d *directory.Directory) {
			d.Machines = append(d.Machines, directory.Machine{Name: "probe.x", Key: trust.FormatKey(k3.PublicKey()), Roles: []string{"deploy"},
				MaxTTLSeconds: 3600, Status: directory.StatusActive})
		})
		e.seedDirectory(t, doc, sigs)
		e.docs = append(e.docs, doc)
		e.restart(t)
		e.refusedMachine(t, e.machineReq(k3, "probe.x"), "machine_name_reserved", wire.CodeRefused)
		e.refusedMachine(t, e.machineReq(newEd25519(t), "probe.x"), "machine_name_reserved", wire.CodeRefused)
	})
	t.Run("request_id_reuse_refused", func(t *testing.T) {
		e := readyEnv()
		req := e.machineReq(e.k1, "ci")
		e.mustMachine(t, req)
		again := e.machineReq(e.k1, "ci")
		again.RequestID = req.RequestID
		e.refusedMachine(t, e.machineSign(again, e.k1, wire.MachinePoPNamespace), "duplicate_request", wire.CodeRefused)
	})
	t.Run("nothing_released_before_commit", func(t *testing.T) {
		e := readyEnv()
		leaves, issued, last := e.counts()
		before := liveMachines(e)
		e.s.mu.Lock()
		orig := e.s.cpSigner
		e.s.cpSigner = failingSigner{orig}
		e.s.mu.Unlock()
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		resp, err := e.s.MachineIssue(ctx, Peer{UID: 1000}, e.machineReq(e.k1, "ci"))
		e.s.mu.Lock()
		e.s.cpSigner = orig
		e.s.mu.Unlock()
		if resp != nil || err == nil {
			t.Fatalf("MachineIssue with a failing append: %+v, %v; want no certificate", resp, err)
		}
		if l, i, s := e.counts(); l != leaves || i != issued || s != last {
			t.Fatalf("after the failed append: %d leaves, %d rows, serial %d; want %d, %d, %d", l, i, s, leaves, issued, last)
		}
		if !sameMachineIndex(liveMachines(e), before) {
			t.Fatal("the machine index changed although nothing committed")
		}
	})
	t.Run("directory_changed_before_commit", func(t *testing.T) {
		e := newMachineEnv(t)
		e.close()
		be := newSignHookBackend(e.backend)
		fp := ssh.FingerprintSHA256(e.fx.Roles[keystore.RoleMachine].PublicKey())
		db, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{Backend: be, DB: db, Clock: e.clock.Now, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
		e.db, e.s = db, s
		other, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		next := uint64(len(e.docs) + 1)
		var once sync.Once
		be.hooks[fp] = func() {
			once.Do(func() {
				if err := other.WithTx(ctx, func(tx *sql.Tx) error {
					_, err := tx.Exec(`INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (?, 'x', 'x', 1, 1)`, next)
					return err
				}); err != nil {
					t.Error(err)
				}
			})
		}
		leaves, issued, last := e.counts()
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		resp, er := s.machineIssueOrRefuse(ctx, Peer{UID: 1000}, e.machineReq(e.k1, "ci"))
		if resp != nil || er == nil || er.Message != "directory_changed" {
			t.Fatalf("machine request with a directory written before commit: %+v, %+v; want directory_changed", resp, er)
		}
		if n := be.count(fp); n != 1 {
			t.Fatalf("machine CA signed %d times, want 1", n)
		}
		n, i, sr := e.counts()
		if i != issued || sr != last || n != leaves+1 || e.leafCount(tlog.KindMachineIssue) != 0 {
			t.Fatalf("after the refusal: %d leaves, %d rows, serial %d; want %d, %d, %d", n, i, sr, leaves+1, issued, last)
		}
	})
}

// skEd25519Signer is a test-local copy of internal/sshsig's software
// stand-in for a FIDO key holding an sk-ssh-ed25519@openssh.com key with
// application "ssh:" (the helper cannot be imported): Ed25519 over
// SHA-256(application) || flags || counter || SHA-256(data).
type skEd25519Signer struct {
	priv  ed25519.PrivateKey
	pub   ssh.PublicKey
	flags byte
}

func newSKEd25519Signer(t testing.TB, flags byte) *skEd25519Signer {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Name string
		Key  []byte
		App  string
	}{ssh.KeyAlgoSKED25519, pubKey, "ssh:"})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return &skEd25519Signer{priv: priv, pub: pub, flags: flags}
}

func (s *skEd25519Signer) PublicKey() ssh.PublicKey { return s.pub }

func (s *skEd25519Signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	app := sha256.Sum256([]byte("ssh:"))
	msg := sha256.Sum256(data)
	var rest [5]byte
	rest[0] = s.flags
	binary.BigEndian.PutUint32(rest[1:], 7)
	signed := append(append(append([]byte{}, app[:]...), rest[:]...), msg[:]...)
	return &ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(s.priv, signed), Rest: rest[:]}, nil
}

// skSSHSIG assembles an armored SSHSIG by s under namespace over msg
// (sha512), as internal/sshsig's customBlob does: sshsig.Sign refuses a
// signer whose user-presence flag is clear, so the test builds the blob
// itself.
func skSSHSIG(t *testing.T, s ssh.Signer, namespace string, msg []byte) []byte {
	t.Helper()
	h := sshsig.DigestOf(msg)
	var data cryptobyte.Builder
	data.AddBytes([]byte("SSHSIG"))
	for _, f := range [][]byte{[]byte(namespace), nil, []byte("sha512"), h[:]} {
		data.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	sig, err := s.Sign(rand.Reader, data.BytesOrPanic())
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte("SSHSIG"))
	b.AddUint32(1)
	for _, f := range [][]byte{s.PublicKey().Marshal(), []byte(namespace), nil, []byte("sha512"), ssh.Marshal(sig)} {
		b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	enc := base64.StdEncoding.EncodeToString(b.BytesOrPanic())
	var out strings.Builder
	out.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(enc) > 70 {
		out.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	out.WriteString(enc + "\n-----END SSH SIGNATURE-----\n")
	return []byte(out.String())
}

// TestMachineIssueSK (OQ-2): an sk machine key verifies only with the
// user-presence flag.
func TestMachineIssueSK(t *testing.T) {
	setup := func(t *testing.T, flags byte) (*machineEnv, *skEd25519Signer, *wire.MachineIssueRequest) {
		t.Helper()
		e := newMachineEnv(t)
		sk := newSKEd25519Signer(t, flags)
		e.machines = append(e.machines, directory.Machine{Name: "sk1", Key: trust.FormatKey(sk.PublicKey()), Roles: []string{"deploy"},
			MaxTTLSeconds: 3600, Status: directory.StatusActive})
		e.publishMachines(t)
		req := &wire.MachineIssueRequest{InstallationID: testInstallationID, MachineName: "sk1", MachineKey: sk.PublicKey().Marshal(),
			CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: skSSHSIG(t, sk, wire.MachinePoPNamespace, req.SigningBytes())}}
		return e, sk, req
	}
	t.Run("sk_ed25519_with_user_presence_issues", func(t *testing.T) {
		e, sk, req := setup(t, 1)
		c, _ := e.mustMachine(t, req)
		if !bytes.Equal(c.Key.Marshal(), sk.PublicKey().Marshal()) || c.Key.Type() != ssh.KeyAlgoSKED25519 {
			t.Fatalf("the certificate carries %s", c.Key.Type())
		}
	})
	t.Run("sk_without_user_presence_refused_pop_invalid", func(t *testing.T) {
		e, _, req := setup(t, 0)
		sig, err := sshsig.Parse(req.Evidence[0].Blob)
		if err != nil {
			t.Fatalf("the assembled blob does not parse: %v", err)
		}
		if err := sig.Verify(wire.MachinePoPNamespace, req.SigningBytes()); !errors.Is(err, sshsig.ErrUserPresence) {
			t.Fatalf("Verify = %v, want ErrUserPresence", err)
		}
		e.refusedMachine(t, req, "machine_pop_invalid", wire.CodeRefused)
	})
}

// TestMachineIssueRestart: the start-up check counts machine_issue leaves
// and the machine index is rebuilt from the log (03-11, T-03-75).
func TestMachineIssueRestart(t *testing.T) {
	t.Run("counts_machine_leaf", func(t *testing.T) {
		e := newMachineEnv(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.restart(t)
		if _, issued, _ := e.counts(); issued != 1 {
			t.Fatalf("%d issuance rows", issued)
		}
		e.clock.set(e.clock.Now().Add(time.Second))
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("index_matches_rebuild", func(t *testing.T) {
		e := newMachineEnv(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.publishMachines(t)
		e.clock.set(e.clock.Now().Add(time.Second))
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		live := liveMachines(e)
		if len(live.latest) != 1 || len(live.recent[trust.FormatKey(e.k1.PublicKey())]) != 2 {
			t.Fatalf("live index %+v", live)
		}
		if !sameMachineIndex(live, rebuiltMachines(t, e)) {
			t.Fatal("the live machine index differs from a fresh rebuild")
		}
	})
}
