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
	"net"
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
		!reflect.DeepEqual(a.recent, b.recent) || !maps.Equal(a.nameHeld, b.nameHeld) || len(a.latest) != len(b.latest) {
		return false
	}
	for k, x := range a.latest {
		y, ok := b.latest[k]
		if !ok || x.serial != y.serial || x.leaf != y.leaf || x.capSeconds != y.capSeconds || x.issuedUnderDir != y.issuedUnderDir ||
			!bytes.Equal(x.certBytes, y.certBytes) ||
			!slices.Equal(x.principals, y.principals) || x.issued != y.issued || x.revoked != y.revoked || x.revokedAtDir != y.revokedAtDir {
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
	t.Run("clock_step_back_after_bound_check_refused", func(t *testing.T) {
		// Twelve issuances at second T. The rate check reads T + 3600, where
		// none of them counts; every later read is a second back, at
		// T + 3599, where all twelve do. Issuing there would log a 13th
		// within the hour, so the tail refuses it as a clock regression.
		e := newMachineEnv(t)
		e.issueN(t, e.k1, "ci", 12)
		var T uint64
		for i, l := range e.machineLeaves(t) {
			c := parseIssued(t, l.Cert)
			if i == 0 {
				T = issuedSecs(c)
			} else if issuedSecs(c) != T {
				t.Fatalf("issuance %d at second %d, want all twelve at %d", i+1, issuedSecs(c), T)
			}
		}
		e.tickTo(T + 3600)
		req := e.machineReq(e.k1, "ci")
		sc := &stepClock{t: e.clock.Now().Add(time.Millisecond), back: time.Second}
		sc.arm(1)
		e.s.mu.Lock()
		e.s.clock = sc.Now
		e.s.mu.Unlock()
		e.refusedMachine(t, req, "clock_regression", wire.CodeUnavailable)
		e.s.mu.Lock()
		e.s.clock = e.clock.Now
		e.s.mu.Unlock()
		e.verifyExport()
		e.clock.set(sc.t.Add(time.Millisecond))
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if rep := e.verifyExport(); rep.Counts[tlog.KindMachineIssue] != 13 {
			t.Fatalf("audit counts %d machine_issue entries, want 13", rep.Counts[tlog.KindMachineIssue])
		}
	})
	machineHoldBoundCases(t)
}

// addCI3 adds the active machine ci3 (a new key, role deploy) to e's
// directory, installs it and returns the key.
func (e *machineEnv) addCI3(t *testing.T) ssh.Signer {
	t.Helper()
	k3 := newEd25519(t)
	e.machines = append(e.machines, directory.Machine{Name: "ci3", Key: trust.FormatKey(k3.PublicKey()), Roles: []string{"deploy"},
		MaxTTLSeconds: 3600, Status: directory.StatusActive})
	e.publishMachines(t)
	return k3
}

// issueN issues n certificates for key under name and returns their
// requests.
func (e *machineEnv) issueN(t *testing.T, key ssh.Signer, name string, n int) []*wire.MachineIssueRequest {
	t.Helper()
	var out []*wire.MachineIssueRequest
	for range n {
		req := e.machineReq(key, name)
		e.mustMachine(t, req)
		out = append(out, req)
	}
	return out
}

// revokeMachineSerial revokes serial under the machine CA (a TargetSerial
// revoke by the first admin).
func (e *machineEnv) revokeMachineSerial(t *testing.T, serial uint64) {
	t.Helper()
	e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleMachine, Serial: serial})
}

// opsMachine stores, as an earlier signer would have, a directory whose
// machine opsm lists the bundle's ops key, restarts the signer on it and
// returns the ops key's signer.
func (e *machineEnv) opsMachine(t *testing.T) ssh.Signer {
	t.Helper()
	ops := e.fx.Roles[keystore.RoleOps]
	doc, sigs := e.machineDirectory(t, func(d *directory.Directory) {
		d.Machines = append(d.Machines, directory.Machine{Name: "opsm", Key: trust.FormatKey(ops.PublicKey()), Roles: []string{"deploy"},
			MaxTTLSeconds: 3600, Status: directory.StatusActive})
	})
	e.seedDirectory(t, doc, sigs)
	e.docs = append(e.docs, doc)
	e.restart(t)
	return ops
}

// restoredMachines is e restored from snapshot (restoredFrom) as a
// machineEnv on e's clock, keys and directory documents.
func (e *machineEnv) restoredMachines(t *testing.T, snapshot string) *machineEnv {
	t.Helper()
	h := &hostEnv{revokeEnv: e.restored(t, snapshot), ed: e.ed, ec: e.ec, off: e.off, other: e.other, hosts: e.hosts, docs: slices.Clone(e.docs)}
	return &machineEnv{hostEnv: h, k1: e.k1, k2: e.k2, roles: e.roles, machines: e.machines}
}

// machineHoldBoundCases are TestMachineIssue's hold, bound and unusable
// key cases (03-11 Task 2). Each env that holds state of its own is the
// subtest's own; the shared ones are built on first use, so every subtest
// passes alone.
func machineHoldBoundCases(t *testing.T) {
	// held: ci issued once and that certificate revoked by serial; ci3
	// active and never issued.
	var held *machineEnv
	var heldK3 ssh.Signer
	heldEnv := func(_ *testing.T) *machineEnv {
		if held == nil {
			held = newMachineEnv(t)
			heldK3 = held.addCI3(t)
			c, _ := held.mustMachine(t, held.machineReq(held.k1, "ci"))
			held.revokeMachineSerial(t, c.Serial)
		}
		return held
	}
	// bound: ci issued twelve times inside the hour; ci3 active.
	var bound *machineEnv
	var boundReqs []*wire.MachineIssueRequest
	var boundK3 ssh.Signer
	boundEnv := func(_ *testing.T) *machineEnv {
		if bound == nil {
			bound = newMachineEnv(t)
			boundK3 = bound.addCI3(t)
			boundReqs = bound.issueN(t, bound.k1, "ci", 12)
		}
		return bound
	}
	// unusable: a stored directory lists the ops key as machine opsm.
	var unusable *machineEnv
	var opsKey ssh.Signer
	unusableEnv := func(_ *testing.T) *machineEnv {
		if unusable == nil {
			unusable = newMachineEnv(t)
			opsKey = unusable.opsMachine(t)
		}
		return unusable
	}
	t.Run("hold_after_revoke_same_dir", func(t *testing.T) {
		e := heldEnv(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
	})
	t.Run("hold_after_key_id_revoke", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleMachine, KeyID: c.KeyId})
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
	})
	t.Run("hold_released_by_newer_dir", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSerial(t, c.Serial)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.publishMachines(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.verifyExport()
	})
	t.Run("hold_equal_dir_version_still_holds", func(t *testing.T) {
		// Time does not release the hold: with the revoked certificate
		// expired and the same directory version in force, it still holds.
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSerial(t, c.Serial)
		e.tickTo(c.ValidBefore + 3600)
		e.restart(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
	})
	t.Run("hold_is_latest_only", func(t *testing.T) {
		e := newMachineEnv(t)
		c1, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSerial(t, c1.Serial)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("hold_not_for_other_key", func(t *testing.T) {
		e := heldEnv(t)
		e.mustMachine(t, e.machineReq(heldK3, "ci3"))
	})
	t.Run("hold_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := heldEnv(t)
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("installation_key_unusable", func(t *testing.T) {
		e := unusableEnv(t)
		e.refusedMachine(t, e.machineReq(opsKey, "opsm"), "machine_key_unusable", wire.CodeRefused)
	})
	t.Run("machine_key_unusable_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := unusableEnv(t)
		e.refusedMachine(t, e.badPoP(e.machineReq(opsKey, "opsm"), opsKey), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("renew_bound_12_then_refused", func(t *testing.T) {
		e := boundEnv(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_renew_too_often", wire.CodeRefused)
	})
	t.Run("renew_bound_window_edge", func(t *testing.T) {
		e := newMachineEnv(t)
		c1, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		first := issuedSecs(c1)
		e.tickTo(first + 10)
		e.issueN(t, e.k1, "ci", 11)
		e.tickTo(first + 3599)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_renew_too_often", wire.CodeRefused)
		e.tickTo(first + 3601)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("rename_keeps_window", func(t *testing.T) {
		// T-03-401, Q-09-2: the window is keyed by the key, so a rename
		// does not reset it.
		e := newMachineEnv(t)
		e.issueN(t, e.k1, "ci", 12)
		e.machines[0].Name = "ci-new"
		e.publishMachines(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci-new"), "machine_renew_too_often", wire.CodeRefused)
		e.verifyExport()
	})
	t.Run("bound_is_per_key", func(t *testing.T) {
		e := boundEnv(t)
		e.mustMachine(t, e.machineReq(boundK3, "ci3"))
	})
	t.Run("bad_pop_attempts_do_not_consume_the_bound", func(t *testing.T) {
		e := newMachineEnv(t)
		e.issueN(t, e.k1, "ci", 11)
		for range 20 {
			e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
		}
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("bound_reached_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := boundEnv(t)
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("request_id_reuse_before_bound", func(t *testing.T) {
		e := boundEnv(t)
		again := e.machineReq(e.k1, "ci")
		again.RequestID = boundReqs[0].RequestID
		e.refusedMachine(t, e.machineSign(again, e.k1, wire.MachinePoPNamespace), "duplicate_request", wire.CodeRefused)
	})
	t.Run("relist_then_issue_after_newer_dir_audits", func(t *testing.T) {
		// Keep-first: the second listing of the serial, at V+1, does not
		// move the version the key is held at, so V+1 released it.
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSerial(t, c.Serial)
		e.publishMachines(t)
		e.revokeMachineSerial(t, c.Serial)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.verifyExport()
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
	t.Run("hold_and_bound_survive_restart", func(t *testing.T) {
		e := newMachineEnv(t)
		k3 := e.addCI3(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSerial(t, c.Serial)
		e.issueN(t, k3, "ci3", 12)
		e.restart(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.refusedMachine(t, e.machineReq(k3, "ci3"), "machine_renew_too_often", wire.CodeRefused)
		e.verifyExport()
	})
	t.Run("recovery_carried_revoked_holds_the_key", func(t *testing.T) {
		// PD3: a recovery carries a lost kr3 machine certificate of ci,
		// above the indexed one, and revokes it: it is the key's latest, so
		// the key is held until a newer directory version.
		e := newMachineEnv(t)
		c1, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		snapshot := e.snapshotDB(t)
		e.clock.set(e.clock.Now().Add(time.Second))
		lost, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if lost.Serial <= c1.Serial {
			t.Fatal("the lost certificate was not issued")
		}
		r := e.restoredMachines(t, snapshot)
		r.tick(2 * time.Second)
		r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil))
		r.refusedMachine(t, r.machineReq(r.k1, "ci"), "cert_revoked", wire.CodeRefused)
		r.publishMachines(t)
		r.mustMachine(t, r.machineReq(r.k1, "ci"))
		r.verifyExport()
	})
	t.Run("recovery_carried_unrevoked_not_counted_toward_bound", func(t *testing.T) {
		// PD3: a carried certificate's issuance belongs to the lost log, so
		// it does not count toward the twelve an hour.
		e := newMachineEnv(t)
		snapshot := e.snapshotDB(t)
		lost, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		r := e.restoredMachines(t, snapshot)
		r.tick(2 * time.Second)
		r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: false}}, nil))
		if live := liveMachines(r); live.latest[trust.FormatKey(r.k1.PublicKey())].serial != lost.Serial {
			t.Fatal("the carried certificate is not the key's latest")
		}
		r.issueN(t, r.k1, "ci", 12)
		r.refusedMachine(t, r.machineReq(r.k1, "ci"), "machine_renew_too_often", wire.CodeRefused)
		r.verifyExport()
	})
	t.Run("name_hold_index_matches_rebuild", func(t *testing.T) {
		e := idleMachine(t)
		e.revokeMachineSubject(t, "ci")
		live := liveMachines(e)
		if live.nameHeld["ci"] == 0 {
			t.Fatalf("the sweep armed no name hold: %+v", live.nameHeld)
		}
		if !sameMachineIndex(live, rebuiltMachines(t, e)) {
			t.Fatal("the live machine index differs from a fresh rebuild")
		}
	})
}

// TestInstallDirectoryMachineReservations (03-11, default 5, PD5): a new
// directory may not name a machine probe.* or give a machine a principal
// union above cert.MaxPrincipals; a directory already stored with either
// still loads and verifies.
func TestInstallDirectoryMachineReservations(t *testing.T) {
	// wide gives ci the roles r1 and r2 whose principals p00.. overlap so
	// that their union has n principals.
	wide := func(n int) func(*directory.Directory) {
		return func(d *directory.Directory) {
			var p1, p2 []string
			for i := range n {
				p := "p" + string(rune('a'+i/26)) + string(rune('a'+i%26))
				if i < 20 {
					p1 = append(p1, p)
				}
				if i >= n-20 {
					p2 = append(p2, p)
				}
			}
			d.Roles = append(d.Roles, directory.Role{Name: "r1", Principals: p1, MaxTTLSeconds: 3600},
				directory.Role{Name: "r2", Principals: p2, MaxTTLSeconds: 3600})
			for i := range d.Machines {
				if d.Machines[i].Name == "ci" {
					d.Machines[i].Roles = []string{"r1", "r2"}
				}
			}
		}
	}
	probeMachine := func(name string) func(*directory.Directory) {
		return func(d *directory.Directory) {
			d.Machines = append(d.Machines, directory.Machine{Name: name, Key: trust.FormatKey(newEd25519(t).PublicKey()), Roles: []string{"deploy"},
				MaxTTLSeconds: 3600, Status: directory.StatusActive})
		}
	}
	t.Run("machine_name_reserved", func(t *testing.T) {
		e := newMachineEnv(t)
		doc, sigs := e.machineDirectory(t, probeMachine("probe.x"))
		e.refuseInstall(t, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}, "machine_name_reserved")
	})
	t.Run("names_near_the_prefix_fine", func(t *testing.T) {
		e := newMachineEnv(t)
		doc, sigs := e.machineDirectory(t, func(d *directory.Directory) {
			for _, n := range []string{"probe", "probe-x", "xprobe.x"} {
				probeMachine(n)(d)
			}
		})
		e.installDirectory(t, doc, sigs)
	})
	t.Run("machine_principals_exceed", func(t *testing.T) {
		e := newMachineEnv(t)
		doc, sigs := e.machineDirectory(t, wide(33))
		e.refuseInstall(t, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}, "machine_principals_exceed")
	})
	t.Run("machine_principals_32_allowed", func(t *testing.T) {
		// Two roles of twenty principals that share eight: the union is 32.
		e := newMachineEnv(t)
		doc, sigs := e.machineDirectory(t, wide(32))
		e.installDirectory(t, doc, sigs)
	})
	t.Run("stored_directory_still_loads", func(t *testing.T) {
		e := newMachineEnv(t)
		doc, sigs := e.machineDirectory(t, func(d *directory.Directory) {
			probeMachine("probe.x")(d)
			wide(33)(d)
		})
		e.seedDirectory(t, doc, sigs)
		e.docs = append(e.docs, doc)
		e.restart(t)
		if got := e.s.GetDirectory(); got.Version != uint64(len(e.docs)) || !got.Authorized {
			t.Fatalf("the stored directory: version %d, authorized %t; want %d, true", got.Version, got.Authorized, len(e.docs))
		}
		e.verifyExport()
	})
	t.Run("refusal_classes", func(t *testing.T) {
		for _, d := range []string{"machine_name_reserved", "machine_principals_exceed"} {
			if c := classify(d); c != tlog.ReasonUnauthorized || codeFor(c) != wire.CodeRefused {
				t.Errorf("%s: class %d, code %s", d, c, codeFor(c))
			}
		}
	})
}

// TestMachineRefusalClasses: every detail the machine path returns has its
// class and wire code, and none is internal (03-11).
func TestMachineRefusalClasses(t *testing.T) {
	t.Run("class_table", func(t *testing.T) {
		for d, want := range map[string]struct {
			class uint8
			code  wire.ErrorCode
		}{
			"machine_issue_no_installation_id":    {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_issue_installation_mismatch": {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_pop_not_enabled":             {tlog.ReasonUnauthorized, wire.CodeRefused},
			"unknown_machine":                     {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_key_mismatch":                {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_pop_invalid":                 {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_key_revoked":                 {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_disabled":                    {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_name_reserved":               {tlog.ReasonUnauthorized, wire.CodeRefused},
			"machine_key_unusable":                {tlog.ReasonBadSubjectKey, wire.CodeRefused},
			"machine_issue_valid_for_not_zero":    {tlog.ReasonTTLExceeded, wire.CodeRefused},
			"machine_renew_too_often":             {tlog.ReasonDuplicateRequest, wire.CodeRefused},
			"cert_revoked":                        {tlog.ReasonUnauthorized, wire.CodeRefused},
			"duplicate_request":                   {tlog.ReasonDuplicateRequest, wire.CodeRefused},
			"malformed_request":                   {tlog.ReasonMalformed, wire.CodeMalformed},
			"request_time_skew":                   {tlog.ReasonStaleRequest, wire.CodeRefused},
			"directory_changed":                   {tlog.ReasonUnavailable, wire.CodeUnavailable},
			"machine_principals_exceed":           {tlog.ReasonUnauthorized, wire.CodeRefused},
			"subject_reserved":                    {tlog.ReasonMalformed, wire.CodeMalformed},
		} {
			if got := classify(d); got != want.class || codeFor(got) != want.code {
				t.Errorf("classify(%q) = %d (%s), want %d (%s)", d, got, codeFor(got), want.class, want.code)
			}
		}
	})
}

// TestMachineIssueBucket: machine refusals and 0x0C frames that do not
// parse log on the machine bucket, so an anonymous flood never drains the
// shared one (03-11, T-03-398).
func TestMachineIssueBucket(t *testing.T) {
	ctx := context.Background()
	// flood refuses machine requests until the machine bucket logs no more.
	flood := func(e *machineEnv) {
		for range 1000 {
			before := e.leafCount(tlog.KindRefusal)
			_, _ = e.s.machineIssueOrRefuse(ctx, Peer{UID: 1000}, e.machineReq(e.k1, "nope"))
			if e.leafCount(tlog.KindRefusal) == before {
				return
			}
		}
		e.t.Fatal("the machine bucket never ran dry")
	}
	t.Run("flood_does_not_drain_shared_bucket", func(t *testing.T) {
		e := newMachineEnv(t)
		flood(e)
		req := &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal(), InstallationID: testInstallationID,
			CreatedAt: uint64(e.clock.Now().Unix()), Reason: "test"} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, newEd25519(t), wire.RevokeSSHSIGNamespace, req.SigningBytes())
		if err != nil {
			t.Fatal(err)
		}
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
		before := e.leafCount(tlog.KindRefusal)
		if _, er := e.s.revokeOrRefuse(ctx, Peer{UID: 1000}, req); er == nil {
			t.Fatal("a revoke signed by no admin was accepted")
		}
		if e.leafCount(tlog.KindRefusal) != before+1 {
			t.Fatal("after a machine flood a refused revoke was not logged as its own refusal leaf")
		}
	})
	t.Run("malformed_frames_use_machine_bucket", func(t *testing.T) {
		e := newMachineEnv(t)
		sock, stop := serveMachineSigner(t, e)
		send := func(typ byte, body []byte) {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteMessage(conn, typ, body); err != nil {
				t.Fatal(err)
			}
			if rt, _, err := wire.ReadMessage(conn, wire.ResponseCaps(typ)); err != nil || rt != wire.TypeError {
				t.Fatalf("response type %#x, %v; want an error response", rt, err)
			}
		}
		for range 3 * DefaultRefusalLogBurst {
			send(wire.TypeMachineIssueRequest, []byte{1, 2, 3})
		}
		send(0xEE, []byte{1})
		stop()
		if err := e.open(); err != nil {
			t.Fatal(err)
		}
		var malformed, shared int
		for _, l := range e.leavesOf() {
			if l.Kind != tlog.KindRefusal {
				continue
			}
			b, err := tlog.DecodeRefusalBody(l.Body)
			if err != nil {
				t.Fatal(err)
			}
			switch b.Detail {
			case "malformed_request":
				malformed++
			case "unknown_message_type":
				shared++
			}
		}
		if malformed != DefaultRefusalLogBurst || shared != 1 {
			t.Fatalf("%d malformed_request and %d unknown_message_type refusal leaves; want the machine burst %d and 1", malformed, shared, DefaultRefusalLogBurst)
		}
	})
	t.Run("admin_refusals_still_logged", func(t *testing.T) {
		e := newMachineEnv(t)
		flood(e)
		req := &wire.IssueRequest{CARole: wire.CARoleUser, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: "u:alice", Principals: []string{"alice"},
			ValidForSeconds: 600, CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		req.Evidence = SignRequest(t, req, newEd25519(t))
		before := e.leafCount(tlog.KindRefusal)
		if _, er := e.s.issueOrRefuse(ctx, Peer{UID: 1000}, req); er == nil {
			t.Fatal("an issue signed by no admin was accepted")
		}
		if e.leafCount(tlog.KindRefusal) != before+1 {
			t.Fatal("after a machine flood a refused admin issue was not logged as its own refusal leaf")
		}
	})
}
