//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// snapshotDB closes e's database, copies signer.db and its -wal and -shm
// files, where present, into a new directory, reopens e and returns the
// copy's signer.db path: a backup taken from a stopped signer.
func (e *logEnv) snapshotDB(t *testing.T) string {
	t.Helper()
	e.close()
	dir := t.TempDir()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(e.dbPath + suffix) //nolint:gosec // G304: the test's own database
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "signer.db"+suffix), data, 0o600); err != nil { //nolint:gosec // G703: a fixed name in the test's temporary directory
			t.Fatal(err)
		}
	}
	if err := e.open(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "signer.db")
}

// restoredFrom opens a second signer, the restored one, on the database
// copy at path, with e's fixture, backend and clock.
func (e *logEnv) restoredFrom(t *testing.T, path string) *logEnv {
	t.Helper()
	r := &logEnv{t: t, dbPath: path, fx: e.fx, backend: e.backend, base: e.base, clock: e.clock}
	if err := r.open(); err != nil {
		t.Fatalf("open the restored signer: %v", err)
	}
	t.Cleanup(r.close)
	return r
}

// served returns the KRL the signer serves as an import, the way
// keyroster-server keeps it (krl-served.json).
func (e *logEnv) served(t *testing.T) wire.RecoveryImport {
	t.Helper()
	got := e.s.GetKRL()
	if len(got.KRL) == 0 {
		t.Fatal("the signer serves no KRL")
	}
	return wire.RecoveryImport{KRL: got.KRL, Manifest: got.Manifest, Sig: got.Sig}
}

// recoveryRequest is a recovery request for e's log as it is now (its
// size and root), importing imports and carrying certs, created now on
// the signer's clock and signed under keyroster/revoke-recovery/v1 by
// signers (the fixture's first admin when none is given). edit (optional)
// changes the request before it is signed.
func (e *logEnv) recoveryRequest(t *testing.T, imports []wire.RecoveryImport, certs []wire.RecoveredCertificate, edit func(*wire.RecoveryRequest), signers ...ssh.Signer) *wire.RecoveryRequest {
	t.Helper()
	now := time.Now()
	if e.clock != nil {
		now = e.clock()
	}
	req := &wire.RecoveryRequest{InstallationID: e.fx.InstallationID, CreatedAt: uint64(now.Unix()), //nolint:gosec // G115: after 1970
		RestoredSize: e.s.tree.Size(), Imports: imports, Certificates: certs}
	root, err := e.s.tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	copy(req.RestoredRoot[:], root)
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(req)
	}
	if len(signers) == 0 {
		signers = []ssh.Signer{e.fx.Admins[0]}
	}
	sb, err := req.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, wire.RecoverySSHSIGNamespace, sb)
		if err != nil {
			t.Fatal(err)
		}
		req.Evidence = append(req.Evidence, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return req
}

// recover applies req and requires success.
func (e *logEnv) recover(t *testing.T, req *wire.RecoveryRequest) *RecoveryResult {
	t.Helper()
	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.s.RecoverRevocations(context.Background(), data)
	if err != nil {
		t.Fatalf("RecoverRevocations: %v (%v)", err, errors.Unwrap(err))
	}
	return res
}

// issuedCert returns the certificate with serial from the issuance table.
func (e *logEnv) issuedCert(t *testing.T, serial uint64) []byte {
	t.Helper()
	var out []byte
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		is, err := e.db.IssuanceBySerialTx(context.Background(), tx, serial)
		if err != nil || is == nil {
			return fmt.Errorf("no issuance with serial %d: %w", serial, err)
		}
		out = is.Cert
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// certOf parses the certificate of an issue response.
func certOf(t *testing.T, resp *wire.IssueResponse) *ssh.Certificate {
	t.Helper()
	pub, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	return c
}

// TestRecoveryTracer (03-06b Task 2): a real signer with a software CA
// issues alice two certificates; its database is copied (the snapshot);
// it then revokes the first by serial and publishes, and that KRL document
// is kept as keyroster-server keeps it. A second signer opened on the
// snapshot is the restored one: it lost the revocation. A recovery request
// built from the kept KRL document and signed by the policy admin is
// applied with RecoverRevocations: the restored signer's KRL then makes
// ssh-keygen -Q refuse the first certificate and accept the second, audit
// verify of the exported restored-plus-recovered log passes and counts one
// recovery, and a new signer opened on that database starts (no
// revocations_not_logged).
func TestRecoveryTracer(t *testing.T) {
	keygen := keygenOracle(t)
	e := newRevokeEnv(t, 1, 1, testInstallationID)
	e.clock.set(e.clock.Now().Add(time.Millisecond)) // serials come from the clock
	second, err := e.issue()
	if err != nil {
		t.Fatal(err)
	}
	first := e.serial
	firstCert := certOf(t, &wire.IssueResponse{Cert: e.issuedCert(t, first)})
	secondCert := certOf(t, second)

	// The snapshot, then the revocation after it.
	snapshot := e.snapshotDB(t)
	e.clock.set(e.clock.Now().Add(time.Second))
	resp, _ := e.revoked(e.revokeRequest(first, wire.CARoleUser, wire.RevokeSSHSIGNamespace, e.fx.Admins[0]), 0)
	kept := e.served(t)
	if !keygenRevoked(t, keygen, kept.KRL, firstCert) {
		t.Fatal("the KRL of the revocation does not refuse the first certificate")
	}

	// The restore: the restored signer lost the revocation.
	r := e.restoredFrom(t, snapshot)
	if got := r.s.GetKRL(); len(got.KRL) != 0 {
		t.Fatal("the restored signer serves a KRL")
	}

	// The recovery, a second later.
	e.clock.set(e.clock.Now().Add(time.Second))
	res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
	if res.Imports != 1 || res.Entries != 1 || res.Revoked != 0 || res.Kept != 0 || res.KRLVersion <= resp.KRLVersion ||
		res.PublishLeaf != res.RecoveryLeaf+1 {
		t.Fatalf("recovery result %+v, want one import, one entry and a KRL above v%d", res, resp.KRLVersion)
	}
	got := r.s.GetKRL()
	if !keygenRevoked(t, keygen, got.KRL, firstCert) {
		t.Fatal("after the recovery, ssh-keygen -Q accepts the first certificate")
	}
	if keygenRevoked(t, keygen, got.KRL, secondCert) {
		t.Fatal("after the recovery, ssh-keygen -Q refuses the second certificate")
	}
	rep := r.verifyExport()
	if rep.Recoveries != 1 || rep.KRLVersion != res.KRLVersion {
		t.Fatalf("audit.Verify: %d recoveries, KRL v%d; want 1 and v%d", rep.Recoveries, rep.KRLVersion, res.KRLVersion)
	}
	r.close()
	if err := r.open(); err != nil {
		t.Fatalf("a signer opened on the recovered database: %v", err)
	}
}

// otherInstallation is an installation ID that no fixture bundle carries.
const otherInstallation = "ffffffffffffffffffffffffffffffff"

// importKRL encodes set as KRL version and returns it as an import: its
// manifest (for installation, bundle version 1, issued at issued) signed
// by ops under krl.Namespace.
func importKRL(t *testing.T, set krl.Set, version uint64, issued time.Time, installation string, ops ssh.Signer) wire.RecoveryImport {
	t.Helper()
	data, err := krl.Encode(set, version, issued)
	if err != nil {
		t.Fatal(err)
	}
	return signImport(t, data, version, issued, installation, ops)
}

// signImport is importKRL over KRL bytes data, whose manifest names
// version.
func signImport(t *testing.T, data []byte, version uint64, issued time.Time, installation string, ops ssh.Signer) wire.RecoveryImport {
	t.Helper()
	m := krl.Manifest{InstallationID: installation, KRLVersion: version, KRLSHA256: krl.SHA256Hex(data),
		IssuedAt: issued.UTC().Truncate(time.Second).Format(trust.TimeFormat), BundleVersion: 1, LogIndex: 1}
	manifest, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, ops, krl.Namespace, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return wire.RecoveryImport{KRL: data, Manifest: manifest, Sig: sig}
}

// makeCert returns a certificate of certType for subject under role, with
// serial, a key ID naming keyIDSerial, valid before validBefore, signed by
// ca, for key (a fresh key when nil).
func makeCert(t *testing.T, ca ssh.Signer, certType uint32, role, subject string, serial, keyIDSerial, validBefore uint64, key ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	if key == nil {
		key = newEd25519(t).PublicKey()
	}
	c := &ssh.Certificate{Key: key, Serial: serial, CertType: certType, ValidPrincipals: []string{"alice"},
		KeyId:      cert.KeyID{CA: role, Subject: subject, Request: strings.Repeat("cd", 16), Policy: 1, Serial: keyIDSerial}.String(),
		ValidAfter: validBefore - 3600, ValidBefore: validBefore, Nonce: make([]byte, 32), SignatureKey: ca.PublicKey()}
	return signTestCert(t, ca, c)
}

// makeProbeCert returns a probe certificate as signer/probeissue.go gives
// one (03-10d): a user certificate for keyroster-probe:<host> whose kr3
// key ID has ca=machine and subject probe.<host>, with serial, valid
// before validBefore, signed by ca (the machine CA). Nothing in it says
// whether it was a positive or a negative probe.
func makeProbeCert(t *testing.T, ca ssh.Signer, host string, serial, validBefore uint64) *ssh.Certificate {
	t.Helper()
	req := make([]byte, 16)
	if _, err := rand.Read(req); err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{Key: newEd25519(t).PublicKey(), Serial: serial, CertType: ssh.UserCert, ValidPrincipals: []string{cert.ReservedPrincipalPrefix + host},
		KeyId: cert.KeyID{V3: true, CA: wire.CARoleMachine.String(), Subject: "probe." + host, Request: hex.EncodeToString(req), Policy: 1, Directory: 1,
			Serial: serial}.String(),
		ValidAfter: validBefore - 3600, ValidBefore: validBefore, Nonce: make([]byte, 32), SignatureKey: ca.PublicKey()}
	return signTestCert(t, ca, c)
}

// signTestCert signs c by ca and returns it.
func signTestCert(t *testing.T, ca ssh.Signer, c *ssh.Certificate) *ssh.Certificate {
	t.Helper()
	// Signed by hand, as audit's forgeCert does: cert.Build refuses the
	// malformed certificates some cases need (a key ID naming another
	// serial), and only cert.Build may call SignCert (CA-06).
	if _, err := rand.Read(c.Nonce); err != nil {
		t.Fatal(err)
	}
	out := c.Marshal()
	sig, err := ca.Sign(rand.Reader, out[:len(out)-4]) // without the empty signature's length prefix
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	return c
}

// issueRole issues a certificate under role through the admin path.
func (e *revokeEnv) issueRole(t *testing.T, role wire.CARole) *ssh.Certificate {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond)) // serials come from the clock
	req := e.request()
	req.CARole = role
	req.Evidence = SignRequest(t, req, e.fx.Admins...)
	resp, err := e.s.Issue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("issue %s: %v", role, err)
	}
	return certOf(t, resp)
}

// revokeAny revokes req (completed with the installation, the clock, a
// request ID and the admin's signature) and requires success.
func (e *revokeEnv) revokeAny(t *testing.T, req *wire.RevokeRequest) *wire.RevokeResponse {
	t.Helper()
	req.InstallationID, req.CreatedAt, req.Reason = e.fx.InstallationID, uint64(e.clock.Now().Unix()), "test" //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, e.fx.Admins[0], wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	resp, er := e.s.revokeOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		t.Fatalf("revoke refused: %s", er.Message)
	}
	return resp
}

// tick advances the env's clock by d.
func (e *revokeEnv) tick(d time.Duration) { e.clock.set(e.clock.Now().Add(d)) }

// restored is restoredFrom as a revokeEnv on e's clock.
func (e *revokeEnv) restored(t *testing.T, snapshot string) *revokeEnv {
	t.Helper()
	return &revokeEnv{logEnv: e.restoredFrom(t, snapshot), clock: e.clock, serial: e.serial}
}

// recState is everything a refused recovery must leave as it was: the
// stored leaves and checkpoint size, the revocation rows, the used revoke
// request IDs and the KRL state.
func (e *logEnv) recState(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	hashes, err := e.db.LeafHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, size, err := e.db.LatestCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, err := e.db.KRLState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var requests int
	if err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM revoke_request`).Scan(&requests)
	}); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("leaves %x size %d rows %+v requests %d krl %+v", hashes, size, e.revocationRows(t), requests, st)
}

// refusedRecovery applies data and requires the refusal name, with the
// state unchanged.
func (e *logEnv) refusedRecovery(t *testing.T, data []byte, name string) {
	t.Helper()
	_ = e.refusedRecoveryErr(t, data, name)
}

// refusedRecoveryErr is refusedRecovery that returns the refusal.
func (e *logEnv) refusedRecoveryErr(t *testing.T, data []byte, name string) error {
	t.Helper()
	before := e.recState(t)
	krlBefore := e.s.GetKRL()
	res, err := e.s.RecoverRevocations(context.Background(), data)
	if err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("RecoverRevocations = %+v, %v (%v); want the refusal %s", res, err, errors.Unwrap(err), name)
	}
	if after := e.recState(t); after != before {
		t.Fatalf("the state changed after the refusal %s:\nbefore %s\nafter  %s", name, before, after)
	}
	if got := e.s.GetKRL(); !bytes.Equal(got.KRL, krlBefore.KRL) {
		t.Fatalf("the served KRL changed after the refusal %s", name)
	}
	return err
}

// marshal is req's file form.
func marshal(t *testing.T, req *wire.RecoveryRequest) []byte {
	t.Helper()
	data, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rowsOf returns the revocation rows written with the leaf at index.
func rowsOf(rows []signerdb.Revocation, leaf uint64) []signerdb.Revocation {
	var out []signerdb.Revocation
	for _, r := range rows {
		if r.LeafIndex == leaf {
			out = append(out, r)
		}
	}
	return out
}

// failingOps is an ops key whose Sign always fails.
type failingOps struct{ keystore.CAKey }

func (failingOps) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("injected ops key failure")
}

// keygenRevokedKey reports whether ssh-keygen -Q -f refuses the plain key
// pub under the KRL data.
func keygenRevokedKey(t *testing.T, keygen string, data []byte, pub ssh.PublicKey) bool {
	t.Helper()
	dir := t.TempDir()
	krlFile, keyFile := filepath.Join(dir, "revoked.krl"), filepath.Join(dir, "id.pub")
	if err := os.WriteFile(krlFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keygen, "-Q", "-f", krlFile, keyFile).CombinedOutput() //nolint:gosec // G204: test oracle
	if err == nil {
		return false
	}
	if !strings.Contains(string(out), "REVOKED") {
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	return true
}

// lostSetup is a signer with one user certificate issued before the
// snapshot (e.serial), the snapshot, then after runs on the original
// signer (what the restore loses), and the restored signer, a second
// later.
func lostSetup(t *testing.T, after func(e *revokeEnv)) (e, r *revokeEnv) {
	t.Helper()
	e = newRevokeEnv(t, 1, 1, testInstallationID)
	snapshot := e.snapshotDB(t)
	e.tick(time.Second)
	if after != nil {
		after(e)
	}
	r = e.restored(t, snapshot)
	e.tick(time.Second)
	return e, r
}

// TestRecoverRevocations (03-06b Task 3): every refusal of
// Signer.RecoverRevocations, each leaving the state byte-identical; the
// pending-recovery cases; every revocation 03-03 writes, recovered; and
// successive recoveries.
func TestRecoverRevocations(t *testing.T) {
	ctx := context.Background()

	// Refusals.
	t.Run("recovery_malformed", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		r.refusedRecovery(t, []byte("not a recovery request"), "recovery_malformed")
	})
	t.Run("recovery_installation_mismatch", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		req := r.recoveryRequest(t, nil, nil, func(q *wire.RecoveryRequest) { q.InstallationID = otherInstallation })
		r.refusedRecovery(t, marshal(t, req), "recovery_installation_mismatch")
	})
	t.Run("recovery_log_mismatch", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		req := r.recoveryRequest(t, nil, nil, nil)
		r.tick(time.Millisecond)
		if _, err := r.issue(); err != nil { // one leaf after the request was built
			t.Fatal(err)
		}
		r.refusedRecovery(t, marshal(t, req), "recovery_log_mismatch")
		// The size and the root each bind the request on their own.
		r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, nil, nil, func(q *wire.RecoveryRequest) { q.RestoredRoot[0] ^= 1 })), "recovery_log_mismatch")
		r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, nil, nil, func(q *wire.RecoveryRequest) { q.RestoredSize-- })), "recovery_log_mismatch")
	})
	t.Run("recovery_evidence_invalid", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, nil, nil, nil, newEd25519(t))), "recovery_evidence_invalid")
		// Signed under the revoke namespace instead of the recovery one.
		req := r.recoveryRequest(t, nil, nil, nil)
		sb, err := req.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, r.fx.Admins[0], wire.RevokeSSHSIGNamespace, sb)
		if err != nil {
			t.Fatal(err)
		}
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
		r.refusedRecovery(t, marshal(t, req), "recovery_evidence_invalid")
	})
	t.Run("recovery_import_invalid", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		ops := r.fx.Roles[keystore.RoleOps]
		userCA := r.fx.Roles[keystore.RoleUser].PublicKey()
		set := krl.Set{Certs: []krl.CertSection{{CAKey: userCA, Serials: []uint64{r.serial}}}}
		now := r.clock.Now()
		v := uint64(now.Unix()) - 10 //nolint:gosec // G115: after 1970
		digest := importKRL(t, set, v, now, testInstallationID, ops)
		digest.KRL = append(bytes.Clone(digest.KRL[:len(digest.KRL)-1]), digest.KRL[len(digest.KRL)-1]^1)
		data, err := krl.Encode(set, v, now)
		if err != nil {
			t.Fatal(err)
		}
		for name, im := range map[string]wire.RecoveryImport{
			"ops_key_of_another_bundle": importKRL(t, set, v, now, testInstallationID, newEd25519(t)),
			"another_installation_id":   importKRL(t, set, v, now, otherInstallation, ops),
			"krl_bytes_not_the_digest":  digest,
			"header_version_differs":    signImport(t, data, v+1, now, testInstallationID, ops),
		} {
			t.Run(name, func(t *testing.T) {
				r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, []wire.RecoveryImport{im}, nil, nil)), "recovery_import_invalid")
			})
		}
	})
	t.Run("recovery_certificate_invalid", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		userCA := r.fx.Roles[keystore.RoleUser]
		s := uint64(r.clock.Now().UnixMicro()) + 1000 //nolint:gosec // G115: after 1970
		vb := uint64(r.clock.Now().Unix()) + 3600     //nolint:gosec // G115: after 1970
		for name, c := range map[string]*ssh.Certificate{
			"not_a_ca_key_of_its_role": makeCert(t, newEd25519(t), ssh.UserCert, "user", "u:alice", s, s, vb, nil),
			"key_id_names_another":     makeCert(t, userCA, ssh.UserCert, "user", "u:alice", s, s+1, vb, nil),
			"host_role_user_ca":        makeCert(t, userCA, ssh.HostCert, "host", "h:web", s, s, vb, nil),
		} {
			t.Run(name, func(t *testing.T) {
				req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: c.Marshal(), Revoke: true}}, nil)
				r.refusedRecovery(t, marshal(t, req), "recovery_certificate_invalid")
			})
		}
	})
	t.Run("recovery_certificate_not_lost", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		userCA := r.fx.Roles[keystore.RoleUser]
		vb := uint64(r.clock.Now().Unix()) + 3600 //nolint:gosec // G115: after 1970
		below := makeCert(t, userCA, ssh.UserCert, "user", "u:alice", r.serial-1, r.serial-1, vb, nil)
		for name, raw := range map[string][]byte{
			"at_or_below_high_water": below.Marshal(),
			"in_the_issuance_table":  r.issuedCert(t, r.serial),
		} {
			t.Run(name, func(t *testing.T) {
				req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: raw, Revoke: true}}, nil)
				r.refusedRecovery(t, marshal(t, req), "recovery_certificate_not_lost")
			})
		}
	})
	// A recovery carries only the lost certificates krl.CheckCarriedLost admits
	// at its CreatedAt (PR #69 review, D-R2): an expired one it does not
	// revoke is refused; revoked, it is carried.
	t.Run("recovery_certificate_expired", func(t *testing.T) {
		var host *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { host = e.issueRole(t, wire.CARoleHost) })
		late := func(rq *wire.RecoveryRequest) { rq.CreatedAt = host.ValidBefore + 600 }
		r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: host.Marshal()}}, late)), "recovery_certificate_expired")
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: host.Marshal(), Revoke: true}}, late))
		if res.Revoked != 1 || !r.parsedKRL(t).RevokesSerial(host.SignatureKey.Marshal(), host.Serial) {
			t.Fatalf("result %+v; want the expired host certificate named for revocation carried and revoked", res)
		}
		r.verifyExport()
	})
	// Prepared while the certificate was live, applied after it expired:
	// accepted, since the rule reads only the request's CreatedAt.
	t.Run("carried_certificate_applied_late", func(t *testing.T) {
		var host *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { host = e.issueRole(t, wire.CARoleHost) })
		req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: host.Marshal()}}, nil)
		r.clock.set(time.Unix(int64(host.ValidBefore)+2*3600, 0)) //nolint:gosec // G115: a test time
		if res := r.recover(t, req); res.Kept != 1 {
			t.Fatalf("result %+v; want the host certificate kept", res)
		}
		r.verifyExport()
	})
	t.Run("recovery_user_certificate_kept", func(t *testing.T) {
		var lost *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { lost = e.issueRole(t, wire.CARoleUser) })
		req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: false}}, nil)
		r.refusedRecovery(t, marshal(t, req), "recovery_user_certificate_kept")
	})
	// Round 2 (PR #69 review): a carried user certificate is revoked
	// whatever any clock says. Kept, it is refused even when the recovery
	// is applied after it expired.
	t.Run("recovery_user_certificate_kept_applied_late", func(t *testing.T) {
		var lost *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { lost = e.issueRole(t, wire.CARoleUser) })
		req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: false}}, nil)
		r.clock.set(time.Unix(int64(lost.ValidBefore)+2*3600, 0)) //nolint:gosec // G115: a test time
		r.refusedRecovery(t, marshal(t, req), "recovery_user_certificate_kept")
	})
	// A request prepared on a clock far ahead (CreatedAt two hours past the
	// lost user certificate's expiry, while it is still live at the
	// signer) revokes it: the recovery applies and the KRL revokes it.
	t.Run("clock_ahead_user_revoked", func(t *testing.T) {
		var lost *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { lost = e.issueRole(t, wire.CARoleUser) })
		if now := uint64(r.clock.Now().Unix()); now >= lost.ValidBefore { //nolint:gosec // G115: after 1970
			t.Fatalf("the lost user certificate is not live at the signer: now %d, valid before %d", now, lost.ValidBefore)
		}
		ahead := func(rq *wire.RecoveryRequest) { rq.CreatedAt = lost.ValidBefore + 2*3600 }
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, ahead))
		if res.Revoked != 1 || !r.parsedKRL(t).RevokesSerial(lost.SignatureKey.Marshal(), lost.Serial) {
			t.Fatalf("result %+v; want the lost user certificate revoked", res)
		}
		r.verifyExport()
	})
	// Above the entry cap: one range of adjacent serials, a tiny KRL,
	// refused before it is expanded.
	t.Run("recovery_too_large", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		serials := make([]uint64, krl.MaxRecoveryEntries+1)
		for i := range serials {
			serials[i] = uint64(i) + 1 //nolint:gosec // G115: a test index
		}
		now := r.clock.Now()
		im := importKRL(t, krl.Set{Certs: []krl.CertSection{{CAKey: r.fx.Roles[keystore.RoleUser].PublicKey(), Serials: serials}}},
			uint64(now.Unix())-10, now, testInstallationID, r.fx.Roles[keystore.RoleOps]) //nolint:gosec // G115: after 1970
		r.refusedRecovery(t, marshal(t, r.recoveryRequest(t, []wire.RecoveryImport{im}, nil, nil)), "recovery_too_large")
	})
	// Under the entry cap but above the body cap (PR #69 review, D-R1:
	// the body cap binds first): two imports of about 3.9 MB, each with
	// 3,800 distinct key IDs of 1,000 bytes, give 7,600 entries of about
	// 1 KB beside the 7.8 MB of imports.
	t.Run("recovery_too_large_body", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		now := r.clock.Now()
		ca := r.fx.Roles[keystore.RoleUser].PublicKey()
		var imports []wire.RecoveryImport
		for n := range 2 {
			ids := make([]string, 3800)
			for i := range ids {
				ids[i] = fmt.Sprintf("%d-%06d-%s", n, i, strings.Repeat("k", 990))
			}
			imports = append(imports, importKRL(t, krl.Set{Certs: []krl.CertSection{{CAKey: ca, KeyIDs: ids}}},
				uint64(now.Unix())-10+uint64(n), now, testInstallationID, r.fx.Roles[keystore.RoleOps])) //nolint:gosec // G115: after 1970
		}
		err := r.refusedRecoveryErr(t, marshal(t, r.recoveryRequest(t, imports, nil, nil)), "recovery_too_large")
		if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), "above") {
			t.Fatalf("the refusal %v (%v) does not name the body cap", err, cause)
		}
	})
	// A KRL near what the signer publishes, 70,000 serials that are not
	// adjacent, is recovered (PR #69 review, D-R1).
	t.Run("recovers_near_publishable_maximum", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		serials := make([]uint64, 70000)
		for i := range serials {
			serials[i] = 2*uint64(i) + 1 //nolint:gosec // G115: a test index
		}
		now := r.clock.Now()
		ca := r.fx.Roles[keystore.RoleUser].PublicKey()
		im := importKRL(t, krl.Set{Certs: []krl.CertSection{{CAKey: ca, Serials: serials}}},
			uint64(now.Unix())-10, now, testInstallationID, r.fx.Roles[keystore.RoleOps]) //nolint:gosec // G115: after 1970
		res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{im}, nil, nil))
		p := r.parsedKRL(t)
		if res.Entries != len(serials) || !p.RevokesSerial(ca.Marshal(), 1) || !p.RevokesSerial(ca.Marshal(), 139999) || p.RevokesSerial(ca.Marshal(), 2) {
			t.Fatalf("result %+v; want %d entries, all in the published KRL", res, len(serials))
		}
		r.verifyExport()
	})
	t.Run("recovery_version_not_above_import", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		now := r.clock.Now()
		ahead := uint64(now.Unix()) + 100 //nolint:gosec // G115: after 1970
		im := importKRL(t, krl.Set{}, ahead, now, testInstallationID, r.fx.Roles[keystore.RoleOps])
		err := r.refusedRecoveryErr(t, marshal(t, r.recoveryRequest(t, []wire.RecoveryImport{im}, nil, nil)), "recovery_version_not_above_import")
		if !strings.Contains(errors.Unwrap(err).Error(), "wait 101 s") {
			t.Fatalf("the refusal does not name the seconds to wait: %v", errors.Unwrap(err))
		}
	})
	t.Run("duplicate_request", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		r.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()})
		var id [16]byte
		for _, row := range r.revocationRows(t) {
			id = row.RequestID
		}
		r.tick(time.Second)
		req := r.recoveryRequest(t, nil, nil, func(q *wire.RecoveryRequest) { q.RequestID = id })
		r.refusedRecovery(t, marshal(t, req), "duplicate_request")
	})

	// Pending recovery: the transaction-level cases.
	t.Run("recovery_rolls_back_on_publish_failure", func(t *testing.T) {
		var kept wire.RecoveryImport
		_, r := lostSetup(t, func(e *revokeEnv) {
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: e.serial})
			kept = e.served(t)
		})
		data := marshal(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		r.s.mu.Lock()
		ops := r.s.opsKey
		r.s.opsKey = failingOps{ops}
		r.s.mu.Unlock()
		r.refusedRecovery(t, data, "ops_key_unavailable")
		r.s.mu.Lock()
		r.s.opsKey = ops
		r.s.mu.Unlock()
		if _, err := r.s.RecoverRevocations(ctx, data); err != nil {
			t.Fatalf("the same request after the failure: %v (%v)", err, errors.Unwrap(err))
		}
		r.refusedRecovery(t, data, "recovery_log_mismatch") // it succeeded once
	})
	t.Run("recovery_second_run_refused", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		data := marshal(t, r.recoveryRequest(t, nil, nil, nil))
		if _, err := r.s.RecoverRevocations(ctx, data); err != nil {
			t.Fatal(err)
		}
		r.refusedRecovery(t, data, "recovery_log_mismatch")
	})
	t.Run("restart_after_recovery", func(t *testing.T) {
		var kept wire.RecoveryImport
		_, r := lostSetup(t, func(e *revokeEnv) {
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: e.serial})
			kept = e.served(t)
		})
		r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		logKey := r.s.LogPublicKey()
		r.close()
		if err := r.open(); err != nil {
			t.Fatalf("New on the recovered database: %v", err)
		}
		if err := CheckLog(ctx, r.db, logKey); err != nil {
			t.Fatalf("CheckLog on the recovered database: %v", err)
		}
		before := len(publishes(r.logEnv))
		stop := serveKRL(t, r.logEnv, make(chan time.Time))
		stop()
		if n := len(publishes(r.logEnv)); n != before {
			t.Fatalf("a Serve start published %d KRL versions while the recovered KRL is under an hour old", n-before)
		}
		r.tick(krlRepublishAfter + time.Second)
		if !r.s.republishIfDue(ctx) {
			t.Fatal("republishIfDue an hour later published nothing")
		}
		p := r.parsedKRL(t)
		at := p.GeneratedDate
		for _, row := range r.revocationRows(t) {
			if krl.Prunable(row.ValidBeforeMicros/1_000_000, at) {
				continue
			}
			switch row.Kind {
			case signerdb.RevocationSerial:
				if !p.RevokesSerial(row.CAKey, row.Serial) {
					t.Fatalf("the hourly publish drops serial %d", row.Serial)
				}
			case signerdb.RevocationKeyID:
				if !p.RevokesKeyID(row.CAKey, row.KeyID) {
					t.Fatalf("the hourly publish drops key ID %q", row.KeyID)
				}
			case signerdb.RevocationKey:
				if !p.RevokesKey(row.Key) {
					t.Fatal("the hourly publish drops an explicit key")
				}
			}
		}
		r.verifyExport()
	})
	t.Run("recovered_entries_never_dropped", func(t *testing.T) {
		var versions []*krl.Parsed
		record := func(e *logEnv) {
			t.Helper()
			p := e.parsedKRL(t)
			if n := len(versions); n == 0 || versions[n-1].Version != p.Version {
				versions = append(versions, p)
			}
		}
		e := newRevokeEnv(t, 1, 1, testInstallationID)
		keyA := newEd25519(t).PublicKey().Marshal()
		e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: keyA})
		record(e.logEnv)
		snapshot := e.snapshotDB(t)
		e.tick(time.Second)
		lost := e.issueRole(t, wire.CARoleUser)
		e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: e.serial})
		e.tick(time.Second)
		e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: lost.Serial})
		record(e.logEnv)
		kept := e.served(t)
		r := e.restored(t, snapshot)
		e.tick(time.Second)
		r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil))
		record(r.logEnv)
		for _, d := range []time.Duration{2 * time.Hour, 2 * time.Hour} {
			r.tick(d)
			if !r.s.republishIfDue(ctx) {
				t.Fatal("republishIfDue published nothing")
			}
			record(r.logEnv)
		}
		if len(versions) != 5 {
			t.Fatalf("%d KRL versions, want 5", len(versions))
		}
		revs := r.revocationRows(t)
		prunable := func(match func(signerdb.Revocation) bool, at uint64) bool {
			n := 0
			for _, row := range revs {
				if match(row) {
					n++
					if !krl.Prunable(row.ValidBeforeMicros/1_000_000, at) {
						return false
					}
				}
			}
			return n > 0
		}
		pruned := false
		for i := 1; i < len(versions); i++ {
			prev, next := versions[i-1], versions[i]
			at := next.GeneratedDate
			for _, sec := range prev.Certs {
				for _, rg := range sec.Serials {
					for s := rg.Lo; s <= rg.Hi; s++ {
						if next.RevokesSerial(sec.CAKey, s) {
							continue
						}
						if !prunable(func(row signerdb.Revocation) bool {
							return row.Kind == signerdb.RevocationSerial && row.Serial == s && bytes.Equal(row.CAKey, sec.CAKey)
						}, at) {
							t.Fatalf("version %d drops serial %d, which is not prunable at %d", next.Version, s, at)
						}
						pruned = true
					}
				}
			}
			for _, k := range prev.Keys {
				if !next.RevokesKey(k) {
					t.Fatalf("version %d drops an explicit key", next.Version)
				}
			}
			if next.Version <= prev.Version {
				t.Fatalf("version %d after %d", next.Version, prev.Version)
			}
		}
		if !pruned {
			t.Fatal("no version pruned an expired entry, so the property was not exercised")
		}
		r.verifyExport()
	})

	// Every revocation 03-03 writes, recovered.
	t.Run("recovers_serial_issued_before_snapshot", func(t *testing.T) {
		var kept wire.RecoveryImport
		e, r := lostSetup(t, func(e *revokeEnv) {
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: e.serial})
			kept = e.served(t)
		})
		c := certOf(t, &wire.IssueResponse{Cert: r.issuedCert(t, r.serial)})
		res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		rows := rowsOf(r.revocationRows(t), res.RecoveryLeaf)
		if len(rows) != 1 || rows[0].Serial != c.Serial || rows[0].ValidBeforeMicros != c.ValidBefore*1_000_000 {
			t.Fatalf("recovered rows %+v, want serial %d valid before %d (from the restored issuance)", rows, c.Serial, c.ValidBefore)
		}
		// Listed until ValidBefore + 300, pruned after.
		e.clock.set(time.Unix(int64(c.ValidBefore)+krl.PruneMargin-1, 0)) //nolint:gosec // G115: a test time
		r.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()})
		if !r.parsedKRL(t).RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
			t.Fatal("the serial left the KRL before ValidBefore + 300")
		}
		e.clock.set(time.Unix(int64(c.ValidBefore)+krl.PruneMargin+1, 0)) //nolint:gosec // G115: a test time
		r.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()})
		if r.parsedKRL(t).RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
			t.Fatal("the serial stays in the KRL after ValidBefore + 300")
		}
		r.verifyExport()
	})
	t.Run("recovers_serial_issued_after_snapshot", func(t *testing.T) {
		var (
			host *ssh.Certificate
			kept wire.RecoveryImport
		)
		_, r := lostSetup(t, func(e *revokeEnv) {
			host = e.issueRole(t, wire.CARoleHost)
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleHost, Serial: host.Serial})
			kept = e.served(t)
		})
		res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, []wire.RecoveredCertificate{{Cert: host.Marshal()}}, nil))
		rows := rowsOf(r.revocationRows(t), res.RecoveryLeaf)
		if len(rows) != 1 || rows[0].Serial != host.Serial || rows[0].ValidBeforeMicros != host.ValidBefore*1_000_000 || res.Kept != 1 {
			t.Fatalf("recovered rows %+v (result %+v), want serial %d valid before %d (from the carried certificate)", rows, res, host.Serial, host.ValidBefore)
		}
		r.verifyExport()
	})
	t.Run("recovers_serial_without_certificate", func(t *testing.T) {
		var (
			lost *ssh.Certificate
			kept wire.RecoveryImport
		)
		_, r := lostSetup(t, func(e *revokeEnv) {
			lost = e.issueRole(t, wire.CARoleUser)
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: lost.Serial})
			kept = e.served(t)
		})
		res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		rows := rowsOf(r.revocationRows(t), res.RecoveryLeaf)
		if len(rows) != 1 || rows[0].Serial != lost.Serial || rows[0].ValidBeforeMicros != 0 {
			t.Fatalf("recovered rows %+v, want serial %d with ValidBefore 0", rows, lost.Serial)
		}
		r.tick(48 * time.Hour)
		if !r.s.republishIfDue(ctx) || !r.parsedKRL(t).RevokesSerial(lost.SignatureKey.Marshal(), lost.Serial) {
			t.Fatal("a serial with ValidBefore 0 left the KRL")
		}
		r.verifyExport()
	})
	t.Run("recovers_key_id", func(t *testing.T) {
		var kept wire.RecoveryImport
		_, r := lostSetup(t, func(e *revokeEnv) {
			c := certOf(t, &wire.IssueResponse{Cert: e.issuedCert(t, e.serial)})
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: c.KeyId})
			kept = e.served(t)
		})
		c := certOf(t, &wire.IssueResponse{Cert: r.issuedCert(t, r.serial)})
		res := r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		rows := rowsOf(r.revocationRows(t), res.RecoveryLeaf)
		if len(rows) != 1 || rows[0].Kind != signerdb.RevocationKeyID || rows[0].KeyID != c.KeyId || rows[0].ValidBeforeMicros != c.ValidBefore*1_000_000 {
			t.Fatalf("recovered rows %+v, want key ID %q valid before %d", rows, c.KeyId, c.ValidBefore)
		}
		if !r.parsedKRL(t).RevokesKeyID(c.SignatureKey.Marshal(), c.KeyId) {
			t.Fatal("the recovered KRL does not list the key ID")
		}
		r.verifyExport()
	})
	t.Run("recovers_explicit_key", func(t *testing.T) {
		keygen := keygenOracle(t)
		key := newEd25519(t).PublicKey()
		var kept wire.RecoveryImport
		_, r := lostSetup(t, func(e *revokeEnv) {
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: key.Marshal()})
			kept = e.served(t)
		})
		r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		data := r.s.GetKRL().KRL
		vb := uint64(r.clock.Now().Unix()) + 3600 //nolint:gosec // G115: after 1970
		forKey := makeCert(t, r.fx.Roles[keystore.RoleUser], ssh.UserCert, "user", "u:alice", 99, 99, vb, key)
		if !keygenRevokedKey(t, keygen, data, key) || !keygenRevoked(t, keygen, data, forKey) {
			t.Fatal("after the recovery, ssh-keygen -Q accepts the key or a certificate for it")
		}
		r.verifyExport()
	})
	t.Run("recovers_subject_revoke", func(t *testing.T) {
		var (
			lost *ssh.Certificate
			kept wire.RecoveryImport
		)
		_, r := lostSetup(t, func(e *revokeEnv) {
			lost = e.issueRole(t, wire.CARoleUser)
			e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "u:alice"})
			kept = e.served(t)
		})
		c := certOf(t, &wire.IssueResponse{Cert: r.issuedCert(t, r.serial)})
		r.recover(t, r.recoveryRequest(t, []wire.RecoveryImport{kept}, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil))
		p := r.parsedKRL(t)
		if !p.RevokesSerial(c.SignatureKey.Marshal(), c.Serial) || !p.RevokesSerial(lost.SignatureKey.Marshal(), lost.Serial) {
			t.Fatal("the recovered KRL does not list both serials of the subject revocation")
		}
		r.verifyExport()
	})
	t.Run("revokes_lost_live_user_certificate", func(t *testing.T) {
		var lost *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { lost = e.issueRole(t, wire.CARoleUser) })
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil))
		if res.Revoked != 1 || res.Entries != 1 || !r.parsedKRL(t).RevokesSerial(lost.SignatureKey.Marshal(), lost.Serial) {
			t.Fatalf("result %+v; want the lost user certificate revoked", res)
		}
		r.verifyExport()
	})
	t.Run("keeps_lost_host_certificate", func(t *testing.T) {
		var host *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { host = e.issueRole(t, wire.CARoleHost) })
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: host.Marshal()}}, nil))
		if res.Kept != 1 || res.Entries != 0 || len(rowsOf(r.revocationRows(t), res.RecoveryLeaf)) != 0 {
			t.Fatalf("result %+v; want the host certificate kept, with no entry", res)
		}
		r.tick(time.Second)
		r.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: host.Key.Marshal()})
		if !r.parsedKRL(t).RevokesKey(host.Key.Marshal()) {
			t.Fatal("revoke key of the kept host certificate's key is not listed")
		}
		r.verifyExport()
	})
	// 03-10d (Q-R option 1): a lost probe certificate cannot be told apart
	// by polarity from its bytes, so a recovery revokes every one, told
	// apart by its key ID; one carried unrevoked is refused.
	t.Run("lost_probe_certificate_kept_is_refused", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		machineCA := r.fx.Roles[keystore.RoleMachine]
		s := uint64(r.clock.Now().UnixMicro()) + 1000 //nolint:gosec // G115: after 1970
		vb := uint64(r.clock.Now().Unix()) + 3600     //nolint:gosec // G115: after 1970
		probe := makeProbeCert(t, machineCA, "web1", s, vb)
		req := r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: probe.Marshal(), Revoke: false}}, nil)
		err := r.refusedRecoveryErr(t, marshal(t, req), "recovery_probe_certificate_kept")
		if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), "a recovery revokes every lost probe certificate") {
			t.Fatalf("refusal %v (%v); want its cause to say that a recovery revokes every lost probe certificate", err, cause)
		}
		// Beside a revoked one (sorted by serial), a kept one is still refused.
		other := makeProbeCert(t, machineCA, "web1", s+1, vb)
		req = r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: probe.Marshal(), Revoke: false}, {Cert: other.Marshal(), Revoke: true}}, nil)
		r.refusedRecovery(t, marshal(t, req), "recovery_probe_certificate_kept")
	})
	t.Run("lost_probe_certificate_revoked_is_listed", func(t *testing.T) {
		_, r := lostSetup(t, nil)
		machineCA := r.fx.Roles[keystore.RoleMachine]
		s := uint64(r.clock.Now().UnixMicro()) + 1000 //nolint:gosec // G115: after 1970
		vb := uint64(r.clock.Now().Unix()) + 3600     //nolint:gosec // G115: after 1970
		positive, negative := makeProbeCert(t, machineCA, "web1", s, vb), makeProbeCert(t, machineCA, "web1", s+1, vb)
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: positive.Marshal(), Revoke: true}, {Cert: negative.Marshal(), Revoke: true}}, nil))
		p := r.parsedKRL(t)
		ca := machineCA.PublicKey().Marshal()
		if res.Revoked != 2 || res.Kept != 0 || !p.RevokesSerial(ca, positive.Serial) || !p.RevokesSerial(ca, negative.Serial) {
			t.Fatalf("result %+v; want both lost probe certificates revoked and listed under the machine CA key", res)
		}
		r.verifyExport()
	})
	t.Run("lost_machine_certificate_still_keepable", func(t *testing.T) {
		var machine *ssh.Certificate
		_, r := lostSetup(t, func(e *revokeEnv) { machine = e.issueRole(t, wire.CARoleMachine) })
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: machine.Marshal()}}, nil))
		if res.Kept != 1 || res.Revoked != 0 || res.Entries != 0 || r.parsedKRL(t).RevokesSerial(machine.SignatureKey.Marshal(), machine.Serial) {
			t.Fatalf("result %+v; want the lost machine certificate (not a probe) kept, with no entry", res)
		}
		r.verifyExport()
	})
	t.Run("recovered_login_certificate", func(t *testing.T) {
		e := newSubjectEnv(t)
		snapshot := e.snapshotDB(t)
		lost := e.login(t, "alice") // kr2, lost with the restore
		r := e.restoredFrom(t, snapshot)
		res := r.recover(t, r.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil))
		if res.Revoked != 1 || !r.parsedKRL(t).RevokesSerial(lost.SignatureKey.Marshal(), lost.Serial) {
			t.Fatalf("result %+v; want the lost login certificate revoked", res)
		}
		r.verifyExport()
	})

	// Successive recoveries (PR #66 review).
	t.Run("recovery_after_recovery_vb_zero", func(t *testing.T) {
		var u *ssh.Certificate
		e, r1 := lostSetup(t, func(e *revokeEnv) { u = e.issueRole(t, wire.CARoleUser) })
		res1 := r1.recover(t, r1.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: u.Marshal(), Revoke: true}}, nil))
		// The recovered database is the snapshot of a second restore; the
		// signer revokes on after it, and a later KRL lists U's serial.
		snapshot2 := r1.snapshotDB(t)
		e.tick(time.Second)
		r1.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()})
		kept := r1.served(t)
		r2 := e.restored(t, snapshot2)
		e.tick(time.Second)
		res2 := r2.recover(t, r2.recoveryRequest(t, []wire.RecoveryImport{kept}, nil, nil))
		var newRow, oldRow *signerdb.Revocation
		for _, row := range r2.revocationRows(t) {
			if row.Kind == signerdb.RevocationSerial && row.Serial == u.Serial {
				switch row.LeafIndex {
				case res2.RecoveryLeaf:
					newRow = &row
				case res1.RecoveryLeaf:
					oldRow = &row
				}
			}
		}
		if newRow == nil || oldRow == nil || newRow.ValidBeforeMicros != 0 || oldRow.ValidBeforeMicros != u.ValidBefore*1_000_000 {
			t.Fatalf("rows for U: new %+v, restored %+v; want ValidBefore 0 and %d", newRow, oldRow, u.ValidBefore)
		}
		e.clock.set(time.Unix(int64(u.ValidBefore)+krl.PruneMargin+3600, 0)) //nolint:gosec // G115: a test time
		if !r2.s.republishIfDue(ctx) || !r2.parsedKRL(t).RevokesSerial(u.SignatureKey.Marshal(), u.Serial) {
			t.Fatal("U's serial left the KRL after its ValidBefore + 300, though the second recovery's entry is never pruned")
		}
		r2.verifyExport()
	})
	t.Run("recarried_certificate_accepted", func(t *testing.T) {
		var u, h *ssh.Certificate
		e := newRevokeEnv(t, 1, 1, testInstallationID)
		snapshot1 := e.snapshotDB(t)
		e.tick(time.Second)
		u, h = e.issueRole(t, wire.CARoleUser), e.issueRole(t, wire.CARoleHost)
		r1 := e.restored(t, snapshot1)
		e.tick(time.Second)
		carried := []wire.RecoveredCertificate{{Cert: u.Marshal(), Revoke: true}, {Cert: h.Marshal()}}
		r1.recover(t, r1.recoveryRequest(t, nil, carried, nil))
		kept := r1.served(t)
		// A second restore goes back before the first recovery: the request
		// carries U and H again, as keyroster revoke recover builds it.
		r2 := e.restored(t, snapshot1)
		e.tick(time.Second)
		res := r2.recover(t, r2.recoveryRequest(t, []wire.RecoveryImport{kept}, carried, nil))
		rows := rowsOf(r2.revocationRows(t), res.RecoveryLeaf)
		if res.Revoked != 1 || res.Kept != 1 || len(rows) != 1 || rows[0].Serial != u.Serial || rows[0].ValidBeforeMicros != u.ValidBefore*1_000_000 {
			t.Fatalf("result %+v, rows %+v; want U revoked at its ValidBefore %d and H kept", res, rows, u.ValidBefore)
		}
		r2.verifyExport()
	})
}

// countingBackend is a genBackend that counts, by role, every key a
// signer opens from it (03-12e).
type countingBackend struct {
	*genBackend
	cmu    sync.Mutex
	opened map[keystore.Role]int
}

func (b *countingBackend) count(role keystore.Role) {
	b.cmu.Lock()
	defer b.cmu.Unlock()
	if b.opened == nil {
		b.opened = map[keystore.Role]int{}
	}
	b.opened[role]++
}

// opens is how often a key of role was opened.
func (b *countingBackend) opens(role keystore.Role) int {
	b.cmu.Lock()
	defer b.cmu.Unlock()
	return b.opened[role]
}

func (b *countingBackend) Key(role keystore.Role, fp string) (keystore.CAKey, error) {
	b.count(role)
	return b.genBackend.Key(role, fp)
}

func (b *countingBackend) KeyAt(role keystore.Role, generation uint32, fp, location string) (keystore.CAKey, error) {
	b.count(role)
	return b.genBackend.KeyAt(role, generation, fp, location)
}

// startConfig tries to start k's signer with cfg completed by the env's
// database handles, clock and peer allowlist, and returns New's error; on
// success the env holds the new signer (03-12e).
func (k *swKit) startConfig(t *testing.T, cfg Config) error {
	t.Helper()
	k.e.close()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sdb, err := signerdb.OpenReadOnly(k.e.dbPath)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	cfg.DB, cfg.StatusDB, cfg.Clock, cfg.AllowUIDs = db, sdb, k.clk.Now, []uint32{1000}
	s, err := New(cfg)
	if err != nil {
		_ = sdb.Close()
		_ = db.Close()
		return err
	}
	k.e.db, k.e.sdb, k.e.s = db, sdb, s
	return nil
}

// TestRecoveryOpensNoCAKey (03-12e, RC-01 and RC-02): the recovery
// configuration starts on a switched state whose old key the backend still
// holds, opens only the ops and log keys, and its signer issues nothing
// and serves nothing.
func TestRecoveryOpensNoCAKey(t *testing.T) {
	recoverySigner := func(t *testing.T) (*swKit, *countingBackend) {
		t.Helper()
		k, _ := heldSwitch(t, trust.RoleUser)
		cb := &countingBackend{genBackend: k.gb}
		if err := k.startConfig(t, Config{Backend: cb, Recovery: true}); err != nil {
			t.Fatalf("start in the recovery configuration: %v", err)
		}
		return k, cb
	}
	t.Run("opens_only_ops_and_log", func(t *testing.T) {
		_, cb := recoverySigner(t)
		for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine} {
			if n := cb.opens(role); n != 0 {
				t.Fatalf("the recovery configuration opened the %s CA key %d times", role, n)
			}
		}
		if cb.opens(keystore.RoleOps) == 0 || cb.opens(keystore.RoleLog) == 0 {
			t.Fatalf("the recovery configuration opened ops %d and log %d times, want both", cb.opens(keystore.RoleOps), cb.opens(keystore.RoleLog))
		}
	})
	t.Run("recovery_signer_cannot_issue", func(t *testing.T) {
		k, _ := recoverySigner(t)
		req := k.e.request()
		req.Evidence = SignRequest(t, req, k.e.fx.Admins...)
		if _, err := k.e.s.Issue(context.Background(), Peer{UID: 1000}, req); err == nil || !strings.Contains(err.Error(), "ca_not_configured") {
			t.Fatalf("issue on the recovery signer = %v, want ca_not_configured", err)
		}
	})
	t.Run("recovery_signer_cannot_serve", func(t *testing.T) {
		k, _ := recoverySigner(t)
		dir, err := os.MkdirTemp("", "krrc")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s.sock"), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := k.e.s.Serve(ctx, l); !errors.Is(err, ErrRecoveryConfiguration) {
			t.Fatalf("Serve on the recovery signer = %v, want recovery_configuration", err)
		}
	})
}

// TestNewDefaultConfigIsServing (03-12e, SR-05): a Config that leaves
// Recovery unset is the serving configuration: it refuses a held draining
// key and, once the key is gone, opens every CA key.
func TestNewDefaultConfigIsServing(t *testing.T) {
	k, _ := heldSwitch(t, trust.RoleUser)
	cb := &countingBackend{genBackend: k.gb}
	if err := k.startConfig(t, Config{Backend: cb}); !errors.Is(err, ErrDrainingKeyUsable) {
		t.Fatalf("a zero Config with the draining key held: %v, want draining_key_still_usable", err)
	}
	k.gb.drop(t, keystore.RoleUser, 1)
	if err := k.startConfig(t, Config{Backend: cb}); err != nil {
		t.Fatalf("a zero Config once the draining key is gone: %v", err)
	}
	for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine} {
		if cb.opens(role) == 0 {
			t.Fatalf("the serving configuration did not open the %s CA key", role)
		}
	}
}

// drainedState is drainEnv with the switch of role installed and its old
// key removed, the signer serving and its clock 20 s after the ceremony
// (03-12e). It returns the kit and the draining entry's trusted_until, in
// seconds and as written.
func drainedState(t *testing.T, role string) (*swKit, uint64, string) {
	t.Helper()
	k, at := drainEnv(t)
	k.at(t, at.Add(10*time.Second))
	notes, err := k.install(t, k.switchDocs(t, at, 0, role), true)
	if err != nil || len(notes) != 1 {
		t.Fatalf("the %s switch: %v", role, err)
	}
	tu, err := unixSeconds(notes[0].TrustedUntil)
	if err != nil {
		t.Fatal(err)
	}
	k.at(t, at.Add(20*time.Second))
	return k, tu, notes[0].TrustedUntil
}

// TestRecoveryNamesCertificateBeyondDrain (03-12e, RC-04): a recovery that
// carries a certificate of a draining key whose ValidBefore is above
// trusted_until minus 300 s names it, kept or revoked, and applies as
// before; a certificate at trusted_until minus 300 s, one of the active
// key and one of a role that does not drain are not named.
func TestRecoveryNamesCertificateBeyondDrain(t *testing.T) {
	carry := func(t *testing.T, k *swKit, certs ...wire.RecoveredCertificate) *RecoveryResult {
		t.Helper()
		return k.e.recover(t, k.e.recoveryRequest(t, nil, certs, nil))
	}
	t.Run("kept_beyond_the_drain_named", func(t *testing.T) {
		k, tu, tus := drainedState(t, trust.RoleHost)
		c := k.lostCert(t, keystore.RoleHost, tu-299)
		res := carry(t, k, wire.RecoveredCertificate{Cert: c.Marshal()})
		want := BeyondDrain{Role: trust.RoleHost, Generation: 1, Serial: c.Serial, KeyID: c.KeyId, ValidBefore: tu - 299, TrustedUntil: tus, Kept: true}
		if res.Kept != 1 || len(res.BeyondDrain) != 1 || res.BeyondDrain[0] != want {
			t.Fatalf("recovery result %+v, want one kept certificate named %+v", res, want)
		}
		line := fmt.Sprintf("warning: carried certificate serial %d (key ID %s, kept) of the draining host CA generation 1 is valid until %s, after %s minus 300 s; a kept one stops working at %s",
			c.Serial, c.KeyId, unixTime(tu-299), tus, tus)
		if got := res.BeyondDrain[0].String(); got != line {
			t.Fatalf("the recovery line:\n got %q\nwant %q", got, line)
		}
	})
	t.Run("revoked_beyond_the_drain_named", func(t *testing.T) {
		k, tu, tus := drainedState(t, trust.RoleUser)
		c := k.lostCert(t, keystore.RoleUser, tu+86400)
		res := carry(t, k, wire.RecoveredCertificate{Cert: c.Marshal(), Revoke: true})
		want := BeyondDrain{Role: trust.RoleUser, Generation: 1, Serial: c.Serial, KeyID: c.KeyId, ValidBefore: tu + 86400, TrustedUntil: tus, Kept: false}
		if res.Revoked != 1 || len(res.BeyondDrain) != 1 || res.BeyondDrain[0] != want {
			t.Fatalf("recovery result %+v, want one revoked certificate named %+v", res, want)
		}
	})
	t.Run("within_the_drain_not_named", func(t *testing.T) {
		k, tu, _ := drainedState(t, trust.RoleHost)
		res := carry(t, k, wire.RecoveredCertificate{Cert: k.lostCert(t, keystore.RoleHost, tu-300).Marshal()})
		if res.Kept != 1 || len(res.BeyondDrain) != 0 {
			t.Fatalf("recovery result %+v, want the certificate at trusted_until minus 300 s kept and not named", res)
		}
	})
	t.Run("active_key_certificate_not_named", func(t *testing.T) {
		k, tu, _ := drainedState(t, trust.RoleHost)
		k.gb.mu.Lock()
		active := k.gb.keys[k.fpGen(t, keystore.RoleHost, 2)]
		k.gb.mu.Unlock()
		s := nextSerial(t, k.e.db) + 1000
		c := makeCert(t, active, ssh.HostCert, string(keystore.RoleHost), "u:lost", s, s, tu+86400, nil)
		res := carry(t, k, wire.RecoveredCertificate{Cert: c.Marshal()})
		if res.Kept != 1 || len(res.BeyondDrain) != 0 {
			t.Fatalf("recovery result %+v, want the certificate of the active key kept and not named", res)
		}
	})
	t.Run("other_role_not_named", func(t *testing.T) {
		k, tu, _ := drainedState(t, trust.RoleHost)
		res := carry(t, k, wire.RecoveredCertificate{Cert: k.lostCert(t, keystore.RoleUser, tu+86400).Marshal(), Revoke: true})
		if res.Revoked != 1 || len(res.BeyondDrain) != 0 {
			t.Fatalf("recovery result %+v, want the user certificate revoked and not named", res)
		}
	})
}

// TestRestoredPreSwitchSignerCannotIssue (03-12e, RC-03): a copy of the
// state database taken before the switch install, restored over the
// backend after retire-key removed the old key. Serve is refused (its
// bundle names the old key active), the recovery applies without any CA
// key, and after a fresh export, the switch install behind that export's
// checkpoint and retire-key, the signer issues with the new key.
func TestRestoredPreSwitchSignerCannotIssue(t *testing.T) {
	k, at := drainEnv(t)
	k.at(t, at.Add(10*time.Second))
	k.e.close()
	restored := copyState(t, k.e.dbPath)
	k.reopen(t)
	if _, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true); err != nil {
		t.Fatalf("the switch install: %v", err)
	}
	r := &swKit{e: &logEnv{t: t, dbPath: restored, fx: k.e.fx, clock: k.clk.Now}, clk: k.clk, gb: k.gb}
	t.Cleanup(r.e.close)
	recovered := false
	t.Run("start_is_refused", func(t *testing.T) {
		if err := r.start(t, r.gb); err == nil || !strings.Contains(err.Error(), "bundle key for role user") {
			t.Fatalf("serve on the restored database without the old key: %v, want the missing user key", err)
		}
	})
	t.Run("recovery_works_without_ca_keys", func(t *testing.T) {
		if err := r.startConfig(t, Config{Backend: r.gb, Recovery: true}); err != nil {
			t.Fatalf("the recovery configuration on the restored database: %v", err)
		}
		c := r.lostCert(t, keystore.RoleUser, uint64(at.Unix())+600) //nolint:gosec // G115: after 1970
		res := r.e.recover(t, r.e.recoveryRequest(t, nil, []wire.RecoveredCertificate{{Cert: c.Marshal(), Revoke: true}}, nil))
		if res.Revoked != 1 {
			t.Fatalf("recovery result %+v, want one revoked certificate", res)
		}
		recovered = true
	})
	t.Run("fresh_export_then_switch_install_with_previous", func(t *testing.T) {
		r.offline(t, func(db *signerdb.DB) {
			if err := auditExport(t, r.e.fx, db); err != nil {
				t.Fatalf("audit of the restored log: %v", err)
			}
			cp, _, err := db.LatestCheckpoint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			d := switchDocsDB(t, db, r.e.fx.Root, at, 0, trust.RoleUser)
			if _, _, err := InstallBundleWithPrevious(context.Background(), db, r.gb, nil, 0, d[0], d[1], d[2], d[3], r.clk.Now, cp); err != nil {
				t.Fatalf("the switch install on the restored database: %v", err)
			}
		})
	})
	t.Run("serve_issues_with_the_new_key", func(t *testing.T) {
		if !recovered {
			t.Fatal("the recovery of the restored database did not apply")
		}
		if res, err := r.retire(t, keystore.RoleUser); err != nil || outcomes(res) != "1 not held" {
			t.Fatalf("retire-key on the restored database = %s, %v; want generation 1 not held", outcomes(res), err)
		}
		if err := r.start(t, r.gb); err != nil {
			t.Fatalf("serve after the switch install and retire-key: %v", err)
		}
		req := r.e.request()
		req.Evidence = SignRequest(t, req, r.e.fx.Admins...)
		resp, err := r.e.s.Issue(context.Background(), Peer{UID: 1000}, req)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if got, want := ssh.FingerprintSHA256(certOf(t, resp).SignatureKey), r.fpGen(t, keystore.RoleUser, 2); got != want {
			t.Fatalf("the certificate is signed by %s, want generation 2 (%s)", got, want)
		}
	})
}

// TestUnloggedSignatureNotCovered (03-12e, a documentation test of a
// residual): a certificate signed directly with the old key, outside the
// signer, with ValidBefore a day after the switch's trusted_until, is in no
// row and no leaf, so neither the install binding nor audit sees it: both
// pass. The guarantee covers what the verified log records.
func TestUnloggedSignatureNotCovered(t *testing.T) {
	k, at := drainEnv(t)
	k.at(t, at.Add(10*time.Second))
	d := k.switchDocs(t, at, 0, trust.RoleUser)
	b, err := trust.ParseBundle(d[0])
	if err != nil {
		t.Fatal(err)
	}
	var tu uint64
	for _, ca := range b.CAs {
		if ca.Role == trust.RoleUser && ca.State == "draining" {
			if tu, err = unixSeconds(ca.TrustedUntil); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := gen1Cert(t, k.e.fx, keystore.RoleUser, nextSerial(t, k.e.db)+1000, tu+86400)
	if _, err := k.install(t, d, true); err != nil {
		t.Fatalf("the switch install with an unlogged certificate outliving it: %v", err)
	}
	if err := k.audit(t); err != nil {
		t.Fatalf("audit of the switch with an unlogged certificate outliving it: %v", err)
	}
	var n int
	if err := k.e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM issuance WHERE serial = ?`, c.Serial).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("the unlogged certificate has %d issuance rows (%v), want none", n, err)
	}
}

// TestRotationKRLKeepsLiveEntry (03-12e): after a switch, the KRL the
// signer publishes still lists a revoked certificate of the old generation
// that is still live, under the old CA key.
func TestRotationKRLKeepsLiveEntry(t *testing.T) {
	re := newRevokeEnv(t, 1, 1, testInstallationID)
	k := newSwKit(re)
	at := k.ceremonyTime(t)
	k.ceremony1(t, at, keystore.RoleUser)
	k.at(t, at.Add(5*time.Second))
	old := re.issueRole(t, wire.CARoleUser)
	re.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: old.Serial})
	k.at(t, at.Add(10*time.Second))
	if _, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true); err != nil {
		t.Fatalf("the switch install: %v", err)
	}
	k.at(t, at.Add(15*time.Second))
	newer := re.issueRole(t, wire.CARoleUser)
	re.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: newer.Serial})
	p, err := krl.Parse(re.s.GetKRL().KRL)
	if err != nil {
		t.Fatal(err)
	}
	listed := func(ca ssh.PublicKey, serial uint64) bool {
		for _, sec := range p.Certs {
			if !bytes.Equal(sec.CAKey, ca.Marshal()) {
				continue
			}
			for _, r := range sec.Serials {
				if r.Lo <= serial && serial <= r.Hi {
					return true
				}
			}
		}
		return false
	}
	if !listed(old.SignatureKey, old.Serial) {
		t.Fatalf("the KRL published after the switch (v%d) does not list serial %d under the old CA key", p.Version, old.Serial)
	}
	if !listed(newer.SignatureKey, newer.Serial) || bytes.Equal(old.SignatureKey.Marshal(), newer.SignatureKey.Marshal()) {
		t.Fatal("the certificate issued after the switch is not signed by the new key, or not listed under it")
	}
}
