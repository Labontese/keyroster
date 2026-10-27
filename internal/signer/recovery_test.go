package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
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
