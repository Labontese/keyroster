package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// memKey is a software CA key for in-package tests.
type memKey struct{ ssh.Signer }

func (k memKey) Custody() keystore.Custody { return keystore.CustodySoftware }
func (k memKey) Algorithm() string         { return k.PublicKey().Type() }

// memBackend serves keys by fingerprint.
type memBackend struct{ keys map[string]ssh.Signer }

func (b *memBackend) Key(_ keystore.Role, fp string) (keystore.CAKey, error) {
	if s, ok := b.keys[fp]; ok {
		return memKey{s}, nil
	}
	return nil, errors.New("pinned key not present")
}

func (b *memBackend) Close() error { return nil }

func newEd25519(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// logEnv is a signer over a state database in a temporary directory,
// driven through Issue directly.
type logEnv struct {
	t       *testing.T
	dbPath  string
	backend *memBackend
	caFP    string
	logFP   string
	logPub  ssh.PublicKey
	db      *signerdb.DB
	s       *Signer
}

func newLogEnv(t *testing.T) *logEnv {
	t.Helper()
	ca, lk := newEd25519(t), newEd25519(t)
	e := &logEnv{
		t:       t,
		dbPath:  filepath.Join(t.TempDir(), "signer.db"),
		backend: &memBackend{keys: map[string]ssh.Signer{}},
		caFP:    ssh.FingerprintSHA256(ca.PublicKey()),
		logFP:   ssh.FingerprintSHA256(lk.PublicKey()),
		logPub:  lk.PublicKey(),
	}
	e.backend.keys[e.caFP], e.backend.keys[e.logFP] = ca, lk
	if err := e.open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e
}

func (e *logEnv) open() error {
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		return err
	}
	s, err := New(Config{
		Backend: e.backend, UserCAFingerprint: e.caFP, LogKeyFingerprint: e.logFP,
		DB: db, AllowUIDs: []uint32{1000}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		_ = db.Close()
		return err
	}
	e.db, e.s = db, s
	return nil
}

func (e *logEnv) close() {
	if e.db != nil {
		_ = e.db.Close()
		e.db, e.s = nil, nil
	}
}

func (e *logEnv) request() *wire.IssueRequest {
	e.t.Helper()
	req := &wire.IssueRequest{
		CARole:          wire.CARoleUser,
		SubjectKey:      newEd25519(e.t).PublicKey().Marshal(),
		Subject:         "u:alice",
		Principals:      []string{"alice"},
		ValidForSeconds: 600,
		CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	return req
}

func (e *logEnv) issue() (*wire.IssueResponse, error) {
	return e.s.Issue(context.Background(), Peer{UID: 1000}, e.request())
}

func (e *logEnv) counts() (leaves, issued int, last uint64) {
	e.t.Helper()
	hashes, err := e.db.LeafHashes(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	err = e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM issuance`).Scan(&issued)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	last, err = e.db.LastSerial(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return len(hashes), issued, last
}

// verifyExport exports the log and verifies it with the pinned log key.
func (e *logEnv) verifyExport() *audit.Report {
	e.t.Helper()
	var buf bytes.Buffer
	if _, err := audit.Export(context.Background(), &buf, e.db); err != nil {
		e.t.Fatal(err)
	}
	rep, err := audit.Verify(&buf, audit.Options{LogKey: e.logPub})
	if err != nil {
		e.t.Fatalf("audit.Verify: %v", err)
	}
	return rep
}

// failingSigner is a checkpoint signer whose Sign always fails.
type failingSigner struct{ note.Signer }

func (failingSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("injected checkpoint signing failure")
}

// TestCheckpointFailureReleasesNoCertificate: when the checkpoint cannot be
// signed inside the issuance transaction, no certificate is returned, no
// leaf, issuance row or serial is committed, and the next issuance works.
func TestCheckpointFailureReleasesNoCertificate(t *testing.T) {
	e := newLogEnv(t)
	first, err := e.issue()
	if err != nil || first.LeafIndex != 0 {
		t.Fatalf("first issuance: %+v, %v", first, err)
	}
	leaves, issued, last := e.counts()

	e.s.mu.Lock()
	orig := e.s.cpSigner
	e.s.cpSigner = failingSigner{orig}
	e.s.mu.Unlock()

	resp, err := e.issue()
	if resp != nil {
		t.Fatalf("a certificate was returned although the checkpoint was not signed: serial %d", resp.Serial)
	}
	var r *refusal
	if !errors.As(err, &r) || r.code != wire.CodeUnavailable {
		t.Fatalf("error = %v, want an unavailable refusal", err)
	}
	if l, i, s := e.counts(); l != leaves || i != issued || s != last {
		t.Fatalf("after the failure: %d leaves, %d issuances, serial %d; want unchanged %d, %d, %d", l, i, s, leaves, issued, last)
	}

	e.s.mu.Lock()
	e.s.cpSigner = orig
	e.s.mu.Unlock()
	next, err := e.issue()
	if err != nil || next.LeafIndex != 1 || next.Serial <= first.Serial {
		t.Fatalf("issuance after the failure: %+v, %v", next, err)
	}
	if rep := e.verifyExport(); rep.Size != 2 || rep.Serials != 2 {
		t.Fatalf("export after the failure: %+v", rep)
	}
}

// TestIssueResponseCarriesCommittedLeaf: the leaf index in the response
// names a committed leaf that holds exactly the returned certificate.
func TestIssueResponseCarriesCommittedLeaf(t *testing.T) {
	e := newLogEnv(t)
	for i := range 3 {
		resp, err := e.issue()
		if err != nil {
			t.Fatal(err)
		}
		if resp.LeafIndex != uint64(i) { //nolint:gosec // G115: small test index
			t.Fatalf("leaf index %d, want %d", resp.LeafIndex, i)
		}
		var found bool
		err = e.db.ForEachLeaf(context.Background(), func(idx uint64, raw []byte) error {
			if idx != resp.LeafIndex {
				return nil
			}
			l, err := tlog.DecodeLeaf(raw)
			if err != nil {
				return err
			}
			b, err := tlog.DecodeIssueBody(l.Body)
			if err != nil {
				return err
			}
			found = bytes.Equal(b.Cert, resp.Cert) && b.Serial == resp.Serial
			return nil
		})
		if err != nil || !found {
			t.Fatalf("leaf %d does not hold the returned certificate (%v)", resp.LeafIndex, err)
		}
	}
	if rep := e.verifyExport(); rep.Size != 3 || rep.Serials != 3 {
		t.Fatalf("report %+v", rep)
	}
}

// TestStartRefusedOnLogMismatch: a signer whose stored leaves do not
// reproduce the latest signed checkpoint refuses to start.
func TestStartRefusedOnLogMismatch(t *testing.T) {
	cases := map[string]string{
		"leaf_bytes_modified":          `UPDATE log_leaf SET leaf = substr(leaf, 1, length(leaf) - 1) || x'00' WHERE idx = 0`,
		"leaf_and_hash_modified":       `UPDATE log_leaf SET leaf = substr(leaf, 1, length(leaf) - 1) || x'00', leaf_hash = zeroblob(32) WHERE idx = 1`,
		"last_leaf_deleted":            `DELETE FROM log_leaf WHERE idx = 2`,
		"latest_checkpoint_deleted":    `DELETE FROM checkpoint WHERE size = 3`,
		"checkpoint_from_another_size": `UPDATE checkpoint SET note = (SELECT note FROM checkpoint WHERE size = 1) WHERE size = 3`,
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogEnv(t)
			for range 3 {
				if _, err := e.issue(); err != nil {
					t.Fatal(err)
				}
			}
			e.close()
			raw, err := sql.Open("sqlite", e.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			err = e.open()
			if err == nil || !strings.Contains(err.Error(), "log state mismatch") {
				t.Fatalf("New after %s: %v, want log state mismatch", name, err)
			}
		})
	}
	t.Run("unmodified_restarts", func(t *testing.T) {
		e := newLogEnv(t)
		if _, err := e.issue(); err != nil {
			t.Fatal(err)
		}
		e.close()
		if err := e.open(); err != nil {
			t.Fatalf("restart: %v", err)
		}
		if resp, err := e.issue(); err != nil || resp.LeafIndex != 1 {
			t.Fatalf("issue after restart: %+v, %v", resp, err)
		}
	})
}

func TestLogKeyPinning(t *testing.T) {
	e := newLogEnv(t)
	e.close()
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for name, cfg := range map[string]Config{
		"log_key_missing":   {LogKeyFingerprint: ""},
		"log_key_is_ca_key": {LogKeyFingerprint: e.caFP},
		"log_key_absent":    {LogKeyFingerprint: "SHA256:absent"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.Backend, cfg.DB, cfg.UserCAFingerprint, cfg.AllowUIDs = e.backend, db, e.caFP, []uint32{1}
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted the configuration")
			}
		})
	}
}
