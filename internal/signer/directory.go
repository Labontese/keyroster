package signer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// directoryState is the installed directory (D-01) as the signer uses it.
// Every field is guarded by Signer.mu.
type directoryState struct {
	// directory is the parsed directory in force, nil when none is
	// installed or the stored one does not parse.
	directory *directory.Directory
	// directoryRaw is the canonical bytes of the installed directory (nil
	// when none is installed): the next version's prev is their SHA-256.
	directoryRaw []byte
	// directorySigs is the admins' signatures it was installed with.
	directorySigs []byte
	// directoryVersion is the installed directory's version, 0 for none.
	directoryVersion uint64
	// directoryAuthorized is set when the installed directory parses, is
	// signed by the admin quorum of the policy in force and fits that
	// policy. Login issuance refuses while it is false.
	directoryAuthorized bool
}

// loadDirectory reads the installed directory at start. The stored row
// must be exactly the one the verified log's last directory_install entry
// records (checkDirectoryLogged), or the signer refuses to start (T-02-14).
// Then it checks the directory against the policy in force (s.policy): it
// must parse, carry the admin quorum's signatures and fit the user CA
// profile. On any of those failures the signer still starts, because the
// admin path needs no directory, but refuses every login
// (directory_not_authorized) until a directory signed under the policy in
// force is installed (T-02-15).
func (s *Signer) loadDirectory(ctx context.Context) error {
	stored, err := s.db.LatestDirectory(ctx)
	if err != nil {
		return err
	}
	if err := checkDirectoryLogged(stored, s.loaded.lastDirectory); err != nil {
		return err
	}
	if stored == nil {
		return nil
	}
	s.directoryRaw, s.directorySigs, s.directoryVersion = stored.Doc, stored.Sigs, stored.Version
	d, err := directory.Parse(stored.Doc)
	if err != nil {
		s.log.Error("installed directory does not parse: logins are refused until a valid directory is installed",
			"directory_version", stored.Version, "error", err.Error())
		return nil
	}
	s.directory = d
	if _, err := directory.VerifySignatures(stored.Doc, stored.Sigs, s.policy); err != nil {
		s.log.Error("installed directory is not signed by the admin quorum of the policy in force: logins are refused until a re-signed directory is installed",
			"directory_version", stored.Version, "policy_version", s.policy.Version, "error", err.Error())
		return nil
	}
	if err := directory.CheckPolicy(d, s.policy); err != nil {
		s.log.Error("installed directory exceeds the policy in force: logins are refused until a conforming directory is installed",
			"directory_version", stored.Version, "policy_version", s.policy.Version, "error", err.Error())
		return nil
	}
	s.directoryAuthorized = true
	s.log.Info("directory loaded", "directory_version", stored.Version, "policy_version", s.policy.Version)
	return nil
}

// InstallDirectory installs a new directory version online, without a
// restart (D-01). Under s.mu it checks that the policy in force's admin
// quorum signed the document (directory_quorum_not_met), first, so a peer
// the admins did not authorize never gets it parsed (T-02-12). Then it
// parses the document strictly (directory_invalid) and checks that it
// follows the installed version (directory_version_chain) and fits the
// user CA profile (directory_exceeds_policy). Then one transaction stores it and
// appends a directory_install leaf with the document and its signatures,
// and only after COMMIT does the signer switch to it.
func (s *Signer) InstallDirectory(ctx context.Context, peer Peer, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req == nil {
		return nil, refusalErr(wire.CodeMalformed, "malformed_request", nil)
	}
	admins, err := directory.VerifySignatures(req.Directory, req.Sigs, s.policy)
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_quorum_not_met", err)
	}
	d, err := directory.Parse(req.Directory)
	if err != nil {
		return nil, refusalErr(wire.CodeMalformed, "directory_invalid", err)
	}
	if err := directory.CheckSuccessor(s.directoryRaw, d); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_version_chain", err)
	}
	if err := directory.CheckPolicy(d, s.policy); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_exceeds_policy", err)
	}
	now := s.clock()
	body, err := (&tlog.DirectoryInstallBody{
		Version:       d.Version,
		PolicyVersion: s.policy.Version,
		Directory:     req.Directory,
		Sigs:          req.Sigs,
	}).Encode()
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_invalid", err)
	}
	var leafIndex uint64
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The admin set the signatures were counted against is the policy
		// loaded at start; commit only while that is still in force.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		if err := s.db.InsertDirectory(tx, signerdb.StoredDirectory{
			Version:       d.Version,
			Doc:           req.Directory,
			Sigs:          req.Sigs,
			PolicyVersion: s.policy.Version,
			InstalledAt:   now,
		}); err != nil {
			return err
		}
		idx, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindDirectoryInstall, Body: body})
		leafIndex = idx
		return err
	})
	if err != nil {
		var r *refusal
		if errors.As(err, &r) {
			return nil, err
		}
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}
	s.directory = d
	s.directoryRaw = append([]byte(nil), req.Directory...)
	s.directorySigs = append([]byte(nil), req.Sigs...)
	s.directoryVersion = d.Version
	s.directoryAuthorized = true
	sum := sha256.Sum256(req.Directory)
	s.log.Info("directory installed",
		"directory_version", d.Version,
		"sha256", trust.SHA256Hex(req.Directory),
		"leaf_index", leafIndex,
		"admins", len(admins),
		"users", len(d.Users),
		"roles", len(d.Roles),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.InstallDirectoryResponse{Version: d.Version, LeafIndex: leafIndex, SHA256: sum}, nil
}

// GetDirectory reports the installed directory as the signer holds it:
// its version (0 when none is installed), its canonical bytes and
// signatures as installed, and whether it is authorized under the policy
// in force. A stored directory that no longer verifies is reported with
// its bytes and Authorized false, so the server can mirror exactly what
// the signer holds.
func (s *Signer) GetDirectory() *wire.GetDirectoryResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.directoryRaw == nil {
		return &wire.GetDirectoryResponse{}
	}
	return &wire.GetDirectoryResponse{
		Version:    s.directoryVersion,
		Directory:  append([]byte(nil), s.directoryRaw...),
		Sigs:       append([]byte(nil), s.directorySigs...),
		Authorized: s.directoryAuthorized,
	}
}
