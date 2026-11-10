package signer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"

	"github.com/Labontese/keyroster/internal/cert"
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

// loadDirectory reads the installed directory at start (readDirectory)
// and makes it the signer's directory state through setDirectoryLocked,
// which publishes the Status snapshot (03-08i), also when no directory is
// stored. It runs in New, before Serve.
func (s *Signer) loadDirectory(ctx context.Context) error {
	ds, err := s.readDirectory(ctx)
	if err != nil {
		return err
	}
	s.setDirectoryLocked(ds)
	return nil
}

// readDirectory reads the installed directory at start and returns the
// directory state it gives. The stored row
// must be exactly the one the verified log's last directory_install entry
// records (checkDirectoryLogged), or the signer refuses to start (T-02-14).
// Then it checks the directory against the policy in force (s.policy): it
// must parse, name this installation or none (CheckStoredInstallation:
// the owner's lenient D-04 answer, 03-01, keeps an ID-less directory
// authorized under a bundle with an ID, with a warning), carry the admin
// quorum's signatures and fit the policy's CA profiles. On any of those
// failures the signer still starts, because the
// admin path needs no directory, but refuses every login
// (directory_not_authorized) until a directory signed under the policy in
// force is installed (T-02-15). It returns the zero state when nothing is
// stored; the bytes, signatures and version without a parsed directory
// when the stored document does not parse; a parsed directory that is not
// authorized when it fails the installation, signature or policy check;
// and an authorized one only when every check passes (03-08i).
func (s *Signer) readDirectory(ctx context.Context) (directoryState, error) {
	var ds directoryState
	stored, err := s.db.LatestDirectory(ctx)
	if err != nil {
		return ds, err
	}
	if err := checkDirectoryLogged(stored, s.loaded.lastDirectory); err != nil {
		return ds, err
	}
	if stored == nil {
		return ds, nil
	}
	ds.directoryRaw, ds.directorySigs, ds.directoryVersion = stored.Doc, stored.Sigs, stored.Version
	d, err := directory.Parse(stored.Doc)
	if err != nil {
		// UNVERIFIED (03-08i): installs accept only parsed documents and
		// start-up requires the stored row to match the log, so no stored
		// state reaches this today.
		s.log.Error("installed directory does not parse: logins are refused until a valid directory is installed",
			"directory_version", stored.Version, "error", err.Error())
		return ds, nil
	}
	ds.directory = d
	if err := directory.CheckStoredInstallation(d, s.installationID); err != nil {
		s.log.Error("installed directory is bound to another installation than the trust bundle in force: logins are refused until a directory for this installation is installed",
			"directory_version", stored.Version, "error", err.Error())
		return ds, nil
	}
	if d.InstallationID == "" && s.installationID != "" {
		// The owner's lenient D-04 answer (03-01): an ID-less directory
		// keeps authorizing logins on the signer; agents never accept it.
		s.log.Warn("installed directory names no installation, but the trust bundle in force does: logins stay authorized (lenient transition); bind it with keyroster directory rebind",
			"directory_version", stored.Version, "installation_id", s.installationID)
	}
	if _, err := directory.VerifySignatures(stored.Doc, stored.Sigs, s.policy); err != nil {
		s.log.Error("installed directory is not signed by the admin quorum of the policy in force: logins are refused until a re-signed directory is installed",
			"directory_version", stored.Version, "policy_version", s.policy.Version, "error", err.Error())
		return ds, nil
	}
	if err := directory.CheckPolicy(d, s.policy); err != nil {
		s.log.Error("installed directory exceeds the policy in force: logins are refused until a conforming directory is installed",
			"directory_version", stored.Version, "policy_version", s.policy.Version, "error", err.Error())
		return ds, nil
	}
	ds.directoryAuthorized = true
	s.log.Info("directory loaded", "directory_version", stored.Version, "policy_version", s.policy.Version)
	return ds, nil
}

// setDirectoryLocked makes ds the signer's directory state and publishes
// the Status snapshot of it (publishStatusLocked), in one call (03-08i). It
// is the only writer of the directory state (TestStatusWriters). The
// caller holds s.mu, or runs in New before Serve; InstallDirectory calls it
// only after its transaction committed.
func (s *Signer) setDirectoryLocked(ds directoryState) {
	s.directoryState = ds
	s.publishStatusLocked()
}

// InstallDirectory installs a new directory version online, without a
// restart (D-01). Under s.mu it checks that the policy in force's admin
// quorum signed the document (directory_quorum_not_met) and that its
// version and prev follow the installed version (directory_version_chain)
// before it parses the document, so neither an unsigned document nor a
// replayed older version is parsed (T-02-12). Then it parses the
// document strictly (directory_invalid), checks that it names the
// installation of the bundle in force (directory_installation_missing,
// directory_installation_mismatch, directory_installation_unknown; D-04),
// checks the chain again on the parsed document, checks that it fits
// the policy's CA profiles (directory_exceeds_policy), and checks that host
// agents can render it against the installed directory
// (directory_unrenderable, directory.CheckRenderable; F07 (03-08h)). Then
// one transaction stores it and appends a directory_install leaf with the
// document and its signatures, and only after COMMIT does the signer
// switch to it and publish the Status snapshot (setDirectoryLocked,
// 03-08i).
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
	if err := directory.CheckSuccessorBytes(s.directoryRaw, req.Directory); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_version_chain", err)
	}
	d, err := directory.Parse(req.Directory)
	if err != nil {
		return nil, refusalErr(wire.CodeMalformed, "directory_invalid", err)
	}
	// D-04, the T-03-20 rule: a directory signed by these admins for
	// another installation, or for none while this one has an ID, never
	// installs here.
	switch err := directory.CheckInstallation(d, s.installationID); {
	case errors.Is(err, directory.ErrInstallationMissing):
		return nil, refusalErr(wire.CodeRefused, "directory_installation_missing", err)
	case errors.Is(err, directory.ErrInstallationMismatch):
		return nil, refusalErr(wire.CodeRefused, "directory_installation_mismatch", err)
	case err != nil:
		return nil, refusalErr(wire.CodeRefused, "directory_installation_unknown", err)
	}
	// The names reserved for probe certificates (03-10, Q4): a new
	// directory may not grant the probe principal prefix to a role, map the
	// probe account or name a machine probe.* (03-11, PD5); nor give a
	// machine more principals than a certificate holds (03-11, default 5).
	// Not in directory.Validate or CheckPolicy, so a directory already
	// stored still loads and verifies.
	if detail := reservedNames(d); detail != "" {
		return nil, refusalErr(wire.CodeRefused, detail, nil)
	}
	// Not reachable today: Parse accepts only canonical bytes, whose
	// version and prev CheckSuccessorBytes read the same way. Kept so the
	// chain is checked on the parsed document should that ever change.
	if err := directory.CheckSuccessor(s.directoryRaw, d); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_version_chain", err)
	}
	if err := directory.CheckPolicy(d, s.policy); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_exceeds_policy", err)
	}
	// F07 (03-08h): a directory host agents cannot render, alone or in the
	// intermediate generation of a move from the installed version, is
	// refused here, never on stored state. s.directory is nil before the
	// first install.
	if err := directory.CheckRenderable(d, s.directory); err != nil {
		return nil, refusalErr(wire.CodeRefused, "directory_unrenderable", err)
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
	// After COMMIT, before the answer (03-08i): a Status after this
	// install's answer reports it.
	s.setDirectoryLocked(directoryState{
		directory:           d,
		directoryRaw:        append([]byte(nil), req.Directory...),
		directorySigs:       append([]byte(nil), req.Sigs...),
		directoryVersion:    d.Version,
		directoryAuthorized: true,
	})
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

// reservedNames returns principal_reserved for a directory with a role
// principal that has cert.ReservedPrincipalPrefix, account_reserved for
// one with a host-group account named cert.ReservedAccountName (03-10,
// Q4), machine_name_reserved for one with a machine named with the probe
// key ID prefix, machine_principals_exceed for one with a machine whose
// roles' principals together exceed cert.MaxPrincipals, so that it could
// never renew (03-11, default 5), and "" otherwise. InstallDirectory alone
// calls it.
func reservedNames(d *directory.Directory) string {
	for _, r := range d.Roles {
		for _, p := range r.Principals {
			if strings.HasPrefix(p, cert.ReservedPrincipalPrefix) {
				return "principal_reserved"
			}
		}
	}
	for _, g := range d.HostGroups {
		for _, a := range g.Accounts {
			if a.Account == cert.ReservedAccountName {
				return "account_reserved"
			}
		}
	}
	for i := range d.Machines {
		m := &d.Machines[i]
		if strings.HasPrefix(m.Name, reservedMachinePrefix) {
			return "machine_name_reserved"
		}
		// A MachineGrant error cannot occur after Parse validated the
		// roles; such a machine is left to Parse.
		if g, err := d.MachineGrant(m); err == nil && len(g.Principals) > cert.MaxPrincipals {
			return "machine_principals_exceed"
		}
	}
	return ""
}
