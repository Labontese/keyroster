//go:build linux

// Package state holds what the root applier alone trusts: its pins
// (trust-root fingerprints and threshold, installation ID), written once
// at enrollment, and the signed documents it accepted last, under
// <state>/accepted/. Verify checks every document a spool capture offers
// against those, and only the bytes it verified are rendered and stored.
package state

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// File names in the state directory and in accepted/.
const (
	PinsFile    = "pins.json"
	AcceptedDir = "accepted"

	bundleFile       = "bundle.json"
	bundleSigsFile   = "bundle.json.sigs"
	policyFile       = "policy.json"
	policySigsFile   = "policy.json.sigs"
	directoryFile    = "directory.json"
	directorySigs    = "directory.json.sigs"
	krlFile          = "krl.krl"
	krlManifestFile  = "krl.manifest.json"
	krlManifestSig   = "krl.manifest.sig"
	maxPinsFileBytes = 64 << 10
)

// Refusals. Each error's text starts with its code.
var (
	ErrPins           = errors.New("pins_invalid")
	ErrStored         = errors.New("stored_state_invalid")
	ErrBundleOlder    = errors.New("bundle_older")
	ErrBundleChainGap = errors.New("bundle_chain_gap")
	ErrBundle         = errors.New("bundle_not_verified")
	ErrBundleInstall  = errors.New("bundle_installation")
	ErrPolicyMissing  = errors.New("policy_missing")
	ErrNoBundle       = errors.New("bundle_missing")
	ErrDirOlder       = errors.New("directory_older")
	ErrDirChainGap    = errors.New("directory_chain_gap")
	ErrDir            = errors.New("directory_not_verified")
	ErrDirInstall     = errors.New("directory_installation")
	ErrKRLOlder       = errors.New("krl_older")
	ErrKRL            = errors.New("krl_not_verified")
	// ErrKRLHeader is a KRL whose header krl_version differs from the
	// KRLVersion its signed manifest names (PR #67 round-2 carry-over): the
	// agent orders KRLs by the header version (the KRL floor, RollbackTarget),
	// the manifest by its own, so the two must be one number.
	ErrKRLHeader = errors.New("krl_header_version_mismatch")
)

// Pins are the applier's trust anchors (pins.json, root 0600): the
// SHA256 fingerprints of the trust roots, how many of them must sign, and
// the installation ID every bundle, directory and KRL must name.
type Pins struct {
	TrustPins      []string `json:"trust_pins"`
	Threshold      int      `json:"threshold"`
	InstallationID string   `json:"installation_id"`
}

// Validate refuses empty pins, a threshold below 1 or above the pins, and
// an empty or malformed installation ID.
func (p *Pins) Validate() error {
	if err := trust.CheckPins(p.TrustPins, p.Threshold); err != nil {
		return fmt.Errorf("%w: %w", ErrPins, err)
	}
	if !trust.IsInstallationID(p.InstallationID) {
		return fmt.Errorf("%w: installation_id must be 32 lowercase hex digits", ErrPins)
	}
	return nil
}

// LoadPins reads pins.json from the state directory descriptor stateFd
// through spool.ReadFileAtInfo: a regular file of mode 0600 owned by the
// applier's effective uid, canonical JSON, valid pins.
func LoadPins(stateFd int) (*Pins, error) {
	b, info, err := spool.ReadFileAtInfo(stateFd, PinsFile, maxPinsFileBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPins, err)
	}
	if info.Mode != 0o600 || int(info.UID) != os.Geteuid() {
		return nil, fmt.Errorf("%w: %s must be mode 0600 and owned by uid %d (it is mode %04o, uid %d)", ErrPins, PinsFile, os.Geteuid(), info.Mode, info.UID)
	}
	var p Pins
	if err := trust.DecodeStrict(b, &p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPins, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// WritePins stores p as canonical JSON, mode 0600, in the state directory
// of l. It is enrollment's writer (03-07) and the tests'.
func WritePins(l paths.Layout, stateFd int, p *Pins) error {
	if err := p.Validate(); err != nil {
		return err
	}
	b, err := trust.CanonicalJSON(p)
	if err != nil {
		return err
	}
	if err := paths.Allowed(l, l.State(PinsFile)); err != nil {
		return err
	}
	return spool.WriteFileAt(stateFd, PinsFile, b, 0o600)
}

// Stored is the applier's accepted state: the newest bundle, its policy,
// directory and KRL it accepted, with their signatures, and their
// versions. A field is empty when nothing of that kind was accepted yet.
type Stored struct {
	Bundle, BundleSigs, Policy, PolicySigs []byte
	Directory, DirectorySigs               []byte
	KRL, KRLManifest, KRLSig               []byte
	BundleVersion, DirectoryVersion        uint64
	KRLVersion                             uint64

	bundle *trust.Bundle
	policy *trust.Policy
}

// storedFiles maps each accepted/ file to its field and cap.
func (s *Stored) files() []struct {
	name string
	dst  *[]byte
	max  int64
} {
	return []struct {
		name string
		dst  *[]byte
		max  int64
	}{
		{bundleFile, &s.Bundle, spool.MaxBundle}, {bundleSigsFile, &s.BundleSigs, spool.MaxBundle},
		{policyFile, &s.Policy, spool.MaxBundle}, {policySigsFile, &s.PolicySigs, spool.MaxBundle},
		{directoryFile, &s.Directory, wire.MaxDirectory}, {directorySigs, &s.DirectorySigs, wire.MaxDirectorySigs},
		{krlFile, &s.KRL, krl.MaxKRL}, {krlManifestFile, &s.KRLManifest, krl.MaxManifest}, {krlManifestSig, &s.KRLSig, krl.MaxManifestSig},
	}
}

// Floor is what s accepted, for spool.Read (nil s: nothing).
func (s *Stored) Floor() spool.Floor {
	if s == nil {
		return spool.Floor{}
	}
	f := spool.Floor{Bundle: s.BundleVersion, Directory: s.DirectoryVersion}
	if s.policy != nil {
		f.Policy = s.policy.Version
	}
	return f
}

// accepted/ layout (PR #67 review: the accepted documents are one
// atomic unit). Each save writes a new snapshot directory accepted/<N>/
// holding the documents, then replaces accepted/current.json, which names
// N and the SHA-256 of every file in it; that rename is the one step that
// moves the accepted state. A crash before it leaves the previous
// snapshot in force, and LoadStored refuses a snapshot whose files do not
// match their hashes, or whose bundle does not name its policy.
const (
	pointerFile    = "current.json"
	maxPointerFile = 4 << 10
)

// pointer is accepted/current.json.
type pointer struct {
	Snapshot uint64            `json:"snapshot"`
	Files    map[string]string `json:"files"`
}

// ErrSnapshot is a snapshot Activate is asked for that is missing or
// does not load.
var ErrSnapshot = errors.New("accepted_snapshot_invalid")

// LoadStored reads the accepted state through accepted/'s descriptor
// acceptedFd: current.json, then each file it names from that snapshot
// with spool.ReadFileAt, checked against its SHA-256. No current.json
// means nothing was accepted yet (nil, nil), unless accepted/ holds
// anything else, which is refused. The stored documents were verified
// when they were accepted; they are parsed again only for their versions
// and for the bundle and policy a successor is checked against, and the
// bundle must name the policy stored with it.
func LoadStored(acceptedFd int) (*Stored, error) {
	b, err := spool.ReadFileAt(acceptedFd, pointerFile, maxPointerFile)
	if errors.Is(err, unix.ENOENT) {
		names, err := spool.ListDir(acceptedFd)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStored, err)
		}
		for _, n := range names {
			if !strings.HasPrefix(n, ".") {
				if _, err := strconv.ParseUint(n, 10, 64); err != nil {
					return nil, fmt.Errorf("%w: accepted/ holds %s but no %s", ErrStored, n, pointerFile)
				}
			}
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStored, err)
	}
	var p pointer
	if err := trust.DecodeStrict(b, &p); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStored, pointerFile, err)
	}
	return loadSnapshot(acceptedFd, &p)
}

// loadSnapshot reads the snapshot p names and checks it.
func loadSnapshot(acceptedFd int, p *pointer) (*Stored, error) {
	dfd, err := openSnapshot(acceptedFd, p.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStored, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	s := &Stored{}
	known := 0
	for _, f := range s.files() {
		sum, ok := p.Files[f.name]
		if !ok {
			continue
		}
		known++
		b, err := spool.ReadFileAt(dfd, f.name, f.max)
		if err != nil {
			return nil, fmt.Errorf("%w: snapshot %d: %w", ErrStored, p.Snapshot, err)
		}
		if trust.SHA256Hex(b) != sum {
			return nil, fmt.Errorf("%w: snapshot %d: %s does not match its SHA-256 in %s", ErrStored, p.Snapshot, f.name, pointerFile)
		}
		*f.dst = b
	}
	if known != len(p.Files) {
		return nil, fmt.Errorf("%w: %s names a file that is not an accepted document", ErrStored, pointerFile)
	}
	if s.Bundle == nil || s.Policy == nil {
		return nil, fmt.Errorf("%w: accepted/ holds no bundle and policy", ErrStored)
	}
	b, err := trust.ParseBundle(s.Bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: bundle: %w", ErrStored, err)
	}
	pol, err := trust.ParsePolicy(s.Policy)
	if err != nil {
		return nil, fmt.Errorf("%w: policy: %w", ErrStored, err)
	}
	if b.PolicySHA256 != trust.SHA256Hex(s.Policy) {
		return nil, fmt.Errorf("%w: the accepted bundle %d does not name the accepted policy", ErrStored, b.Version)
	}
	s.bundle, s.policy, s.BundleVersion = b, pol, b.Version
	if s.Directory != nil {
		d, err := directory.Parse(s.Directory)
		if err != nil {
			return nil, fmt.Errorf("%w: directory: %w", ErrStored, err)
		}
		s.DirectoryVersion = d.Version
	}
	if s.KRLManifest != nil {
		m, err := krl.ParseManifest(s.KRLManifest)
		if err != nil {
			return nil, fmt.Errorf("%w: KRL manifest: %w", ErrStored, err)
		}
		s.KRLVersion = m.KRLVersion
	}
	return s, nil
}

// openSnapshot opens accepted/<n> with O_DIRECTORY|O_NOFOLLOW.
func openSnapshot(acceptedFd int, n uint64) (int, error) {
	name := strconv.FormatUint(n, 10)
	fd, err := unix.Openat(acceptedFd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("snapshot %s: %w", name, err)
	}
	return fd, nil
}

// snapshots lists the snapshot numbers in accepted/.
func snapshots(acceptedFd int) ([]uint64, error) {
	names, err := spool.ListDir(acceptedFd)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, n := range names {
		if v, err := strconv.ParseUint(n, 10, 64); err == nil && v > 0 {
			out = append(out, v)
		}
	}
	return out, nil
}

// Stage writes s, the whole accepted state (Verify's Next is), as a new
// snapshot accepted/<N>/ through spool.WriteFileAt, mode 0600, after
// paths.Allowed, and returns N. It is not in force until Activate. fault,
// when set, is called before each file (the apply engine's crash hook).
func (s *Stored) Stage(l paths.Layout, acceptedFd int, fault func(point string) error) (uint64, error) {
	existing, err := snapshots(acceptedFd)
	if err != nil {
		return 0, err
	}
	n := uint64(1)
	for _, v := range existing {
		n = max(n, v+1)
	}
	name := strconv.FormatUint(n, 10)
	if err := paths.Allowed(l, l.State(AcceptedDir, name)); err != nil {
		return 0, err
	}
	if err := unix.Mkdirat(acceptedFd, name, 0o700); err != nil {
		return 0, fmt.Errorf("snapshot %s: %w", name, err)
	}
	if err := unix.Fsync(acceptedFd); err != nil {
		return 0, err
	}
	dfd, err := openSnapshot(acceptedFd, n)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(dfd) }()
	for _, f := range s.files() {
		if *f.dst == nil {
			continue
		}
		if fault != nil {
			if err := fault("accepted:" + f.name); err != nil {
				return 0, err
			}
		}
		if err := paths.Allowed(l, l.State(AcceptedDir, name, f.name)); err != nil {
			return 0, err
		}
		if err := spool.WriteFileAt(dfd, f.name, *f.dst, 0o600); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Activate makes snapshot n the accepted state: it reads the snapshot's
// files, checks that they load as one consistent set, writes
// accepted/current.json naming them by SHA-256 (spool.WriteFileAt, an
// atomic rename), and removes every other snapshot. It is idempotent, so
// crash recovery runs it again for a commit that stopped after Stage.
func Activate(l paths.Layout, acceptedFd int, n uint64) error {
	dfd, err := openSnapshot(acceptedFd, n)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshot, err)
	}
	p := pointer{Snapshot: n, Files: map[string]string{}}
	for _, f := range (&Stored{}).files() {
		b, err := spool.ReadFileAt(dfd, f.name, f.max)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			_ = unix.Close(dfd)
			return fmt.Errorf("%w: snapshot %d: %w", ErrSnapshot, n, err)
		}
		p.Files[f.name] = trust.SHA256Hex(b)
	}
	_ = unix.Close(dfd)
	if _, err := loadSnapshot(acceptedFd, &p); err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshot, err)
	}
	b, err := trust.CanonicalJSON(p)
	if err != nil {
		return err
	}
	if err := paths.Allowed(l, l.State(AcceptedDir, pointerFile)); err != nil {
		return err
	}
	if err := spool.WriteFileAt(acceptedFd, pointerFile, b, 0o600); err != nil {
		return err
	}
	return prune(l, acceptedFd, n)
}

// prune removes every snapshot of accepted/ but keep.
func prune(l paths.Layout, acceptedFd int, keep uint64) error {
	existing, err := snapshots(acceptedFd)
	if err != nil {
		return err
	}
	for _, v := range existing {
		if v == keep {
			continue
		}
		name := strconv.FormatUint(v, 10)
		if err := paths.Allowed(l, l.State(AcceptedDir, name)); err != nil {
			return err
		}
		dfd, err := openSnapshot(acceptedFd, v)
		if err != nil {
			return err
		}
		files, err := spool.ListDir(dfd)
		for _, f := range files {
			if err == nil {
				err = unix.Unlinkat(dfd, f, 0)
			}
		}
		_ = unix.Close(dfd)
		if err != nil {
			return fmt.Errorf("remove snapshot %s: %w", name, err)
		}
		if err := unix.Unlinkat(acceptedFd, name, unix.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("remove snapshot %s: %w", name, err)
		}
	}
	return unix.Fsync(acceptedFd)
}

// Save stages s and activates it: the accepted state moves in one step.
func (s *Stored) Save(l paths.Layout, acceptedFd int, fault func(point string) error) error {
	n, err := s.Stage(l, acceptedFd, fault)
	if err != nil {
		return err
	}
	return Activate(l, acceptedFd, n)
}
