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

// LoadStored reads accepted/ through its descriptor acceptedFd with
// spool.ReadFileAt. No bundle.json means nothing was accepted yet (nil,
// nil). The stored documents were verified when they were accepted; they
// are parsed again only for their versions and for the bundle and policy
// a successor is checked against.
func LoadStored(acceptedFd int) (*Stored, error) {
	s := &Stored{}
	found := false
	for _, f := range s.files() {
		b, err := spool.ReadFileAt(acceptedFd, f.name, f.max)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStored, err)
		}
		*f.dst, found = b, true
	}
	if !found {
		return nil, nil
	}
	if s.Bundle == nil || s.Policy == nil {
		return nil, fmt.Errorf("%w: accepted/ holds no bundle and policy", ErrStored)
	}
	b, err := trust.ParseBundle(s.Bundle)
	if err != nil {
		return nil, fmt.Errorf("%w: bundle: %w", ErrStored, err)
	}
	p, err := trust.ParsePolicy(s.Policy)
	if err != nil {
		return nil, fmt.Errorf("%w: policy: %w", ErrStored, err)
	}
	s.bundle, s.policy, s.BundleVersion = b, p, b.Version
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

// Save writes s to accepted/ (descriptor acceptedFd, path
// l.State(AcceptedDir)) through spool.WriteFileAt, mode 0600, after
// paths.Allowed. A file whose field is empty is left as it is: a kind is
// never un-accepted.
func (s *Stored) Save(l paths.Layout, acceptedFd int) error {
	for _, f := range s.files() {
		if *f.dst == nil {
			continue
		}
		if err := paths.Allowed(l, l.State(AcceptedDir, f.name)); err != nil {
			return err
		}
		if err := spool.WriteFileAt(acceptedFd, f.name, *f.dst, 0o600); err != nil {
			return err
		}
	}
	return nil
}
