//go:build linux

package state

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// UnappliedFile is the unapplied record in the state directory (root,
// 0600; PR #76 review F8 (03-08j)).
const UnappliedFile = "unapplied.json"

// MaxUnapplied caps unapplied.json. Its largest form is four fields of
// spool.MaxBundle (bundle, bundle_sigs, policy, policy_sigs), one of
// wire.MaxDirectory and one of wire.MaxDirectorySigs: about 5.1 MiB raw,
// 6.8 MiB in base64.
const MaxUnapplied = 8 << 20

// ErrUnapplied is an unapplied record that does not parse. The applier
// drops such a record and reads from accepted/ again.
var ErrUnapplied = errors.New("unapplied_record_invalid")

// Unapplied is the unapplied record (PR #76 review F8 (03-08j)): the parts
// of a capture's verified state that are ahead of accepted/, recorded when
// the applier refused the generation rendered from it for its content (a
// render error, a generation above the caps, a CA line the host's
// ssh-keygen refuses). The bundle part (Bundle, its signatures, its policy
// and the policy's signatures) is present when Bundle is non-nil, the
// directory part (Directory and its signatures) when Directory is
// non-nil. It never holds a KRL: the KRL in force is accepted/'s.
//
// The next capture is read and chained from the record (Base,
// VerifyAhead), so a host whose read window ends at a version it cannot
// apply reads past it. The record holds copies, not hashes of spool files:
// a fetcher that deletes or swaps spool files cannot redirect the chain,
// and the record is fork evidence as accepted/ is.
type Unapplied struct {
	Bundle        []byte `json:"bundle,omitempty"`
	BundleSigs    []byte `json:"bundle_sigs,omitempty"`
	Policy        []byte `json:"policy,omitempty"`
	PolicySigs    []byte `json:"policy_sigs,omitempty"`
	Directory     []byte `json:"directory,omitempty"`
	DirectorySigs []byte `json:"directory_sigs,omitempty"`
}

// Encode is the record's file content (trust.CanonicalJSON).
func (u *Unapplied) Encode() ([]byte, error) { return trust.CanonicalJSON(u) }

// ParseUnapplied decodes unapplied.json (trust.DecodeStrict, at most
// MaxUnapplied bytes). Every field is held to the cap spool.Read applies
// to the same file, a bundle part needs all four of its fields and a
// directory part both of its own, and a record with neither part is
// refused: the applier never writes one. Its errors wrap ErrUnapplied.
func ParseUnapplied(b []byte) (*Unapplied, error) {
	if len(b) > MaxUnapplied {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrUnapplied, len(b), MaxUnapplied)
	}
	u := &Unapplied{}
	if err := trust.DecodeStrict(b, u); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnapplied, err)
	}
	for _, f := range []struct {
		name string
		b    []byte
		max  int
	}{
		{"bundle", u.Bundle, spool.MaxBundle}, {"bundle_sigs", u.BundleSigs, spool.MaxBundle},
		{"policy", u.Policy, spool.MaxBundle}, {"policy_sigs", u.PolicySigs, spool.MaxBundle},
		{"directory", u.Directory, wire.MaxDirectory}, {"directory_sigs", u.DirectorySigs, wire.MaxDirectorySigs},
	} {
		if len(f.b) > f.max {
			return nil, fmt.Errorf("%w: %s is %d bytes, above %d", ErrUnapplied, f.name, len(f.b), f.max)
		}
	}
	bundle := u.Bundle != nil || u.BundleSigs != nil || u.Policy != nil || u.PolicySigs != nil
	if bundle && (u.Bundle == nil || u.BundleSigs == nil || u.Policy == nil || u.PolicySigs == nil) {
		return nil, fmt.Errorf("%w: a bundle part needs bundle, bundle_sigs, policy and policy_sigs", ErrUnapplied)
	}
	dir := u.Directory != nil || u.DirectorySigs != nil
	if dir && (u.Directory == nil || u.DirectorySigs == nil) {
		return nil, fmt.Errorf("%w: a directory part needs directory and directory_sigs", ErrUnapplied)
	}
	if !bundle && !dir {
		return nil, fmt.Errorf("%w: the record holds neither a bundle nor a directory", ErrUnapplied)
	}
	return u, nil
}

// Unapplied is the record of v against accepted: the parts of v.Next ahead
// of accepted/. It is nil when v.Refused is set (only a capture Verify
// accepted is recorded), when nothing is accepted yet or accepted holds no
// bundle, and when no part is ahead.
func (v *Verified) Unapplied(accepted *Stored) *Unapplied {
	if v.Refused != nil || accepted == nil || accepted.Bundle == nil {
		return nil
	}
	u := &Unapplied{}
	if v.Next.BundleVersion > accepted.BundleVersion {
		// After holdBundle, Next names the held step: that is what is
		// recorded.
		u.Bundle, u.BundleSigs, u.Policy, u.PolicySigs = v.Next.Bundle, v.Next.BundleSigs, v.Next.Policy, v.Next.PolicySigs
	}
	if v.Next.Directory != nil && v.Next.DirectoryVersion > accepted.DirectoryVersion {
		u.Directory, u.DirectorySigs = v.Next.Directory, v.Next.DirectorySigs
	}
	if u.Bundle == nil && u.Directory == nil {
		return nil
	}
	return u
}

// Base is the state a capture is read and chained from while the record
// exists: a copy of accepted, with the KRL, its manifest, signature and
// version accepted's, and each part of the record whose version is above
// accepted's in place of accepted's. It is (nil, nil) when accepted is nil
// and when no part is ahead (a record a commit has passed); a part that
// does not parse is ErrUnapplied.
func (u *Unapplied) Base(accepted *Stored) (*Stored, error) {
	if accepted == nil {
		return nil, nil
	}
	base := *accepted
	taken := false
	if u.Bundle != nil {
		b, err := trust.ParseBundle(u.Bundle)
		if err != nil {
			return nil, fmt.Errorf("%w: bundle: %w", ErrUnapplied, err)
		}
		pol, err := trust.ParsePolicy(u.Policy)
		if err != nil {
			return nil, fmt.Errorf("%w: policy: %w", ErrUnapplied, err)
		}
		if b.PolicySHA256 != trust.SHA256Hex(u.Policy) {
			return nil, fmt.Errorf("%w: the recorded bundle %d does not name the recorded policy", ErrUnapplied, b.Version)
		}
		if b.Version > accepted.BundleVersion {
			base.Bundle, base.BundleSigs, base.Policy, base.PolicySigs, base.BundleVersion = u.Bundle, u.BundleSigs, u.Policy, u.PolicySigs, b.Version
			base.bundle, base.policy = b, pol
			taken = true
		}
	}
	if u.Directory != nil {
		d, err := directory.Parse(u.Directory)
		if err != nil {
			return nil, fmt.Errorf("%w: directory: %w", ErrUnapplied, err)
		}
		if d.Version > accepted.DirectoryVersion {
			base.Directory, base.DirectorySigs, base.DirectoryVersion = u.Directory, u.DirectorySigs, d.Version
			taken = true
		}
	}
	if !taken {
		return nil, nil
	}
	return &base, nil
}

// VerifyAhead is Verify for a capture read from an unapplied record (PR #76
// review F8 (03-08j)): the bundle, directory and KRL steps run against
// base (Unapplied.Base), and a refused step takes the KRL alone against
// accepted (owner decision D-R2, KRLAlone), never against the record. The
// base carries accepted/'s KRL, so the newest KRL is verified against the
// bundle actually put in force and against accepted/'s KRL version. As in
// Verify, the versions between the record and the newest one are only
// chain-checked and never rendered, and the bundle in force stays the
// lowest hold step (verify).
//
// Changed is computed against accepted, not the base: an apply with nothing
// newer than the record renders it again and reports the refusal again,
// and a capture held at the bundle in force has BundleChanged false, as in
// Verify.
func VerifyAhead(p *Pins, accepted, base *Stored, in spool.State) (*Verified, error) {
	v, err := verify(p, base, accepted, in)
	if err != nil || v.Refused != nil || accepted == nil {
		return v, err
	}
	v.BundleChanged = !bytes.Equal(v.Next.Bundle, accepted.Bundle) || !bytes.Equal(v.Next.Policy, accepted.Policy)
	v.DirectoryChanged = !bytes.Equal(v.Next.Directory, accepted.Directory)
	return v, nil
}
