//go:build linux

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// Verified is a spool capture checked against the pins and the accepted
// state: the bundle, policy, directory and KRL in force after it, and
// Next, the accepted state to store once the generation rendered from
// them has passed its self-test. Directory is nil while no directory was
// ever accepted, KRL nil while no KRL was ever published.
type Verified struct {
	Bundle    *trust.Bundle
	Policy    *trust.Policy
	Directory *directory.Directory
	KRL       *krl.Parsed
	Next      Stored

	BundleChanged, DirectoryChanged, KRLChanged bool

	// BundleHeld is set when the capture offered a newer bundle than the
	// one in force after it: the newest offered directory verifies only
	// under an earlier policy of the bundle chain, so the bundle (and a
	// KRL only its ops key verifies) waits for the next capture (PR #67
	// review).
	BundleHeld bool

	// steps is the bundle chain of this capture: the stored bundle (when
	// there is one), then each successor verified.
	steps []bundleStep
}

// bundleStep is one bundle of the chain Verify walked, with its policy
// and their documents.
type bundleStep struct {
	bundle      *trust.Bundle
	policy      *trust.Policy
	doc, polDoc spool.Doc
}

// Changed reports whether the capture moved any kind forward.
func (v *Verified) Changed() bool { return v.BundleChanged || v.DirectoryChanged || v.KRLChanged }

// AsStored returns Next as a *Stored with its parsed bundle and policy,
// the prev a later capture is verified against (a capture superseding a
// pending transition, 03-05 PR #57 review).
func (v *Verified) AsStored() *Stored {
	s := v.Next
	s.bundle, s.policy = v.Bundle, v.Policy
	return &s
}

// Verify checks the spool capture in against the pins p and the accepted
// state prev (nil when nothing was accepted yet):
//
//   - Bundle. With no stored bundle, the newest offered bundle must pass
//     the rule keyroster's clients apply (serverclient.Trust): its root
//     set is exactly the pins at the pinned threshold and that many
//     pinned roots signed it and its policy, it verifies under its own
//     roots, it names its policy's SHA-256 and no policy admin is a root.
//     With a stored bundle, every offered bundle above it must be the next
//     version by trust.VerifySuccessor, in order (a missing version is
//     bundle_chain_gap); offering only older versions is bundle_older;
//     equal is a no-op. Every accepted bundle must name the pinned
//     installation ID.
//   - Directory. The newest offered directory above the stored one must
//     carry the admin quorum of the policy in force, parse, name the pinned installation
//     (directory.CheckInstallation, strict: agents never accept a
//     directory without an ID) and fit the policy (directory.CheckPolicy).
//     With a stored directory, every version from it to the newest must be
//     offered and chain by version and prev hash (directory.CheckSuccessor):
//     the newest one's signatures then authenticate the versions between,
//     which are never rendered. With none stored the newest is checked
//     standalone. Offering only older versions is directory_older. When it
//     carries the quorum only of an earlier policy of this capture's
//     bundle chain (a host catching up, MaxVersionsPerKind directory
//     versions at a time, across a policy rotation; PR #67 review), the
//     bundle is taken only up to that policy (BundleHeld) and the rest
//     waits for the next capture: what a fetcher withholding the newer
//     bundles would have shown, so nothing is accepted that could not be
//     accepted already.
//   - KRL. The newest complete KRL: equal to the stored one is a no-op,
//     an older version krl_older; otherwise krl.VerifyManifest against the
//     bundle in force, the pinned installation ID and the stored version,
//     then krl.Parse, and the KRL's header krl_version must be the
//     manifest's (krl_header_version_mismatch). With BundleHeld, a KRL whose manifest the bundle in
//     force does not verify waits with the bundle.
//
// Verify reads only in; the bytes it checks are the bytes it returns in
// Next.
func Verify(p *Pins, prev *Stored, in spool.State) (*Verified, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	v := &Verified{}
	if prev != nil {
		v.Next = *prev
	}
	if err := v.verifyBundle(p, prev, in); err != nil {
		return nil, err
	}
	if err := v.verifyDirectory(p, prev, in); err != nil {
		return nil, err
	}
	if err := v.verifyKRL(p, prev, in); err != nil {
		return nil, err
	}
	return v, nil
}

func sortedVersions[T any](m map[uint64]T) []uint64 {
	vs := slices.Collect(maps.Keys(m))
	slices.Sort(vs)
	return vs
}

// leanBundle is what is read from an offered bundle before any signature
// over it is checked: its root set (compared with the pins) and the
// policy hash (to pick the policy among the offered ones).
type leanBundle struct {
	Root         trust.RootSet `json:"root"`
	PolicySHA256 string        `json:"policy_sha256"`
}

// findPolicy returns the offered policy, or the stored one, whose SHA-256
// is sum.
func findPolicy(sum string, prev *Stored, in spool.State) (spool.Doc, bool) {
	if prev != nil && prev.Policy != nil && trust.SHA256Hex(prev.Policy) == sum {
		return spool.Doc{Body: prev.Policy, Sigs: prev.PolicySigs}, true
	}
	for _, pv := range sortedVersions(in.Policies) {
		if d := in.Policies[pv]; trust.SHA256Hex(d.Body) == sum {
			return d, true
		}
	}
	return spool.Doc{}, false
}

func (v *Verified) verifyBundle(p *Pins, prev *Stored, in spool.State) error {
	vs := sortedVersions(in.Bundles)
	if prev == nil || prev.Bundle == nil {
		if len(vs) == 0 {
			return fmt.Errorf("%w: the spool offers no trust bundle and none is accepted", ErrNoBundle)
		}
		doc := in.Bundles[vs[len(vs)-1]]
		b, pol, polDoc, err := verifyPinned(doc, p, in)
		if err != nil {
			return err
		}
		v.Bundle, v.Policy, v.BundleChanged = b, pol, true
		v.Next.Bundle, v.Next.BundleSigs, v.Next.Policy, v.Next.PolicySigs, v.Next.BundleVersion = doc.Body, doc.Sigs, polDoc.Body, polDoc.Sigs, b.Version
		v.steps = []bundleStep{{bundle: b, policy: pol, doc: doc, polDoc: polDoc}}
		return nil
	}
	v.Bundle, v.Policy = prev.bundle, prev.policy
	v.steps = []bundleStep{{bundle: prev.bundle, policy: prev.policy, doc: spool.Doc{Body: prev.Bundle, Sigs: prev.BundleSigs}, polDoc: spool.Doc{Body: prev.Policy, Sigs: prev.PolicySigs}}}
	if len(vs) == 0 || vs[len(vs)-1] == prev.BundleVersion {
		return nil
	}
	if vs[len(vs)-1] < prev.BundleVersion {
		return fmt.Errorf("%w: the spool offers bundle version %d, below the accepted version %d", ErrBundleOlder, vs[len(vs)-1], prev.BundleVersion)
	}
	cur, curBytes, curPolicy := prev.bundle, prev.Bundle, prev.Policy
	for ver := prev.BundleVersion + 1; ver <= vs[len(vs)-1]; ver++ {
		doc, ok := in.Bundles[ver]
		if !ok {
			return fmt.Errorf("%w: bundle version %d is missing between the accepted version %d and the offered version %d", ErrBundleChainGap, ver, prev.BundleVersion, vs[len(vs)-1])
		}
		var lean leanBundle
		if err := json.Unmarshal(doc.Body, &lean); err != nil {
			return fmt.Errorf("%w: bundle version %d is not a JSON document", ErrBundle, ver)
		}
		pol, ok := findPolicy(lean.PolicySHA256, &Stored{Policy: curPolicy, PolicySigs: v.Next.PolicySigs}, in)
		if !ok {
			return fmt.Errorf("%w: no offered policy has the SHA-256 that bundle version %d names", ErrPolicyMissing, ver)
		}
		nb, np, err := trust.VerifySuccessor(cur, curBytes, curPolicy, doc.Body, doc.Sigs, pol.Body, pol.Sigs)
		if err != nil {
			return fmt.Errorf("%w: bundle version %d: %w", ErrBundle, ver, err)
		}
		if nb.InstallationID != p.InstallationID {
			return fmt.Errorf("%w: bundle version %d names installation %q, the pin is %s", ErrBundleInstall, ver, nb.InstallationID, p.InstallationID)
		}
		cur, curBytes, curPolicy = nb, doc.Body, pol.Body
		v.Bundle, v.Policy, v.BundleChanged = nb, np, true
		v.Next.Bundle, v.Next.BundleSigs, v.Next.Policy, v.Next.PolicySigs, v.Next.BundleVersion = doc.Body, doc.Sigs, pol.Body, pol.Sigs, nb.Version
		v.steps = append(v.steps, bundleStep{bundle: nb, policy: np, doc: doc, polDoc: pol})
	}
	return nil
}

// holdBundle takes the bundle chain only up to step k: the bundle,
// policy and their documents in force after this capture are step k's.
// Only a capture with a stored bundle holds one, so step 0 is the stored
// bundle and the bundle changed exactly when k > 0.
func (v *Verified) holdBundle(k int) {
	st := v.steps[k]
	v.Bundle, v.Policy, v.BundleHeld, v.BundleChanged = st.bundle, st.policy, true, k > 0
	v.Next.Bundle, v.Next.BundleSigs, v.Next.Policy, v.Next.PolicySigs, v.Next.BundleVersion = st.doc.Body, st.doc.Sigs, st.polDoc.Body, st.polDoc.Sigs, st.bundle.Version
}

// verifyPinned is the first acceptance of a bundle, serverclient.Trust's
// rule on spool bytes: authenticate before parsing (the root set must be
// exactly the pins, and that many of them must have signed bundle and
// policy), then trust.VerifySelfSigned, trust.MatchPins, the policy hash,
// the policy's own rules and no admin a root, and the pinned installation.
func verifyPinned(doc spool.Doc, p *Pins, in spool.State) (*trust.Bundle, *trust.Policy, spool.Doc, error) {
	var lean leanBundle
	if err := json.Unmarshal(doc.Body, &lean); err != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: the offered bundle is not a JSON document", ErrBundle)
	}
	if trust.MatchPins(&trust.Bundle{Root: lean.Root}, p.TrustPins, p.Threshold) != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: the offered bundle's root set is not the pinned roots at the pinned threshold", ErrBundle)
	}
	roots := make(map[string]ssh.PublicKey, len(lean.Root.Keys))
	for _, rk := range lean.Root.Keys {
		pub, err := trust.ParseKey(rk.Key)
		if err != nil {
			return nil, nil, spool.Doc{}, fmt.Errorf("%w: a pinned root key does not parse", ErrBundle)
		}
		roots[ssh.FingerprintSHA256(pub)] = pub
	}
	polDoc, ok := findPolicy(lean.PolicySHA256, nil, in)
	if !ok {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: no offered policy has the SHA-256 the bundle names", ErrPolicyMissing)
	}
	for _, d := range []struct {
		what, namespace string
		doc             spool.Doc
	}{{"bundle", trust.NamespaceBundle, doc}, {"policy", trust.NamespacePolicy, polDoc}} {
		signed, err := trust.CountPinnedSigners(d.doc.Body, d.doc.Sigs, d.namespace, roots)
		if err != nil {
			return nil, nil, spool.Doc{}, fmt.Errorf("%w: %s signatures: %w", ErrBundle, d.what, err)
		}
		if len(signed) < p.Threshold {
			return nil, nil, spool.Doc{}, fmt.Errorf("%w: the %s is signed by %d of the pinned roots, below the threshold %d", ErrBundle, d.what, len(signed), p.Threshold)
		}
	}
	b, err := trust.VerifySelfSigned(doc.Body, doc.Sigs, polDoc.Body, polDoc.Sigs)
	if err != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if err := trust.MatchPins(b, p.TrustPins, p.Threshold); err != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if b.PolicySHA256 != trust.SHA256Hex(polDoc.Body) {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: the policy is not the bundle's", ErrBundle)
	}
	pol, err := trust.ParsePolicy(polDoc.Body)
	if err != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: policy: %w", ErrBundle, err)
	}
	if err := trust.CheckAdminsNotRoots(pol, b.Root.Keys); err != nil {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if b.InstallationID != p.InstallationID {
		return nil, nil, spool.Doc{}, fmt.Errorf("%w: the bundle names installation %q, the pin is %s", ErrBundleInstall, b.InstallationID, p.InstallationID)
	}
	return b, pol, polDoc, nil
}

// chainHead is what a directory link is checked by: its version and prev.
type chainHead struct {
	Version uint64 `json:"version"`
	Prev    string `json:"prev"`
}

func (v *Verified) verifyDirectory(p *Pins, prev *Stored, in spool.State) error {
	var stored []byte
	var storedVersion uint64
	if prev != nil && prev.Directory != nil {
		stored, storedVersion = prev.Directory, prev.DirectoryVersion
		d, err := directory.Parse(stored)
		if err != nil {
			return fmt.Errorf("%w: the accepted directory: %w", ErrStored, err)
		}
		v.Directory = d
	}
	vs := sortedVersions(in.Directories)
	if len(vs) == 0 {
		return nil
	}
	newest := vs[len(vs)-1]
	switch {
	case stored != nil && newest == storedVersion:
		return nil
	case stored != nil && newest < storedVersion:
		return fmt.Errorf("%w: the spool offers directory version %d, below the accepted version %d", ErrDirOlder, newest, storedVersion)
	}
	doc := in.Directories[newest]
	if _, err := directory.VerifySignatures(doc.Body, doc.Sigs, v.Policy); err != nil {
		// The newest policy refuses it; an earlier one of the chain may
		// carry its quorum (holdBundle).
		held := false
		for k := len(v.steps) - 2; k >= 0 && !held; k-- {
			if _, e := directory.VerifySignatures(doc.Body, doc.Sigs, v.steps[k].policy); e == nil {
				v.holdBundle(k)
				held = true
			}
		}
		if !held {
			return fmt.Errorf("%w: version %d: %w", ErrDir, newest, err)
		}
	}
	d, err := directory.Parse(doc.Body)
	if err != nil {
		return fmt.Errorf("%w: version %d: %w", ErrDir, newest, err)
	}
	if d.Version != newest {
		return fmt.Errorf("%w: directory-%d.json holds version %d", ErrDir, newest, d.Version)
	}
	if err := directory.CheckInstallation(d, p.InstallationID); err != nil {
		return fmt.Errorf("%w: version %d: %w", ErrDirInstall, newest, err)
	}
	if err := directory.CheckPolicy(d, v.Policy); err != nil {
		return fmt.Errorf("%w: version %d: %w", ErrDir, newest, err)
	}
	if stored != nil {
		link := stored
		for ver := storedVersion + 1; ver <= newest; ver++ {
			next, ok := in.Directories[ver]
			if !ok {
				return fmt.Errorf("%w: directory version %d is missing between the accepted version %d and the offered version %d", ErrDirChainGap, ver, storedVersion, newest)
			}
			var head chainHead
			if err := json.Unmarshal(next.Body, &head); err != nil {
				return fmt.Errorf("%w: directory version %d is not a JSON document", ErrDir, ver)
			}
			if head.Version != ver {
				return fmt.Errorf("%w: directory-%d.json holds version %d", ErrDir, ver, head.Version)
			}
			if err := directory.CheckSuccessor(link, &directory.Directory{Version: head.Version, Prev: head.Prev}); err != nil {
				return fmt.Errorf("%w: directory version %d does not chain to version %d: %w", ErrDir, ver, ver-1, err)
			}
			link = next.Body
		}
	}
	v.Directory, v.DirectoryChanged = d, true
	v.Next.Directory, v.Next.DirectorySigs, v.Next.DirectoryVersion = doc.Body, doc.Sigs, d.Version
	return nil
}

func (v *Verified) verifyKRL(p *Pins, prev *Stored, in spool.State) error {
	var storedVersion uint64
	if prev != nil && prev.KRL != nil {
		parsed, err := krl.Parse(prev.KRL)
		if err != nil {
			return fmt.Errorf("%w: the accepted KRL: %w", ErrStored, err)
		}
		v.KRL, storedVersion = parsed, prev.KRLVersion
	}
	vs := sortedVersions(in.KRLs)
	if len(vs) == 0 {
		return nil
	}
	ver := vs[len(vs)-1]
	files := in.KRLs[ver]
	if prev != nil && bytes.Equal(files.Manifest, prev.KRLManifest) && bytes.Equal(files.KRL, prev.KRL) {
		return nil
	}
	m, err := krl.ParseManifest(files.Manifest)
	if err != nil {
		return fmt.Errorf("%w: krl-%d: %w", ErrKRL, ver, err)
	}
	switch {
	case m.KRLVersion != ver:
		return fmt.Errorf("%w: krl-%d.manifest.json names KRL version %d", ErrKRL, ver, m.KRLVersion)
	case m.KRLVersion == storedVersion:
		// The version stays; a KRL is never replaced at the same version.
		return nil
	case m.KRLVersion < storedVersion:
		return fmt.Errorf("%w: the spool offers KRL version %d, below the accepted version %d", ErrKRLOlder, m.KRLVersion, storedVersion)
	}
	if _, err := krl.VerifyManifest(files.Manifest, files.Sig, files.KRL, v.Bundle, p.InstallationID, storedVersion); err != nil {
		if v.BundleHeld {
			// Signed by an ops key of a bundle this capture holds back:
			// it waits for that bundle.
			return nil
		}
		return fmt.Errorf("%w: KRL version %d: %w", ErrKRL, ver, err)
	}
	parsed, err := krl.Parse(files.KRL)
	if err != nil {
		return fmt.Errorf("%w: KRL version %d: %w", ErrKRL, ver, err)
	}
	if parsed.Version != m.KRLVersion {
		// The manifest's SHA-256 covers these bytes, but the agent orders
		// installed KRLs by their header (keepKRLInForce, RollbackTarget,
		// krl_rollback_refused), so a header above the manifest would set a
		// floor no later KRL could pass, and one below it would let an
		// older list replace a newer one.
		return fmt.Errorf("%w: KRL version %d: the KRL's header says krl_version %d, its signed manifest %d", ErrKRLHeader, ver, parsed.Version, m.KRLVersion)
	}
	v.KRL, v.KRLChanged = parsed, true
	v.Next.KRL, v.Next.KRLManifest, v.Next.KRLSig, v.Next.KRLVersion = files.KRL, files.Manifest, files.Sig, m.KRLVersion
	return nil
}
