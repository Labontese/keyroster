//go:build linux

package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
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
	// under an earlier policy of the bundle chain, so the bundle waits for
	// the next capture (PR #67 review). A KRL the newer bundle's ops key
	// signed lands with the held step (03-08k, krlStep).
	BundleHeld bool

	// KRLRefused is set only under BundleHeld, when the capture's newest
	// KRL was refused because its authoriser's ops key is retired (03-08k,
	// krl_signer_retired): the capture's held step is taken, the KRL in
	// force stays, and the caller reports KRLRefused after the commit. It
	// is not Refused, which marks a KRL-alone Verified.
	KRLRefused error

	// Refused is set when the capture's bundle or directory step was
	// refused (owner decision D-R2, PR #71 review F5), or when the applier
	// refused the generation rendered from a verified capture for its
	// content (F07 (03-08d)): the capture then takes only its KRL,
	// verified against the bundle in force (the accepted one; KRLAlone)
	// or, on krl.ErrSigner, against the apply's fully verified successor
	// (03-08k), and the bundle, policy and directory stay as accepted.
	// Revocations only narrow what sshd accepts, so they never wait for a
	// chain that does not verify, or for a bundle or directory the host
	// cannot apply. The caller reports Refused.
	Refused error

	// DirectoryUnauthorized is set when the stored directory does not carry
	// the admin quorum of the policy in force, or does not fit it
	// (ErrDirUnauthorized); derived on every verification, never stored
	// (F03 (03-08f)).
	DirectoryUnauthorized error

	// steps is the bundle chain of this capture: the stored bundle (when
	// there is one), then each successor verified.
	steps []bundleStep

	// fullyVerified is the newest bundle this apply verified in full up to
	// this capture (03-08k). verify starts it at what its caller carries:
	// nothing from Verify, the record's bundle from VerifyAhead, the pending
	// capture's from VerifyAfter, and the higher of those two from
	// VerifyAheadAfter. It is raised to the capture's newest bundle step,
	// when above, only when the whole bundle chain verified (the bundle step
	// returned nil). A refused bundle step never raises it, not even to a
	// step verified before the refusal (owner answer Q2), and a bundle that
	// was only offered never is one. A fully verified successor, a
	// fullyVerified above the bundle a KRL is checked under first, may
	// authorise it (krlStep, KRLAlone). During a widening wait the pending
	// target's is raised with every raise of a poll's (VerifyAfter,
	// VerifyAheadAfter; PR #80 review), so it is the newest bundle any
	// verification of the apply verified in full.
	fullyVerified *trust.Bundle
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
//     installation ID. A successor that carries the policy over is checked
//     with the stored policy signatures first; only when that fails with
//     trust.ErrThreshold, as for a rotation to new roots or a raised
//     threshold, is it retried once with the union of the admitted policy
//     signature files: the stored ones, those delivered with the bundle
//     and the offered policy file's (F02 (03-08f), verifyBundle). The
//     thresholds still come from the bundles, each root counts once and
//     only for a valid signature over the exact policy bytes, and the
//     bundle signatures are never united, so the union never lowers a
//     threshold; accepted/ stores one admitted file, never the union.
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
//     accepted already. The stored directory is checked again under the
//     policy in force on every verification (F03 (03-08f), verifyDirectory):
//     while that policy's admin quorum did not sign it, or it does not fit
//     the policy, DirectoryUnauthorized is set, unless an offered directory
//     at or above the stored version that the policy authorizes is
//     accepted standalone.
//   - KRL. The newest complete KRL: equal to the stored one is a no-op,
//     an older version krl_older; otherwise krl.VerifyManifest against the
//     bundle in force, the pinned installation ID and the stored version,
//     then krl.Parse, and the KRL's header krl_version must be the
//     manifest's (krl_header_version_mismatch). Its authoriser (03-08k,
//     krlStep) is the first of the bundle in force after the capture, the
//     apply's fully verified successor and the accepted bundle that
//     verifies it. A KRL whose authoriser's ops key a newer known bundle
//     dropped is refused with krl_signer_retired: under BundleHeld the
//     held step is taken without it (KRLRefused), and otherwise Verify
//     returns the refusal. Any other authorised KRL lands with the capture,
//     a held step included. A KRL no candidate verifies waits under
//     BundleHeld and is an error otherwise.
//
// A refused bundle or directory step does not stop the KRL (owner decision
// D-R2, PR #71 review F5): with an accepted bundle, the KRL is verified
// against it and taken alone (KRLAlone), everything else stays as accepted,
// and the refusal is returned in Refused with a nil error. Before any
// bundle was accepted the refusal stands, and a refused KRL is an error
// with the earlier refusal joined to it.
//
// Verify reads only in; the bytes it checks are the bytes it returns in
// Next. VerifyAhead is Verify for a capture read from an unapplied record
// (PR #76 review F8 (03-08j)).
func Verify(p *Pins, prev *Stored, in spool.State) (*Verified, error) {
	return verify(p, prev, prev, in, nil, nil)
}

// VerifyAfter is Verify for a capture during a widening wait (03-08k),
// verified against pending, the pending target: it knows every bundle the
// apply verified in full before it (pending's fully verified bundle), so a
// poll decides a KRL as forward does. Every Verified it returns, KRLAlone's
// included, carries that bundle on, so a later poll after a supersede
// knows it too. A bundle the capture verifies in full above it raises
// pending's as well, before the directory or KRL step can refuse the
// capture (PR #80 review): a later poll of the same wait knows it whether
// this poll supersedes the target, renders its bytes, brings nothing new
// or is refused.
func VerifyAfter(p *Pins, pending *Verified, in spool.State) (*Verified, error) {
	prev := pending.AsStored()
	return verify(p, prev, prev, in, pending.fullyVerified, pending)
}

// verify is Verify with the bundle, directory and KRL steps run against
// chain, and the KRL-alone pass of a refused step against alone, the
// accepted state. When chain holds a bundle above alone's (an unapplied
// record's bundle part, VerifyAhead), alone's bundle stays the lowest hold
// step, below chain's, so holdBundle can still hold the capture at the
// bundle in force (PR #76 review F8 (03-08j)). Only BundleVersion is
// compared: with chain's bundle alone's, the steps are exactly Verify's.
// carried is a bundle this apply verified in full outside the capture
// (03-08k), the start of v's fully verified bundle. pending is a widening
// wait's pending target, nil outside a poll: each raise of v's fully
// verified bundle raises pending's to the same bundle (PR #80 review).
// The raise is by version only, so a fork at an equal version raises
// neither.
func verify(p *Pins, chain, alone *Stored, in spool.State, carried *trust.Bundle, pending *Verified) (*Verified, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	v := &Verified{fullyVerified: carried}
	if chain != nil {
		v.Next = *chain
	}
	refused := v.verifyBundle(p, chain, in)
	if refused == nil && len(v.steps) > 0 {
		if n := v.steps[len(v.steps)-1].bundle; carried == nil || n.Version > carried.Version {
			v.fullyVerified = n
			if pending != nil {
				pending.fullyVerified = n
			}
		}
	}
	if refused == nil && alone != nil && alone.Bundle != nil && chain != nil && chain.BundleVersion > alone.BundleVersion {
		inForce := bundleStep{bundle: alone.bundle, policy: alone.policy, doc: spool.Doc{Body: alone.Bundle, Sigs: alone.BundleSigs}, polDoc: spool.Doc{Body: alone.Policy, Sigs: alone.PolicySigs}}
		v.steps = append([]bundleStep{inForce}, v.steps...)
	}
	if refused == nil {
		refused = v.verifyDirectory(p, chain, in)
	}
	if refused != nil {
		return KRLAlone(p, alone, in, refused, v)
	}
	if err := v.krlStep(p, chain, alone, in); err != nil {
		return nil, err
	}
	return v, nil
}

// KRLAlone is owner decision D-R2's KRL-alone state (PR #71 review F5):
// the capture in takes only its KRL, and refusal, the refused bundle or
// directory step, or a content refusal of the generation the applier
// rendered from a verified capture (F07 (03-08d)), is returned in Refused.
// It uses only prev's bundle, policy and directory, unchanged: prev is the
// accepted state, or during a widening wait the pending target's state
// (Verified.AsStored), which Verify accepted in the same run. The KRL is
// verified again against prev's bundle, the pins and prev's KRL version.
//
// from is the capture the caller verified (03-08k). The owner's rule: a
// fully verified successor may authorise a KRL, which then lands with the
// bundle and directory in force. When the KRL fails under prev's bundle
// with krl.ErrSigner, and from's fully verified bundle (Verified.
// fullyVerified) is above prev's bundle and names another ops key, the KRL
// is verified again under that successor: its ops key, the pins'
// installation ID, prev's KRL version and the header check. A bundle that
// was only offered, and a step verified before a refused bundle step,
// authorise nothing. Otherwise prev's bundle's error stands. A new KRL
// whose authoriser's ops key is retired by a bundle from knows (retiredBy:
// a newer verified bundle names another key) never lands: the refusal is
// joined to krl_signer_retired, and nothing is installed (03-08k). The
// returned Verified's bundle, policy and directory stay prev's, and it
// carries from's fully verified bundle. A nil from tries prev's bundle
// alone. With no accepted bundle the refusal stands; a refused KRL is an
// error with the refusal joined to it.
func KRLAlone(p *Pins, prev *Stored, in spool.State, refusal error, from *Verified) (*Verified, error) {
	if err := p.Validate(); err != nil {
		return nil, errors.Join(refusal, err)
	}
	if prev == nil || prev.Bundle == nil {
		return nil, refusal
	}
	w, err := storedOnly(prev)
	if err != nil {
		return nil, errors.Join(refusal, err)
	}
	if from != nil {
		w.fullyVerified = from.fullyVerified
	}
	k, err := w.verifyKRLUnder(p, prev, in, prev.bundle)
	auth := prev.bundle
	if err != nil {
		s := w.successorAbove(prev.bundle)
		if !errors.Is(err, krl.ErrSigner) || s == nil || s.OpsKey.Key == prev.bundle.OpsKey.Key {
			return nil, errors.Join(refusal, err)
		}
		sk, serr := w.verifyKRLUnder(p, prev, in, s)
		if serr != nil {
			return nil, errors.Join(refusal, err)
		}
		k, auth = sk, s
	}
	if k != nil {
		if n := from.retiredBy(auth); n != nil {
			return nil, errors.Join(refusal, retiredError(k, auth, n))
		}
		w.take(k)
	}
	w.Refused = refusal
	return w, nil
}

// successorAbove is the successor of a KRL checked first under x (03-08k):
// v's fully verified bundle when its version is above x's, nil otherwise.
func (v *Verified) successorAbove(x *trust.Bundle) *trust.Bundle {
	if s := v.fullyVerified; s != nil && s.Version > x.Version {
		return s
	}
	return nil
}

// newestKnown is the newest bundle v knows above x (03-08k): v's bundle
// steps above x, those verified before a refused bundle step included, and
// v's fully verified bundle when above x. The newest is the highest
// version; on a tie, which only a fork of the root-signed chain can cause,
// the fully verified bundle counts. It is nil when v knows none.
func (v *Verified) newestKnown(x *trust.Bundle) *trust.Bundle {
	var n *trust.Bundle
	for _, st := range v.steps {
		if st.bundle.Version > x.Version && (n == nil || st.bundle.Version > n.Version) {
			n = st.bundle
		}
	}
	if s := v.successorAbove(x); s != nil && (n == nil || s.Version >= n.Version) {
		n = s
	}
	return n
}

// retiredBy returns the newest bundle v knows above x when it names
// another ops key than x (krl.VerifyManifest's comparison): x's key is then
// retired (03-08k). A key the newest bundle names again is current (owner
// answer Q4). A nil v knows nothing.
func (v *Verified) retiredBy(x *trust.Bundle) *trust.Bundle {
	if v == nil {
		return nil
	}
	if n := v.newestKnown(x); n != nil && n.OpsKey.Key != x.OpsKey.Key {
		return n
	}
	return nil
}

// retiredError is the krl_signer_retired refusal of k, authorised only by
// auth's ops key, which n retired (03-08k).
func retiredError(k *newKRL, auth, n *trust.Bundle) error {
	return fmt.Errorf("%w: KRL version %d: its signer, the ops key of bundle version %d, is retired by bundle version %d, which names another ops key", ErrKRLSignerRetired, k.version, auth.Version, n.Version)
}

// storedOnly is the Verified of a capture that takes nothing but, later,
// its KRL: the accepted bundle, policy and directory in force, unchanged.
func storedOnly(prev *Stored) (*Verified, error) {
	w := &Verified{Next: *prev, Bundle: prev.bundle, Policy: prev.policy}
	w.steps = []bundleStep{{bundle: prev.bundle, policy: prev.policy, doc: spool.Doc{Body: prev.Bundle, Sigs: prev.BundleSigs}, polDoc: spool.Doc{Body: prev.Policy, Sigs: prev.PolicySigs}}}
	if prev.Directory != nil {
		d, err := directory.Parse(prev.Directory)
		if err != nil {
			return nil, fmt.Errorf("%w: the accepted directory: %w", ErrStored, err)
		}
		w.Directory = d
	}
	return w, nil
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

// verifyBundle is verify's bundle step against prev, the chain base. Each
// successor step is verified with the policy signatures findPolicy returns:
// the chain base's or the previous step's while the policy is unchanged.
// F02 (03-08f): only when trust.VerifySuccessor fails with
// trust.ErrThreshold does the step retry once, with the union of the
// admitted policy signature files (unitePolicySigs): those signatures, the
// ones delivered with the bundle (bundle-<N>.policy.sigs) and the offered
// policy file's. The union cannot widen trust: the thresholds come from
// the bundles, CountPinnedSigners counts a root once and only for a valid
// signature over the exact policy bytes, and the bundle signatures are
// never united. A step stores one admitted file, never the union
// (storedPolicySigs).
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
		if errors.Is(err, trust.ErrThreshold) {
			// F02 (03-08f): the policy signatures delivered with this bundle
			// and the offered policy file may carry the new roots' policy
			// signatures, which the stored ones do not.
			offered, _ := findPolicy(lean.PolicySHA256, nil, in)
			nb, np, pol.Sigs, err = unitePolicySigs(cur, curBytes, curPolicy, doc, pol, in.BundlePolicySigs[ver], offered.Sigs, err)
		}
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

// unitePolicySigs is F02 (03-08f)'s one retry of a successor step whose
// plain check (trust.VerifySuccessor with pol.Sigs, the chain base's or the
// previous step's policy signatures) failed with trust.ErrThreshold, plain.
// The sources are pol.Sigs, delivered (the policy signatures delivered
// with this bundle, spool.State.BundlePolicySigs) and offered (the offered
// policy file whose body has the bundle's policy SHA-256). A source is
// admitted only when sshsig.ParseAll accepts it on its own (it refuses a
// whole file for one malformed block), and identical files are admitted
// once; the union is the admitted files concatenated, each ending in a
// newline. The bundle signatures are never united. When the union is
// pol.Sigs, plain stands; otherwise VerifySuccessor is retried once with
// it, and its error, if any, is returned.
//
// The union cannot widen trust (internal/trust/verify.go): both thresholds
// come from the bundles (prev.Root.Threshold and the successor's
// Root.Threshold); CountPinnedSigners counts each pinned root at most once,
// and only for a block whose public key is the pinned key and whose SSHSIG
// verifies over the exact policy bytes under the policy namespace; and
// every source is a signature file the signer accepted or served, which a
// spool writer could already present. So the union never refuses a
// successor the plain check accepts, and accepts only what VerifySuccessor
// accepts for a file of genuine signatures over those policy bytes.
//
// The union is never stored. On success it returns the one file the step
// stores in Next.PolicySigs (storedPolicySigs), which an unapplied record's
// bundle part then copies (03-08j).
func unitePolicySigs(prev *trust.Bundle, prevBytes, prevPolicy []byte, doc, pol spool.Doc, delivered, offered []byte, plain error) (*trust.Bundle, *trust.Policy, []byte, error) {
	var admitted [][]byte
	var union []byte
	for _, src := range [][]byte{pol.Sigs, delivered, offered} {
		if !admitPolicySigs(src) || slices.ContainsFunc(admitted, func(a []byte) bool { return bytes.Equal(a, src) }) {
			continue
		}
		admitted = append(admitted, src)
		union = append(union, src...)
		if !bytes.HasSuffix(src, []byte("\n")) {
			union = append(union, '\n')
		}
	}
	if bytes.Equal(union, pol.Sigs) {
		return nil, nil, nil, plain
	}
	nb, np, err := trust.VerifySuccessor(prev, prevBytes, prevPolicy, doc.Body, doc.Sigs, pol.Body, union)
	if err != nil {
		return nil, nil, nil, err
	}
	return nb, np, storedPolicySigs(prev, prevBytes, prevPolicy, doc, pol, delivered, offered), nil
}

// storedPolicySigs is the policy signature file a step the union verified
// stores (F02 (03-08f)): of the admitted delivered and offered files, the
// first that passes trust.VerifySuccessor alone; otherwise the admitted
// offered file; otherwise the admitted delivered file. It is never the
// union, which grows with every hop, and never a file sshsig.ParseAll
// refused, so the next hop's plain check never fails on a parse error that
// would keep it from its own retry. Every candidate was read under
// spool.MaxBundle, so LoadStored's and ParseUnapplied's caps hold.
func storedPolicySigs(prev *trust.Bundle, prevBytes, prevPolicy []byte, doc, pol spool.Doc, delivered, offered []byte) []byte {
	for _, src := range [][]byte{delivered, offered} {
		if !admitPolicySigs(src) {
			continue
		}
		if _, _, err := trust.VerifySuccessor(prev, prevBytes, prevPolicy, doc.Body, doc.Sigs, pol.Body, src); err == nil {
			return src
		}
	}
	for _, src := range [][]byte{offered, delivered} {
		if admitPolicySigs(src) {
			return src
		}
	}
	return pol.Sigs
}

// admitPolicySigs reports whether sigs is a policy signature file the
// union admits: sshsig.ParseAll accepts it on its own (F02 (03-08f)).
func admitPolicySigs(sigs []byte) bool {
	_, err := sshsig.ParseAll(sigs)
	return err == nil
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

// checkStored checks the stored directory prev holds, parsed as d, again
// under pol, the policy in force (F03 (03-08f)): directory.VerifySignatures
// over its stored signatures, then directory.CheckPolicy, as the signer
// checks its installed directory at start-up (loadDirectory). A failure is
// ErrDirUnauthorized.
func checkStored(prev *Stored, d *directory.Directory, pol *trust.Policy) error {
	if _, err := directory.VerifySignatures(prev.Directory, prev.DirectorySigs, pol); err != nil {
		return fmt.Errorf("%w: the stored directory version %d is not signed by the admin quorum of policy version %d: %w", ErrDirUnauthorized, d.Version, pol.Version, err)
	}
	if err := directory.CheckPolicy(d, pol); err != nil {
		return fmt.Errorf("%w: the stored directory version %d exceeds policy version %d: %w", ErrDirUnauthorized, d.Version, pol.Version, err)
	}
	return nil
}

// verifyDirectory is verify's directory step against prev, the state the
// capture chains from: accepted/ for Verify, the unapplied record's base
// for VerifyAhead and VerifyAheadAfter (the record's directory part when
// the record holds one, 03-08j), the pending target's state for
// VerifyAfter.
//
// F03 (03-08f): the stored directory is checked again under v.Policy, the
// newest policy the bundle step reached, before any hold (checkStored).
// While it is authorized, the offered directories are checked as before
// (offeredDirectory). While it is not, the newest offered directory at or
// above the stored version (at the stored version only with other bytes)
// that carries v.Policy's admin quorum, parses, names the pinned
// installation and fits v.Policy is accepted standalone, with no chain to
// the stored bytes (standaloneDirectory); a version below the stored one
// never is (owner decision Q-F03b). Without one, the offered directories
// are checked as before, the hold included, and when that accepts none,
// v.DirectoryUnauthorized names the stored directory's failure. The stored
// directory stays in v, so the flag is derived again on every run.
func (v *Verified) verifyDirectory(p *Pins, prev *Stored, in spool.State) error {
	var stored []byte
	var storedVersion uint64
	var unauth error
	if prev != nil && prev.Directory != nil {
		stored, storedVersion = prev.Directory, prev.DirectoryVersion
		d, err := directory.Parse(stored)
		if err != nil {
			return fmt.Errorf("%w: the accepted directory: %w", ErrStored, err)
		}
		v.Directory = d
		unauth = checkStored(prev, d, v.Policy)
	}
	vs := sortedVersions(in.Directories)
	if unauth == nil {
		return v.offeredDirectory(p, in, vs, stored, storedVersion)
	}
	if v.standaloneDirectory(p, in, vs, stored, storedVersion) {
		return nil
	}
	if err := v.offeredDirectory(p, in, vs, stored, storedVersion); err != nil {
		return err
	}
	if !v.DirectoryChanged {
		v.DirectoryUnauthorized = unauth
	}
	return nil
}

// standaloneDirectory is F03 (03-08f)'s recovery while the stored
// directory is unauthorized: the offered versions vs from the newest down
// to the stored version, that one only when its bytes differ from stored,
// and the first that carries v.Policy's admin quorum (no hold), parses
// with its version, names the pinned installation and fits v.Policy is
// accepted, with no chain to the stored bytes. A candidate that fails is
// skipped, not refused. It reports whether one was accepted.
func (v *Verified) standaloneDirectory(p *Pins, in spool.State, vs []uint64, stored []byte, storedVersion uint64) bool {
	for i := len(vs) - 1; i >= 0 && vs[i] >= storedVersion; i-- {
		ver := vs[i]
		doc := in.Directories[ver]
		if ver == storedVersion && bytes.Equal(doc.Body, stored) {
			continue
		}
		if _, err := directory.VerifySignatures(doc.Body, doc.Sigs, v.Policy); err != nil {
			continue
		}
		d, err := directory.Parse(doc.Body)
		if err != nil || d.Version != ver {
			continue
		}
		if directory.CheckInstallation(d, p.InstallationID) != nil || directory.CheckPolicy(d, v.Policy) != nil {
			continue
		}
		v.Directory, v.DirectoryChanged = d, true
		v.Next.Directory, v.Next.DirectorySigs, v.Next.DirectoryVersion = doc.Body, doc.Sigs, d.Version
		return true
	}
	return false
}

// offeredDirectory is the offered-directory check of verifyDirectory, with
// vs the offered versions and stored the stored directory (nil: none) at
// storedVersion.
func (v *Verified) offeredDirectory(p *Pins, in spool.State, vs []uint64, stored []byte, storedVersion uint64) error {
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

// krlStep is verify's KRL step (03-08k). The skip rules come first and
// try no candidate: a newest KRL byte-equal to the stored one or at its
// version is no change, an older version krl_older. Otherwise K, the
// newest KRL, is checked under candidates in order, and the first that
// verifies it is its authoriser: P, the bundle the capture puts in force
// (v.Bundle: under BundleHeld the held step, possibly the bundle in
// force); S, the apply's fully verified successor, when above P; F, the
// bundle in force (alone's), when alone has a bundle. A later candidate is
// tried only after krl.ErrSigner, and only when its ops key differs from
// those tried.
//
// The owner's rule: no KRL lands that neither the bundle in force nor a
// fully verified successor authorises. A KRL whose authoriser's ops key is
// retired (retiredBy: a newer bundle this capture knows names another key)
// never lands, because a retired key may be a compromised one: without
// BundleHeld krlStep returns krl_signer_retired, so nothing of the capture
// is installed; under BundleHeld it sets KRLRefused and returns nil, so
// the held step commits with the KRL in force unchanged. F is tried only
// to name that refusal: reaching it means P or S, a newer known bundle,
// names another key, so F's key is retired. Any other authorised KRL lands
// with the capture, a held step included. A KRL no candidate verifies
// returns P's error unchanged, never a later candidate's; under BundleHeld
// a manifest P does not verify waits instead, as before.
func (v *Verified) krlStep(p *Pins, chain, alone *Stored, in spool.State) error {
	k, err := v.verifyKRLUnder(p, chain, in, v.Bundle)
	auth := v.Bundle
	if errors.Is(err, krl.ErrSigner) {
		tried := []*trust.Bundle{v.Bundle}
		candidates := []*trust.Bundle{v.successorAbove(v.Bundle)}
		if alone != nil && alone.Bundle != nil {
			candidates = append(candidates, alone.bundle)
		}
		for _, c := range candidates {
			if c == nil || slices.ContainsFunc(tried, func(b *trust.Bundle) bool { return b.OpsKey.Key == c.OpsKey.Key }) {
				continue
			}
			tried = append(tried, c)
			if ck, cerr := v.verifyKRLUnder(p, chain, in, c); cerr == nil {
				k, err, auth = ck, nil, c
				break
			}
		}
	}
	if err != nil {
		if mr := (manifestRefused{}); v.BundleHeld && errors.As(err, &mr) {
			// Signed by no known key: it waits for the next capture.
			return nil
		}
		return err
	}
	if k == nil {
		return nil
	}
	if n := v.retiredBy(auth); n != nil {
		refusal := retiredError(k, auth, n)
		if v.BundleHeld {
			v.KRLRefused = refusal
			return nil
		}
		return refusal
	}
	v.take(k)
	return nil
}

// newKRL is a KRL verifyKRLUnder verified: newer than the stored one,
// signed by the given bundle's ops key, with its header version its
// manifest's (03-08k). Nothing of it is in a Verified until take.
type newKRL struct {
	parsed  *krl.Parsed
	files   spool.KRLFiles
	version uint64
}

// take puts k in force in v: the parsed KRL, KRLChanged and Next's KRL,
// manifest, signature and version, all six together (03-08k). It runs
// only for a KRL that lands, so a refused KRL never reaches accepted/,
// where the next quiet apply's byte-equal skip would install it.
func (v *Verified) take(k *newKRL) {
	v.KRL, v.KRLChanged = k.parsed, true
	v.Next.KRL, v.Next.KRLManifest, v.Next.KRLSig, v.Next.KRLVersion = k.files.KRL, k.files.Manifest, k.files.Sig, k.version
}

// manifestRefused marks verifyKRLUnder's refusal of a KRL's signed
// manifest under the bundle it was given: the one KRL error a held step
// lets wait (03-08k).
type manifestRefused struct{ error }

func (e manifestRefused) Unwrap() error { return e.error }

// verifyKRLUnder checks the capture's newest KRL with b as the bundle whose
// ops key must have signed its manifest (03-08k), and returns it when it
// is newer and verifies; it is (nil, nil) for the skip rules. It assigns
// nothing of the KRL it checks (take does); it sets v.KRL to the stored
// KRL, the KRL in force.
func (v *Verified) verifyKRLUnder(p *Pins, prev *Stored, in spool.State, b *trust.Bundle) (*newKRL, error) {
	var storedVersion uint64
	if prev != nil && prev.KRL != nil {
		parsed, err := krl.Parse(prev.KRL)
		if err != nil {
			return nil, fmt.Errorf("%w: the accepted KRL: %w", ErrStored, err)
		}
		v.KRL, storedVersion = parsed, prev.KRLVersion
	}
	vs := sortedVersions(in.KRLs)
	if len(vs) == 0 {
		return nil, nil
	}
	ver := vs[len(vs)-1]
	files := in.KRLs[ver]
	if prev != nil && bytes.Equal(files.Manifest, prev.KRLManifest) && bytes.Equal(files.KRL, prev.KRL) {
		return nil, nil
	}
	m, err := krl.ParseManifest(files.Manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: krl-%d: %w", ErrKRL, ver, err)
	}
	switch {
	case m.KRLVersion != ver:
		return nil, fmt.Errorf("%w: krl-%d.manifest.json names KRL version %d", ErrKRL, ver, m.KRLVersion)
	case m.KRLVersion == storedVersion:
		// The version stays; a KRL is never replaced at the same version.
		return nil, nil
	case m.KRLVersion < storedVersion:
		return nil, fmt.Errorf("%w: the spool offers KRL version %d, below the accepted version %d", ErrKRLOlder, m.KRLVersion, storedVersion)
	}
	if _, err := krl.VerifyManifest(files.Manifest, files.Sig, files.KRL, b, p.InstallationID, storedVersion); err != nil {
		return nil, manifestRefused{fmt.Errorf("%w: KRL version %d: %w", ErrKRL, ver, err)}
	}
	parsed, err := krl.Parse(files.KRL)
	if err != nil {
		return nil, fmt.Errorf("%w: KRL version %d: %w", ErrKRL, ver, err)
	}
	if parsed.Version != m.KRLVersion {
		// The manifest's SHA-256 covers these bytes, but the agent orders
		// installed KRLs by their header (keepKRLInForce, RollbackTarget,
		// krl_rollback_refused), so a header above the manifest would set a
		// floor no later KRL could pass, and one below it would let an
		// older list replace a newer one.
		return nil, fmt.Errorf("%w: KRL version %d: the KRL's header says krl_version %d, its signed manifest %d", ErrKRLHeader, ver, parsed.Version, m.KRLVersion)
	}
	return &newKRL{parsed: parsed, files: files, version: m.KRLVersion}, nil
}
