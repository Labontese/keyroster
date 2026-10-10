package trust

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
)

// Verification errors.
var (
	ErrPins         = errors.New("trust: pinned root fingerprints do not match the bundle's root set")
	ErrThreshold    = errors.New("trust: root threshold not met")
	ErrPolicyHash   = errors.New("trust: policy_sha256 does not match the policy document")
	ErrVersionChain = errors.New("trust: bundle version or prev hash breaks the chain")
)

// CountPinnedSigners returns the sorted, distinct fingerprints of pinned
// keys that made a valid signature over doc under namespace. pinned maps a
// SHA256 fingerprint to its key. A signature by a key that is not pinned, an
// invalid signature and a signature under another namespace do not count;
// a pinned key that signed twice counts once. A sigs input that is not a
// sequence of well-formed SSHSIG blocks is an error.
func CountPinnedSigners(doc, sigs []byte, namespace string, pinned map[string]ssh.PublicKey) ([]string, error) {
	for fp, pub := range pinned {
		if pub == nil || ssh.FingerprintSHA256(pub) != fp {
			return nil, fmt.Errorf("trust: pinned key for %s does not have that fingerprint", fp)
		}
	}
	parsed, err := sshsig.ParseAll(sigs)
	if err != nil {
		return nil, err
	}
	signed := map[string]bool{}
	for _, s := range parsed {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		pub, ok := pinned[fp]
		if !ok || !bytes.Equal(pub.Marshal(), s.PublicKey().Marshal()) {
			continue
		}
		if s.Verify(namespace, doc) != nil {
			continue
		}
		signed[fp] = true
	}
	out := make([]string, 0, len(signed))
	for fp := range signed {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out, nil
}

// VerifyGenesisBundle verifies a version 1 bundle and its policy against the
// operator's pinned root fingerprints. The bundle's root set must be exactly
// the pinned set and its threshold exactly threshold, so a bundle cannot
// widen its own trust (Pitfall 4); at least threshold distinct pinned roots
// must have signed each document under its namespace; and policy_sha256
// must be the SHA-256 of the policy bytes; and no policy admin may be a root
// key (CheckAdminsNotRoots). Non-canonical documents are refused before any
// signature is checked.
func VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs []byte, pins []string, threshold int) (*Bundle, *Policy, error) {
	if err := CheckPins(pins, threshold); err != nil {
		return nil, nil, err
	}
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: %w", err)
	}
	p, err := ParsePolicy(policy)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %w", err)
	}
	if b.Version != 1 || b.Prev != GenesisPrev {
		return nil, nil, fmt.Errorf("%w: a genesis bundle is version 1 with an all-zero prev", ErrVersionChain)
	}
	if p.Version != 1 {
		return nil, nil, fmt.Errorf("%w: a genesis policy is version 1", ErrVersionChain)
	}
	if err := MatchPins(b, pins, threshold); err != nil {
		return nil, nil, err
	}
	roots, err := b.rootKeys()
	if err != nil {
		return nil, nil, err
	}
	if b.PolicySHA256 != SHA256Hex(policy) {
		return nil, nil, ErrPolicyHash
	}
	if err := CheckAdminsNotRoots(p, b.Root.Keys); err != nil {
		return nil, nil, err
	}
	if err := requireSigners(bundle, bundleSigs, NamespaceBundle, roots, threshold, "bundle"); err != nil {
		return nil, nil, err
	}
	if err := requireSigners(policy, policySigs, NamespacePolicy, roots, threshold, "policy"); err != nil {
		return nil, nil, err
	}
	return b, p, nil
}

// VerifySelfSigned parses bundle and requires at least its own threshold of
// its own root keys to have signed both bundle and policy under their
// namespaces. It says nothing about whose roots those are, nor whether
// policy is the bundle's policy: a bundle that names an attacker's roots
// and is signed by them passes. The caller must authenticate the bundle by
// other means (pinned roots, or the SHA-256 recorded at its install).
func VerifySelfSigned(bundle, bundleSigs, policy, policySigs []byte) (*Bundle, error) {
	b, err := ParseBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	roots, err := b.rootKeys()
	if err != nil {
		return nil, err
	}
	if err := requireSigners(bundle, bundleSigs, NamespaceBundle, roots, int(b.Root.Threshold), "bundle (its own roots)"); err != nil {
		return nil, err
	}
	if err := requireSigners(policy, policySigs, NamespacePolicy, roots, int(b.Root.Threshold), "policy (its own roots)"); err != nil {
		return nil, err
	}
	return b, nil
}

// CheckPins checks operator pins on their own: at least one pin, each a
// SHA256:<base64> fingerprint, none repeated, and a threshold in
// 1..len(pins). It returns ErrPins or ErrThreshold.
func CheckPins(pins []string, threshold int) error {
	set, err := pinSet(pins)
	if err != nil {
		return err
	}
	if threshold < 1 || threshold > len(set) {
		return fmt.Errorf("%w: threshold %d with %d pins", ErrThreshold, threshold, len(set))
	}
	return nil
}

// MatchPins reports whether b's root set is exactly the pinned set at
// exactly the pinned threshold: the pins pass CheckPins, the bundle has as
// many roots as there are pins, every root is pinned, and the bundle's
// threshold equals threshold. So a bundle cannot widen its own trust
// (Pitfall 4). It checks no signature; the caller must have verified b.
// It returns ErrPins or ErrThreshold.
func MatchPins(b *Bundle, pins []string, threshold int) error {
	if err := CheckPins(pins, threshold); err != nil {
		return err
	}
	set, _ := pinSet(pins) // CheckPins accepted pins
	roots, err := b.rootKeys()
	if err != nil {
		return err
	}
	if len(roots) != len(set) {
		return fmt.Errorf("%w: %d pins, %d roots", ErrPins, len(set), len(roots))
	}
	for fp := range roots {
		if !set[fp] {
			return fmt.Errorf("%w: bundle root %s is not pinned", ErrPins, fp)
		}
	}
	if int(b.Root.Threshold) != threshold {
		return fmt.Errorf("%w: bundle threshold %d, pinned threshold %d", ErrPins, b.Root.Threshold, threshold)
	}
	return nil
}

// CheckAdminsNotRoots refuses a policy that names a key of any of the root
// sets as an admin. A root signs only trust bundles and policies (KEY-07);
// an admin authorizes issuance online, so a root listed as an admin would
// turn an offline root into a routine issuance authorizer. Keys are
// compared by their wire encoding.
func CheckAdminsNotRoots(p *Policy, rootSets ...[]RootKey) error {
	roots := map[string]bool{}
	for _, set := range rootSets {
		for _, rk := range set {
			pub, err := ParseKey(rk.Key)
			if err != nil {
				return fmt.Errorf("%w: root key: %w", ErrInvalid, err)
			}
			roots[string(pub.Marshal())] = true
		}
	}
	for _, a := range p.Admins {
		pub, err := ParseKey(a.Key)
		if err != nil {
			return fmt.Errorf("%w: admin %s: %w", ErrInvalid, a.Name, err)
		}
		if roots[string(pub.Marshal())] {
			return fmt.Errorf("%w: policy admin %s is root %s", ErrKeyIsRoot, a.Name, ssh.FingerprintSHA256(pub))
		}
	}
	return nil
}

// requireSigners requires at least threshold distinct keys of roots to have
// signed doc.
func requireSigners(doc, sigs []byte, namespace string, roots map[string]ssh.PublicKey, threshold int, what string) error {
	signed, err := CountPinnedSigners(doc, sigs, namespace, roots)
	if err != nil {
		return fmt.Errorf("%s signatures: %w", what, err)
	}
	if len(signed) < threshold {
		return fmt.Errorf("%w: %s signed by %d of %d roots, need %d", ErrThreshold, what, len(signed), len(roots), threshold)
	}
	return nil
}

// rootKeys returns the bundle's root keys by fingerprint.
func (b *Bundle) rootKeys() (map[string]ssh.PublicKey, error) {
	m := make(map[string]ssh.PublicKey, len(b.Root.Keys))
	for _, rk := range b.Root.Keys {
		pub, err := ParseKey(rk.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: root key: %w", ErrInvalid, err)
		}
		m[ssh.FingerprintSHA256(pub)] = pub
	}
	return m, nil
}

// pinSet parses operator pins (SHA256:<base64> fingerprints).
func pinSet(pins []string) (map[string]bool, error) {
	if len(pins) == 0 {
		return nil, fmt.Errorf("%w: no pins given", ErrPins)
	}
	m := make(map[string]bool, len(pins))
	for _, p := range pins {
		// A SHA256 fingerprint is "SHA256:" plus 43 unpadded base64 chars.
		if !strings.HasPrefix(p, "SHA256:") || len(p) != len("SHA256:")+43 {
			return nil, fmt.Errorf("%w: %q is not a SHA256:... fingerprint", ErrPins, p)
		}
		if m[p] {
			return nil, fmt.Errorf("%w: %s pinned twice", ErrPins, p)
		}
		m[p] = true
	}
	return m, nil
}

// VerifySuccessor verifies next against prev, the previously accepted
// bundle, whose canonical bytes are prevCanonical (TUF rule). The trust
// anchors are prev's roots and the roots next declares: at least
// prev.Root.Threshold distinct previous roots AND at least next's own
// threshold of its roots must have signed both next and the policy. The
// two counts are independent, and a root in both sets counts toward both.
// So a freshly listed new root cannot rotate trust without
// prev.Root.Threshold current roots, but at threshold 1 any single current
// root can: alone, if next keeps it as a root, or together with a fresh
// key it lists in next. next must be version prev+1, carry prev's SHA-256
// as prev, not be issued before prev, and carry the policy's SHA-256. No
// policy admin may be one of next's or prev's roots (CheckAdminsNotRoots).
//
// prevPolicy is the policy document in force under prev (its SHA-256 must
// be prev's policy_sha256). The policy chains like the bundle: it is either
// byte-identical to prevPolicy, or it is version prevPolicy.version+1 with
// prevPolicy's SHA-256 as its prev. So a policy version names exactly one
// policy, and the key ID's pol=N identifies the admins and profiles that
// authorized a certificate.
func VerifySuccessor(prev *Bundle, prevCanonical, prevPolicy, next, nextSigs, policy, policySigs []byte) (*Bundle, *Policy, error) {
	b, err := ParseBundle(next)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: %w", err)
	}
	p, err := checkSuccessorChain(prev, prevCanonical, prevPolicy, b, policy)
	if err != nil {
		return nil, nil, err
	}
	oldRoots, err := prev.rootKeys()
	if err != nil {
		return nil, nil, err
	}
	newRoots, err := b.rootKeys()
	if err != nil {
		return nil, nil, err
	}
	for _, check := range []struct {
		roots     map[string]ssh.PublicKey
		threshold int
		who       string
	}{{oldRoots, int(prev.Root.Threshold), "previous roots"}, {newRoots, int(b.Root.Threshold), "new roots"}} {
		if err := requireSigners(next, nextSigs, NamespaceBundle, check.roots, check.threshold, "bundle ("+check.who+")"); err != nil {
			return nil, nil, err
		}
		if err := requireSigners(policy, policySigs, NamespacePolicy, check.roots, check.threshold, "policy ("+check.who+")"); err != nil {
			return nil, nil, err
		}
	}
	return b, p, nil
}

// errIssuedBeforePrev marks the issued_at-order refusal of
// checkSuccessorChain. Its text is ErrVersionChain's and it wraps
// ErrVersionChain, so the verifier's error text is unchanged while
// BuildSuccessor can add a hint about the ceremony clock.
var errIssuedBeforePrev = fmt.Errorf("%w", ErrVersionChain)

// checkSuccessorChain enforces every rule of the successor chain that does
// not involve a signature, for VerifySuccessor and BuildSuccessor alike, so
// the builder cannot drift from the verifier. next must already be a
// structurally valid bundle (ParseBundle or Validate). It checks, in this
// order: prev validates and prevCanonical is its canonical encoding;
// prevPolicy is prev's policy; policy parses; next is version prev+1,
// carries prev's SHA-256 as prev and is not issued before prev; next
// carries policy's SHA-256; policy is prevPolicy unchanged or chained to it
// as the next version; a root in both prev and next keeps its custody
// label; and no policy admin is a root of next or of prev. It returns the
// parsed policy.
func checkSuccessorChain(prev *Bundle, prevCanonical, prevPolicy []byte, next *Bundle, policy []byte) (*Policy, error) {
	if prev == nil {
		return nil, fmt.Errorf("%w: no previous bundle", ErrVersionChain)
	}
	if err := prev.Validate(); err != nil {
		return nil, fmt.Errorf("previous bundle: %w", err)
	}
	pc, err := prev.Canonical()
	if err != nil || !bytes.Equal(pc, prevCanonical) {
		return nil, fmt.Errorf("%w: prevCanonical is not the canonical encoding of the previous bundle", ErrVersionChain)
	}
	if SHA256Hex(prevPolicy) != prev.PolicySHA256 {
		return nil, fmt.Errorf("%w: prevPolicy is not the previous bundle's policy", ErrVersionChain)
	}
	pp, err := ParsePolicy(prevPolicy)
	if err != nil {
		return nil, fmt.Errorf("previous policy: %w", err)
	}
	p, err := ParsePolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if next.Version != prev.Version+1 {
		return nil, fmt.Errorf("%w: version %d after %d", ErrVersionChain, next.Version, prev.Version)
	}
	if next.Prev != SHA256Hex(prevCanonical) {
		return nil, fmt.Errorf("%w: prev %s is not the previous bundle's SHA-256", ErrVersionChain, next.Prev)
	}
	// Both timestamps are validated TimeFormat strings, which order
	// lexicographically.
	if next.IssuedAt < prev.IssuedAt {
		return nil, fmt.Errorf("%w: issued_at %s is before the previous bundle's %s", errIssuedBeforePrev, next.IssuedAt, prev.IssuedAt)
	}
	if next.PolicySHA256 != SHA256Hex(policy) {
		return nil, ErrPolicyHash
	}
	if !bytes.Equal(policy, prevPolicy) && (p.Version != pp.Version+1 || p.Prev != SHA256Hex(prevPolicy)) {
		return nil, fmt.Errorf("%w: a changed policy must be version %d with the previous policy's SHA-256 as prev, got version %d",
			ErrVersionChain, pp.Version+1, p.Version)
	}
	if err := checkCarriedCustody(prev, next); err != nil {
		return nil, err
	}
	// A root that next retires may still exist, so it must not become an
	// admin either.
	if err := CheckAdminsNotRoots(p, next.Root.Keys, prev.Root.Keys); err != nil {
		return nil, err
	}
	return p, nil
}

// checkCarriedCustody refuses a root key that is in both prev's and next's
// root sets with another custody label in next. The key, and so whatever
// exposure it had, is unchanged: a new label would only launder, say, a
// software key into a hardware claim (D-10, D-11). A key moved into new
// custody is a new root. Keys are compared by their wire encoding; both
// bundles have been validated.
func checkCarriedCustody(prev, next *Bundle) error {
	custody := make(map[string]string, len(prev.Root.Keys))
	for _, rk := range prev.Root.Keys {
		pub, err := ParseKey(rk.Key)
		if err != nil {
			return fmt.Errorf("%w: previous root key: %w", ErrInvalid, err)
		}
		custody[string(pub.Marshal())] = rk.Custody
	}
	for _, rk := range next.Root.Keys {
		pub, err := ParseKey(rk.Key)
		if err != nil {
			return fmt.Errorf("%w: root key: %w", ErrInvalid, err)
		}
		if c, ok := custody[string(pub.Marshal())]; ok && c != rk.Custody {
			return fmt.Errorf("%w: root %s is carried over from the previous bundle but changes custody from %s to %s; a key moved into new custody is a new root",
				ErrCustody, ssh.FingerprintSHA256(pub), c, rk.Custody)
		}
	}
	return nil
}
