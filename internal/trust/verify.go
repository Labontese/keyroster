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
// must be the SHA-256 of the policy bytes. Non-canonical documents are
// refused before any signature is checked.
func VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs []byte, pins []string, threshold int) (*Bundle, *Policy, error) {
	pinSet, err := pinSet(pins)
	if err != nil {
		return nil, nil, err
	}
	if threshold < 1 || threshold > len(pinSet) {
		return nil, nil, fmt.Errorf("%w: threshold %d with %d pins", ErrThreshold, threshold, len(pinSet))
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
	roots, err := b.rootKeys()
	if err != nil {
		return nil, nil, err
	}
	if len(roots) != len(pinSet) {
		return nil, nil, fmt.Errorf("%w: %d pins, %d roots", ErrPins, len(pinSet), len(roots))
	}
	for fp := range roots {
		if !pinSet[fp] {
			return nil, nil, fmt.Errorf("%w: bundle root %s is not pinned", ErrPins, fp)
		}
	}
	if int(b.Root.Threshold) != threshold {
		return nil, nil, fmt.Errorf("%w: bundle threshold %d, pinned threshold %d", ErrPins, b.Root.Threshold, threshold)
	}
	if b.PolicySHA256 != SHA256Hex(policy) {
		return nil, nil, ErrPolicyHash
	}
	if err := requireSigners(bundle, bundleSigs, NamespaceBundle, roots, threshold, "bundle"); err != nil {
		return nil, nil, err
	}
	if err := requireSigners(policy, policySigs, NamespacePolicy, roots, threshold, "policy"); err != nil {
		return nil, nil, err
	}
	return b, p, nil
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

// VerifySuccessor verifies a successor bundle against the previously
// accepted bundle (TUF rule). Not implemented yet.
func VerifySuccessor(prev *Bundle, prevCanonical []byte, next, nextSigs, policy, policySigs []byte) (*Bundle, *Policy, error) {
	return nil, nil, errors.New("trust: VerifySuccessor is not implemented")
}
