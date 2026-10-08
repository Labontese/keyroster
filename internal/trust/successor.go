package trust

import (
	"bytes"
	"fmt"
)

// BuildSuccessor returns the unsigned successor of prev, the trust bundle in
// force, whose canonical bytes are prevCanonical and whose policy document
// is prevPolicy (KEY-07 root rotation). The successor is version prev+1,
// carries prev's SHA-256 as prev, is issued at issuedAt, names roots at
// threshold as its root set and carries the SHA-256 of policy. Its CA, ops
// and log keys are prev's, unchanged: rotating a root never changes an
// online key (CA rotation is KEY-08).
//
// The result satisfies every rule of VerifySuccessor that does not involve
// a signature, and is refused with the same sentinel errors otherwise; it
// still needs prev.Root.Threshold signatures by the previous roots AND
// threshold signatures by the new roots on both documents.
func BuildSuccessor(prev *Bundle, prevCanonical, prevPolicy []byte, roots []RootKey, threshold uint32, policy []byte, issuedAt string) (*Bundle, error) {
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
	if err := checkTimestamp(issuedAt); err != nil {
		return nil, err
	}
	if issuedAt < prev.IssuedAt {
		return nil, fmt.Errorf("%w: issued_at %s is before the previous bundle's %s; check the ceremony machine's clock",
			ErrVersionChain, issuedAt, prev.IssuedAt)
	}
	if !bytes.Equal(policy, prevPolicy) && (p.Version != pp.Version+1 || p.Prev != SHA256Hex(prevPolicy)) {
		return nil, fmt.Errorf("%w: a changed policy must be version %d with the previous policy's SHA-256 as prev, got version %d",
			ErrVersionChain, pp.Version+1, p.Version)
	}
	if err := CheckAdminsNotRoots(p, roots, prev.Root.Keys); err != nil {
		return nil, err
	}
	next := &Bundle{
		Version:      prev.Version + 1,
		Prev:         SHA256Hex(prevCanonical),
		IssuedAt:     issuedAt,
		Root:         RootSet{Keys: append([]RootKey(nil), roots...), Threshold: threshold},
		CAs:          append([]CAEntry(nil), prev.CAs...),
		OpsKey:       prev.OpsKey,
		Log:          prev.Log,
		PolicySHA256: SHA256Hex(policy),
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return next, nil
}
