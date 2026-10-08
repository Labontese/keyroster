package trust

import (
	"errors"
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
// a signature (checkSuccessorChain, which the two share), and is refused
// with the same sentinel errors otherwise; an issued_at before prev's also
// names the ceremony clock. It still needs prev.Root.Threshold signatures
// by the previous roots AND threshold signatures by the new roots on both
// documents.
func BuildSuccessor(prev *Bundle, prevCanonical, prevPolicy []byte, roots []RootKey, threshold uint32, policy []byte, issuedAt string) (*Bundle, error) {
	if prev == nil {
		return nil, fmt.Errorf("%w: no previous bundle", ErrVersionChain)
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
	// Structure first, as VerifySuccessor parses next before the chain
	// check; then the chain rule the verifier enforces.
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if _, err := checkSuccessorChain(prev, prevCanonical, prevPolicy, next, policy); err != nil {
		if errors.Is(err, errIssuedBeforePrev) {
			return nil, fmt.Errorf("%w; check the ceremony machine's clock", err)
		}
		return nil, err
	}
	return next, nil
}
