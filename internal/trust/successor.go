package trust

import (
	"errors"
	"fmt"
)

// SuccessorOptions are what a successor changes or sets, beside the version,
// prev and the online keys that BuildSuccessor derives from the bundle in
// force. Later plans add their fields here instead of cutting the signature
// of BuildSuccessor again (03-13, 03-14; 03-12b).
type SuccessorOptions struct {
	// Roots at Threshold are the successor's root set.
	Roots     []RootKey
	Threshold uint32
	// Policy is the successor's policy document; the successor carries its
	// SHA-256.
	Policy []byte
	// IssuedAt is the successor's issued_at.
	IssuedAt string
	// InstallationID is prev's ID when prev has one, which the chain rule
	// requires; a fresh one or none when prev has none.
	InstallationID string
	// CANext are CA entries to add in state next, and CARetire the next
	// entries to retire (an abort) (03-12b).
	CANext   []CAEntry
	CARetire []CARef
}

// CARef names one CA entry of a bundle by role and generation (03-12b).
type CARef struct {
	Role       string
	Generation uint32
}

// BuildSuccessor returns the unsigned successor of prev, the trust bundle in
// force, whose canonical bytes are prevCanonical and whose policy document
// is prevPolicy (KEY-07 root rotation). The successor is version prev+1,
// carries prev's SHA-256 as prev, is issued at o.IssuedAt, names o.Roots at
// o.Threshold as its root set, carries the SHA-256 of o.Policy and carries
// o.InstallationID (prev's ID when prev has one, which the chain rule
// requires; a fresh one or none when prev has none). Its CA, ops
// and log keys are prev's, unchanged: rotating a root never changes an
// online key (CA rotation is KEY-08).
//
// The result satisfies every rule of VerifySuccessor that does not involve
// a signature (checkSuccessorChain, which the two share), and is refused
// with the same sentinel errors otherwise; an issued_at before prev's also
// names the ceremony clock. It still needs prev.Root.Threshold signatures
// by the previous roots AND threshold signatures by the new roots on both
// documents.
func BuildSuccessor(prev *Bundle, prevCanonical, prevPolicy []byte, o SuccessorOptions) (*Bundle, error) {
	if prev == nil {
		return nil, fmt.Errorf("%w: no previous bundle", ErrVersionChain)
	}
	next := &Bundle{
		Version:        prev.Version + 1,
		Prev:           SHA256Hex(prevCanonical),
		IssuedAt:       o.IssuedAt,
		Root:           RootSet{Keys: append([]RootKey(nil), o.Roots...), Threshold: o.Threshold},
		CAs:            append([]CAEntry(nil), prev.CAs...),
		OpsKey:         prev.OpsKey,
		Log:            prev.Log,
		PolicySHA256:   SHA256Hex(o.Policy),
		InstallationID: o.InstallationID,
	}
	// Structure first, as VerifySuccessor parses next before the chain
	// check; then the chain rule the verifier enforces.
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if _, err := checkSuccessorChain(prev, prevCanonical, prevPolicy, next, o.Policy); err != nil {
		if errors.Is(err, errIssuedBeforePrev) {
			return nil, fmt.Errorf("%w; check the ceremony machine's clock", err)
		}
		return nil, err
	}
	return next, nil
}
