package trust

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
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
	// CASwitch are the roles whose next entry becomes active and whose
	// active entry becomes draining, and DrainAllowance what the switch
	// adds to the floor of its trusted_until (03-12e).
	CASwitch       []string
	DrainAllowance time.Duration
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
// requires; a fresh one or none when prev has none). Its ops and log keys
// are prev's, unchanged, and so are its CA entries, except that each
// o.CANext entry is added in state next, in generation order within its
// role, and each o.CARetire reference, which must name a next entry of
// prev, is retired (an abort; CA rotation, KEY-08, 03-12b). For each role
// of o.CASwitch, first, the role's next entry becomes active and its
// active entry draining until DrainFloor of o.IssuedAt and the role's
// max_ttl_seconds in prevPolicy and in o.Policy, plus o.DrainAllowance
// (the switch, 03-12e).
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
	if err := applySwitch(next, prevPolicy, o); err != nil {
		return nil, err
	}
	for _, add := range o.CANext {
		add.State = "next"
		next.CAs = insertCA(next.CAs, add)
	}
	for _, ref := range o.CARetire {
		i := slices.IndexFunc(next.CAs, func(c CAEntry) bool { return c.Role == ref.Role && c.Generation == ref.Generation })
		if i < 0 {
			return nil, fmt.Errorf("%w: CA %s generation %d: no such entry", ErrVersionChain, ref.Role, ref.Generation)
		}
		if next.CAs[i].State != "next" {
			return nil, fmt.Errorf("%w: CA %s generation %d: only a next entry can be retired", ErrVersionChain, ref.Role, ref.Generation)
		}
		next.CAs[i].State = "retired"
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

// applySwitch applies the switch of every role of o.CASwitch to next, a
// copy of prev's CA entries (03-12e): the role's next entry becomes active
// and its active entry draining until the switch floor plus
// o.DrainAllowance.
func applySwitch(next *Bundle, prevPolicy []byte, o SuccessorOptions) error {
	if len(o.CASwitch) == 0 {
		return nil
	}
	pp, err := ParsePolicy(prevPolicy)
	if err != nil {
		return fmt.Errorf("previous policy: %w", err)
	}
	np, err := ParsePolicy(o.Policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	allowance := uint64(max(o.DrainAllowance, 0) / time.Second)
	for _, role := range o.CASwitch {
		ni, ai := roleEntry(next.CAs, role, "next"), roleEntry(next.CAs, role, "active")
		if ni < 0 {
			return fmt.Errorf("%w: CA %s: no next entry to switch to", ErrVersionChain, role)
		}
		if ai < 0 {
			return fmt.Errorf("%w: CA %s: no active entry to drain", ErrVersionChain, role)
		}
		ttlPrev, okPrev := RoleMaxTTL(pp, role)
		ttlNext, okNext := RoleMaxTTL(np, role)
		if !okPrev || !okNext {
			return fmt.Errorf("%w: CA %s: the switch floor cannot be computed: a policy has no %s profile", ErrVersionChain, role, role)
		}
		floor, err := DrainFloor(o.IssuedAt, ttlPrev, ttlNext)
		if err != nil {
			return fmt.Errorf("%w: CA %s: the switch floor cannot be computed: %w", ErrVersionChain, role, err)
		}
		if floor > math.MaxInt64-allowance {
			return fmt.Errorf("%w: CA %s: the switch floor %d plus the allowance overflows", ErrInvalid, role, floor)
		}
		end := int64(floor + allowance) //nolint:gosec // G115: at most math.MaxInt64, checked above
		next.CAs[ai].State, next.CAs[ai].TrustedUntil = "draining", time.Unix(end, 0).UTC().Format(TimeFormat)
		next.CAs[ni].State = "active"
	}
	return nil
}

// insertCA inserts e into cas, which are ordered by role and then by
// generation as Validate requires: after the last entry of e's role whose
// generation is not above e's, or, when there is none, before the role's
// first entry (or after the last entry of an earlier role). Validate
// refuses the result if e repeats a generation (03-12b).
func insertCA(cas []CAEntry, e CAEntry) []CAEntry {
	role := indexOf(caRoles, e.Role)
	at := 0
	for i, c := range cas {
		r := indexOf(caRoles, c.Role)
		if r < role || (r == role && c.Generation <= e.Generation) {
			at = i + 1
		}
	}
	return slices.Insert(cas, at, e)
}
