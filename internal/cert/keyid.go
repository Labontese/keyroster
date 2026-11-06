package cert

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// KeyID is the structured certificate key ID (CA-04). Three versions
// exist:
//
//	kr1/ca={ca}/sub={subject}/req={request id}/pol={policy}/ser={serial}
//	kr2/ca={ca}/sub={subject}/req={request id}/pol={policy}/dir={directory}/roles={r1}+{r2}/ser={serial}
//	kr3/ca={ca}/sub={subject}/req={request id}/pol={policy}/dir={directory}/ser={serial}
//
// The fields appear in that fixed order. ca is user, host or machine; the
// subject matches ^[a-z0-9][a-z0-9._@:+-]{0,63}$; the request id is exactly
// 32 lowercase hex digits; policy, directory and serial are decimals
// without leading zeros. Policy 0 means that no policy was installed.
//
// kr1 is the admin path's key ID (Phase 1, unchanged). kr2 is the passkey
// login's (D-08): it adds the directory version the signer authorized the
// login under and the roles it selected, 1 to 16 role names matching
// ^[a-z0-9][a-z0-9._-]{0,31}$, sorted, unique and joined by "+". A KeyID
// with nil Roles is kr1; Directory must then be 0. A key ID is at most
// MaxKeyIDLen bytes.
//
// kr3 (03-09) is the key ID of a certificate obtained by proof of
// possession: a host certificate (ca=host, 03-09), and later machine and
// probe certificates (ca=machine, 03-10 and 03-11). It is selected by V3
// alone, so kr1 and kr2 output is unchanged; it carries the directory
// version the signer issued under and no roles (Roles nil). Its subject
// follows kr1's grammar, at most 64 bytes, except that a ca=machine
// subject starting "probe." may be up to 70 bytes ("probe." and a 64-byte
// host name, 03-10; Q-09-8): the longest kr3 key ID is then 201 bytes,
// within the 211-byte key ID budget (docs/format-registry.md). Only those
// probe subjects exceed 64 bytes, so every other subject stays revocable
// by subject with wire's 64-byte grammar, and probes are never revoked by
// subject.
type KeyID struct {
	CA        string
	Subject   string
	Request   string
	Policy    uint64
	Directory uint64   // kr2 only
	Roles     []string // kr2 only; nil means kr1 (or kr3 with V3)
	Serial    uint64
	// V3 selects kr3 (03-09); Roles must then be nil.
	V3 bool
}

// Key ID limits.
const (
	MaxKeyIDLen    = 1024
	MaxKeyIDRoles  = 16
	keyIDPrefix    = "kr1/"
	keyIDPrefixKr2 = "kr2/"
	keyIDPrefixKr3 = "kr3/"
)

var (
	keyIDSubjectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:+-]{0,63}$`)
	keyIDRequestRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	keyIDDecimalRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
	keyIDRoleRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	// keyIDProbeRE is the one kr3 subject above 64 bytes: a ca=machine
	// probe subject, "probe." and up to 64 more bytes (Q-09-8).
	keyIDProbeRE = regexp.MustCompile(`^probe\.[a-z0-9._@:+-]{0,64}$`)
)

// String formats the key ID: kr3 when V3 is set, else kr1 when Roles is
// nil and kr2 otherwise. It does not validate; use ParseKeyID on the
// result (Build does) to check it.
func (k KeyID) String() string {
	if k.V3 {
		return fmt.Sprintf("kr3/ca=%s/sub=%s/req=%s/pol=%d/dir=%d/ser=%d", k.CA, k.Subject, k.Request, k.Policy, k.Directory, k.Serial)
	}
	if k.Roles == nil {
		return fmt.Sprintf("kr1/ca=%s/sub=%s/req=%s/pol=%d/ser=%d", k.CA, k.Subject, k.Request, k.Policy, k.Serial)
	}
	return fmt.Sprintf("kr2/ca=%s/sub=%s/req=%s/pol=%d/dir=%d/roles=%s/ser=%d",
		k.CA, k.Subject, k.Request, k.Policy, k.Directory, strings.Join(k.Roles, "+"), k.Serial)
}

// Equal reports whether k and o are the same key ID.
func (k KeyID) Equal(o KeyID) bool {
	return k.CA == o.CA && k.Subject == o.Subject && k.Request == o.Request && k.Policy == o.Policy &&
		k.Directory == o.Directory && k.Serial == o.Serial && (k.Roles == nil) == (o.Roles == nil) &&
		slices.Equal(k.Roles, o.Roles) && k.V3 == o.V3
}

// ParseKeyID parses a kr1, kr2 or kr3 key ID strictly. A kr3 key ID needs
// ca host or machine.
func ParseKeyID(s string) (KeyID, error) {
	var k KeyID
	if len(s) > MaxKeyIDLen {
		return k, fmt.Errorf("%w: longer than %d bytes", ErrKeyID, MaxKeyIDLen)
	}
	names := []string{"ca", "sub", "req", "pol", "ser"}
	kr2, kr3 := false, false
	rest, ok := strings.CutPrefix(s, keyIDPrefix)
	switch {
	case ok:
	case strings.HasPrefix(s, keyIDPrefixKr2):
		rest, kr2 = s[len(keyIDPrefixKr2):], true
		names = []string{"ca", "sub", "req", "pol", "dir", "roles", "ser"}
	case strings.HasPrefix(s, keyIDPrefixKr3):
		rest, kr3 = s[len(keyIDPrefixKr3):], true
		names = []string{"ca", "sub", "req", "pol", "dir", "ser"}
	default:
		return k, fmt.Errorf("%w: missing kr1, kr2 or kr3 prefix", ErrKeyID)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != len(names) {
		return k, fmt.Errorf("%w: want %d fields, got %d", ErrKeyID, len(names), len(parts))
	}
	vals := map[string]string{}
	for i, part := range parts {
		name, val, ok := strings.Cut(part, "=")
		if !ok || name != names[i] {
			return k, fmt.Errorf("%w: field %d is not %q", ErrKeyID, i, names[i])
		}
		vals[name] = val
	}
	switch vals["ca"] {
	case "user", "host", "machine":
		k.CA = vals["ca"]
	default:
		return k, fmt.Errorf("%w: unknown ca", ErrKeyID)
	}
	if kr3 && k.CA == "user" {
		return k, fmt.Errorf("%w: a kr3 key ID is for ca host or machine", ErrKeyID)
	}
	probe := kr3 && k.CA == "machine" && keyIDProbeRE.MatchString(vals["sub"])
	if !keyIDSubjectRE.MatchString(vals["sub"]) && !probe {
		return k, fmt.Errorf("%w: invalid subject", ErrKeyID)
	}
	k.Subject = vals["sub"]
	if !keyIDRequestRE.MatchString(vals["req"]) {
		return k, fmt.Errorf("%w: invalid request id", ErrKeyID)
	}
	k.Request = vals["req"]
	var err error
	if k.Policy, err = parseDecimal(vals["pol"]); err != nil {
		return k, fmt.Errorf("%w: invalid policy: %w", ErrKeyID, err)
	}
	if kr2 || kr3 {
		if k.Directory, err = parseDecimal(vals["dir"]); err != nil {
			return k, fmt.Errorf("%w: invalid directory: %w", ErrKeyID, err)
		}
	}
	if kr2 {
		if k.Roles, err = parseRoles(vals["roles"]); err != nil {
			return k, err
		}
	}
	k.V3 = kr3
	if k.Serial, err = parseDecimal(vals["ser"]); err != nil {
		return k, fmt.Errorf("%w: invalid serial: %w", ErrKeyID, err)
	}
	return k, nil
}

// parseRoles parses the roles field of a kr2 key ID: 1 to 16 role names,
// sorted, unique, joined by "+".
func parseRoles(s string) ([]string, error) {
	roles := strings.Split(s, "+")
	if len(roles) > MaxKeyIDRoles {
		return nil, fmt.Errorf("%w: more than %d roles", ErrKeyID, MaxKeyIDRoles)
	}
	for i, r := range roles {
		if !keyIDRoleRE.MatchString(r) {
			return nil, fmt.Errorf("%w: invalid role name", ErrKeyID)
		}
		if i > 0 && roles[i-1] >= r {
			return nil, fmt.Errorf("%w: roles must be sorted and unique", ErrKeyID)
		}
	}
	return roles, nil
}

func parseDecimal(s string) (uint64, error) {
	if !keyIDDecimalRE.MatchString(s) {
		return 0, fmt.Errorf("not a canonical decimal")
	}
	return strconv.ParseUint(s, 10, 64)
}
