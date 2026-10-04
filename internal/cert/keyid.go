package cert

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// KeyID is the structured certificate key ID (CA-04):
//
//	kr1/ca={ca}/sub={subject}/req={request id}/pol={policy}/ser={serial}
//
// The fields appear in that fixed order. ca is user, host or machine; the
// subject matches ^[a-z0-9][a-z0-9._@:+-]{0,63}$; the request id is exactly
// 32 lowercase hex digits; policy and serial are decimals without leading
// zeros. Policy 0 means that no policy was installed.
type KeyID struct {
	CA      string
	Subject string
	Request string
	Policy  uint64
	Serial  uint64
}

const keyIDPrefix = "kr1/"

var (
	keyIDSubjectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:+-]{0,63}$`)
	keyIDRequestRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	keyIDDecimalRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
)

// String formats the key ID. It does not validate; use ParseKeyID on the
// result (Build does) to check it.
func (k KeyID) String() string {
	return fmt.Sprintf("kr1/ca=%s/sub=%s/req=%s/pol=%d/ser=%d", k.CA, k.Subject, k.Request, k.Policy, k.Serial)
}

// ParseKeyID parses a key ID strictly.
func ParseKeyID(s string) (KeyID, error) {
	var k KeyID
	rest, ok := strings.CutPrefix(s, keyIDPrefix)
	if !ok {
		return k, fmt.Errorf("%w: missing kr1 prefix", ErrKeyID)
	}
	parts := strings.Split(rest, "/")
	names := [...]string{"ca", "sub", "req", "pol", "ser"}
	if len(parts) != len(names) {
		return k, fmt.Errorf("%w: want %d fields, got %d", ErrKeyID, len(names), len(parts))
	}
	vals := make([]string, len(names))
	for i, part := range parts {
		name, val, ok := strings.Cut(part, "=")
		if !ok || name != names[i] {
			return k, fmt.Errorf("%w: field %d is not %q", ErrKeyID, i, names[i])
		}
		vals[i] = val
	}
	switch vals[0] {
	case "user", "host", "machine":
		k.CA = vals[0]
	default:
		return k, fmt.Errorf("%w: unknown ca", ErrKeyID)
	}
	if !keyIDSubjectRE.MatchString(vals[1]) {
		return k, fmt.Errorf("%w: invalid subject", ErrKeyID)
	}
	k.Subject = vals[1]
	if !keyIDRequestRE.MatchString(vals[2]) {
		return k, fmt.Errorf("%w: invalid request id", ErrKeyID)
	}
	k.Request = vals[2]
	var err error
	if k.Policy, err = parseDecimal(vals[3]); err != nil {
		return k, fmt.Errorf("%w: invalid policy: %w", ErrKeyID, err)
	}
	if k.Serial, err = parseDecimal(vals[4]); err != nil {
		return k, fmt.Errorf("%w: invalid serial: %w", ErrKeyID, err)
	}
	return k, nil
}

func parseDecimal(s string) (uint64, error) {
	if !keyIDDecimalRE.MatchString(s) {
		return 0, fmt.Errorf("not a canonical decimal")
	}
	return strconv.ParseUint(s, 10, 64)
}
