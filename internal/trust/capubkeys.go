package trust

import "fmt"

// CAPubKeys is the unsigned list of online public keys the CA host hands to
// the offline root ceremony (ca-pubkeys.json): one key per role user, host,
// machine, ops and log, in that order.
type CAPubKeys struct {
	Keys []CAPubKey `json:"keys"`
}

// CAPubKey is one online public key with its algorithm and custody.
type CAPubKey struct {
	Role    string `json:"role"`
	Key     string `json:"key"`
	Alg     string `json:"alg"`
	Custody string `json:"custody"`
}

// CAPubKeyRoles is the fixed role order of ca-pubkeys.json.
var CAPubKeyRoles = []string{RoleUser, RoleHost, RoleMachine, "ops", "log"}

// ParseCAPubKeys decodes a canonical ca-pubkeys document and validates it.
func ParseCAPubKeys(data []byte) (*CAPubKeys, error) {
	var c CAPubKeys
	if err := decodeStrict(data, &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Canonical returns the canonical encoding of c.
func (c *CAPubKeys) Canonical() ([]byte, error) { return canonical(c) }

// Validate checks roles, order, algorithms, custody and key distinctness.
func (c *CAPubKeys) Validate() error {
	if len(c.Keys) != len(CAPubKeyRoles) {
		return fmt.Errorf("%w: ca-pubkeys needs exactly %d keys (user, host, machine, ops, log), got %d", ErrCARole, len(CAPubKeyRoles), len(c.Keys))
	}
	seen := map[string]bool{}
	for i, k := range c.Keys {
		if k.Role != CAPubKeyRoles[i] {
			return fmt.Errorf("%w: keys[%d] is %q, want %q", ErrCARole, i, k.Role, CAPubKeyRoles[i])
		}
		pub, err := checkOnlineKey(k.Role, k.Key, k.Alg, k.Custody)
		if err != nil {
			return err
		}
		if seen[string(pub.Marshal())] {
			return fmt.Errorf("%w: %s repeats another role's key", ErrDuplicateKey, k.Role)
		}
		seen[string(pub.Marshal())] = true
	}
	return nil
}

// Key returns the entry for role.
func (c *CAPubKeys) Key(role string) (CAPubKey, bool) {
	for _, k := range c.Keys {
		if k.Role == role {
			return k, true
		}
	}
	return CAPubKey{}, false
}
