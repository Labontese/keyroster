package trust

import (
	"fmt"
	"math"
	"sort"

	"golang.org/x/crypto/ssh"
)

// Policy is the root-signed issuance policy. The genesis policy (version 1)
// names the admin keys whose SSHSIG authorizes issuance (D-13) and one
// certificate profile per CA role. Later phases change values through
// quorum-signed successors, not the format.
type Policy struct {
	Version         uint64      `json:"version"`
	Prev            string      `json:"prev"`
	AdminQuorum     uint32      `json:"admin_quorum"`
	Admins          []AdminKey  `json:"admins"`
	CAProfiles      []CAProfile `json:"ca_profiles"`
	TimelockSeconds uint64      `json:"timelock_seconds"`
}

// AdminKey is one admin's SSH public key.
type AdminKey struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// CAProfile bounds the certificates one CA role may issue. Default
// extensions are always granted; allowed extensions may be requested in
// addition; allowed critical options may be requested.
type CAProfile struct {
	Role                   string   `json:"role"`
	MaxTTLSeconds          uint64   `json:"max_ttl_seconds"`
	DefaultExtensions      []string `json:"default_extensions"`
	AllowedExtensions      []string `json:"allowed_extensions"`
	AllowedCriticalOptions []string `json:"allowed_critical_options"`
}

// NamespacePolicy is the SSHSIG namespace of root signatures over a policy.
const NamespacePolicy = "keyroster/policy/v1"

var (
	adminKeyTypes = set(ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256)
	// The OpenSSH certificate extensions and critical options
	// (PROTOCOL.certkeys).
	certExtensions  = set("permit-pty", "permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc", "no-touch-required")
	criticalOptions = set("force-command", "source-address", "verify-required")
)

// ParsePolicy decodes a canonical policy and validates it.
func ParsePolicy(data []byte) (*Policy, error) {
	var p Policy
	if err := decodeStrict(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Canonical returns the canonical encoding of p (the bytes roots sign).
func (p *Policy) Canonical() ([]byte, error) { return canonical(p) }

// Validate checks every structural rule of a policy.
func (p *Policy) Validate() error {
	if p.Version < 1 {
		return fmt.Errorf("%w: policy version must be >= 1", ErrInvalid)
	}
	if !isHash(p.Prev) {
		return fmt.Errorf("%w: policy prev must be 64 lowercase hex digits", ErrInvalid)
	}
	if p.Version == 1 && p.Prev != GenesisPrev {
		return fmt.Errorf("%w: a version 1 policy must have an all-zero prev", ErrInvalid)
	}
	if p.AdminQuorum < 1 || int(p.AdminQuorum) > len(p.Admins) {
		return fmt.Errorf("%w: admin_quorum %d with %d admins", ErrInvalid, p.AdminQuorum, len(p.Admins))
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i, a := range p.Admins {
		where := fmt.Sprintf("admins[%d]", i)
		if !validName(a.Name) {
			return fmt.Errorf("%w: %s: name %q (want 1-64 of a-z 0-9 . _ -)", ErrInvalid, where, a.Name)
		}
		if names[a.Name] {
			return fmt.Errorf("%w: %s: duplicate admin name %q", ErrInvalid, where, a.Name)
		}
		names[a.Name] = true
		pub, err := ParseKey(a.Key)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalid, where, err)
		}
		if !adminKeyTypes[pub.Type()] {
			return fmt.Errorf("%w: %s: admin key type %s", ErrAlgorithm, where, pub.Type())
		}
		if keys[string(pub.Marshal())] {
			return fmt.Errorf("%w: %s repeats an admin key", ErrDuplicateKey, where)
		}
		keys[string(pub.Marshal())] = true
	}
	if len(p.CAProfiles) != len(caRoles) {
		return fmt.Errorf("%w: want one profile per role (user, host, machine), got %d", ErrCARole, len(p.CAProfiles))
	}
	for i, prof := range p.CAProfiles {
		if prof.Role != caRoles[i] {
			return fmt.Errorf("%w: ca_profiles[%d] is %q, want %q", ErrCARole, i, prof.Role, caRoles[i])
		}
		if err := prof.validate(); err != nil {
			return fmt.Errorf("ca_profiles[%d] (%s): %w", i, prof.Role, err)
		}
	}
	return nil
}

func (c *CAProfile) validate() error {
	if c.MaxTTLSeconds == 0 || c.MaxTTLSeconds > math.MaxUint32 {
		return fmt.Errorf("%w: max_ttl_seconds %d (want 1 to %d)", ErrInvalid, c.MaxTTLSeconds, uint64(math.MaxUint32))
	}
	if err := checkList("default_extensions", c.DefaultExtensions, certExtensions); err != nil {
		return err
	}
	if err := checkList("allowed_extensions", c.AllowedExtensions, certExtensions); err != nil {
		return err
	}
	if err := checkList("allowed_critical_options", c.AllowedCriticalOptions, criticalOptions); err != nil {
		return err
	}
	for _, d := range c.DefaultExtensions {
		if indexOf(c.AllowedExtensions, d) >= 0 {
			return fmt.Errorf("%w: %s is both a default and an allowed extension", ErrInvalid, d)
		}
	}
	if c.Role == RoleHost && (len(c.DefaultExtensions) != 0 || len(c.AllowedExtensions) != 0 || len(c.AllowedCriticalOptions) != 0) {
		return fmt.Errorf("%w: host certificates carry no extensions or critical options", ErrInvalid)
	}
	return nil
}

// checkList requires a non-null, sorted, duplicate-free list of allowed
// values, so each policy has one encoding.
func checkList(name string, list []string, allowed map[string]bool) error {
	if list == nil {
		return fmt.Errorf("%w: %s must be an array, not null", ErrInvalid, name)
	}
	if !sort.StringsAreSorted(list) {
		return fmt.Errorf("%w: %s must be sorted", ErrInvalid, name)
	}
	for i, v := range list {
		if !allowed[v] {
			return fmt.Errorf("%w: %s: unknown value %q", ErrInvalid, name, v)
		}
		if i > 0 && list[i-1] == v {
			return fmt.Errorf("%w: %s: duplicate %q", ErrInvalid, name, v)
		}
	}
	return nil
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
