package trust

import (
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
	// WebAuthn is the WebAuthn relying party passkey logins are bound to
	// (Phase 2, D-09). It is a pointer with omitempty and the last field,
	// so a policy without it (every Phase 1 policy) keeps its exact bytes,
	// and "webauthn":null is refused as non-canonical. The signer refuses
	// every login issuance while it is absent.
	WebAuthn *WebAuthnRP `json:"webauthn,omitempty"`
	// PoP enables certificate issuance on proof of possession of a key the
	// admin-signed directory names: host certificates for host agents and
	// renewals for machine identities (Phase 3). A pointer with omitempty
	// and the last field, like WebAuthn, so every earlier policy keeps its
	// exact bytes and "pop":null is refused as non-canonical. Once a policy
	// sets hosts, no successor may clear it (CheckPoPSuccessor).
	PoP *PoPPolicy `json:"pop,omitempty"`
}

// PoPPolicy says which proof-of-possession issuance the root allows: host
// certificates to enrolled host agents (Hosts) and machine certificate
// renewals (Machines). At least one is true when the policy carries it.
type PoPPolicy struct {
	Hosts    bool `json:"hosts"`
	Machines bool `json:"machines"`
}

// ErrPoPHostsRemoved refuses a successor policy that turns host proof of
// possession off once a policy turned it on (owner decision 2026-10-24):
// host agents get their probe certificates through it, and without them
// they could not confirm a new KRL, so revocations would stall (D-06).
var ErrPoPHostsRemoved = errors.New("trust: pop_hosts_removed: a successor policy may not turn pop.hosts off once a policy set it")

// CheckPoPSuccessor checks the PoP change from prev to next: when prev's
// pop.hosts is true, next must carry pop with hosts true, else
// ErrPoPHostsRemoved. Every other change passes: pop absent or hosts
// false to hosts true, hosts true to true, and any change of machines,
// whose off direction only stops machine renewals (the fail-safe
// direction) and holds up no revocation.
func CheckPoPSuccessor(prev, next *Policy) error {
	if prev == nil || next == nil {
		return fmt.Errorf("%w: no policy to compare", ErrInvalid)
	}
	if prev.PoP != nil && prev.PoP.Hosts && (next.PoP == nil || !next.PoP.Hosts) {
		return fmt.Errorf("%w (policy v%d sets it; v%d clears it)", ErrPoPHostsRemoved, prev.Version, next.Version)
	}
	return nil
}

// WebAuthnRP is the WebAuthn relying party of a policy: the RP ID (one DNS
// hostname, which every enrolled passkey is bound to forever) and the
// exact origins a login page may be served from. The signer checks
// rpIdHash against RPID and the clientDataJSON origin against Origins.
type WebAuthnRP struct {
	RPID    string   `json:"rp_id"`
	Origins []string `json:"origins"`
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

// MaxAdminQuorum is the largest admin quorum a policy may require: an issue
// request carries at most this many evidence items (wire.MaxEvidence, kept
// equal by a test in internal/signer), so a larger quorum could never be
// met and the CA could never issue.
const MaxAdminQuorum = 4

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
	if err := DecodeStrict(data, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Canonical returns the canonical encoding of p (the bytes roots sign).
func (p *Policy) Canonical() ([]byte, error) { return CanonicalJSON(p) }

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
	if p.AdminQuorum > MaxAdminQuorum {
		return fmt.Errorf("%w: admin_quorum %d is above %d, the most admin signatures one issue request can carry", ErrInvalid, p.AdminQuorum, MaxAdminQuorum)
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
	if p.WebAuthn != nil {
		if err := p.WebAuthn.validate(); err != nil {
			return fmt.Errorf("webauthn: %w", err)
		}
	}
	if p.PoP != nil && !p.PoP.Hosts && !p.PoP.Machines {
		return fmt.Errorf("%w: pop: at least one of hosts and machines must be true; omit pop to enable neither", ErrInvalid)
	}
	return nil
}

// rpLabelRE is one lowercase DNS label.
var rpLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validate checks the relying party (D-09). The RP ID is a lowercase DNS
// hostname of at least two labels: no IP literal, no port, no trailing
// dot, no all-digit last label. A Tailscale name must be a machine name
// (machine.tailnet.ts.net, or one more label under c.ts.net): ts.net is a
// public suffix, so a bare tailnet domain could be claimed as RP by any
// machine of that tailnet (RESEARCH Pitfall 6). Every origin is exactly
// https://<rp_id>, optionally with a port other than 443 (browsers drop
// the default port), and the list is sorted and duplicate-free.
func (w *WebAuthnRP) validate() error {
	rp := w.RPID
	if len(rp) == 0 || len(rp) > 253 {
		return fmt.Errorf("%w: rp_id must be 1 to 253 bytes", ErrInvalid)
	}
	if net.ParseIP(strings.Trim(rp, "[]")) != nil {
		return fmt.Errorf("%w: rp_id %q is an IP address; WebAuthn needs a DNS name", ErrInvalid, rp)
	}
	labels := strings.Split(rp, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: rp_id %q needs at least two labels", ErrInvalid, rp)
	}
	for _, l := range labels {
		if !rpLabelRE.MatchString(l) {
			return fmt.Errorf("%w: rp_id %q is not a lowercase DNS hostname without port or trailing dot", ErrInvalid, rp)
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("%w: rp_id %q has an all-digit last label", ErrInvalid, rp)
	}
	if (rp == "ts.net" || strings.HasSuffix(rp, ".ts.net")) && len(labels) < 4 {
		return fmt.Errorf("%w: rp_id %q is a tailnet domain; use the machine name (machine.tailnet.ts.net)", ErrInvalid, rp)
	}
	if (rp == "c.ts.net" || strings.HasSuffix(rp, ".c.ts.net")) && len(labels) < 5 {
		return fmt.Errorf("%w: rp_id %q is a tailnet domain; use the machine name (machine.tailnet.c.ts.net)", ErrInvalid, rp)
	}
	if len(w.Origins) == 0 {
		return fmt.Errorf("%w: origins must list at least one origin", ErrInvalid)
	}
	if !sort.StringsAreSorted(w.Origins) {
		return fmt.Errorf("%w: origins must be sorted", ErrInvalid)
	}
	for i, o := range w.Origins {
		if i > 0 && w.Origins[i-1] == o {
			return fmt.Errorf("%w: origins: duplicate %q", ErrInvalid, o)
		}
		if !validOrigin(o, rp) {
			return fmt.Errorf("%w: origin %q is not https://%s with an optional port other than 443", ErrInvalid, o, rp)
		}
	}
	return nil
}

// validOrigin reports whether o is exactly https://rp or https://rp:PORT
// with PORT a decimal 1-65535 without leading zeros, other than 443.
func validOrigin(o, rp string) bool {
	rest, ok := strings.CutPrefix(o, "https://"+rp)
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	port, ok := strings.CutPrefix(rest, ":")
	if !ok || port == "" || len(port) > 5 || port[0] == '0' || strings.Trim(port, "0123456789") != "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && n != 443
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
