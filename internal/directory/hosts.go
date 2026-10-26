package directory

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/trust"
)

// Limits of the host and machine entries (D-15, D-16).
const (
	// MaxHostKeys bounds the host public keys of one host entry.
	MaxHostKeys = 8
	// MaxHostPrincipals bounds the host-certificate principals of one
	// host entry.
	MaxHostPrincipals = 8
	// MaxMachineRoles bounds the roles of one machine entry.
	MaxMachineRoles = 16
	// MinMachineTTLSeconds is the shortest machine max TTL.
	MinMachineTTLSeconds = 60
	// maxDNSName is the longest DNS name a host principal may be.
	maxDNSName = 253
)

// Errors of the installation binding (D-04). The signer and audit verify
// refuse a directory install with them; see CheckInstallation.
var (
	// ErrInstallationMissing is a directory without an installation ID
	// while the trust bundle in force carries one.
	ErrInstallationMissing = errors.New("directory: names no installation, but the trust bundle in force does")
	// ErrInstallationMismatch is a directory whose installation ID is not
	// the one of the trust bundle in force: it was signed for another
	// installation.
	ErrInstallationMismatch = errors.New("directory: names another installation than the trust bundle in force")
	// ErrInstallationUnknown is a directory with an installation ID while
	// the trust bundle in force has none.
	ErrInstallationUnknown = errors.New("directory: names an installation, but the trust bundle in force has none")
)

// Host is one host of the fleet (D-11, D-16). It belongs to exactly one
// host group, whose account maps decide the AuthorizedPrincipalsFile the
// host's agent writes. Principals are the names the host's own host
// certificate carries (the names clients connect to), typed by the admin
// and accepted only in their one canonical spelling; they are not the
// role principals of an AuthorizedPrincipalsFile. Keys are the host's
// public keys (Ed25519 or ECDSA) in trust.FormatKey form. Every value
// comes only from an admin-signed directory, never from the host, the
// server or an enrollment request.
type Host struct {
	Name       string   `json:"name"`
	HostGroup  string   `json:"host_group"`
	Keys       []string `json:"keys"`
	Principals []string `json:"principals"`
	Status     string   `json:"status"`
}

// Machine is one automation identity (D-15): its public key, the roles
// whose principals its certificates carry and its own max TTL.
type Machine struct {
	Name          string   `json:"name"`
	Key           string   `json:"key"`
	Roles         []string `json:"roles"`
	MaxTTLSeconds uint64   `json:"max_ttl_seconds"`
	Status        string   `json:"status"`
}

var (
	// hostKeyTypes are the host key types a host entry may name: no RSA,
	// no security keys (a host key is used unattended).
	hostKeyTypes = map[string]bool{
		ssh.KeyAlgoED25519: true, ssh.KeyAlgoECDSA256: true, ssh.KeyAlgoECDSA384: true, ssh.KeyAlgoECDSA521: true,
	}
	// machineKeyTypes are the machine key types: the host key types plus
	// security keys, which an automation may hold.
	machineKeyTypes = map[string]bool{
		ssh.KeyAlgoED25519: true, ssh.KeyAlgoECDSA256: true, ssh.KeyAlgoECDSA384: true, ssh.KeyAlgoECDSA521: true,
		ssh.KeyAlgoSKED25519: true, ssh.KeyAlgoSKECDSA256: true,
	}
)

// CheckInstallation is the installation rule of a directory install
// (D-04), applied by the signer to every directory it installs and by
// audit verify to every directory_install entry, against bundleID, the
// installation ID of the trust bundle in force: while the bundle carries
// one, the directory must carry the same (ErrInstallationMissing,
// ErrInstallationMismatch); while it has none, the directory must have
// none either (ErrInstallationUnknown).
func CheckInstallation(d *Directory, bundleID string) error {
	switch {
	case bundleID != "" && d.InstallationID == "":
		return fmt.Errorf("%w (bundle installation %s)", ErrInstallationMissing, bundleID)
	case bundleID != "" && d.InstallationID != bundleID:
		return fmt.Errorf("%w (directory installation %s, bundle installation %s)", ErrInstallationMismatch, d.InstallationID, bundleID)
	case bundleID == "" && d.InstallationID != "":
		return fmt.Errorf("%w (directory installation %s)", ErrInstallationUnknown, d.InstallationID)
	}
	return nil
}

// CheckStoredInstallation is the installation rule for a directory that is
// already installed when the trust bundle in force changes (the signer's
// start-up check, audit verify after a bundle_install entry). It is
// CheckInstallation, except that a directory without an installation ID
// stays authorized under a bundle that carries one: the owner's lenient
// transition answer to D-04 (03-01), so that the installation that gains
// an ID keeps logging in until keyroster directory rebind installs the
// bound version. Agents never accept a directory without an ID (03-07).
func CheckStoredInstallation(d *Directory, bundleID string) error {
	if d.InstallationID == "" {
		return nil
	}
	return CheckInstallation(d, bundleID)
}

// HostByName returns the host entry named name.
func (d *Directory) HostByName(name string) (*Host, bool) {
	i := slices.IndexFunc(d.Hosts, func(h Host) bool { return h.Name == name })
	if i < 0 {
		return nil, false
	}
	return &d.Hosts[i], true
}

// HostForKey returns the host entry that names pub as one of its host
// keys, whatever its status; Validate guarantees there is at most one.
func (d *Directory) HostForKey(pub ssh.PublicKey) (*Host, bool) {
	if pub == nil {
		return nil, false
	}
	k := trust.FormatKey(pub)
	for i := range d.Hosts {
		if slices.Contains(d.Hosts[i].Keys, k) {
			return &d.Hosts[i], true
		}
	}
	return nil, false
}

// MachineByName returns the machine entry named name.
func (d *Directory) MachineByName(name string) (*Machine, bool) {
	i := slices.IndexFunc(d.Machines, func(m Machine) bool { return m.Name == name })
	if i < 0 {
		return nil, false
	}
	return &d.Machines[i], true
}

// sortHostsAndMachines is Sort for the host and machine lists: by name,
// their inner lists sorted, and an empty list as nil, because both lists
// are omitted from the canonical encoding when empty.
func (d *Directory) sortHostsAndMachines() {
	if len(d.Hosts) == 0 {
		d.Hosts = nil
	}
	if len(d.Machines) == 0 {
		d.Machines = nil
	}
	sort.SliceStable(d.Hosts, func(i, j int) bool { return d.Hosts[i].Name < d.Hosts[j].Name })
	for i := range d.Hosts {
		d.Hosts[i].Keys = sortedStrings(d.Hosts[i].Keys)
		d.Hosts[i].Principals = sortedStrings(d.Hosts[i].Principals)
	}
	sort.SliceStable(d.Machines, func(i, j int) bool { return d.Machines[i].Name < d.Machines[j].Name })
	for i := range d.Machines {
		d.Machines[i].Roles = sortedStrings(d.Machines[i].Roles)
	}
}

// validateInstallation checks the installation ID's form.
func (d *Directory) validateInstallation() error {
	if d.InstallationID != "" && !trust.IsInstallationID(d.InstallationID) {
		return fmt.Errorf("%w: installation_id %q is not an installation ID", ErrInvalid, d.InstallationID)
	}
	return nil
}

// validateHosts checks the host entries against the host groups of d:
// names in the user name grammar, sorted and unique; status active or
// disabled; an existing host group; 1 to MaxHostKeys sorted unique host
// keys of a host key type in trust.FormatKey form, none on two hosts; and
// 1 to MaxHostPrincipals sorted unique principals, each in its canonical
// spelling (CheckHostPrincipal), none on two hosts. It returns the host
// keys, for the machine key check.
func (d *Directory) validateHosts() (map[string]string, error) {
	keyOwner := map[string]string{}
	if d.Hosts != nil && len(d.Hosts) == 0 {
		return nil, fmt.Errorf("%w: hosts must be omitted, not an empty array", ErrInvalid)
	}
	if err := checkSorted("hosts", names(d.Hosts, func(h Host) string { return h.Name })); err != nil {
		return nil, err
	}
	principalOwner := map[string]string{}
	for _, h := range d.Hosts {
		if !ValidUserName(h.Name) {
			return nil, fmt.Errorf("%w: host %q: invalid name", ErrInvalid, h.Name)
		}
		if h.Status != StatusActive && h.Status != StatusDisabled {
			return nil, fmt.Errorf("%w: host %s: status %q (want active or disabled)", ErrInvalid, h.Name, h.Status)
		}
		if !slices.ContainsFunc(d.HostGroups, func(g HostGroup) bool { return g.Name == h.HostGroup }) {
			return nil, fmt.Errorf("%w: host %s: unknown host group %q", ErrInvalid, h.Name, h.HostGroup)
		}
		if len(h.Keys) == 0 || len(h.Keys) > MaxHostKeys {
			return nil, fmt.Errorf("%w: host %s: needs 1 to %d host keys", ErrInvalid, h.Name, MaxHostKeys)
		}
		if err := checkSorted("host "+h.Name+" keys", h.Keys); err != nil {
			return nil, err
		}
		for _, k := range h.Keys {
			pub, err := trust.ParseKey(k)
			if err != nil {
				return nil, fmt.Errorf("%w: host %s: key: %w", ErrInvalid, h.Name, err)
			}
			if !hostKeyTypes[pub.Type()] {
				return nil, fmt.Errorf("%w: host %s: key type %s (want ssh-ed25519 or ecdsa-sha2-nistp256/384/521)", ErrInvalid, h.Name, pub.Type())
			}
			if other, dup := keyOwner[k]; dup {
				return nil, fmt.Errorf("%w: host key %s is on hosts %s and %s", ErrInvalid, ssh.FingerprintSHA256(pub), other, h.Name)
			}
			keyOwner[k] = h.Name
		}
		if len(h.Principals) == 0 || len(h.Principals) > MaxHostPrincipals {
			return nil, fmt.Errorf("%w: host %s: needs 1 to %d principals", ErrInvalid, h.Name, MaxHostPrincipals)
		}
		if err := checkSorted("host "+h.Name+" principals", h.Principals); err != nil {
			return nil, err
		}
		for _, p := range h.Principals {
			if err := CheckHostPrincipal(p); err != nil {
				return nil, fmt.Errorf("%w: host %s: %w", ErrInvalid, h.Name, err)
			}
			if other, dup := principalOwner[p]; dup {
				return nil, fmt.Errorf("%w: host principal %s is on hosts %s and %s", ErrInvalid, p, other, h.Name)
			}
			principalOwner[p] = h.Name
		}
		if err := cert.ValidatePrincipals(h.Principals); err != nil {
			return nil, fmt.Errorf("%w: host %s: %w", ErrInvalid, h.Name, err)
		}
	}
	return keyOwner, nil
}

// validateMachines checks the machine entries: names in the user name
// grammar, sorted and unique; status active or disabled; a key of a
// machine key type in trust.FormatKey form, unique across machines and
// not a host key; 1 to MaxMachineRoles sorted unique existing roles; and
// max_ttl_seconds at least MinMachineTTLSeconds.
func (d *Directory) validateMachines(hostKeys map[string]string, roles map[string]*Role) error {
	if d.Machines != nil && len(d.Machines) == 0 {
		return fmt.Errorf("%w: machines must be omitted, not an empty array", ErrInvalid)
	}
	if err := checkSorted("machines", names(d.Machines, func(m Machine) string { return m.Name })); err != nil {
		return err
	}
	keys := map[string]string{}
	for _, m := range d.Machines {
		if !ValidUserName(m.Name) {
			return fmt.Errorf("%w: machine %q: invalid name", ErrInvalid, m.Name)
		}
		if m.Status != StatusActive && m.Status != StatusDisabled {
			return fmt.Errorf("%w: machine %s: status %q (want active or disabled)", ErrInvalid, m.Name, m.Status)
		}
		pub, err := trust.ParseKey(m.Key)
		if err != nil {
			return fmt.Errorf("%w: machine %s: key: %w", ErrInvalid, m.Name, err)
		}
		if !machineKeyTypes[pub.Type()] {
			return fmt.Errorf("%w: machine %s: key type %s (want Ed25519, ECDSA or a security key)", ErrInvalid, m.Name, pub.Type())
		}
		if other, dup := keys[m.Key]; dup {
			return fmt.Errorf("%w: machine key %s is on machines %s and %s", ErrInvalid, ssh.FingerprintSHA256(pub), other, m.Name)
		}
		if host, ok := hostKeys[m.Key]; ok {
			return fmt.Errorf("%w: machine %s: key %s is the host key of host %s", ErrInvalid, m.Name, ssh.FingerprintSHA256(pub), host)
		}
		keys[m.Key] = m.Name
		if len(m.Roles) == 0 || len(m.Roles) > MaxMachineRoles {
			return fmt.Errorf("%w: machine %s: needs 1 to %d roles", ErrInvalid, m.Name, MaxMachineRoles)
		}
		if err := checkRefs("machine "+m.Name+" roles", m.Roles, func(n string) bool { return roles[n] != nil }); err != nil {
			return err
		}
		if m.MaxTTLSeconds < MinMachineTTLSeconds {
			return fmt.Errorf("%w: machine %s: max_ttl_seconds must be >= %d", ErrInvalid, m.Name, MinMachineTTLSeconds)
		}
	}
	return nil
}

// dnsLabelOK reports whether l is one lowercase RFC 1123 label: 1 to 63
// bytes of a-z, 0-9 and '-', not starting or ending with '-'.
func dnsLabelOK(l string) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// CheckHostPrincipal accepts p only in its one canonical spelling, so
// that comparing strings compares addresses and names (T-03-21):
//   - an IP literal is a string netip.ParseAddr accepts; it must have no
//     zone, must not be IPv4-mapped IPv6, and must equal the address's
//     String() (IPv4 without leading zeros, IPv6 in RFC 5952 lowercase
//     compressed form);
//   - anything else is a DNS name of lowercase RFC 1123 labels, at most
//     253 bytes, without a trailing dot, whose last label is not all
//     digits;
//   - never '*', '?', ',', whitespace or a control byte.
//
// A refusal names the canonical form when one exists. Nothing is ever
// rewritten: the directory is signed content.
func CheckHostPrincipal(p string) error {
	if p == "" {
		return errors.New("empty host principal")
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c <= ' ' || c >= 0x7f || c == '*' || c == '?' || c == ',' {
			return fmt.Errorf("host principal %s: no wildcard ('*', '?'), comma, whitespace or control byte", strconv.QuoteToASCII(p))
		}
	}
	if addr, err := netip.ParseAddr(p); err == nil {
		switch canon := addr.WithZone("").Unmap().String(); {
		case addr.Zone() != "":
			return fmt.Errorf("host principal %q: an address with a zone is not a host name; write %s", p, canon)
		case addr.Is4In6():
			return fmt.Errorf("host principal %q: an IPv4-mapped IPv6 address; write %s", p, canon)
		case canon != p:
			return fmt.Errorf("host principal %q: not the canonical spelling of its address; write %s", p, canon)
		}
		return nil
	}
	if canon, ok := dottedQuad(p); ok {
		return fmt.Errorf("host principal %q: an IPv4 address with leading zeros; write %s", p, canon)
	}
	if lower := strings.TrimSuffix(strings.ToLower(p), "."); lower != p {
		if dnsNameOK(lower) {
			return fmt.Errorf("host principal %q: write host names in lowercase without a trailing dot, as %s", p, lower)
		}
		return fmt.Errorf("host principal %q: write host names in lowercase without a trailing dot", p)
	}
	if !dnsNameOK(p) {
		return fmt.Errorf("host principal %q: neither an IP address in its canonical form nor a lowercase DNS name (labels of a-z, 0-9 and '-', at most 253 bytes, the last label not all digits)", p)
	}
	return nil
}

// dnsNameOK reports whether s is a lowercase RFC 1123 DNS name of at most
// maxDNSName bytes without a trailing dot, whose last label is not all
// digits.
func dnsNameOK(s string) bool {
	if len(s) == 0 || len(s) > maxDNSName {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if !dnsLabelOK(l) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// dottedQuad reports whether s is four dot-separated decimal octets of at
// most three digits and value 0-255 that netip.ParseAddr refused (leading
// zeros), and returns their canonical spelling.
func dottedQuad(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	out := make([]string, 4)
	for i, part := range parts {
		if part == "" || len(part) > 3 || strings.Trim(part, "0123456789") != "" {
			return "", false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n > 255 {
			return "", false
		}
		out[i] = strconv.Itoa(n)
	}
	return strings.Join(out, "."), true
}
