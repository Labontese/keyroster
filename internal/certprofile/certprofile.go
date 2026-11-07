// Package certprofile maps a root-signed policy's CA profile to the
// certificate profile cert.Build issues under. The signer issues with it
// and audit verify re-checks every logged certificate with it, so both
// read a policy alike. It is a package of its own because internal/trust
// must not depend on internal/cert: the root ceremony imports trust and
// must have no code path to certificate signing (KEY-07,
// internal/rootceremony/imports_test.go).
package certprofile

import (
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/trust"
)

// ForRole returns the certificate profile of a CA role ("user", "host"
// or "machine") under policy pol (CA-04, CA-05): user and machine CAs issue
// user certificates, the host CA issues host certificates. The validity
// cap, the default extensions (always granted), the extensions a request
// may add and the critical options it may set all come from the role's
// root-signed CAProfile. A host profile carries no extensions. The signer
// issues under it (cert.Build) and audit verify re-checks every logged
// certificate against it (cert.CheckIssued).
func ForRole(role string, pol *trust.Policy) (cert.Profile, error) {
	if pol == nil {
		return cert.Profile{}, fmt.Errorf("certprofile: no policy for role %s", role)
	}
	idx := slices.IndexFunc(pol.CAProfiles, func(p trust.CAProfile) bool { return p.Role == role })
	if idx < 0 {
		return cert.Profile{}, fmt.Errorf("certprofile: the policy has no profile for role %s", role)
	}
	cp := pol.CAProfiles[idx]
	if cp.MaxTTLSeconds == 0 || cp.MaxTTLSeconds > uint64(1<<32-1) {
		return cert.Profile{}, fmt.Errorf("certprofile: role %s: max_ttl_seconds %d out of range", role, cp.MaxTTLSeconds)
	}
	p := cert.Profile{
		MaxTTL:                 time.Duration(cp.MaxTTLSeconds) * time.Second, //nolint:gosec // G115: <= 2^32-1, checked above
		DefaultExtensions:      map[string]string{},
		AllowedExtensions:      slices.Clone(cp.AllowedExtensions),
		AllowedCriticalOptions: slices.Clone(cp.AllowedCriticalOptions),
	}
	switch role {
	case trust.RoleUser, trust.RoleMachine:
		p.CertType = ssh.UserCert
		for _, e := range cp.DefaultExtensions {
			p.DefaultExtensions[e] = ""
		}
	case trust.RoleHost:
		p.CertType = ssh.HostCert
		if len(cp.DefaultExtensions) != 0 || len(cp.AllowedExtensions) != 0 || len(cp.AllowedCriticalOptions) != 0 {
			return cert.Profile{}, fmt.Errorf("certprofile: the host profile must carry no extensions or critical options")
		}
	default:
		return cert.Profile{}, fmt.Errorf("certprofile: unknown CA role %q", role)
	}
	return p, nil
}

// The probe certificate's fixed restrictions and lifetime bound (03-10,
// D-06). A probe certificate carries exactly these two critical options
// and no extension, whatever the machine profile grants: sshd runs
// /bin/false for any session and accepts the certificate from loopback
// only (D-05's answer, loopback-only).
const (
	ProbeForceCommand       = "/bin/false"
	ProbeSourceAddress      = "127.0.0.0/8,::1/128"
	MaxProbeLifetimeSeconds = 604800
)

// ProbeCriticalOptions returns a fresh copy of the probe certificate's
// critical options: force-command ProbeForceCommand and source-address
// ProbeSourceAddress (03-10).
func ProbeCriticalOptions() map[string]string {
	return map[string]string{"force-command": ProbeForceCommand, "source-address": ProbeSourceAddress}
}

// ProbeProfile returns the profile every probe certificate is built and
// re-checked under (03-10): a user certificate with the machine role's
// MaxTTL under pol, no default or allowed extension, and exactly the
// critical options force-command and source-address allowed. Nothing else
// of the machine profile carries over, so a machine profile that grants
// permit-pty or forwarding changes nothing.
func ProbeProfile(pol *trust.Policy) (cert.Profile, error) {
	m, err := ForRole(trust.RoleMachine, pol)
	if err != nil {
		return cert.Profile{}, err
	}
	return cert.Profile{
		CertType:               m.CertType,
		MaxTTL:                 m.MaxTTL,
		DefaultExtensions:      map[string]string{},
		AllowedCriticalOptions: []string{"force-command", "source-address"},
	}, nil
}

// ProbeLifetime is the one place that turns the machine cap into a probe
// certificate's lifetime L (03-10): min(MaxProbeLifetimeSeconds, the
// profile's MaxTTL in whole seconds). The signer issues with it and
// records it as the leaf's CapSeconds; audit re-derives it.
func ProbeLifetime(profile cert.Profile) uint64 {
	if profile.MaxTTL <= 0 {
		return 0
	}
	return min(uint64(profile.MaxTTL/time.Second), MaxProbeLifetimeSeconds) //nolint:gosec // G115: MaxTTL > 0, checked above
}
