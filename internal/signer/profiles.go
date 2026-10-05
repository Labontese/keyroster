package signer

import (
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/trust"
)

// profileFor returns the certificate profile of a CA role ("user", "host"
// or "machine") under the installed policy (CA-04, CA-05): user and machine
// CAs issue user certificates, the host CA issues host certificates. The
// validity cap, the default extensions (always granted), the extensions a
// request may add and the critical options it may set all come from the
// role's root-signed CAProfile. A host profile carries no extensions.
func profileFor(role string, pol *trust.Policy) (cert.Profile, error) {
	if pol == nil {
		return cert.Profile{}, fmt.Errorf("signer: no policy for role %s", role)
	}
	idx := slices.IndexFunc(pol.CAProfiles, func(p trust.CAProfile) bool { return p.Role == role })
	if idx < 0 {
		return cert.Profile{}, fmt.Errorf("signer: the policy has no profile for role %s", role)
	}
	cp := pol.CAProfiles[idx]
	if cp.MaxTTLSeconds == 0 || cp.MaxTTLSeconds > uint64(1<<32-1) {
		return cert.Profile{}, fmt.Errorf("signer: role %s: max_ttl_seconds %d out of range", role, cp.MaxTTLSeconds)
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
			return cert.Profile{}, fmt.Errorf("signer: the host profile must carry no extensions or critical options")
		}
	default:
		return cert.Profile{}, fmt.Errorf("signer: unknown CA role %q", role)
	}
	return p, nil
}
