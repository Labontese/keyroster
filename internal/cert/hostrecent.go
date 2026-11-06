package cert

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

// MaxHostLifetime is the longest host certificate lifetime, 30 days
// (D-16): the signer chooses min(MaxHostLifetime, the host cap in force)
// (03-09, Q-09-6).
const MaxHostLifetime = 2592000

// HostPrev is the latest host certificate for one host key (03-09), as the
// signer's host index and audit verify keep it: the certificate, the host
// cap recorded at its issuance (the host_issue leaf's CapSeconds), the
// directory version it was issued under, and whether it was revoked, at
// which directory version.
type HostPrev struct {
	Cert           *ssh.Certificate
	CapSeconds     uint64
	IssuedUnderDir uint64
	Revoked        bool
	RevokedAtDir   uint64
}

// HostCertRecent is the one host_cert_recent rule (03-09, Q-09-2, Q-09-5,
// Q-09-6), shared by the signer and audit verify. For a new request for the
// host key whose latest certificate is prev, at now, under the host cap in
// force capInForce (the policy in force's host max_ttl_seconds: directory
// host entries carry no TTL; a later plan that adds a host TTL elsewhere
// passes the smaller value), the directory version in force curDir and the
// entry's principals, it returns:
//   - "cert_revoked" while prev is revoked and no newer directory version
//     than the one in force when it was revoked is installed (Q-09-5); ""
//     once one is;
//   - "" when the principals differ (as sorted lists) and prev was issued
//     under an older directory version: an admin-signed principal change
//     lifts the bound once per host key per directory version (Q-09-2);
//   - "host_cert_recent" while now is before prev's issuance (ValidAfter +
//     300) plus a third of min(prev.CapSeconds, min(2592000, capInForce)):
//     the window comes from the policy caps, never from prev's own
//     lifetime or a requested valid_for, and raising the cap never
//     lengthens a window already running;
//   - "" otherwise, and for no prev.
//
// The signer passes uint64(now.Unix()), the instant it gives cert.Build;
// audit passes the new certificate's ValidAfter + 300.
func HostCertRecent(prev HostPrev, now, capInForce, curDir uint64, principals []string) string {
	if prev.Cert == nil {
		return ""
	}
	if prev.Revoked {
		if curDir <= prev.RevokedAtDir {
			return "cert_revoked"
		}
		return ""
	}
	if !sameSorted(prev.Cert.ValidPrincipals, principals) && prev.IssuedUnderDir < curDir {
		return ""
	}
	window := min(prev.CapSeconds, min(MaxHostLifetime, capInForce)) / 3
	if now < prev.Cert.ValidAfter+uint64(backdate.Seconds())+window {
		return "host_cert_recent"
	}
	return ""
}

func sameSorted(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
