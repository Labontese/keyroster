package cert

import (
	"slices"
)

// MachineLifetime is the one machine certificate lifetime rule (03-11,
// Q-09-6, PD6), shared by the signer and audit verify: the smaller of the
// grant's max TTL (directory.MachineGrant: min(the entry's
// max_ttl_seconds, every role's)) and the machine profile's cap in whole
// seconds. The signer issues for exactly this many seconds and logs it as
// the machine_issue leaf's CapSeconds.
func MachineLifetime(grantMaxTTLSeconds uint64, profile Profile) uint64 {
	return min(grantMaxTTLSeconds, uint64(profile.MaxTTL.Seconds()))
}

// machineRecentMax is the number of issuance seconds a machine key's list
// keeps: the bound is twelve issuances an hour.
const machineRecentMax = 12

// machineWindow is the bound's window in seconds.
const machineWindow = 3600

// MachineRecentAdd is the one list rule of the 12-per-hour bound (03-11,
// PD4), called by the signer's machine index and by audit's mirror on the
// same sequence of machine_issue leaves, so the two lists are identical by
// construction. It returns a new slice: recent with issued appended,
// without every second that is 3600 or more below the largest second, and
// cut to the twelve largest by value, ascending. A second below the
// largest (a clock stepped back) is kept while it is within the hour of
// the largest; the larger seconds are never dropped for it.
func MachineRecentAdd(recent []uint64, issued uint64) []uint64 {
	out := append(slices.Clone(recent), issued)
	slices.Sort(out)
	largest := out[len(out)-1]
	out = slices.DeleteFunc(out, func(s uint64) bool { return s+machineWindow <= largest })
	if len(out) > machineRecentMax {
		out = out[len(out)-machineRecentMax:]
	}
	return slices.Clip(out)
}

// MachineRenewTooOften is the one 12-per-hour rule of machine issuance
// (03-11, PD4, T-03-401), shared by the signer and audit verify. recent is
// the key's list (MachineRecentAdd) and now the second of the new request:
// the signer passes its clock before a serial is drawn, audit the new
// certificate's issuance second (ValidAfter + 300), never earlier. A
// second s counts while s + 3600 > now, so a second after now (a clock
// stepped back) counts too. It returns "machine_renew_too_often" when
// twelve or more count, else "".
func MachineRenewTooOften(recent []uint64, now uint64) string {
	n := 0
	for _, s := range recent {
		if s+machineWindow > now {
			n++
		}
	}
	if n >= machineRecentMax {
		return "machine_renew_too_often"
	}
	return ""
}

// MachinePrev is what the cert_revoked hold reads of a machine key's
// latest certificate (03-11), as the signer's machine index and audit's
// mirror keep it: whether there is one, whether it was revoked, and the
// directory version in force when it first was (keep-first).
type MachinePrev struct {
	Have         bool
	Revoked      bool
	RevokedAtDir uint64
}

// MachineCertHeld is the one machine cert_revoked hold rule (03-11,
// Q-09-5, default 2), shared by the signer and audit verify: it returns
// "cert_revoked" while prev is revoked and the directory version in force
// curDir is not above the one it was revoked at (an equal version holds),
// else "". Any newer directory version releases it.
func MachineCertHeld(prev MachinePrev, curDir uint64) string {
	if prev.Have && prev.Revoked && curDir <= prev.RevokedAtDir {
		return "cert_revoked"
	}
	return ""
}
