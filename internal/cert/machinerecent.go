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
