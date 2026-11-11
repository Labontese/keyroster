package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// The policy block (03-14b, F04): what root sign --prev and trust verify
// --prev print about the successor policy against the policy in force, so
// every custodian sees what the roots' signature changes.

// handWrittenFields are the top-level policy fields that root
// successor-policy never writes (it writes only webauthn and pop), in
// policy.json order. A change to any of them gets the block's WARNING line
// (owner decision Q-B1). The wording is tied to Phase 3's root
// successor-policy and is revisited with AUTHZ-03, which adds a path that
// writes these fields.
var handWrittenFields = []string{"admin_quorum", "admins", "ca_profiles", "timelock_seconds"}

// changedPolicyFields returns the top-level policy.json names whose values
// differ between prev and next, in policy.json order, from admin_quorum,
// admins, ca_profiles, timelock_seconds, webauthn and pop. version and prev
// are the block's header and are not listed. Policy documents are canonical,
// so two policies differ in a field exactly when its values differ.
func changedPolicyFields(prev, next *trust.Policy) []string {
	var changed []string
	if prev.AdminQuorum != next.AdminQuorum {
		changed = append(changed, "admin_quorum")
	}
	if !slices.Equal(prev.Admins, next.Admins) {
		changed = append(changed, "admins")
	}
	if !slices.EqualFunc(prev.CAProfiles, next.CAProfiles, profileEqual) {
		changed = append(changed, "ca_profiles")
	}
	if prev.TimelockSeconds != next.TimelockSeconds {
		changed = append(changed, "timelock_seconds")
	}
	if !rpEqual(prev.WebAuthn, next.WebAuthn) {
		changed = append(changed, "webauthn")
	}
	if !popEqual(prev.PoP, next.PoP) {
		changed = append(changed, "pop")
	}
	return changed
}

func profileEqual(a, b trust.CAProfile) bool {
	return a.Role == b.Role && a.MaxTTLSeconds == b.MaxTTLSeconds &&
		slices.Equal(a.DefaultExtensions, b.DefaultExtensions) &&
		slices.Equal(a.AllowedExtensions, b.AllowedExtensions) &&
		slices.Equal(a.AllowedCriticalOptions, b.AllowedCriticalOptions)
}

func rpEqual(a, b *trust.WebAuthnRP) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.RPID == b.RPID && slices.Equal(a.Origins, b.Origins)
}

func popEqual(a, b *trust.PoPPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// policyChange renders the policy block for the successor policy against
// prevPolicy, the policy in force. The base must be the policy in force
// after the successor chain check (trust.BuildSuccessor in root sign,
// trust.VerifySuccessor in trust verify) has bound it to the bundle in
// force that --prev-sha256 pins; a caller must never print the block
// before that check. Both documents are parsed with trust.ParsePolicy, so
// every rendered value has passed trust.Policy.Validate (names, keys as
// fingerprints, hostnames, origins, closed sets, numbers and booleans) and
// no free text reaches the terminal.
//
// Byte-identical documents give the two-line unchanged form. Otherwise the
// header names the successor's version and SHA-256, a WARNING line names
// the changed fields that root successor-policy never writes, and one line
// per field in policy.json order reads "carried over" or "CHANGED" with the
// old and new values.
func policyChange(prevPolicy, policy []byte) (string, error) {
	prev, err := trust.ParsePolicy(prevPolicy)
	if err != nil {
		return "", fmt.Errorf("the policy in force does not parse: %w", err)
	}
	next, err := trust.ParsePolicy(policy)
	if err != nil {
		return "", fmt.Errorf("the successor policy does not parse: %w", err)
	}
	var w strings.Builder
	fmt.Fprintf(&w, "Policy in force: v%d, sha256 %s\n", prev.Version, trust.SHA256Hex(prevPolicy))
	if bytes.Equal(prevPolicy, policy) {
		w.WriteString("Successor policy: unchanged, every field carried over\n")
		return w.String(), nil
	}
	fmt.Fprintf(&w, "Successor policy: v%d, sha256 %s, chained to the policy in force; against it:\n", next.Version, trust.SHA256Hex(policy))
	var hand []string
	for _, f := range changedPolicyFields(prev, next) {
		if slices.Contains(handWrittenFields, f) {
			hand = append(hand, f)
		}
	}
	if len(hand) > 0 {
		fmt.Fprintf(&w, "WARNING: this successor changes %s, which root successor-policy never writes; sign only if each is part of the agreed change\n", strings.Join(hand, ", "))
	}

	if prev.AdminQuorum == next.AdminQuorum {
		w.WriteString("  admin_quorum: carried over\n")
	} else {
		fmt.Fprintf(&w, "  admin_quorum: CHANGED %d -> %d\n", prev.AdminQuorum, next.AdminQuorum)
	}
	writeAdminsChange(&w, prev.Admins, next.Admins)
	// Validate pins the profiles user, host and machine, in that order.
	for _, n := range next.CAProfiles {
		var p trust.CAProfile
		for _, c := range prev.CAProfiles {
			if c.Role == n.Role {
				p = c
			}
		}
		writeProfileChange(&w, p, n)
	}
	if prev.TimelockSeconds == next.TimelockSeconds {
		w.WriteString("  timelock_seconds: carried over\n")
	} else {
		fmt.Fprintf(&w, "  timelock_seconds: CHANGED %d (%s) -> %d (%s)\n",
			prev.TimelockSeconds, diffSeconds(prev.TimelockSeconds), next.TimelockSeconds, diffSeconds(next.TimelockSeconds))
	}
	writeWebAuthnChange(&w, prev.WebAuthn, next.WebAuthn)
	if popEqual(prev.PoP, next.PoP) {
		w.WriteString("  pop: carried over\n")
	} else {
		fmt.Fprintf(&w, "  pop: CHANGED %s -> %s\n", popText(prev.PoP), popText(next.PoP))
		if next.PoP != nil && next.PoP.Hosts && (prev.PoP == nil || !prev.PoP.Hosts) {
			w.WriteString("    pop.hosts is one-way: no later policy may turn it off (pop_hosts_removed)\n")
		}
	}
	return w.String(), nil
}

// writeAdminsChange writes the admins line. Admins are matched by key, so a
// key replaced under the same name reads as removed plus added.
func writeAdminsChange(w *strings.Builder, prev, next []trust.AdminKey) {
	if slices.Equal(prev, next) {
		w.WriteString("  admins: carried over\n")
		return
	}
	w.WriteString("  admins: CHANGED\n")
	prevName, nextName := map[string]string{}, map[string]string{}
	for _, a := range prev {
		prevName[a.Key] = a.Name
	}
	for _, a := range next {
		nextName[a.Key] = a.Name
	}
	var oldOrder, newOrder, oldKeys, newKeys, carried []string
	for _, a := range prev {
		if _, ok := nextName[a.Key]; !ok {
			fmt.Fprintf(w, "    - admin %s %s\n", a.Name, describeKey(a.Key))
		} else {
			oldOrder, oldKeys = append(oldOrder, a.Name), append(oldKeys, a.Key)
		}
	}
	for _, a := range next {
		if _, ok := prevName[a.Key]; !ok {
			fmt.Fprintf(w, "    + admin %s %s\n", a.Name, describeKey(a.Key))
		}
	}
	for _, a := range next {
		old, ok := prevName[a.Key]
		if !ok {
			continue
		}
		newOrder, newKeys = append(newOrder, a.Name), append(newKeys, a.Key)
		if old != a.Name {
			fmt.Fprintf(w, "    ~ admin %s renamed %s -> %s\n", describeKey(a.Key), old, a.Name)
		} else {
			carried = append(carried, a.Name)
		}
	}
	if !slices.Equal(oldKeys, newKeys) {
		fmt.Fprintf(w, "    order: %s -> %s\n", strings.Join(oldOrder, " "), strings.Join(newOrder, " "))
	}
	if len(carried) == 0 {
		w.WriteString("    carried over: (none)\n")
	} else {
		fmt.Fprintf(w, "    carried over: %s\n", strings.Join(carried, " "))
	}
}

// writeProfileChange writes the line of one CA profile, with a sub-line per
// changed sub-field.
func writeProfileChange(w *strings.Builder, prev, next trust.CAProfile) {
	if profileEqual(prev, next) {
		fmt.Fprintf(w, "  ca_profiles %s: carried over\n", next.Role)
		return
	}
	fmt.Fprintf(w, "  ca_profiles %s: CHANGED\n", next.Role)
	if prev.MaxTTLSeconds != next.MaxTTLSeconds {
		fmt.Fprintf(w, "    max_ttl_seconds: %d (%s) -> %d (%s)\n",
			prev.MaxTTLSeconds, diffSeconds(prev.MaxTTLSeconds), next.MaxTTLSeconds, diffSeconds(next.MaxTTLSeconds))
	}
	for _, l := range []struct {
		name       string
		prev, next []string
	}{
		{"default_extensions", prev.DefaultExtensions, next.DefaultExtensions},
		{"allowed_extensions", prev.AllowedExtensions, next.AllowedExtensions},
		{"allowed_critical_options", prev.AllowedCriticalOptions, next.AllowedCriticalOptions},
	} {
		if !slices.Equal(l.prev, l.next) {
			fmt.Fprintf(w, "    %s: [%s] -> [%s]\n", l.name, strings.Join(l.prev, " "), strings.Join(l.next, " "))
		}
	}
}

// writeWebAuthnChange writes the webauthn line. rp_id is one-way (Phase 2
// D-09), so a change to it, none and some included, is marked.
func writeWebAuthnChange(w *strings.Builder, prev, next *trust.WebAuthnRP) {
	if rpEqual(prev, next) {
		w.WriteString("  webauthn: carried over\n")
		return
	}
	rpID := func(rp *trust.WebAuthnRP) string {
		if rp == nil {
			return "(none)"
		}
		return rp.RPID
	}
	origins := func(rp *trust.WebAuthnRP) string {
		if rp == nil {
			return "(none)"
		}
		return "[" + strings.Join(rp.Origins, " ") + "]"
	}
	if rpID(prev) != rpID(next) {
		w.WriteString("  webauthn: CHANGED (rp_id is one-way)\n")
		fmt.Fprintf(w, "    rp_id: %s -> %s\n", rpID(prev), rpID(next))
	} else {
		w.WriteString("  webauthn: CHANGED\n")
	}
	if origins(prev) != origins(next) {
		fmt.Fprintf(w, "    origins: %s -> %s\n", origins(prev), origins(next))
	}
}

// describeKey returns a validated key's SHA256 fingerprint and type, as
// successorHeader prints root keys.
func describeKey(key string) string {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "<invalid key> ?"
	}
	return ssh.FingerprintSHA256(pub) + " " + pub.Type()
}

// diffSeconds renders s as rootceremony's unexported seconds does: a Go
// duration, or "<n>s" above time.Duration's bound.
func diffSeconds(s uint64) string {
	if s > uint64(1<<62)/uint64(time.Second) {
		return fmt.Sprintf("%ds", s)
	}
	return (time.Duration(s) * time.Second).String() //nolint:gosec // G115: bounded above
}
