package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// The policy block's gates (03-14b, F04, T-03-331, T-03-332).

const policyFieldNeed = "a new policy field needs a policydiff.go line, a TestPolicyChangeFields case, and a Summary line (TestSummaryFieldsCovered)"

// pinnedPolicyTypes is every struct type reachable from trust.Policy, with
// its fields as "Name Type json-tag", the same lists as
// internal/rootceremony's TestSummaryFieldsCovered.
var pinnedPolicyTypes = map[reflect.Type][]string{
	reflect.TypeFor[trust.Policy](): {
		"Version uint64 version",
		"Prev string prev",
		"AdminQuorum uint32 admin_quorum",
		"Admins []trust.AdminKey admins",
		"CAProfiles []trust.CAProfile ca_profiles",
		"TimelockSeconds uint64 timelock_seconds",
		"WebAuthn *trust.WebAuthnRP webauthn,omitempty",
		"PoP *trust.PoPPolicy pop,omitempty",
	},
	reflect.TypeFor[trust.AdminKey](): {"Name string name", "Key string key"},
	reflect.TypeFor[trust.CAProfile](): {
		"Role string role",
		"MaxTTLSeconds uint64 max_ttl_seconds",
		"DefaultExtensions []string default_extensions",
		"AllowedExtensions []string allowed_extensions",
		"AllowedCriticalOptions []string allowed_critical_options",
	},
	reflect.TypeFor[trust.WebAuthnRP](): {"RPID string rp_id", "Origins []string origins"},
	reflect.TypeFor[trust.PoPPolicy]():  {"Hosts bool hosts", "Machines bool machines"},
}

// walkPolicyTypes calls visit for every struct type reachable from t,
// unwrapping pointer, slice, array and map types.
func walkPolicyTypes(t reflect.Type, seen map[reflect.Type]bool, visit func(reflect.Type)) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		if t.Kind() == reflect.Map {
			walkPolicyTypes(t.Key(), seen, visit)
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	visit(t)
	for i := range t.NumField() {
		walkPolicyTypes(t.Field(i).Type, seen, visit)
	}
}

func policyFieldList(t reflect.Type) []string {
	var l []string
	for i := range t.NumField() {
		f := t.Field(i)
		l = append(l, fmt.Sprintf("%s %s %s", f.Name, f.Type.String(), f.Tag.Get("json")))
	}
	return l
}

// policyCaseKey is a case name up to an optional "_suffix".
func policyCaseKey(name string) string {
	key, _, _ := strings.Cut(name, "_")
	return key
}

// TestPolicyFieldsCovered requires a TestPolicyChangeFields case for every
// field of every type reachable from trust.Policy, except Policy.Version and
// Policy.Prev (the block's header) and CAProfile.Role (Validate pins the
// roles and their order), and requires the walk to reach every pinned type.
func TestPolicyFieldsCovered(t *testing.T) {
	cases := map[string]bool{}
	for _, c := range policyChangeCases {
		cases[policyCaseKey(c.name)] = true
	}
	skip := map[string]bool{"Policy.Version": true, "Policy.Prev": true, "CAProfile.Role": true}
	reached := map[reflect.Type]bool{}
	walkPolicyTypes(reflect.TypeFor[trust.Policy](), map[reflect.Type]bool{}, func(typ reflect.Type) {
		reached[typ] = true
		want, ok := pinnedPolicyTypes[typ]
		if !ok {
			t.Errorf("unpinned policy type %s: pin its fields; %s", typ, policyFieldNeed)
			return
		}
		if got := policyFieldList(typ); !slices.Equal(got, want) {
			t.Errorf("policy type %s has fields %q, pinned %q; %s", typ, got, want, policyFieldNeed)
		}
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			if !cases[key] && !skip[key] {
				t.Errorf("no TestPolicyChangeFields case for %s; %s", key, policyFieldNeed)
			}
		}
	})
	for typ := range pinnedPolicyTypes {
		if !reached[typ] {
			t.Errorf("pinned type not reached: %s; the walk must reach every type reachable from trust.Policy", typ)
		}
	}
}

// policyFieldLines are the block's eight field lines, in order.
var policyFieldLines = []string{"admin_quorum", "admins", "ca_profiles user", "ca_profiles host", "ca_profiles machine", "timelock_seconds", "webauthn", "pop"}

const oneWayLine = "    pop.hosts is one-way: no later policy may turn it off (pop_hosts_removed)"

// diffBase returns the canonical bytes of the test base policy, version 1:
// policy_genesis_v1 with admins alice (seed 20) and bob (seed 22) at quorum
// 1, the RP keyroster.example.org and pop hosts=false machines=true, then
// edited by edit.
func diffBase(t *testing.T, edit func(p *trust.Policy)) []byte {
	t.Helper()
	p, err := trust.ParsePolicy(readGoldenVector(t, "policy_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	p.Admins = append(p.Admins, trust.AdminKey{Name: "bob", Key: seedPub(t, 22)})
	p.WebAuthn = &trust.WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org"}}
	p.PoP = &trust.PoPPolicy{Hosts: false, Machines: true}
	if edit != nil {
		edit(p)
	}
	return canonicalPolicy(t, p)
}

func canonicalPolicy(t *testing.T, p *trust.Policy) []byte {
	t.Helper()
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParsePolicy(data); err != nil {
		t.Fatalf("test policy does not validate: %v", err)
	}
	return data
}

// diffSuccessor derives version 2 of base, chained to it, edited by edit.
func diffSuccessor(t *testing.T, base []byte, edit func(p *trust.Policy)) []byte {
	t.Helper()
	p, err := trust.ParsePolicy(base)
	if err != nil {
		t.Fatal(err)
	}
	p.Version, p.Prev = 2, trust.SHA256Hex(base)
	if edit != nil {
		edit(p)
	}
	return canonicalPolicy(t, p)
}

// fpType is "<fp> <type>" of seedKey(n), as the block prints an admin key.
func fpType(t *testing.T, n byte) string {
	t.Helper()
	return describeKey(seedPub(t, n))
}

type policyChangeCase struct {
	name  string                      // the key Type.Field, with an optional _suffix
	base  func(p *trust.Policy)       // edits the default base; nil keeps it
	edit  func(p *trust.Policy)       // the successor's single change
	field string                      // the top-level field changedPolicyFields returns
	line  string                      // the one field line that reads CHANGED
	text  string                      // that line's exact text
	sub   func(t *testing.T) []string // its sub-lines
}

// policyChangeCases changes one field each (TestPolicyChangeFields).
var policyChangeCases = []policyChangeCase{
	{name: "Policy.AdminQuorum", edit: func(p *trust.Policy) { p.AdminQuorum = 2 },
		field: "admin_quorum", line: "admin_quorum", text: "  admin_quorum: CHANGED 1 -> 2"},
	{name: "Policy.Admins", edit: func(p *trust.Policy) { p.Admins = append(p.Admins, trust.AdminKey{Name: "dave", Key: seedPubNoT(24)}) },
		field: "admins", line: "admins", text: "  admins: CHANGED",
		sub: func(t *testing.T) []string {
			return []string{"    + admin dave " + fpType(t, 24), "    carried over: alice bob"}
		}},
	{name: "AdminKey.Name", edit: func(p *trust.Policy) { p.Admins[1].Name = "robert" },
		field: "admins", line: "admins", text: "  admins: CHANGED",
		sub: func(t *testing.T) []string {
			return []string{"    ~ admin " + fpType(t, 22) + " renamed bob -> robert", "    carried over: alice"}
		}},
	{name: "AdminKey.Key", edit: func(p *trust.Policy) { p.Admins[1].Key = seedPubNoT(23) },
		field: "admins", line: "admins", text: "  admins: CHANGED",
		sub: func(t *testing.T) []string {
			return []string{"    - admin bob " + fpType(t, 22), "    + admin bob " + fpType(t, 23), "    carried over: alice"}
		}},
	{name: "CAProfile.MaxTTLSeconds", edit: func(p *trust.Policy) { p.CAProfiles[0].MaxTTLSeconds = 3600 },
		field: "ca_profiles", line: "ca_profiles user", text: "  ca_profiles user: CHANGED",
		sub: lines("    max_ttl_seconds: 43200 (12h0m0s) -> 3600 (1h0m0s)")},
	{name: "Policy.CAProfiles", edit: func(p *trust.Policy) { p.CAProfiles[1].MaxTTLSeconds = 604800 },
		field: "ca_profiles", line: "ca_profiles host", text: "  ca_profiles host: CHANGED",
		sub: lines("    max_ttl_seconds: 2592000 (720h0m0s) -> 604800 (168h0m0s)")},
	{name: "CAProfile.DefaultExtensions", edit: func(p *trust.Policy) { p.CAProfiles[2].DefaultExtensions = []string{} },
		field: "ca_profiles", line: "ca_profiles machine", text: "  ca_profiles machine: CHANGED",
		sub: lines("    default_extensions: [permit-pty] -> []")},
	{name: "CAProfile.AllowedExtensions", edit: func(p *trust.Policy) { p.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding"} },
		field: "ca_profiles", line: "ca_profiles user", text: "  ca_profiles user: CHANGED",
		sub: lines("    allowed_extensions: [] -> [permit-agent-forwarding]")},
	{name: "CAProfile.AllowedCriticalOptions", edit: func(p *trust.Policy) { p.CAProfiles[0].AllowedCriticalOptions = []string{"force-command"} },
		field: "ca_profiles", line: "ca_profiles user", text: "  ca_profiles user: CHANGED",
		sub: lines("    allowed_critical_options: [] -> [force-command]")},
	{name: "Policy.TimelockSeconds", edit: func(p *trust.Policy) { p.TimelockSeconds = 3600 },
		field: "timelock_seconds", line: "timelock_seconds", text: "  timelock_seconds: CHANGED 0 (0s) -> 3600 (1h0m0s)"},
	{name: "WebAuthnRP.RPID", edit: func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: "other.example.org", Origins: []string{"https://other.example.org"}}
	},
		field: "webauthn", line: "webauthn", text: "  webauthn: CHANGED (rp_id is one-way)",
		sub: lines("    rp_id: keyroster.example.org -> other.example.org", "    origins: [https://keyroster.example.org] -> [https://other.example.org]")},
	{name: "WebAuthnRP.Origins", edit: func(p *trust.Policy) {
		p.WebAuthn.Origins = []string{"https://keyroster.example.org", "https://keyroster.example.org:8443"}
	},
		field: "webauthn", line: "webauthn", text: "  webauthn: CHANGED",
		sub: lines("    origins: [https://keyroster.example.org] -> [https://keyroster.example.org https://keyroster.example.org:8443]")},
	{name: "Policy.WebAuthn", edit: func(p *trust.Policy) { p.WebAuthn = nil },
		field: "webauthn", line: "webauthn", text: "  webauthn: CHANGED (rp_id is one-way)",
		sub: lines("    rp_id: keyroster.example.org -> (none)", "    origins: [https://keyroster.example.org] -> (none)")},
	{name: "PoPPolicy.Hosts", edit: func(p *trust.Policy) { p.PoP.Hosts = true },
		field: "pop", line: "pop", text: "  pop: CHANGED hosts=false machines=true -> hosts=true machines=true",
		sub: lines(oneWayLine)},
	{name: "PoPPolicy.Machines", base: func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true, Machines: true} },
		edit:  func(p *trust.Policy) { p.PoP.Machines = false },
		field: "pop", line: "pop", text: "  pop: CHANGED hosts=true machines=true -> hosts=true machines=false"},
	{name: "Policy.PoP_added", base: func(p *trust.Policy) { p.PoP = nil },
		edit:  func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: false, Machines: true} },
		field: "pop", line: "pop", text: "  pop: CHANGED (none) -> hosts=false machines=true"},
	{name: "Policy.PoP_removed", edit: func(p *trust.Policy) { p.PoP = nil },
		field: "pop", line: "pop", text: "  pop: CHANGED hosts=false machines=true -> (none)"},
}

func lines(l ...string) func(*testing.T) []string {
	return func(*testing.T) []string { return l }
}

// seedPubNoT is seedPub for the package-level case table, which has no t.
func seedPubNoT(n byte) string {
	k, err := sshPublicKey(seedKey(n))
	if err != nil {
		panic(err)
	}
	return k
}

// diffLeaves adds to out the "Type.Field" of every leaf field that differs
// between a and b, which must have the same shape (no nil on one side
// only, equal slice lengths of structs). It reports a shape difference as
// the key "shape".
func diffLeaves(a, b reflect.Value, out map[string]bool) {
	switch a.Kind() {
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			if a.IsNil() != b.IsNil() {
				out["shape"] = true
			}
			return
		}
		diffLeaves(a.Elem(), b.Elem(), out)
	case reflect.Struct:
		for i := range a.NumField() {
			f := a.Type().Field(i)
			fa, fb := a.Field(i), b.Field(i)
			switch {
			case f.Type.Kind() == reflect.Pointer, f.Type.Kind() == reflect.Struct,
				f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Struct:
				diffLeaves(fa, fb, out)
			case !reflect.DeepEqual(normalizeSlice(fa), normalizeSlice(fb)):
				out[a.Type().Name()+"."+f.Name] = true
			}
		}
	case reflect.Slice:
		if a.Len() != b.Len() {
			out["shape"] = true
			return
		}
		for i := range a.Len() {
			diffLeaves(a.Index(i), b.Index(i), out)
		}
	}
}

// normalizeSlice makes a nil and an empty string slice compare equal.
func normalizeSlice(v reflect.Value) any {
	if v.Kind() == reflect.Slice && v.Len() == 0 {
		return []string{}
	}
	return v.Interface()
}

// checkBlock compares the block of a single-field change with what the case
// expects: the changed header, the warning exactly for a field root
// successor-policy never writes, and the eight field lines, only line
// reading CHANGED, with its sub-lines.
func checkBlock(t *testing.T, base, next []byte, field, line, text string, sub []string) {
	t.Helper()
	want := []string{
		fmt.Sprintf("Policy in force: v1, sha256 %s", trust.SHA256Hex(base)),
		fmt.Sprintf("Successor policy: v2, sha256 %s, chained to the policy in force; against it:", trust.SHA256Hex(next)),
	}
	if slices.Contains([]string{"admin_quorum", "admins", "ca_profiles", "timelock_seconds"}, field) {
		want = append(want, "WARNING: this successor changes "+field+", which root successor-policy never writes; sign only if each is part of the agreed change")
	}
	for _, l := range policyFieldLines {
		if l == line {
			want = append(want, text)
			want = append(want, sub...)
		} else {
			want = append(want, "  "+l+": carried over")
		}
	}
	got, err := policyChange(base, next)
	if err != nil {
		t.Fatal(err)
	}
	if exp := strings.Join(want, "\n") + "\n"; got != exp {
		t.Errorf("policy block:\n%s\nwant:\n%s", got, exp)
	}
}

// TestPolicyChangeFields changes one policy field per case and requires the
// block to mark exactly that field CHANGED, with its sub-lines, every other
// field carried over, and the warning exactly for admin_quorum, admins,
// ca_profiles and timelock_seconds (Q-B1). For a leaf key, a reflect walk
// requires the case to change exactly that leaf (leaf honesty).
func TestPolicyChangeFields(t *testing.T) {
	for _, c := range policyChangeCases {
		t.Run(c.name, func(t *testing.T) {
			base := diffBase(t, c.base)
			next := diffSuccessor(t, base, c.edit)
			bp, err := trust.ParsePolicy(base)
			if err != nil {
				t.Fatal(err)
			}
			np, err := trust.ParsePolicy(next)
			if err != nil {
				t.Fatal(err)
			}
			if got := changedPolicyFields(bp, np); !slices.Equal(got, []string{c.field}) {
				t.Errorf("changedPolicyFields = %q, want [%s]", got, c.field)
			}
			key := policyCaseKey(c.name)
			if typ, _, _ := strings.Cut(key, "."); typ != "Policy" {
				bp.Version, bp.Prev, np.Version, np.Prev = 0, "", 0, ""
				diff := map[string]bool{}
				diffLeaves(reflect.ValueOf(bp), reflect.ValueOf(np), diff)
				want := map[string]bool{key: true}
				if key == "WebAuthnRP.RPID" {
					// Validate ties every origin to rp_id.
					want["WebAuthnRP.Origins"] = true
				}
				if !reflect.DeepEqual(diff, want) {
					t.Errorf("leaf honesty: the case changes %v, want exactly %v", diff, want)
				}
			}
			var sub []string
			if c.sub != nil {
				sub = c.sub(t)
			}
			checkBlock(t, base, next, c.field, c.line, c.text, sub)
		})
	}
}

// TestPolicyChangeAdmins pins the admins sub-lines, in the contract's order.
func TestPolicyChangeAdmins(t *testing.T) {
	alice, bob := trust.AdminKey{Name: "alice", Key: seedPub(t, 20)}, trust.AdminKey{Name: "bob", Key: seedPub(t, 22)}
	dave := trust.AdminKey{Name: "dave", Key: seedPub(t, 24)}
	for _, c := range []struct {
		name   string
		admins []trust.AdminKey
		sub    []string
	}{
		{"added_only", []trust.AdminKey{alice, bob, dave}, []string{"    + admin dave " + fpType(t, 24), "    carried over: alice bob"}},
		{"removed_only", []trust.AdminKey{alice}, []string{"    - admin bob " + fpType(t, 22), "    carried over: alice"}},
		{"order_only", []trust.AdminKey{bob, alice}, []string{"    order: alice bob -> bob alice", "    carried over: bob alice"}},
		{"rename_and_add", []trust.AdminKey{alice, {Name: "robert", Key: bob.Key}, dave}, []string{
			"    + admin dave " + fpType(t, 24), "    ~ admin " + fpType(t, 22) + " renamed bob -> robert", "    carried over: alice"}},
		{"all_replaced", []trust.AdminKey{{Name: "erin", Key: seedPub(t, 25)}, {Name: "frank", Key: seedPub(t, 26)}}, []string{
			"    - admin alice " + fpType(t, 20), "    - admin bob " + fpType(t, 22),
			"    + admin erin " + fpType(t, 25), "    + admin frank " + fpType(t, 26), "    carried over: (none)"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := diffBase(t, nil)
			next := diffSuccessor(t, base, func(p *trust.Policy) { p.Admins = c.admins })
			checkBlock(t, base, next, "admins", "admins", "  admins: CHANGED", c.sub)
		})
	}
}

// TestPolicyChangeUnchanged: identical documents give exactly the two
// unchanged lines; a version bump alone gives the changed header, no
// warning and every field carried over.
func TestPolicyChangeUnchanged(t *testing.T) {
	base := diffBase(t, nil)
	t.Run("identical", func(t *testing.T) {
		got, err := policyChange(base, base)
		if err != nil {
			t.Fatal(err)
		}
		want := "Policy in force: v1, sha256 " + trust.SHA256Hex(base) + "\nSuccessor policy: unchanged, every field carried over\n"
		if got != want {
			t.Errorf("policy block:\n%s\nwant:\n%s", got, want)
		}
		p, err := trust.ParsePolicy(base)
		if err != nil {
			t.Fatal(err)
		}
		if f := changedPolicyFields(p, p); len(f) != 0 {
			t.Errorf("changedPolicyFields of identical policies = %q, want none", f)
		}
	})
	t.Run("version_bump_only", func(t *testing.T) {
		checkBlock(t, base, diffSuccessor(t, base, nil), "", "", "", nil)
	})
}

// TestPolicyChangeDurations covers both branches of the duration helper.
func TestPolicyChangeDurations(t *testing.T) {
	base := diffBase(t, nil)
	for _, c := range []struct {
		secs uint64
		text string
	}{
		{1 << 62, "  timelock_seconds: CHANGED 0 (0s) -> 4611686018427387904 (4611686018427387904s)"},
		{3600, "  timelock_seconds: CHANGED 0 (0s) -> 3600 (1h0m0s)"},
	} {
		next := diffSuccessor(t, base, func(p *trust.Policy) { p.TimelockSeconds = c.secs })
		checkBlock(t, base, next, "timelock_seconds", "timelock_seconds", c.text, nil)
	}
}

// TestPolicyChangeInvalid: a document that does not parse is named.
func TestPolicyChangeInvalid(t *testing.T) {
	base := diffBase(t, nil)
	next := diffSuccessor(t, base, func(p *trust.Policy) { p.AdminQuorum = 2 })
	nonCanonical := append([]byte(" "), base...)
	if _, err := policyChange(nonCanonical, next); err == nil || !strings.Contains(err.Error(), "the policy in force does not parse") {
		t.Errorf("non-canonical policy in force: err = %v", err)
	}
	invalid := strings.Replace(string(next), `"admin_quorum":2`, `"admin_quorum":3`, 1)
	if invalid == string(next) {
		t.Fatal("could not build the invalid successor")
	}
	if _, err := policyChange(base, []byte(invalid)); err == nil || !strings.Contains(err.Error(), "the successor policy does not parse") {
		t.Errorf("invalid successor: err = %v", err)
	}
}

// TestPolicyBlockBase (T-03-331): a --prev policy.json that its own roots
// signed but that the pinned bundle does not name is refused by the chain
// check before any policy block is printed, by root sign and by trust
// verify.
func TestPolicyBlockBase(t *testing.T) {
	f := newGoldenFixture(t)
	setCeremonyNow(t, "2026-10-06T00:00:00Z")
	pol := f.writePolicy(t, "rp", true, func(p *trust.Policy) {
		p.WebAuthn = &trust.WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org"}}
	})
	out := filepath.Join(f.dir, "out")
	f.display(t, pol, out, f.fpA)
	f.signWith(t, pol, out, f.fpA)
	f.signWith(t, pol, out, f.fpB)

	// P2: the bundle in force with another valid version 1 policy, re-signed
	// by A and B so the self-signed check passes. The bundle still names the
	// original policy, so --prev-sha256 is unchanged.
	p2 := filepath.Join(f.dir, "p2")
	if err := os.MkdirAll(p2, 0o750); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(p2, "bundle.json"), readTestFile(t, filepath.Join(f.prev, "bundle.json")))
	writeTestFile(t, filepath.Join(p2, "bundle.json.sigs"), readTestFile(t, filepath.Join(f.prev, "bundle.json.sigs")))
	other, err := trust.ParsePolicy(f.genesisPolicy)
	if err != nil {
		t.Fatal(err)
	}
	other.CAProfiles[0].MaxTTLSeconds = 3600
	writeTestFile(t, filepath.Join(p2, "policy.json"), canonicalPolicy(t, other))
	for _, k := range []byte{1, 2} {
		signGoldenPolicy(t, p2, seedKey(k))
	}
	const refusal = "prevPolicy is not the previous bundle's policy"

	t.Run("root_sign", func(t *testing.T) {
		code, stdout, stderr := run(t, "root", "sign", "--prev", p2, "--prev-sha256", f.prevSHA, "--roots", f.roots, "--threshold", "2",
			"--policy", pol, "--out-dir", filepath.Join(f.dir, "fresh"), "--agent-key", f.fpA, "--confirm", "00000000")
		if code != 1 || !strings.Contains(stderr, refusal) {
			t.Errorf("root sign --prev with a policy the pinned bundle does not name: exit %d: %s", code, stderr)
		}
		if strings.Contains(stdout, "Policy in force") {
			t.Errorf("root sign printed a policy block before the chain check:\n%s", stdout)
		}
	})
	t.Run("trust_verify", func(t *testing.T) {
		code, stdout, stderr := run(t, "trust", "verify", "--prev", p2, "--prev-sha256", f.prevSHA, "--pin", f.fpA, "--pin", f.fpB, "--threshold", "2",
			"--bundle", filepath.Join(out, "bundle.json"), "--policy", filepath.Join(out, "policy.json"))
		if code != 1 || !strings.Contains(stderr, refusal) {
			t.Errorf("trust verify --prev with a policy the pinned bundle does not name: exit %d: %s", code, stderr)
		}
		if strings.Contains(stdout, "Policy in force") {
			t.Errorf("trust verify printed a policy block before the chain check:\n%s", stdout)
		}
	})
}

// sshPublicKey returns k's public key in canonical form.
func sshPublicKey(k ed25519.PrivateKey) (string, error) {
	pub, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		return "", err
	}
	return trust.FormatKey(pub), nil
}

// signGoldenPolicy signs dir's policy.json with k and appends the signature
// to policy.json.sigs.
func signGoldenPolicy(t *testing.T, dir string, k ed25519.PrivateKey) {
	t.Helper()
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, s, trust.NamespacePolicy, readTestFile(t, filepath.Join(dir, "policy.json")))
	if err != nil {
		t.Fatal(err)
	}
	if err := appendSignature(filepath.Join(dir, "policy.json.sigs"), sig); err != nil {
		t.Fatal(err)
	}
}
