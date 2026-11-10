package rootceremony

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// updateGolden rewrites testdata/summary/*.golden from the current output
// (03-14b). It is for a deliberate output change only, never with a mutant
// applied.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/summary/*.golden from the current output (a deliberate output change only, never with a mutant applied)")

// checkGolden compares got with testdata/summary/<name>.golden byte for byte,
// or rewrites it with -update-golden (03-14b).
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "summary", name+".golden")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed test file
	if err != nil {
		t.Errorf("golden %s.golden: %v", name, err)
		return
	}
	if string(want) == got {
		return
	}
	wl, gl := strings.Split(string(want), "\n"), strings.Split(got, "\n")
	n := 0
	for n < len(wl) && n < len(gl) && wl[n] == gl[n] {
		n++
	}
	line := func(l []string) string {
		if n < len(l) {
			return l[n]
		}
		return "<end of output>"
	}
	t.Errorf("golden %s.golden: first difference at line %d\nwant: %q\ngot:  %q\nwhole output:\n%s", name, n+1, line(wl), line(gl), got)
}

// summaryPolicy parses the vector policy name and applies edit.
func summaryPolicy(t *testing.T, name string, edit func(p *trust.Policy)) *trust.Policy {
	t.Helper()
	p, err := trust.ParsePolicy(readVector(t, name))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(p)
	}
	return p
}

// TestSummaryGolden pins Summary on the test vectors byte for byte (03-14b,
// F14): the pop line for no PoP, for hosts and machines with pop.hosts'
// one-way note, and for machines only.
func TestSummaryGolden(t *testing.T) {
	b, err := trust.ParseBundle(readVector(t, "bundle_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		p    *trust.Policy
	}{
		{"genesis", summaryPolicy(t, "policy_genesis_v1.json", nil)},
		{"pop_hosts_machines", summaryPolicy(t, "policy_pop_v1.json", nil)},
		{"pop_machines_only", summaryPolicy(t, "policy_genesis_v1.json", func(p *trust.Policy) {
			p.PoP = &trust.PoPPolicy{Hosts: false, Machines: true}
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkGolden(t, tc.name, Summary(b, tc.p))
		})
	}
}

// pinnedPolicyTypes is every struct type reachable from trust.Policy, with
// its fields as "Name Type json-tag" (03-14b). A new policy field or type
// fails TestSummaryFieldsCovered until it is pinned here and has a case.
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

// TestSummaryFieldsCovered requires Summary's output to change for every
// field of every type reachable from trust.Policy, except Policy.Prev, which
// Summary does not print (03-14b, T-03-332). Summary does not validate, so a
// mutation need not give a valid policy.
func TestSummaryFieldsCovered(t *testing.T) {
	const need = "a new policy field needs a Summary line, a policydiff.go line and a TestPolicyChangeFields case"
	other := func(n byte) string {
		pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)).Public())
		if err != nil {
			t.Fatal(err)
		}
		return trust.FormatKey(pub)
	}
	mutations := map[string]func(p *trust.Policy){
		"Policy.Version":                   func(p *trust.Policy) { p.Version++ },
		"Policy.AdminQuorum":               func(p *trust.Policy) { p.AdminQuorum++ },
		"Policy.Admins":                    func(p *trust.Policy) { p.Admins = append(p.Admins, trust.AdminKey{Name: "bob", Key: other(22)}) },
		"Policy.CAProfiles":                func(p *trust.Policy) { p.CAProfiles = p.CAProfiles[:2] },
		"Policy.TimelockSeconds":           func(p *trust.Policy) { p.TimelockSeconds = 3600 },
		"Policy.WebAuthn":                  func(p *trust.Policy) { p.WebAuthn = nil },
		"Policy.PoP":                       func(p *trust.Policy) { p.PoP = nil },
		"AdminKey.Name":                    func(p *trust.Policy) { p.Admins[0].Name = "robert" },
		"AdminKey.Key":                     func(p *trust.Policy) { p.Admins[0].Key = other(23) },
		"CAProfile.Role":                   func(p *trust.Policy) { p.CAProfiles[0].Role = trust.RoleHost },
		"CAProfile.MaxTTLSeconds":          func(p *trust.Policy) { p.CAProfiles[0].MaxTTLSeconds = 3600 },
		"CAProfile.DefaultExtensions":      func(p *trust.Policy) { p.CAProfiles[0].DefaultExtensions = []string{} },
		"CAProfile.AllowedExtensions":      func(p *trust.Policy) { p.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding"} },
		"CAProfile.AllowedCriticalOptions": func(p *trust.Policy) { p.CAProfiles[0].AllowedCriticalOptions = []string{"force-command"} },
		"WebAuthnRP.RPID":                  func(p *trust.Policy) { p.WebAuthn.RPID = "other.example.org" },
		"WebAuthnRP.Origins": func(p *trust.Policy) {
			p.WebAuthn.Origins = append(p.WebAuthn.Origins, "https://keyroster.example.org:8443")
		},
		"PoPPolicy.Hosts":    func(p *trust.Policy) { p.PoP.Hosts = true },
		"PoPPolicy.Machines": func(p *trust.Policy) { p.PoP.Machines = false },
	}
	skip := map[string]bool{"Policy.Prev": true}

	reached := map[reflect.Type]bool{}
	walkPolicyTypes(reflect.TypeFor[trust.Policy](), map[reflect.Type]bool{}, func(typ reflect.Type) {
		reached[typ] = true
		want, ok := pinnedPolicyTypes[typ]
		if !ok {
			t.Errorf("unpinned policy type %s: pin its fields; %s", typ, need)
			return
		}
		if got := policyFieldList(typ); !slices.Equal(got, want) {
			t.Errorf("policy type %s has fields %q, pinned %q; %s", typ, got, want, need)
		}
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			if _, ok := mutations[key]; !ok && !skip[key] {
				t.Errorf("no Summary case for %s; %s", key, need)
			}
		}
	})
	for typ := range pinnedPolicyTypes {
		if !reached[typ] {
			t.Errorf("pinned type not reached: %s; the walk must reach every type reachable from trust.Policy", typ)
		}
	}

	b, err := trust.ParseBundle(readVector(t, "bundle_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := func() *trust.Policy {
		return summaryPolicy(t, "policy_genesis_v1.json", func(p *trust.Policy) {
			p.WebAuthn = &trust.WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org"}}
			p.PoP = &trust.PoPPolicy{Hosts: false, Machines: true}
		})
	}
	want := Summary(b, base())
	keys := make([]string, 0, len(mutations))
	for k := range mutations {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			p := base()
			mutations[key](p)
			if Summary(b, p) == want {
				t.Errorf("Summary's output does not change when %s changes; %s", key, need)
			}
		})
	}
}
