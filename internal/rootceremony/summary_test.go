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
// one-way note, and for machines only; and the rotation vector, whose two
// draining entries, and only they, end in their trusted until (03-12c).
func TestSummaryGolden(t *testing.T) {
	b, err := trust.ParseBundle(readVector(t, "bundle_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	rot, err := trust.ParseBundle(readVector(t, "bundle_rotation_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		b    *trust.Bundle
		p    *trust.Policy
	}{
		{"genesis", b, summaryPolicy(t, "policy_genesis_v1.json", nil)},
		{"pop_hosts_machines", b, summaryPolicy(t, "policy_pop_v1.json", nil)},
		{"pop_machines_only", b, summaryPolicy(t, "policy_genesis_v1.json", func(p *trust.Policy) {
			p.PoP = &trust.PoPPolicy{Hosts: false, Machines: true}
		})},
		{"draining", rot, summaryPolicy(t, "policy_genesis_v1.json", nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Summary(tc.b, tc.p)
			checkGolden(t, tc.name, got)
			var ends []string
			for _, l := range strings.Split(got, "\n") {
				if _, end, ok := strings.Cut(l, "  trusted until "); ok {
					ends = append(ends, end)
				}
			}
			var want []string
			for _, ca := range tc.b.CAs {
				if ca.State == "draining" {
					want = append(want, ca.TrustedUntil)
				}
			}
			if !slices.Equal(ends, want) {
				t.Fatalf("lines ending in trusted until: %q, want exactly the draining entries' %q", ends, want)
			}
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

// pinnedBundleTypes pins the fields of trust.Bundle and of every type
// reachable from it (03-12b, the Bundle reflect gate): a new field fails
// TestBundleReflectGate until it is pinned here and has a mutation, so
// that Summary shows the root holders every field a root signature vouches
// for.
var pinnedBundleTypes = map[reflect.Type][]string{
	reflect.TypeFor[trust.Bundle](): {
		"Version uint64 version",
		"Prev string prev",
		"IssuedAt string issued_at",
		"Root trust.RootSet root",
		"CAs []trust.CAEntry cas",
		"OpsKey trust.KeyEntry ops_key",
		"Log trust.LogEntry log",
		"PolicySHA256 string policy_sha256",
		"InstallationID string installation_id,omitempty",
	},
	reflect.TypeFor[trust.RootSet](): {"Keys []trust.RootKey keys", "Threshold uint32 threshold"},
	reflect.TypeFor[trust.RootKey](): {"Key string key", "Custody string custody"},
	reflect.TypeFor[trust.CAEntry](): {
		"Role string role", "Key string key", "Alg string alg", "Custody string custody", "State string state", "Generation uint32 generation",
		"TrustedUntil string trusted_until,omitempty",
	},
	reflect.TypeFor[trust.KeyEntry](): {"Key string key", "Alg string alg", "Custody string custody"},
	reflect.TypeFor[trust.LogEntry](): {"Key string key", "Alg string alg", "Custody string custody", "Origin string origin"},
}

// bundleReflectExempt are the bundle fields Summary does not print, each
// with the reason. It holds exactly one name.
var bundleReflectExempt = map[string]string{
	"Bundle.InstallationID": "installationLine (cmd/keyroster/root.go) prints it after the summary, and 03-14c's ceremony goldens pin it",
}

// TestBundleReflectGate (03-12b): Summary's output, without its
// Bundle SHA-256 line, changes for every field of trust.Bundle and the
// types it reaches, except the one exempt field. Summary does not
// validate, so a mutation need not give a valid bundle.
func TestBundleReflectGate(t *testing.T) {
	const need = "a new bundle field needs a Summary line and a TestBundleReflectGate mutation"
	other := func(n byte) string {
		pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)).Public())
		if err != nil {
			t.Fatal(err)
		}
		return trust.FormatKey(pub)
	}
	mutations := map[string]func(b *trust.Bundle){
		"Bundle.Version":  func(b *trust.Bundle) { b.Version++ },
		"Bundle.Prev":     func(b *trust.Bundle) { b.Prev = trust.SHA256Hex([]byte("another bundle")) },
		"Bundle.IssuedAt": func(b *trust.Bundle) { b.IssuedAt = "2026-10-06T00:00:00Z" },
		"Bundle.Root":     func(b *trust.Bundle) { b.Root = trust.RootSet{Keys: b.Root.Keys[:1], Threshold: 1} },
		"Bundle.CAs":      func(b *trust.Bundle) { b.CAs = b.CAs[:2] },
		"Bundle.OpsKey": func(b *trust.Bundle) {
			b.OpsKey = trust.KeyEntry{Key: other(31), Alg: ssh.KeyAlgoED25519, Custody: "software"}
		},
		"Bundle.Log": func(b *trust.Bundle) {
			b.Log = trust.LogEntry{Key: other(32), Alg: ssh.KeyAlgoED25519, Custody: "software", Origin: b.Log.Origin}
		},
		"Bundle.PolicySHA256": func(b *trust.Bundle) { b.PolicySHA256 = trust.SHA256Hex([]byte("another policy")) },
		"RootSet.Keys": func(b *trust.Bundle) {
			b.Root.Keys = append(b.Root.Keys, trust.RootKey{Key: other(33), Custody: "software"})
		},
		"RootSet.Threshold":  func(b *trust.Bundle) { b.Root.Threshold++ },
		"RootKey.Key":        func(b *trust.Bundle) { b.Root.Keys[0].Key = other(34) },
		"RootKey.Custody":    func(b *trust.Bundle) { b.Root.Keys[0].Custody = "fido" },
		"CAEntry.Role":       func(b *trust.Bundle) { b.CAs[0].Role = trust.RoleMachine },
		"CAEntry.Key":        func(b *trust.Bundle) { b.CAs[0].Key = other(35) },
		"CAEntry.Alg":        func(b *trust.Bundle) { b.CAs[0].Alg = ssh.KeyAlgoED25519 },
		"CAEntry.Custody":    func(b *trust.Bundle) { b.CAs[0].Custody = "tpm" },
		"CAEntry.State":      func(b *trust.Bundle) { b.CAs[0].State = "next" },
		"CAEntry.Generation": func(b *trust.Bundle) { b.CAs[0].Generation = 2 },
		"KeyEntry.Key":       func(b *trust.Bundle) { b.OpsKey.Key = other(36) },
		"KeyEntry.Alg":       func(b *trust.Bundle) { b.OpsKey.Alg = ssh.KeyAlgoED25519 },
		"KeyEntry.Custody":   func(b *trust.Bundle) { b.OpsKey.Custody = "tpm" },
		"LogEntry.Key":       func(b *trust.Bundle) { b.Log.Key = other(37) },
		"LogEntry.Alg":       func(b *trust.Bundle) { b.Log.Alg = ssh.KeyAlgoED25519 },
		"LogEntry.Custody":   func(b *trust.Bundle) { b.Log.Custody = "tpm" },
		"LogEntry.Origin":    func(b *trust.Bundle) { b.Log.Origin += "0" },
		// 03-12c: another end of the draining entry baseEdits makes.
		"CAEntry.TrustedUntil": func(b *trust.Bundle) { b.CAs[0].TrustedUntil = "2026-10-21T00:00:00Z" },
	}
	// baseEdits gives a mutation a base of its own (03-12c): a
	// trusted_until shows only on a draining entry.
	baseEdits := map[string]func(b *trust.Bundle){
		"CAEntry.TrustedUntil": func(b *trust.Bundle) {
			b.CAs[0].State, b.CAs[0].TrustedUntil = "draining", "2026-10-20T00:00:00Z"
		},
	}

	t.Run("exemptions", func(t *testing.T) {
		if len(bundleReflectExempt) != 1 || bundleReflectExempt["Bundle.InstallationID"] == "" {
			t.Fatalf("bundleReflectExempt = %v, want exactly Bundle.InstallationID", bundleReflectExempt)
		}
	})
	reached := map[reflect.Type]bool{}
	walkPolicyTypes(reflect.TypeFor[trust.Bundle](), map[reflect.Type]bool{}, func(typ reflect.Type) {
		reached[typ] = true
		want, ok := pinnedBundleTypes[typ]
		if !ok {
			t.Errorf("unpinned bundle type %s: pin its fields; %s", typ, need)
			return
		}
		if got := policyFieldList(typ); !slices.Equal(got, want) {
			t.Errorf("bundle type %s has fields %q, pinned %q; %s", typ, got, want, need)
		}
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			if _, ok := mutations[key]; !ok && bundleReflectExempt[key] == "" {
				t.Errorf("no Summary case for %s; %s", key, need)
			}
		}
	})
	for typ := range pinnedBundleTypes {
		if !reached[typ] {
			t.Errorf("pinned type not reached: %s; the walk must reach every type reachable from trust.Bundle", typ)
		}
	}

	base := func() *trust.Bundle {
		b, err := trust.ParseBundle(readVector(t, "bundle_genesis_v1.json"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	p := summaryPolicy(t, "policy_genesis_v1.json", nil)
	// summary is Summary without the Bundle SHA-256 line, which any field
	// changes.
	summary := func(b *trust.Bundle) string {
		var keep []string
		for _, l := range strings.Split(Summary(b, p), "\n") {
			if !strings.HasPrefix(l, "Bundle SHA-256:") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	keys := make([]string, 0, len(mutations))
	for k := range mutations {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			b := base()
			if edit := baseEdits[key]; edit != nil {
				edit(b)
			}
			want := summary(b)
			mutations[key](b)
			if summary(b) == want {
				t.Errorf("Summary's output does not change when %s changes; %s", key, need)
			}
		})
	}
}
