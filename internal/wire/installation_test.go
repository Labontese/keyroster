package wire

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The installation-binding classification (03-14d; D5). Every signed
// request type in internal/wire, and every keyroster/ string literal in
// the module's non-test code under internal/ and cmd/, is pinned here: a
// request names the installation it is for, or carries a recorded
// exemption. The file names only identifiers that exist without 03-14d's
// wire change (IssueRequest's InstallationID is set through reflection),
// and every name in it carries a bind prefix, so it builds on its own.

// bindIDs are the two installation IDs a template is signed with.
var bindIDs = [2]string{"00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"}

// bindType pins one signed request type: a template constructor that
// returns a pointer to a valid request, or the reason it is exempt.
type bindType struct {
	template func() any
	exempt   string
}

// bindTypes is every receiver of a method named SigningBytes in
// internal/wire. A new signed request type names the installation it is
// for (an exported string field InstallationID its signing bytes carry),
// or gets a recorded exemption here.
var bindTypes = map[string]bindType{
	"IssueRequest":        {template: bindIssue},
	"RevokeRequest":       {template: bindRevoke},
	"ForgetRequest":       {template: bindForget},
	"RecoveryRequest":     {template: bindRecovery},
	"HostIssueRequest":    {template: bindHostIssue},
	"ProbeIssueRequest":   {template: bindProbeIssue},
	"MachineIssueRequest": {template: bindMachineIssue},
	"LoginIssueRequest": {exempt: "owner-recorded residual (Q-C8): approved by the user's passkey for a credential " +
		"the installation-bound directory binds, under an origin the policy lists; assumes each installation has " +
		"its own RP hostname (reasoned, UNVERIFIED)"},
}

// bindTag classifies one keyroster/ string value. A bound wire tag names
// the templated type whose signing bytes begin with it, raw (every bound
// format prepends its domain as raw bytes); noID checks the template with
// its InstallationID cleared. A tag outside internal/wire is classified,
// not proven: its reason names the test that pins its binding, and a
// wrong label is caught only by review.
type bindTag struct {
	typ   string
	noID  bool
	class string
}

// bindTags is every keyroster/ string literal in the module's non-test
// code under internal/ and cmd/, keyed by value. A tag without the
// keyroster/ prefix is outside this walk.
var bindTags = map[string]bindTag{
	"keyroster/issue-request/v2":         {typ: "IssueRequest", class: "bound (03-14d, F15)"},
	"keyroster/revoke-request/v2":        {typ: "RevokeRequest", class: "bound"},
	"keyroster/revoke-recovery/v1":       {typ: "RecoveryRequest", class: "bound"},
	"keyroster/host-forget-request/v1":   {typ: "ForgetRequest", class: "bound"},
	"keyroster/host-issue-request/v1":    {typ: "HostIssueRequest", class: "bound (D5; also its PoP namespace)"},
	"keyroster/probe-issue-request/v1":   {typ: "ProbeIssueRequest", class: "bound (D5; also its PoP namespace)"},
	"keyroster/machine-issue-request/v1": {typ: "MachineIssueRequest", class: "bound (D5; also its PoP namespace)"},
	"keyroster/issue-request/v1":         {typ: "IssueRequest", noID: true, class: "bound where the bundle names one: accepted only where the signer's bundle names no installation (Q-C2 A)"},
	"keyroster/directory/v1":             {class: "bound outside internal/wire, classified, not proven: pinned by TestCheckInstallation (internal/directory)"},
	"keyroster/krl/v1":                   {class: "bound outside internal/wire, classified, not proven: pinned by TestVerifyManifest/other_installation_refused (internal/krl)"},
	"keyroster/agent-enroll/v1":          {class: "bound outside internal/wire, classified, not proven: pinned by TestPoP/other_installation_refused (internal/agent/enroll)"},
	"keyroster/trust-bundle/v1":          {class: "bound outside internal/wire, classified, not proven: installation_id optional; carried unchanged by VerifySuccessor (TestInstallationIDSuccessor)"},
	"keyroster/revoke-request/v1":        {class: "refused: refused since 03-03, read by audit"},
	"keyroster/policy/v1":                {class: "not a request tag: bound through the bundle's policy_sha256"},
	"keyroster/log-leaf/v1":              {class: "not a request tag: the log key's own domain"},
	"keyroster/log/":                     {class: "not a request tag: the log key's checkpoint origin"},
	"keyroster/login-request/v1":         {class: "exempt, owner-recorded (Q-C8): as LoginIssueRequest in bindTypes"},
	"keyroster/admin-api/v1":             {class: "exempt, owner-recorded: bound to an exact origin taken from the root-verified policy; assumes each installation has its own hostname, the same assumption as Q-C8 (Q-D1 = A; reasoned, UNVERIFIED)"},
	"keyroster/agent-identity/v1":        {class: "exempt, owner-recorded: accepted only over mTLS, from the same old identity that signs it, and that identity is bound to the installation at enrollment (enroll.PoP) (Q-D1 = A)"},
}

// TestSignedRequestsBindInstallation (03-14d; D5): every signed request
// type in internal/wire and every keyroster/ string literal in the
// module's non-test code is classified by installation binding. A bound
// type's signing bytes change with its InstallationID and contain it; a
// bound wire tag is carried, raw, by its type's signing bytes.
func TestSignedRequestsBindInstallation(t *testing.T) {
	t.Run("types", func(t *testing.T) {
		fset := gotoken.NewFileSet()
		ents, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		found := bindSigningTypes(files)
		for _, m := range bindCompare("type", found, bindKeys(bindTypes)) {
			t.Errorf("%s", m)
		}
		for _, name := range bindKeys(bindTypes) {
			b := bindTypes[name]
			if _, ok := found[name]; !ok || b.template == nil {
				continue
			}
			p := b.template()
			if !bindHasField(p) {
				t.Errorf("%s has no InstallationID string field", name)
				continue
			}
			var (
				sb  [2][]byte
				err error
			)
			for i, id := range bindIDs {
				if sb[i], err = bindSign(p, id); err != nil {
					break
				}
			}
			switch {
			case err != nil:
				t.Errorf("%s: SigningBytes: %v", name, err)
			case bytes.Equal(sb[0], sb[1]) || !bytes.Contains(sb[0], []byte(bindIDs[0])) || !bytes.Contains(sb[1], []byte(bindIDs[1])):
				t.Errorf("%s: signing bytes do not name the installation", name)
			}
		}
	})

	t.Run("tags", func(t *testing.T) {
		fset := gotoken.NewFileSet()
		root := filepath.Join("..", "..")
		found := map[string]string{}
		for _, top := range []string{"internal", "cmd"} {
			err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
					return err
				}
				rel, err := filepath.Rel(root, p)
				if err != nil {
					return err
				}
				f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
				if err != nil {
					return err
				}
				bindTagLiterals(fset, f, filepath.ToSlash(rel), found)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, m := range bindCompare("tag", found, bindKeys(bindTags)) {
			t.Errorf("%s", m)
		}
		for _, v := range bindKeys(bindTags) {
			c := bindTags[v]
			if _, ok := found[v]; !ok || c.typ == "" {
				continue
			}
			b := bindTypes[c.typ]
			if b.template == nil {
				t.Errorf("%s: bound to %s, which has no template", v, c.typ)
				continue
			}
			p := b.template()
			if !bindHasField(p) {
				continue // the types subtest reports the missing field
			}
			id := bindIDs[0]
			if c.noID {
				id = ""
			}
			sb, err := bindSign(p, id)
			if err != nil || !bytes.HasPrefix(sb, []byte(v)) {
				t.Errorf("%s: %s's signing bytes do not carry the tag", v, c.typ)
			}
		}
	})

	t.Run("diff_logic", func(t *testing.T) {
		const src = `package fake

const exampleDomain = "keyroster/x/v1"

type A struct{}

func (a *A) SigningBytes() []byte { return nil }

type B struct{}

func (b B) SigningBytes() []byte { return nil }
`
		fset := gotoken.NewFileSet()
		f, err := parser.ParseFile(fset, "src.go", src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		tags := map[string]string{}
		bindTagLiterals(fset, f, "src.go", tags)
		got := append(bindCompare("type", bindSigningTypes([]*ast.File{f}), []string{"A", "Gone"}),
			bindCompare("tag", tags, []string{"keyroster/y/v1"})...)
		want := []string{
			"unpinned signed request type B",
			"pinned type not found Gone",
			"unclassified tag keyroster/x/v1",
			"classified tag not found keyroster/y/v1",
		}
		ok := len(got) == len(want)
		for i := 0; ok && i < len(want); i++ {
			ok = got[i] == want[i] || strings.HasPrefix(got[i], want[i]+" ") || strings.HasPrefix(got[i], want[i]+":")
		}
		if !ok {
			t.Errorf("bindCompare = %q, want messages starting %q", got, want)
		}
	})
}

// bindCompare compares the names a walk found (each with its site) with
// the pinned names, for kind "type" or "tag", and returns one message per
// difference: found names first, then pinned names, each sorted.
func bindCompare(kind string, found map[string]string, pinned []string) []string {
	pin := map[string]bool{}
	for _, n := range pinned {
		pin[n] = true
	}
	var out []string
	for _, n := range bindKeys(found) {
		if pin[n] {
			continue
		}
		if kind == "type" {
			out = append(out, fmt.Sprintf("unpinned signed request type %s: a new signed request type names the installation it is for "+
				"(an InstallationID string field its signing bytes carry) or gets a recorded exemption in bindTypes", n))
		} else {
			out = append(out, fmt.Sprintf("unclassified tag %s %s: a new keyroster/ tag is classified in bindTags and in docs/format-registry.md", n, found[n]))
		}
	}
	for _, n := range pinned {
		if _, ok := found[n]; ok {
			continue
		}
		if kind == "type" {
			out = append(out, "pinned type not found "+n)
		} else {
			out = append(out, "classified tag not found "+n)
		}
	}
	return out
}

// bindSigningTypes returns the receiver type name, pointer or value, of
// every method named SigningBytes in files.
func bindSigningTypes(files []*ast.File) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Name.Name != "SigningBytes" {
				continue
			}
			if n := bindRecvName(fd.Recv.List[0].Type); n != "" {
				out[n] = ""
			}
		}
	}
	return out
}

// bindRecvName is the type name of a receiver expression.
func bindRecvName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return bindRecvName(x.X)
	case *ast.ParenExpr:
		return bindRecvName(x.X)
	case *ast.IndexExpr:
		return bindRecvName(x.X)
	case *ast.IndexListExpr:
		return bindRecvName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// bindTagLiterals adds to out every string literal in f whose value
// starts with keyroster/, wherever it occurs, keyed by value, with the
// first package and position seen. Comments are not literals.
func bindTagLiterals(fset *gotoken.FileSet, f *ast.File, name string, out map[string]string) {
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != gotoken.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(v, "keyroster/") {
			return true
		}
		if _, seen := out[v]; !seen {
			pos := fset.Position(lit.Pos())
			out[v] = fmt.Sprintf("(%s, %s:%d:%d)", f.Name.Name, name, pos.Line, pos.Column)
		}
		return true
	})
}

// bindKeys returns m's keys, sorted.
func bindKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// bindHasField reports whether the struct p points to has an exported
// string field named exactly InstallationID.
func bindHasField(p any) bool {
	f, ok := reflect.TypeOf(p).Elem().FieldByName("InstallationID")
	return ok && f.IsExported() && f.Type.Kind() == reflect.String
}

// bindSign sets the InstallationID field of the request p points to and
// returns its SigningBytes, accepting a []byte result or a ([]byte,
// error) result.
func bindSign(p any, id string) ([]byte, error) {
	v := reflect.ValueOf(p)
	v.Elem().FieldByName("InstallationID").SetString(id)
	m := v.MethodByName("SigningBytes")
	if !m.IsValid() {
		return nil, errors.New("no SigningBytes method on the template")
	}
	res := m.Call(nil)
	if len(res) == 0 || len(res) > 2 {
		return nil, errors.New("SigningBytes returns neither []byte nor ([]byte, error)")
	}
	b, ok := res[0].Interface().([]byte)
	switch {
	case !ok:
		return nil, errors.New("SigningBytes returns neither []byte nor ([]byte, error)")
	case len(res) == 2 && !res[1].IsNil():
		err, _ := res[1].Interface().(error)
		return nil, err
	}
	return b, nil
}

// bindWithID sets p's InstallationID to the first test ID where the field
// exists, and returns p.
func bindWithID(p any) any {
	if bindHasField(p) {
		reflect.ValueOf(p).Elem().FieldByName("InstallationID").SetString(bindIDs[0])
	}
	return p
}

// bindRequestID is a fixed request ID.
func bindRequestID() (id [16]byte) {
	for i := range id {
		id[i] = byte(i)
	}
	return id
}

// bindKey is a placeholder public key blob, as validRequest's.
func bindKey(b byte) []byte { return bytes.Repeat([]byte{b}, 51) }

func bindIssue() any {
	return bindWithID(&IssueRequest{CARole: CARoleUser, SubjectKey: bindKey(0x5a), Subject: "u:alice",
		Principals: []string{"alice"}, ValidForSeconds: 3600, RequestID: bindRequestID(), CreatedAt: 1_790_000_000})
}

func bindRevoke() any {
	return &RevokeRequest{InstallationID: bindIDs[0], Target: TargetSerial, CARole: CARoleUser, Serial: 1,
		RequestID: bindRequestID(), CreatedAt: 1_790_000_000, Reason: "key lost"}
}

func bindForget() any {
	return &ForgetRequest{InstallationID: bindIDs[0], AgentIdentity: [32]byte{1}, ExpectedName: "web1",
		EnrolledAtMicros: 1_790_000_000_000_000, HostKeyFingerprints: [][32]byte{{2}}, RemovalVersion: 2,
		ConfirmedVersion: 2, ConfirmedSHA256: [32]byte{3}, RequestID: bindRequestID(), CreatedAt: 1_790_000_000}
}

func bindRecovery() any {
	return &RecoveryRequest{InstallationID: bindIDs[0], RequestID: bindRequestID(), CreatedAt: 1_790_000_000,
		RestoredSize: 1, RestoredRoot: [32]byte{4}}
}

func bindHostIssue() any {
	return &HostIssueRequest{InstallationID: bindIDs[0], HostName: "web1", HostKey: bindKey(0x5b),
		ValidForSeconds: 3600, RequestID: bindRequestID(), CreatedAt: 1_790_000_000}
}

func bindProbeIssue() any {
	return &ProbeIssueRequest{InstallationID: bindIDs[0], HostName: "web1", HostKey: bindKey(0x5b),
		ProbeKey: bindKey(0x5c), ValidForSeconds: 3600, RequestID: bindRequestID(), CreatedAt: 1_790_000_000}
}

func bindMachineIssue() any {
	return &MachineIssueRequest{InstallationID: bindIDs[0], MachineName: "backup", MachineKey: bindKey(0x5d),
		ValidForSeconds: 3600, RequestID: bindRequestID(), CreatedAt: 1_790_000_000}
}
