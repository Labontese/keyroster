package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Labontese/keyroster/internal/trust"
)

// maxCANextFile bounds the prepare file that root sign --ca-next reads
// (03-12b).
const maxCANextFile = 4096

// caNextFile is the prepare file that keyroster-signer ca-rotate prepare
// writes (cmd/keyroster-signer/rotate.go, prepareFile): untagged strict
// JSON with these fields in this order and no installation ID. canext_test.go
// and the signer's rotate_test.go pin the same bytes and change together.
type caNextFile struct {
	Role       string `json:"role"`
	Generation uint32 `json:"generation"`
	Key        string `json:"key"`
	Alg        string `json:"alg"`
	Custody    string `json:"custody"`
}

// caChangeRoles are the roles root sign's CA flags name.
var caChangeRoles = []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine}

// parseCANextFile reads a prepare file strictly (03-12b): at most
// maxCANextFile bytes of canonical JSON (trust.DecodeStrict) with role
// user, host or machine, generation at least 2, a key in the canonical
// form trust.FormatKey prints whose type is alg, and a custody. The entry
// it returns is in state next.
func parseCANextFile(data []byte) (trust.CAEntry, error) {
	if len(data) > maxCANextFile {
		return trust.CAEntry{}, fmt.Errorf("the prepare file is more than %d bytes", maxCANextFile)
	}
	var f caNextFile
	if err := trust.DecodeStrict(data, &f); err != nil {
		return trust.CAEntry{}, fmt.Errorf("the prepare file: %w", err)
	}
	if !slices.Contains(caChangeRoles, f.Role) {
		return trust.CAEntry{}, fmt.Errorf("the prepare file names role %q, not one of user, host and machine", f.Role)
	}
	if f.Generation < 2 {
		return trust.CAEntry{}, fmt.Errorf("the prepare file names generation %d; a prepared generation is at least 2", f.Generation)
	}
	pub, err := trust.ParseKey(f.Key)
	if err != nil {
		return trust.CAEntry{}, fmt.Errorf("the prepare file's key: %w", err)
	}
	if f.Alg != pub.Type() {
		return trust.CAEntry{}, fmt.Errorf("the prepare file's alg %q is not its key's type %s", f.Alg, pub.Type())
	}
	if f.Custody == "" {
		return trust.CAEntry{}, errors.New("the prepare file names no custody")
	}
	return trust.CAEntry{Role: f.Role, Key: f.Key, Alg: f.Alg, Custody: f.Custody, State: "next", Generation: f.Generation}, nil
}

// readCANextFile reads the prepare file at path: a regular file, not a
// link, whose size is checked before it is read, then parseCANextFile.
func readCANextFile(path string) (trust.CAEntry, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return trust.CAEntry{}, err
	}
	if !fi.Mode().IsRegular() {
		return trust.CAEntry{}, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > maxCANextFile {
		return trust.CAEntry{}, fmt.Errorf("%s is %d bytes, more than the %d a prepare file can be", path, fi.Size(), maxCANextFile)
	}
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return trust.CAEntry{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCANextFile+1))
	if err != nil {
		return trust.CAEntry{}, err
	}
	e, err := parseCANextFile(data)
	if err != nil {
		return trust.CAEntry{}, fmt.Errorf("%s: %w", path, err)
	}
	return e, nil
}

// repeated is a repeatable string flag: every value, in order.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, ",") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

// caFlagValue is one value of --ca-next (ROLE=FILE), --ca-next-fingerprint
// (ROLE=SHA256:...) or --ca-retire (ROLE:GEN): the role and the rest.
type caFlagValue struct {
	role, rest string
	gen        uint32
}

// usageError is a usage refusal of root sign's CA flags: the text root
// sign prints after "root sign: ", in the output contract's words, which
// name the flags' forms (03-12b).
type usageError string

func (u usageError) Error() string { return string(u) }

func usagef(format string, args ...any) error { return usageError(fmt.Sprintf(format, args...)) }

// parseCAFlag splits one value of flag; sep is '=' or ':'. A usage error is
// returned as the text root sign prints after "root sign: ".
func parseCAFlag(flag, value string, sep byte) (caFlagValue, error) {
	role, rest, found := strings.Cut(value, string(sep))
	notGen := func() error {
		return usagef("%s %s: want ROLE:GEN with GEN a decimal generation number from 1 to 4294967295", flag, value)
	}
	if sep == ':' && !found {
		return caFlagValue{}, notGen()
	}
	if !slices.Contains(caChangeRoles, role) {
		return caFlagValue{}, usagef("%s %s: the role is not one of user, host and machine", flag, value)
	}
	v := caFlagValue{role: role, rest: rest}
	if sep == ':' {
		if v.gen, found = canonicalGeneration(rest); !found {
			return caFlagValue{}, notGen()
		}
	}
	return v, nil
}

// canonicalGeneration parses s as a canonical decimal number from 1 to
// 4294967295: digits only, no sign and no leading zero.
func canonicalGeneration(s string) (uint32, bool) {
	if s == "" || s[0] == '0' || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true //nolint:gosec // G115: ParseUint bounded n to 32 bits
}

// caChanges are root sign's CA flags, checked for their usage (03-12b):
// next and fingerprint by role, the retire references, and the roles of
// --ca-switch in the order given (03-12e2).
type caChanges struct {
	next        map[string]string // role -> prepare file
	fingerprint map[string]string // role -> SHA256:...
	retire      []trust.CARef
	switchRoles []string
}

// parseCAChanges checks the CA flags' values, in the output contract's
// order: each value's form and role, at most one change per role across
// --ca-next, --ca-retire and --ca-switch (a repeated flag included, 03-12e2
// for the switch), and a fingerprint for every --ca-next role and for no
// other. switchRoles are the --ca-switch values, each a role. A refusal is
// the text root sign prints after "root sign: ".
func parseCAChanges(next, fingerprint, retire, switchRoles []string) (*caChanges, error) {
	c := &caChanges{next: map[string]string{}, fingerprint: map[string]string{}}
	named := map[string]int{}
	var order []string
	note := func(role string) {
		if named[role] == 0 {
			order = append(order, role)
		}
		named[role]++
	}
	for _, v := range next {
		f, err := parseCAFlag("--ca-next", v, '=')
		if err != nil {
			return nil, err
		}
		note(f.role)
		c.next[f.role] = f.rest
	}
	fpNamed := map[string]int{}
	for _, v := range fingerprint {
		f, err := parseCAFlag("--ca-next-fingerprint", v, '=')
		if err != nil {
			return nil, err
		}
		fpNamed[f.role]++
		c.fingerprint[f.role] = f.rest
	}
	for _, v := range retire {
		f, err := parseCAFlag("--ca-retire", v, ':')
		if err != nil {
			return nil, err
		}
		note(f.role)
		c.retire = append(c.retire, trust.CARef{Role: f.role, Generation: f.gen})
	}
	for _, role := range switchRoles {
		if !slices.Contains(caChangeRoles, role) {
			return nil, usagef("--ca-switch %s: the role is not one of user, host and machine", role)
		}
		note(role)
		c.switchRoles = append(c.switchRoles, role)
	}
	for _, role := range order {
		if named[role] > 1 {
			return nil, usagef("at most one CA change per role: %s is named more than once", role)
		}
	}
	for _, role := range caChangeRoles {
		if fpNamed[role] > 1 {
			return nil, usagef("at most one CA change per role: %s is named more than once", role)
		}
	}
	for _, role := range caChangeRoles {
		if _, ok := c.next[role]; ok {
			if _, ok := c.fingerprint[role]; !ok {
				return nil, usagef("--ca-next %s needs --ca-next-fingerprint %s=SHA256:...", role, role)
			}
		}
	}
	for _, role := range caChangeRoles {
		if _, ok := c.fingerprint[role]; ok {
			if _, ok := c.next[role]; !ok {
				return nil, usagef("--ca-next-fingerprint %s needs --ca-next %s=FILE", role, role)
			}
		}
	}
	return c, nil
}
