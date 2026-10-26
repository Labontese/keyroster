//go:build linux

package apply

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// Generation file names.
const (
	CAFile        = "user_ca_keys"
	KRLFile       = "revoked.krl"
	PrincipalsDir = "principals"
)

// intermediateHeader heads every principals file of an intermediate
// generation: every principal line below it comes from both rendered
// files (RenderPrincipalsFile output), Intermediate only drops lines.
const intermediateHeader = "# keyroster: intermediate generation; do not edit\n"

// Generation is one set of trust files: by path relative to the
// generation directory (user_ca_keys, revoked.krl, principals/<account>),
// their bytes. N is its number under gen/; 0 for a generation that is
// not on disk yet, or a foreign one (a current the agent did not make).
type Generation struct {
	N     uint64
	Files map[string][]byte
}

// FileClass decides how Intermediate combines a generation file and how a
// swap is classified (Task 2 of 03-05): every file a generation holds has
// exactly one class.
type FileClass int

// The file classes.
const (
	// FileKRL is a revocation list: the intermediate takes the target's
	// bytes, and a widening swap keeps it byte for byte.
	FileKRL FileClass = iota + 1
	// FileCAList is a list of CA keys, one per line: the intermediate
	// keeps the target's lines whose key the source also lists.
	FileCAList
	// FilePrincipals is an AuthorizedPrincipalsFile: the intermediate
	// keeps the target's principal lines the source's file also has.
	FilePrincipals
)

// GenerationFile is one entry of the class registry: Pattern is a file
// name, or "dir/*" for every file in dir.
type GenerationFile struct {
	Pattern string
	Class   FileClass
}

// GenerationFiles is the class registry Intermediate and the swap
// classification walk. 03-10 (probe principals) and 03-14 (break-glass
// files) add their files here and leave Intermediate and swap.go as they
// are; TestIntermediate every_generation_field_classified fails for a
// file Render writes that has no class.
var GenerationFiles = []GenerationFile{
	{Pattern: KRLFile, Class: FileKRL},
	{Pattern: CAFile, Class: FileCAList},
	{Pattern: PrincipalsDir + "/*", Class: FilePrincipals},
}

// ClassOf returns the class of a generation file name.
func ClassOf(name string) (FileClass, bool) {
	for _, f := range GenerationFiles {
		if dir, ok := strings.CutSuffix(f.Pattern, "/*"); ok {
			if rest, ok := strings.CutPrefix(name, dir+"/"); ok && rest != "" && !strings.Contains(rest, "/") {
				return f.Class, true
			}
			continue
		}
		if name == f.Pattern {
			return f.Class, true
		}
	}
	return 0, false
}

// Render refusals.
var (
	ErrHostNotInDirectory = errors.New("host_not_in_directory")
	ErrHostKeysDisagree   = errors.New("host_keys_disagree")
)

// HostError is a Render refusal about this host's entry, with the host
// keys that matched nothing, for the report.
type HostError struct {
	Err       error
	Unmatched []string
}

func (h *HostError) Error() string { return h.Err.Error() }
func (h *HostError) Unwrap() error { return h.Err }

// Render builds the generation the verified state v asks for on the host
// whose sshd host keys are hostKeys (D-03): the host entry is the one
// directory.HostForKey finds for any of them (every match must name the
// same host, else host_keys_disagree; none, or a disabled one, is
// host_not_in_directory and installs nothing new). user_ca_keys holds the
// bundle's active and next user and machine CA keys, one trust.FormatKey
// line each, sorted by role (user, then machine) and generation;
// principals/<account> is directory.RenderPrincipalsFile for each account
// of the host's host group, the one renderer; revoked.krl is the
// verified KRL, or zero bytes when none is published yet.
func Render(v *state.Verified, hostKeys []ssh.PublicKey) (*Generation, error) {
	if v.Directory == nil {
		return nil, &HostError{Err: fmt.Errorf("%w: no directory is accepted yet", ErrHostNotInDirectory), Unmatched: fingerprints(hostKeys)}
	}
	var host *directory.Host
	for _, k := range hostKeys {
		h, ok := v.Directory.HostForKey(k)
		if !ok {
			continue
		}
		if host != nil && host.Name != h.Name {
			return nil, fmt.Errorf("%w: the host keys name hosts %s and %s", ErrHostKeysDisagree, host.Name, h.Name)
		}
		host = h
	}
	if host == nil {
		return nil, &HostError{Err: fmt.Errorf("%w: directory version %d names none of this host's keys", ErrHostNotInDirectory, v.Directory.Version), Unmatched: fingerprints(hostKeys)}
	}
	if host.Status != directory.StatusActive {
		return nil, &HostError{Err: fmt.Errorf("%w: host %s is %s in directory version %d", ErrHostNotInDirectory, host.Name, host.Status, v.Directory.Version)}
	}
	g := &Generation{Files: map[string][]byte{}}
	var ca bytes.Buffer
	for _, role := range []string{trust.RoleUser, trust.RoleMachine} {
		var entries []trust.CAEntry
		for _, c := range v.Bundle.CAs {
			if c.Role == role && (c.State == "active" || c.State == "next") {
				entries = append(entries, c)
			}
		}
		slices.SortFunc(entries, func(a, b trust.CAEntry) int { return cmp.Compare(a.Generation, b.Generation) })
		for _, c := range entries {
			pub, err := trust.ParseKey(c.Key)
			if err != nil {
				return nil, fmt.Errorf("the bundle's %s CA key: %w", role, err)
			}
			ca.WriteString(trust.FormatKey(pub) + "\n")
		}
	}
	g.Files[CAFile] = ca.Bytes()
	i := slices.IndexFunc(v.Directory.HostGroups, func(h directory.HostGroup) bool { return h.Name == host.HostGroup })
	if i < 0 {
		return nil, fmt.Errorf("%w: host %s names host group %s, which the directory does not define", ErrHostNotInDirectory, host.Name, host.HostGroup)
	}
	for _, a := range v.Directory.HostGroups[i].Accounts {
		file, err := directory.RenderPrincipalsFile(v.Directory, host.HostGroup, a.Account)
		if err != nil {
			return nil, err
		}
		g.Files[PrincipalsDir+"/"+a.Account] = file
	}
	g.Files[KRLFile] = append([]byte{}, v.Next.KRL...)
	return g, nil
}

func fingerprints(keys []ssh.PublicKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Type()+" "+ssh.FingerprintSHA256(k))
	}
	return out
}

// lines returns the lines of b without their newline.
func lines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// caKey is the comparison key of one CA-list line: the key's wire
// encoding, or the raw line when it does not parse (sshd reads such a
// line too, so it is part of the list's content). Blank and comment lines
// have none.
func caKey(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(t))
	if err != nil {
		return "raw:" + t, true
	}
	return "key:" + string(pub.Marshal()), true
}

// principalLine is the comparison key of one principals-file line; blank
// and comment lines have none.
func principalLine(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	return t, true
}

func lineSet(b []byte, key func(string) (string, bool)) map[string]bool {
	set := map[string]bool{}
	for _, l := range lines(b) {
		if k, ok := key(l); ok {
			set[k] = true
		}
	}
	return set
}

// keyFunc is the comparison key of a class's lines.
func keyFunc(c FileClass) func(string) (string, bool) {
	if c == FileCAList {
		return caKey
	}
	return principalLine
}

// fileNames is the sorted union of the file names of the generations.
func fileNames(gs ...*Generation) []string {
	set := map[string]bool{}
	for _, g := range gs {
		for n := range g.Files {
			set[n] = true
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// Intermediate returns the generation that allows only what both from and
// to allow (F1, owner decision 2026-10-24): for each file by its class,
// revoked.krl is to's bytes, user_ca_keys holds to's lines whose key from
// also lists (in to's order), and principals/<account>, for every account
// on either side, holds to's principal lines that from's file for that
// account also has, in to's order, under the fixed intermediate header (an
// account on one side only gets the header alone). collapsed is true when
// that result equals to or from in classified content (sameContent): then
// there is nothing between them to wait in, and the caller installs to
// itself in one swap.
func Intermediate(from, to *Generation) (*Generation, bool) {
	m := &Generation{Files: map[string][]byte{}}
	for _, name := range fileNames(from, to) {
		class, ok := ClassOf(name)
		if !ok {
			continue
		}
		switch class {
		case FileKRL:
			if b, ok := to.Files[name]; ok {
				m.Files[name] = append([]byte{}, b...)
			}
		case FileCAList, FilePrincipals:
			key := keyFunc(class)
			have := lineSet(from.Files[name], key)
			var out bytes.Buffer
			if class == FilePrincipals {
				out.WriteString(intermediateHeader)
			}
			for _, l := range lines(to.Files[name]) {
				if k, ok := key(l); ok && have[k] {
					out.WriteString(l + "\n")
				}
			}
			m.Files[name] = out.Bytes()
		}
	}
	if sameContent(m, to) || sameContent(m, from) {
		return to, true
	}
	return m, false
}

// covers reports whether every CA key and principal line of a is also in
// b, file by file and class by class (an absent file is an empty list).
func covers(b, a *Generation) bool {
	for _, name := range fileNames(a, b) {
		class, ok := ClassOf(name)
		if !ok || class == FileKRL {
			continue
		}
		key := keyFunc(class)
		have := lineSet(b.Files[name], key)
		for k := range lineSet(a.Files[name], key) {
			if !have[k] {
				return false
			}
		}
	}
	return true
}

// sameKRL reports whether every revocation-list file is byte-identical
// (absent on both sides counts as identical).
func sameKRL(a, b *Generation) bool {
	for _, name := range fileNames(a, b) {
		if class, ok := ClassOf(name); ok && class == FileKRL {
			x, okx := a.Files[name]
			y, oky := b.Files[name]
			if okx != oky || !bytes.Equal(x, y) {
				return false
			}
		}
	}
	return true
}

// sameContent compares two generations by classified content (PR #57
// review): CA lists as sets of keys, principals files per account as sets
// of non-comment lines (absent equals header-only), revocation lists byte
// for byte. Header and comment lines never make two generations differ.
func sameContent(a, b *Generation) bool {
	return covers(a, b) && covers(b, a) && sameKRL(a, b)
}

// isNarrowing reports whether moving current from src to dst only
// removes: every CA key and principal line of dst is in src. The KRL may
// change.
func isNarrowing(src, dst *Generation) bool { return covers(src, dst) }

// isWidening reports whether moving from src to dst only adds and keeps
// every revocation list byte for byte.
func isWidening(src, dst *Generation) bool { return covers(dst, src) && sameKRL(src, dst) }

// sameBytes reports whether two generations hold the same files with the
// same bytes.
func sameBytes(a, b *Generation) bool {
	if len(a.Files) != len(b.Files) {
		return false
	}
	for n, x := range a.Files {
		y, ok := b.Files[n]
		if !ok || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}
