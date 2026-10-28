//go:build linux

package apply

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// maxIncludeDepth is sshd's SERVCONF_MAX_DEPTH (OpenSSH servconf.c,
// checked in portable 10.2p1): the main configuration is depth 0, and
// sshd stops with "Too many recursive configuration includes" past 16.
// A cycle reaches it too.
const maxIncludeDepth = 16

// maxConfigVisits bounds the files one walk reads, repeats included.
const maxConfigVisits = 512

// configFile is one sshd configuration file the walk read, tokenised.
type configFile struct {
	path  string
	lines []configLine
}

// configLine is one line of an sshd configuration file as sshd reads it
// (sshdTokens): its number, lowercase keyword ("" for a blank line or a
// comment), the rest of the line after the keyword and its separator
// (what sshd takes verbatim as an AuthorizedPrincipalsCommand), its
// arguments and its trimmed text.
type configLine struct {
	n       int
	keyword string
	rest    string
	args    []string
	text    string
}

// configGraph reads the sshd configuration the way sshd reads it (PR #68
// review D-R3, the owner's "whole Include graph + command"): config, and
// every file an Include line names, recursively, wherever the line is
// (inside a Match block too), with sshd's rule that a relative path is
// relative to /etc/ssh (below the layout's root). Every line is tokenised
// as sshd tokenises it (sshdTokens), so a quoted keyword or argument is
// seen. An Include path may hold only the wildcard *, and only in its
// last component (includePattern); a path that matches nothing is
// skipped, as sshd does. Every file is read with readTrusted, and the
// directory of each Include pattern must be one no other user can write
// (a file added there later would be read); one that is not, a line the
// tokeniser cannot read, a ~ path, a cycle, nesting past maxIncludeDepth
// or more than maxConfigVisits files is a sshd_config_unsafe finding.
// Go's glob also matches dot files that sshd's glob(3) skips: more is
// read, never less. Each file is returned once, in the order first read.
//
// own, when not nil, stands in for the agent's drop-in (l.DropIn()) on an
// installed host: the walk evaluates the file the apply is about to write
// (DropIn, mode 0644), not an edited one the apply replaces (owner
// decision D-R2; PR #68 review fix round 2, P1). check passes nil: it
// reports what sshd reads now.
func configGraph(l Layout, config string, own []byte) ([]configFile, []Finding) {
	g := &graph{l: l, own: own, seen: map[string]bool{}}
	g.visit(config, 0, nil, "", 0)
	return g.files, g.problems
}

type graph struct {
	l        Layout
	own      []byte
	files    []configFile
	problems []Finding
	seen     map[string]bool
	visits   int
}

func (g *graph) problem(file string, line int, format string, args ...any) {
	g.problems = append(g.problems, configProblem(file, line, format, args...))
}

// configProblem is one sshd_config_unsafe finding.
func configProblem(file string, line int, format string, args ...any) Finding {
	return Finding{Code: CodeConfigUnsafe, File: file, Line: line,
		Message: fmt.Sprintf(format, args...) + "; the agent cannot rule out a trust setting in what sshd reads",
		Fix:     "make every file sshd reads, and every directory an Include names, owned by root and writable by no one else, with no symlink another user controls; keep the Include nesting within sshd's 16 levels, every Include path a plain path with at most a * in its last component, and every line free of unbalanced quotes; see host-setup.md \"Before the agent: preflight\""}
}

// visit reads path (named by from:line; "" for the main configuration)
// at depth and walks its Include lines.
func (g *graph) visit(path string, depth int, stack []string, from string, line int) {
	switch {
	case slices.Contains(stack, path):
		g.problem(from, line, "Include of %s, which is being read already (a cycle; sshd stops at its nesting limit)", path)
		return
	case depth > maxIncludeDepth:
		g.problem(from, line, "Include of %s nests deeper than sshd's %d levels", path, maxIncludeDepth)
		return
	}
	if g.visits++; g.visits > maxConfigVisits {
		if g.visits == maxConfigVisits+1 {
			g.problem(from, line, "the configuration reads more than %d files", maxConfigVisits)
		}
		return
	}
	var b []byte
	var err error
	if g.own != nil && path == g.l.DropIn() {
		b = g.own
	} else {
		b, err = readTrusted(g.l.Root, path, 1<<20)
	}
	if errors.Is(err, unix.ENOENT) && from != "" {
		return // gone since it matched: sshd would not read it either
	}
	if err != nil {
		where, wl := from, line
		if where == "" {
			where = path
		}
		g.problem(where, wl, "%s: %v", path, err)
		return
	}
	// sshd copies each line it reads up to its first NUL byte only, so the
	// rest of that line and its newline are dropped and the next line is
	// joined to it (PR #68 carry-over; observed with 9.5p1 and 10.5p1:
	// "AuthorizedPrincipalsComma<NUL>" then "nd /x" is one line to sshd).
	// The agent cannot read such a file line by line as sshd does.
	if i := bytes.IndexByte(b, 0); i >= 0 {
		g.problem(path, 1+bytes.Count(b[:i], []byte{'\n'}), "%s holds a NUL byte, at which sshd joins lines", path)
		return
	}
	lines, bad := parseConfig(path, b)
	g.problems = append(g.problems, bad...)
	if !g.seen[path] {
		g.seen[path] = true
		g.files = append(g.files, configFile{path: path, lines: lines})
	}
	stack = append(stack, path)
	for _, l := range lines {
		if l.keyword != "include" {
			continue
		}
		for _, a := range l.args {
			g.include(path, l.n, a, depth+1, stack)
		}
	}
}

// include walks one Include argument of from:line.
func (g *graph) include(from string, line int, arg string, depth int, stack []string) {
	p, why := includePattern(g.l.Root, arg)
	if why != "" {
		g.problem(from, line, "%s:%d: Include %q %s", from, line, arg, why)
		return
	}
	err := trustedDir(g.l.Root, filepath.Dir(p))
	if errors.Is(err, unix.ENOENT) {
		return // nothing can match
	}
	if err != nil {
		g.problem(from, line, "%s:%d: Include %q: %v", from, line, arg, err)
		return
	}
	matches, err := filepath.Glob(p)
	if err != nil {
		g.problem(from, line, "%s:%d: Include %q is not a pattern the agent reads: %v", from, line, arg, err)
		return
	}
	for _, m := range matches {
		g.visit(m, depth, stack, from, line)
	}
}

// includePattern is the clean absolute path below root that an Include
// argument names, or why the agent does not read it. sshd prefixes an
// argument that starts with neither / nor ~ with /etc/ssh/ and passes it
// to glob(3) with no flags (servconf.c, checked in portable 9.2p1 and
// 10.2p1). glob(3) is not one implementation (portable OpenSSH builds its
// openbsd-compat glob or uses the libc one), and none of them is Go's
// filepath.Match: [!...] is a negation in glob(3) and a literal ! in Go,
// [^...] and [:class:] differ between them, ? matches a byte in one and a
// rune in the other, and \ escapes differ at the edges (PR #68 review fix
// round 2, P4). So the one wildcard read is *, which all of them and Go
// match alike, and only in the last component: a * in a directory
// component would make every directory it expands through one the agent
// must check (P9). Any other glob character, a * in a directory
// component and a ~ path (the agent does not resolve it) are refused.
func includePattern(root, arg string) (string, string) {
	switch {
	case arg == "":
		return "", "is empty (sshd refuses it)"
	case strings.HasPrefix(arg, "~"):
		return "", "starts with ~, which the agent does not resolve"
	case strings.ContainsAny(arg, `?[\`):
		return "", `holds ?, [ or \, which the agent does not expand as sshd's glob(3) does (only * is read)`
	case slices.Contains(strings.Split(arg, "/"), ".."):
		// The kernel resolves ".." after a symlink, Clean before it: a
		// root-owned link under /etc/ssh plus link/../x would make the
		// agent read another file than sshd (PR #68 carry-over).
		return "", "holds a .. component, which the agent does not resolve as the kernel does"
	}
	p := filepath.Clean(arg)
	if !strings.HasPrefix(arg, "/") {
		p = filepath.Join(root, "etc", "ssh", arg)
	}
	if strings.Contains(filepath.Dir(p), "*") {
		return "", "has a * in a directory component; the agent reads a * in the last component only"
	}
	return p, ""
}

// parseConfig tokenises every line of an sshd configuration file
// (sshdTokens); a line it cannot read is a sshd_config_unsafe finding.
func parseConfig(path string, b []byte) ([]configLine, []Finding) {
	var lines []configLine
	var bad []Finding
	for i, text := range strings.Split(string(b), "\n") {
		l, err := sshdTokens(text)
		if err != nil {
			bad = append(bad, configProblem(path, i+1, "%s:%d: %v (%q)", path, i+1, err, strings.TrimSpace(text)))
			continue
		}
		l.n = i + 1
		lines = append(lines, l)
	}
	return lines, bad
}

// sshdWhitespace is sshd's WHITESPACE (misc.h).
const sshdWhitespace = " \t\r\n"

// sshdTokens splits one configuration line as sshd does
// (process_server_config_line_depth in servconf.c, strdelim and
// argv_split in misc.c, checked in portable 9.2p1 and 10.2p1; PR #68
// review fix round 2, P3). Trailing whitespace is stripped. The keyword
// is the first token of strdelim, which removes one pair of double quotes
// and splits on whitespace or one "=" (a second strdelim when the line
// starts with whitespace); a keyword that is empty or starts with # makes
// the line a comment. The rest is split by argv_split: single or double
// quotes, the escapes \' \" \\ and (outside quotes) "\ ", and a # at the
// start of an argument ends the line. Where sshd would ignore the line
// or refuse it (a keyword's opening quote with no closing one, unbalanced
// quotes in the arguments), or the keyword still holds a quote, the agent
// cannot be sure what sshd does: an error, never a skipped line.
func sshdTokens(line string) (configLine, error) {
	l := configLine{text: strings.TrimSpace(line)}
	kw, rest, ok := strdelim(strings.TrimRight(line, sshdWhitespace+"\f"))
	if ok && kw == "" {
		kw, rest, ok = strdelim(rest)
	}
	switch {
	case !ok:
		return l, errors.New("a keyword with an opening quote and no closing one")
	case kw == "" || kw[0] == '#':
		return l, nil
	case strings.ContainsAny(kw, `"'`):
		return l, fmt.Errorf("the keyword %q holds a quote", kw)
	}
	args, err := argvSplit(rest)
	if err != nil {
		return l, err
	}
	l.keyword, l.rest, l.args = strings.ToLower(kw), rest, args
	return l, nil
}

// strdelim is sshd's strdelim (misc.c strdelim_internal with
// split_equals): the token at the start of s and the rest after its
// separator. ok is false where sshd's returns NULL: an opening double
// quote with no closing one.
func strdelim(s string) (tok, rest string, ok bool) {
	i := strings.IndexAny(s, sshdWhitespace+`"=`)
	if i < 0 {
		return s, "", true
	}
	if s[i] == '"' {
		s = s[:i] + s[i+1:]
		j := strings.IndexByte(s[i:], '"')
		if j < 0 {
			return "", "", false
		}
		return s[:i+j], strings.TrimLeft(s[i+j+1:], sshdWhitespace), true
	}
	equals := s[i] == '='
	tok, rest = s[:i], strings.TrimLeft(s[i+1:], sshdWhitespace)
	if !equals && strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], sshdWhitespace)
	}
	return tok, rest, true
}

// argvSplit is sshd's argv_split with terminate_on_comment (misc.c):
// unbalanced quotes are an error, as they are for sshd.
func argvSplit(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			continue
		}
		if s[i] == '#' {
			break
		}
		var arg strings.Builder
		var quote byte
	token:
		for ; i < len(s); i++ {
			c := s[i]
			switch {
			case c == '\\':
				if i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '"' || s[i+1] == '\\' || (quote == 0 && s[i+1] == ' ')) {
					i++
				}
				arg.WriteByte(s[i])
			case quote == 0 && (c == ' ' || c == '\t'):
				break token
			case quote == 0 && (c == '"' || c == '\''):
				quote = c
			case quote != 0 && c == quote:
				quote = 0
			default:
				arg.WriteByte(c)
			}
		}
		if quote != 0 {
			return nil, errors.New("an argument with unbalanced quotes (sshd refuses the line)")
		}
		out = append(out, arg.String())
	}
	return out, nil
}

// trustedDir checks that the directory dir (inside root) resolves only
// through entries resolveTrusted accepts: no other user can add a file
// a glob in it would match. A missing directory is its error.
func trustedDir(root, dir string) error {
	resolved, st, err := resolveTrusted(root, dir)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafeFile, resolved)
	}
	return nil
}
