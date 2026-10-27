//go:build linux

package apply

import (
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

// configFile is one sshd configuration file the walk read.
type configFile struct {
	path string
	data []byte
}

// configGraph reads the sshd configuration the way sshd reads it (PR #68
// review D-R3, the owner's "whole Include graph + command"): config, and
// every file an Include line names, recursively, wherever the line is
// (inside a Match block too), with glob expansion and sshd's rule that a
// relative path is relative to /etc/ssh (below the layout's root). A path
// that matches nothing is skipped, as sshd does. Every file is read with
// readTrusted, and the directory of each Include pattern must be one no
// other user can write (a file added there later would be read); one that
// is not, a ~ path, a cycle, nesting past maxIncludeDepth or more than
// maxConfigVisits files is a sshd_config_unsafe finding. Go's glob also
// matches dot files that sshd's glob(3) skips: more is read, never less.
// Each file is returned once, in the order first read.
func configGraph(l Layout, config string) ([]configFile, []Finding) {
	g := &graph{l: l, seen: map[string]bool{}}
	g.visit(config, 0, nil, "", 0)
	return g.files, g.problems
}

type graph struct {
	l        Layout
	files    []configFile
	problems []Finding
	seen     map[string]bool
	visits   int
}

func (g *graph) problem(file string, line int, format string, args ...any) {
	g.problems = append(g.problems, Finding{Code: CodeConfigUnsafe, File: file, Line: line,
		Message: fmt.Sprintf(format, args...) + "; the agent cannot rule out a trust setting in what sshd reads",
		Fix:     "make every file sshd reads, and every directory an Include names, owned by root and writable by no one else, with no symlink another user controls, and keep the Include nesting within sshd's 16 levels; see host-setup.md \"Before the agent: preflight\""})
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
	b, err := readTrusted(g.l.Root, path, 1<<20)
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
	if !g.seen[path] {
		g.seen[path] = true
		g.files = append(g.files, configFile{path: path, data: b})
	}
	stack = append(stack, path)
	for i, text := range strings.Split(string(b), "\n") {
		k, rest := configKeyword(text)
		if k != "include" {
			continue
		}
		args, ok := configArgs(rest)
		if !ok {
			g.problem(path, i+1, "%s:%d: an Include line the agent does not parse (%q)", path, i+1, strings.TrimSpace(text))
			continue
		}
		for _, a := range args {
			g.include(path, i+1, a, depth+1, stack)
		}
	}
}

// include walks one Include argument of from:line.
func (g *graph) include(from string, line int, arg string, depth int, stack []string) {
	if strings.HasPrefix(arg, "~") {
		g.problem(from, line, "%s:%d: Include %q starts with ~, which the agent does not resolve", from, line, arg)
		return
	}
	p := arg
	if !filepath.IsAbs(p) {
		p = filepath.Join(g.l.Root, "etc", "ssh", p)
	}
	p = filepath.Clean(p)
	if dir := filepath.Dir(p); !hasGlobMeta(dir) {
		err := trustedDir(g.l.Root, dir)
		if errors.Is(err, unix.ENOENT) {
			return // nothing can match
		}
		if err != nil {
			g.problem(from, line, "%s:%d: Include %q: %v", from, line, arg, err)
			return
		}
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

// hasGlobMeta reports whether p holds a glob metacharacter.
func hasGlobMeta(p string) bool { return strings.ContainsAny(p, `*?[\`) }

// configKeyword splits an sshd configuration line into its lowercase
// keyword and the rest, after the separating whitespace or "=" (sshd's
// strdelim); a blank line or a # comment has no keyword.
func configKeyword(line string) (string, string) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", ""
	}
	i := strings.IndexAny(t, " \t=")
	if i < 0 {
		return strings.ToLower(t), ""
	}
	rest := strings.TrimLeft(t[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	return strings.ToLower(t[:i]), rest
}

// configArgs splits the arguments of a configuration line on whitespace,
// joining a double-quoted argument (sshd's argv_split); a backslash or an
// unbalanced quote is not parsed.
func configArgs(s string) ([]string, bool) {
	var out []string
	var cur strings.Builder
	quoted, have := false, false
	for _, r := range s {
		switch {
		case r == '\\':
			return nil, false
		case r == '"':
			quoted, have = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if quoted {
		return nil, false
	}
	if have {
		out = append(out, cur.String())
	}
	return out, true
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
