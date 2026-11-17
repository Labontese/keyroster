// narrow.go is the one caller of serverclient.Trust of the CLI and the
// narrowing of the managed known_hosts file (03-12d, D-14, T-03-430).
// Every command that verified a trust bundle with the saved pins goes
// through verifiedTrust, which narrows right after Trust, so no later
// early return of a command can skip it (the narrowing table of the
// 03-12d plan, rows NP-01 to NP-06).
//
// The narrowing has three properties:
//   - it is a filter: the file it writes holds a subsequence of the lines
//     it read, byte for byte, so it never adds a line or changes a name;
//   - it writes one file, keyroster_known_hosts, atomically, and never
//     the state, the KRL or the ssh config, and never moves a floor;
//   - doubt narrows nothing and says so on stderr; it never changes a
//     command's exit status or stdout.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// trustClock is the client's clock for every CA-set reader of the CLI
// (03-12d): the host CA lines of the managed known_hosts, host ca-key,
// init and host status. Tests replace it.
var trustClock = time.Now

// maxNarrowFile bounds the managed known_hosts file the narrowing reads
// (03-12d): five times the names bound of the state. Tests lower it.
var maxNarrowFile = int64(5 * maxHostTrustNames)

// narrowReplace is the narrowing's one write (03-12d); tests replace it
// with one that fails.
var narrowReplace = replaceManagedFile

// narrowHook, when set (tests only), runs between the narrowing's read of
// the file and its write, as hostTrustMergeHook does for the writer.
var narrowHook func()

// errNoHomeDir is the error, wrapped, of a ~/.ssh that cannot be resolved
// because there is no home directory (03-12d).
var errNoHomeDir = errors.New("no home directory")

// verifiedTrust is the one caller of serverclient.Trust of the CLI
// (03-12d, NP-05, NP-06): it calls Trust and, when Trust verified a
// bundle, narrows the managed known_hosts with it on the client's clock.
// It returns exactly what Trust returns, makes no request of its own and
// prints nothing on stdout.
func verifiedTrust(ctx context.Context, c *serverclient.Client, cfg *Config, stderr io.Writer) (*trust.Bundle, *trust.Policy, error) {
	b, pol, err := c.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold, cfg.InstallationID)
	if err == nil {
		narrowHostTrust(b, trustClock(), stderr)
	}
	return b, pol, err
}

// narrowHostTrust removes from the managed keyroster_known_hosts the CA
// lines of host CAs that b no longer trusts at now (03-12d). It never
// creates the file (NP-16), reads and writes nothing else, and reports
// only on stderr: one line when it narrowed, one warning when a write
// failed (NP-22). A ~/.ssh that cannot be resolved is silent, and a
// failed account lookup uses the directory it carries. The guards of the
// floor, the installation, the state and the file are not here yet.
func narrowHostTrust(b *trust.Bundle, now time.Time, stderr io.Writer) {
	sshDir, err := userSSHDir()
	var lw *homeLookupWarning
	if errors.As(err, &lw) {
		sshDir, err = lw.dir, nil
	}
	if err != nil {
		return
	}
	p := filepath.Join(sshDir, hostTrustKnownHosts)
	var trusted []string
	for _, ca := range trust.TrustedCAs(b, trust.RoleHost, now) {
		trusted = append(trusted, ca.Key)
	}
	data, err := os.ReadFile(p) //nolint:gosec // G304: the managed file
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		narrowWarn(stderr, p, fmt.Sprintf("it cannot be read: %v", err))
		return
	}
	out, removed := narrowKnownHosts(data, trusted)
	if removed == 0 {
		return
	}
	if err := replaceManagedFile(sshDir, hostTrustKnownHosts, out, 0o644, nil); err != nil {
		narrowWarn(stderr, p, fmt.Sprintf("writing it failed: %v", err))
		return
	}
	_, _ = fmt.Fprintf(stderr, "Host trust narrowed: removed %d CA line(s) of host CAs the trust bundle no longer trusts from %s.\n", removed, p)
}

// narrowWarn prints the one warning line of a narrowing that did not
// happen (03-12d).
func narrowWarn(stderr io.Writer, path, reason string) {
	_, _ = fmt.Fprintf(stderr, "Warning: host CA lines not narrowed in %s: %s.\n", path, reason)
}

// narrowKnownHosts is the line filter of the managed known_hosts file
// (03-12d, NP-19, NP-25): it returns data's lines minus the CA lines whose
// key is not in trusted, and the number removed. data is split after each
// newline, so every kept line keeps its own bytes (a CRLF, a missing final
// newline). A line whose first field, the fields split on spaces and tabs
// and leading blanks skipped, is @cert-authority without regard to case is
// a CA line (OpenSSH ends a marker at the first space or tab; a case
// variant is a line it refuses, so removing one is harmless). A CA line is
// kept only when it has at least four fields and fields three and four,
// joined by one space, are an entry of trusted: a malformed, foreign or
// untrusted CA line is removed. Every other line is kept untouched.
func narrowKnownHosts(data []byte, trusted []string) ([]byte, int) {
	out := make([]byte, 0, len(data))
	removed := 0
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n') + 1
		if end == 0 {
			end = len(data)
		}
		line := data[:end]
		data = data[end:]
		if untrustedCALine(line, trusted) {
			removed++
			continue
		}
		out = append(out, line...)
	}
	return out, removed
}

// untrustedCALine reports whether line is a CA line that narrowKnownHosts
// removes (03-12d).
func untrustedCALine(line []byte, trusted []string) bool {
	s := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
	if len(f) == 0 || !strings.EqualFold(f[0], "@cert-authority") {
		return false
	}
	return len(f) < 4 || !slices.Contains(trusted, f[2]+" "+f[3])
}
