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

// The refusals of the check right before the narrowing's rename (03-12d,
// NP-20).
var (
	errNarrowFileChanged  = errors.New("the file changed while it was read")
	errNarrowStateChanged = errors.New("another run recorded a newer host trust state meanwhile")
)

// narrowHostTrust removes from the managed keyroster_known_hosts the CA
// lines of host CAs that b no longer trusts at now (03-12d). It reads the
// file and the state and writes only the file, never the state, the KRL
// or the ssh config, and never creates the file (NP-16). Doubt narrows
// nothing and prints one warning line on stderr; it never fails the
// command. The order matters:
//   - ~/.ssh: no home directory is silent; a $HOME that is not the
//     account's home warns (NP-26), because ssh reads the file from the
//     account's home and the narrowing cannot reach it; a failed account
//     lookup uses the directory it carries;
//   - the file: absent is silent; anything but a regular file (a symlink
//     is never read through, NP-17) or a file over maxNarrowFile (NP-18)
//     warns;
//   - the bundle's trusted host CA keys must all parse, since a skipped
//     key would narrow more than the bundle says (NP-21);
//   - the filter; when it would remove nothing the command stays silent,
//     whatever the state says (NP-27);
//   - only then the state, read and never written: it must exist and be
//     whole (NP-15), belong to the bundle's installation (NP-14), and the
//     bundle must not be older than its bundle_version (NP-11) nor, at an
//     equal version, name another ops key (NP-12). These mirror the
//     writer's own refusals (writeHostTrust's trust bundle floor): any
//     bundle at or above the floor names every key the file holds, so it
//     removes a line only when it says the key is no longer trusted. The
//     writer warns about an older bundle at refresh, so a command with
//     nothing to narrow does not repeat it;
//   - the write is atomic, and its check, right before the rename,
//     refuses when the file no longer holds the bytes that were read or
//     the state is not the state that was read (NP-20), so a concurrent
//     refresh is never undone. A rename right after the check can still
//     land behind a concurrent run, as the writer's D-R1 says; the next
//     refresh rewrites every file.
func narrowHostTrust(b *trust.Bundle, now time.Time, stderr io.Writer) {
	sshDir, err := userSSHDir()
	var lw *homeLookupWarning
	if errors.As(err, &lw) {
		sshDir, err = lw.dir, nil
	}
	switch {
	case errors.Is(err, errNoHomeDir):
		return
	case err != nil:
		narrowWarn(stderr, "~/.ssh/"+hostTrustKnownHosts, err.Error())
		return
	}
	p := filepath.Join(sshDir, hostTrustKnownHosts)
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		narrowWarn(stderr, p, fmt.Sprintf("it cannot be read: %v", err))
		return
	case !fi.Mode().IsRegular():
		narrowWarn(stderr, p, "it is not a regular file")
		return
	}
	data, err := readNarrowFile(p, fi)
	switch {
	case errors.Is(err, errNarrowFileChanged):
		narrowWarn(stderr, p, err.Error())
		return
	case err != nil:
		narrowWarn(stderr, p, fmt.Sprintf("it cannot be read: %v", err))
		return
	case int64(len(data)) > maxNarrowFile:
		narrowWarn(stderr, p, fmt.Sprintf("it is larger than %d bytes", maxNarrowFile))
		return
	}
	var trusted []string
	for _, ca := range trust.TrustedCAs(b, trust.RoleHost, now) {
		if _, err := trust.ParseKey(ca.Key); err != nil {
			narrowWarn(stderr, p, "a trusted CA key of the bundle does not parse")
			return
		}
		trusted = append(trusted, ca.Key)
	}
	out, removed := narrowKnownHosts(data, trusted)
	if removed == 0 {
		return
	}
	statePath, err := hostTrustStatePath()
	if err != nil {
		narrowWarn(stderr, p, fmt.Sprintf("the host trust state is damaged (%v)", err))
		return
	}
	stateBytes, st, err := readHostTrustStateBytes(statePath)
	switch {
	case err != nil:
		narrowWarn(stderr, p, fmt.Sprintf("the host trust state is damaged (%s)", strings.TrimPrefix(err.Error(), errStateCorrupt.Error()+": ")))
		return
	case st == nil:
		narrowWarn(stderr, p, "the host trust state is missing")
		return
	case st.InstallationID != b.InstallationID:
		narrowWarn(stderr, p, fmt.Sprintf("the host trust state belongs to installation %s, not to %s", st.InstallationID, b.InstallationID))
		return
	case b.Version < st.BundleVersion:
		narrowWarn(stderr, p, fmt.Sprintf("the server serves trust bundle version %d, older than version %d, which this client verified before", b.Version, st.BundleVersion))
		return
	case b.Version == st.BundleVersion && b.OpsKey.Key != st.OpsKey:
		narrowWarn(stderr, p, fmt.Sprintf("trust bundle version %d names another ops key than the version this client verified before", b.Version))
		return
	}
	if narrowHook != nil {
		narrowHook()
	}
	check := func() error {
		cur, err := os.Lstat(p)
		if err != nil || !cur.Mode().IsRegular() {
			return errNarrowFileChanged
		}
		if got, err := readNarrowFile(p, cur); err != nil || !bytes.Equal(got, data) {
			return errNarrowFileChanged
		}
		if got, _, err := readHostTrustStateBytes(statePath); err != nil || !bytes.Equal(got, stateBytes) {
			return errNarrowStateChanged
		}
		return nil
	}
	err = narrowReplace(sshDir, hostTrustKnownHosts, out, 0o644, check)
	switch {
	case errors.Is(err, errNarrowFileChanged), errors.Is(err, errNarrowStateChanged):
		narrowWarn(stderr, p, err.Error())
	case err != nil:
		narrowWarn(stderr, p, fmt.Sprintf("writing it failed: %v", err))
	default:
		_, _ = fmt.Fprintf(stderr, "Host trust narrowed: removed %d CA line(s) of host CAs the trust bundle no longer trusts from %s.\n", removed, p)
	}
}

// readNarrowFile reads at most maxNarrowFile plus one byte of the regular
// file p that Lstat described as fi (03-12d). A file that is no longer the
// one fi describes (a link or another file swapped in) is
// errNarrowFileChanged.
func readNarrowFile(p string, fi fs.FileInfo) ([]byte, error) {
	fh, err := os.Open(p) //nolint:gosec // G304: the managed file
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	if cur, err := fh.Stat(); err != nil || !os.SameFile(cur, fi) {
		return nil, errNarrowFileChanged
	}
	return io.ReadAll(io.LimitReader(fh, maxNarrowFile+1))
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
