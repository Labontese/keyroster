// machinehosttrust.go is keyroster machine renew's refresh of the host CA
// lines (03-12g, D-14, REVOKE-04, KEY-08): right after the trust bundle
// verifies, it adds to the managed keyroster_known_hosts the line of each
// active or next host CA the file lacks, over the host names the file's own
// lines of host CAs the bundle trusts already carry, and moves the bundle
// floor of host-trust.json to that bundle. It makes no request of its own.
//
// The step has three properties:
//   - it only appends lines in the writer's own form (hostCALine), whose
//     key and generation come only from the verified bundle and whose names
//     come only from the file's own lines; it never adds or changes a host
//     name, never adds a draining or retired host CA, and never creates
//     ~/.ssh or the file;
//   - it writes the state before the file, each atomically and only after
//     the check that what it read is unchanged, and never writes the KRL or
//     the ssh config;
//   - a failure prints one warning line on stderr and makes machine renew
//     exit 4 when the certificate is in place (machineHostTrustExit).

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
)

// machineHostTrustExit is the exit status of a machine renew whose
// certificate was written or is not due but whose host trust step failed
// (03-12g).
const machineHostTrustExit = 4

// machineTrustReplace is the step's one write function (03-12g); tests
// replace it with one that fails.
var machineTrustReplace = replaceManagedFile

// machineTrustHook, when set (tests only), runs after the step's reads and
// before its first write (03-12g).
var machineTrustHook func()

// addHostCALines is the line reader of the step (03-12g, T-03-465). data is
// split after each newline, as narrowKnownHosts splits it. A line is a CA
// line when its first field, the fields split on spaces and tabs after its
// \n and \r are cut, is @cert-authority in any case; it is a source line
// when it is a CA line with at least four fields whose fields three and
// four, joined by one space, are the key of an entry of trusted. Every
// source line must be byte for byte hostCALine of its names and that entry,
// with names that pass hostTrustName and are strictly increasing, and all
// source lines must carry the same names; anything else is an error, with
// nil out and added. With no source line, out is data and nothing is added.
// Otherwise added is every entry of issuing, in its order, whose key no
// source line carries, and out is data, a newline when data does not end
// in one, and the line of each added entry over the source lines' names.
func addHostCALines(data []byte, trusted, issuing []trust.CAEntry) (out []byte, added []trust.CAEntry, err error) {
	errForm := errors.New("a CA line of a host CA the trust bundle trusts is not in the form keyroster writes")
	names, have := "", map[string]bool{}
	for rest := data; len(rest) > 0; {
		end := bytes.IndexByte(rest, '\n') + 1
		if end == 0 {
			end = len(rest)
		}
		line := string(rest[:end])
		rest = rest[end:]
		s := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(f) < 4 || !strings.EqualFold(f[0], "@cert-authority") {
			continue
		}
		i := slices.IndexFunc(trusted, func(e trust.CAEntry) bool { return e.Key == f[2]+" "+f[3] })
		if i < 0 {
			continue
		}
		if line != hostCALine(f[1], trusted[i]) {
			return nil, nil, errForm
		}
		hosts := strings.Split(f[1], ",")
		for j, n := range hosts {
			if !hostTrustName(n) {
				return nil, nil, errForm
			}
			if j > 0 && hosts[j-1] >= n {
				return nil, nil, errForm
			}
		}
		if len(have) > 0 && f[1] != names {
			return nil, nil, errors.New("its CA lines of the host CAs the trust bundle trusts name different hosts")
		}
		names, have[trusted[i].Key] = f[1], true
	}
	if len(have) == 0 {
		return data, nil, nil
	}
	for _, e := range issuing {
		if !have[e.Key] {
			added = append(added, e)
		}
	}
	out = slices.Clone(data)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, e := range added {
		out = append(out, hostCALine(names, e)...)
	}
	return out, added, nil
}

// machineHostTrust is the host trust step of keyroster machine renew
// (03-12g), run once right after the trust bundle b verified, on the
// client's clock now. It returns nil, or an exitError of
// machineHostTrustExit after one warning line on stderr. In this order:
//   - ~/.ssh: a failed account lookup uses the directory it carries; no
//     $HOME, or a $HOME that is not the account's home, fails only when
//     the home the account database names, an absolute path, holds the
//     file in its .ssh, and is nil otherwise;
//   - the file: absent is nil; anything but a regular file, a file that
//     cannot be read or changed while it was read, or one over
//     maxNarrowFile fails;
//   - the host CAs of b (trusted at now, and issuing) must all parse, and
//     addHostCALines must accept the file;
//   - the state must exist, be whole and belong to b's installation, and b
//     must not be older than its bundle_version nor, at an equal version,
//     name another ops key; each fails whether or not a line is missing;
//   - when b is newer than the state's bundle_version, the state is written
//     with b's version and ops key, after the check that it still holds the
//     bytes that were read;
//   - when a line is missing, the file is written, after the check that it
//     still holds the bytes that were read and that the state holds the
//     bytes now on disk, and each added line prints one line on stderr.
//
// It never creates ~/.ssh or the file, never writes the KRL or the ssh
// config, never prints the Include advice and never writes to stdout.
func machineHostTrust(b *trust.Bundle, now time.Time, stderr io.Writer) error {
	fail := func(path, reason string) error {
		_, _ = fmt.Fprintf(stderr, "Warning: host trust not refreshed in %s: %s.\n", path, reason)
		return &exitError{code: machineHostTrustExit, err: errors.New("the machine certificate is in place, but host trust was not refreshed, as reported above")}
	}

	// 1. ~/.ssh.
	dir, err := userSSHDir()
	var lw *homeLookupWarning
	if errors.As(err, &lw) {
		dir, err = lw.dir, nil
	}
	if err != nil {
		// No $HOME, or a $HOME that is not the account's home: ssh reads
		// the account database's home, so the step looks there. A home
		// that is no absolute path is no home.
		home, herr := accountHome()
		if herr != nil || !filepath.IsAbs(home) {
			return nil
		}
		p := filepath.Join(home, ".ssh", hostTrustKnownHosts)
		if _, serr := os.Lstat(p); serr != nil {
			return nil
		}
		return fail(p, err.Error())
	}

	// 2. The file.
	p := filepath.Join(dir, hostTrustKnownHosts)
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fail(p, fmt.Sprintf("it cannot be read: %v", err))
	case !fi.Mode().IsRegular():
		return fail(p, "it is not a regular file")
	}
	data, err := readNarrowFile(p, fi)
	switch {
	case errors.Is(err, errNarrowFileChanged):
		return fail(p, err.Error())
	case err != nil:
		return fail(p, fmt.Sprintf("it cannot be read: %v", err))
	case int64(len(data)) > maxNarrowFile:
		return fail(p, fmt.Sprintf("it is larger than %d bytes", maxNarrowFile))
	}

	// 3. The host CAs of the verified bundle and the lines to add.
	trusted := trust.TrustedCAs(b, trust.RoleHost, now)
	issuing := trust.IssuingCAs(b, trust.RoleHost)
	for _, ca := range slices.Concat(trusted, issuing) {
		if _, err := trust.ParseKey(ca.Key); err != nil {
			return fail(p, "a CA key of the trust bundle does not parse")
		}
	}
	out, added, err := addHostCALines(data, trusted, issuing)
	if err != nil {
		return fail(p, err.Error())
	}

	// 4. The state, with the narrowing's reasons.
	statePath, err := hostTrustStatePath()
	if err != nil {
		return fail(p, fmt.Sprintf("the host trust state is damaged (%v)", err))
	}
	stateBytes, st, err := readHostTrustStateBytes(statePath)
	switch {
	case err != nil:
		return fail(p, fmt.Sprintf("the host trust state is damaged (%s)", strings.TrimPrefix(err.Error(), errStateCorrupt.Error()+": ")))
	case st == nil:
		return fail(p, "the host trust state is missing")
	case st.InstallationID != b.InstallationID:
		return fail(p, fmt.Sprintf("the host trust state belongs to installation %s, not to %s", st.InstallationID, b.InstallationID))
	case b.Version < st.BundleVersion:
		return fail(p, fmt.Sprintf("the server serves trust bundle version %d, older than version %d, which this client verified before", b.Version, st.BundleVersion))
	case b.Version == st.BundleVersion && b.OpsKey.Key != st.OpsKey:
		return fail(p, fmt.Sprintf("trust bundle version %d names another ops key than the version this client verified before", b.Version))
	}

	// 5. The tests' hook.
	if machineTrustHook != nil {
		machineTrustHook()
	}

	// 6. The bundle floor, before the file (T-03-467).
	onDisk := stateBytes
	if b.Version > st.BundleVersion {
		next := *st
		next.BundleVersion, next.OpsKey = b.Version, b.OpsKey.Key
		enc, err := next.encode()
		if err != nil {
			return fail(p, fmt.Sprintf("writing the host trust state failed: %v", err))
		}
		check := func() error {
			if got, _, err := readHostTrustStateBytes(statePath); err != nil || !bytes.Equal(got, stateBytes) {
				return errNarrowStateChanged
			}
			return nil
		}
		switch err := machineTrustReplace(filepath.Dir(statePath), hostTrustStateFile, enc, 0o600, check); {
		case errors.Is(err, errNarrowStateChanged):
			return fail(p, err.Error())
		case err != nil:
			return fail(p, fmt.Sprintf("writing the host trust state failed: %v", err))
		}
		onDisk = enc
	}

	// 7. The lines (T-03-471: the check right before the rename).
	if len(added) == 0 {
		return nil
	}
	check := func() error {
		cur, err := os.Lstat(p)
		if err != nil || !cur.Mode().IsRegular() {
			return errNarrowFileChanged
		}
		if got, err := readNarrowFile(p, cur); err != nil || !bytes.Equal(got, data) {
			return errNarrowFileChanged
		}
		if got, _, err := readHostTrustStateBytes(statePath); err != nil || !bytes.Equal(got, onDisk) {
			return errNarrowStateChanged
		}
		return nil
	}
	switch err := machineTrustReplace(dir, hostTrustKnownHosts, out, 0o644, check); {
	case errors.Is(err, errNarrowFileChanged), errors.Is(err, errNarrowStateChanged):
		return fail(p, err.Error())
	case err != nil:
		return fail(p, fmt.Sprintf("writing it failed: %v", err))
	}
	// The names the added lines cover: those of out's last line, an added
	// one.
	last := strings.TrimSuffix(string(out), "\n")
	n := strings.Count(strings.Fields(last[strings.LastIndexByte(last, '\n')+1:])[1], ",") + 1
	for _, e := range added {
		_, _ = fmt.Fprintf(stderr, "Host trust: added the CA line of host CA generation %d to %s for the %d host name(s) its lines already trust.\n", e.Generation, p, n)
	}
	return nil
}
