package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// Client host trust (03-09b, REVOKE-04, D2): keyroster known-hosts sync
// (admins) and the keyroster login refresh (everyone) give one writer the
// raw bytes the server sent (the root-verified bundle and policy, the
// signed directory and the KRL). The writer verifies them itself and
// writes three files in ~/.ssh and a state file in the CLI's config
// directory:
//
//   - keyroster_known_hosts: one @cert-authority line per trusted host CA
//     over the principals of the active host entries;
//   - keyroster_revoked_hosts.krl: the verified KRL bytes;
//   - keyroster_ssh_config: one strict Host block over every name the
//     client ever saw, which trusts only keyroster_known_hosts and always
//     names the KRL as RevokedHostKeys.
//
// A name in the block without a CA line is refused, never prompted; a
// name outside the block keeps the user's own configuration.
func init() {
	register(command{
		Name: "known-hosts",
		Summary: "sync: refresh the CLI-managed host trust files in ~/.ssh (keyroster_known_hosts, keyroster_revoked_hosts.krl, " +
			"keyroster_ssh_config) from the admin-signed directory and the KRL; keyroster login refreshes them too",
		Run: runKnownHosts,
	})
}

// The managed files and their bounds.
const (
	hostTrustKnownHosts = "keyroster_known_hosts"
	hostTrustKRLFile    = "keyroster_revoked_hosts.krl"
	hostTrustSSHConfig  = "keyroster_ssh_config"
	hostTrustStateFile  = "host-trust.json"
	// maxHostTrustState bounds the state file read.
	maxHostTrustState = 5 << 20
	// maxHostTrustName is the longest name the writer emits (a DNS name).
	maxHostTrustName = 253
	// maxHostTrustOpsKey bounds the state's ops key text.
	maxHostTrustOpsKey = 256
	// hostTrustStale is the KRL manifest age that prints a warning.
	hostTrustStale = 24 * time.Hour
)

// hostTrustHeader is the first line of the two managed text files.
const hostTrustHeader = "# keyroster: managed file, rewritten by keyroster login and keyroster known-hosts sync. Do not edit.\n"

// hostTrustBlockOptions are the trust options of the managed Host block,
// in file order.
const hostTrustBlockOptions = "\tUserKnownHostsFile ~/.ssh/" + hostTrustKnownHosts + "\n" +
	"\tGlobalKnownHostsFile ~/.ssh/" + hostTrustKnownHosts + "\n" +
	"\tStrictHostKeyChecking yes\n" +
	"\tUpdateHostKeys no\n" +
	"\tVerifyHostKeyDNS no\n" +
	"\tRevokedHostKeys ~/.ssh/" + hostTrustKRLFile + "\n"

// userSSHDir returns ~/.ssh, the directory of the three managed files. It
// is the only place that directory is computed (03-09b); tests replace
// it, as they replace userConfigDir.
var userSSHDir = defaultSSHDir

// accountHome returns the running account's home from the account
// database (QB-5): ssh expands ~ from it, never from $HOME. It is os/user's
// LookupId, not Current, which without cgo falls back to $HOME.
var accountHome = func() (string, error) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// hostTrustFault, when set (tests only), is called with the step name
// (state, krl, known_hosts, config) after each step of a write; a non-nil
// error aborts the run there, as a crash would.
var hostTrustFault func(step string) error

// homeLookupWarning is a failed account lookup: the writer warns and
// writes, since the home check cannot be made.
type homeLookupWarning struct {
	dir string
	err error
}

func (w *homeLookupWarning) Error() string {
	return fmt.Sprintf("the account database names no home for this user (%v), so the check that $HOME is the home ssh reads was not made", w.err)
}

// defaultSSHDir returns $HOME/.ssh (the file's single os.UserHomeDir
// call). On every GOOS but windows it refuses a $HOME that is not the
// account's home (QB-5): ssh would read the files from the account's
// home, so files written under another $HOME protect nothing. A failed
// lookup returns the directory with a *homeLookupWarning.
func defaultSSHDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory: %w", err)
	}
	dir := filepath.Join(home, ".ssh")
	if runtime.GOOS == "windows" {
		return dir, nil
	}
	acct, err := accountHome()
	if err != nil {
		return dir, &homeLookupWarning{dir: dir, err: err}
	}
	if !sameDir(home, acct) {
		return "", fmt.Errorf("$HOME (%s) is not your account home (%s), which ssh reads", home, acct)
	}
	return dir, nil
}

// sameDir reports whether a and b name the same directory: equal after
// filepath.Clean, or the same file (a symlink to it).
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

// hostTrustName reports whether s may appear in a managed file: 1 to 253
// bytes of [a-z0-9.:-], not starting with '-'. It refuses every pattern
// byte ('*', '?', ',', '!'), every quote, space and control byte, and so
// independently of the directory's own grammar no name is ever a pattern
// (T-03-59).
func hostTrustName(s string) bool {
	if s == "" || len(s) > maxHostTrustName || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != ':' && c != '-' {
			return false
		}
	}
	return true
}

// hostTrustCAs returns the host CAs of b that clients trust: state active
// or next, sorted by generation and then key. Retired CAs are left out,
// narrower than the agent's krl.RoleCAKeys by design. 03-12 swaps in
// CAEntry.TrustedAt(now) here and nowhere else.
func hostTrustCAs(b *trust.Bundle, _ time.Time) []trust.CAEntry {
	var out []trust.CAEntry
	for _, ca := range b.CAs {
		if ca.Role == trust.RoleHost && (ca.State == "active" || ca.State == "next") {
			out = append(out, ca)
		}
	}
	slices.SortFunc(out, func(a, b trust.CAEntry) int {
		if a.Generation != b.Generation {
			if a.Generation < b.Generation {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

// hostTrustNames returns the sorted unique principals of d's active host
// entries and of all its host entries (any status). Principals are the
// names clients connect to; entry names are not used. A principal that
// fails hostTrustName is an error: the names are not refreshed.
func hostTrustNames(d *directory.Directory) (active, all []string, err error) {
	for _, h := range d.Hosts {
		for _, p := range h.Principals {
			if !hostTrustName(p) {
				return nil, nil, fmt.Errorf("directory version %d names host principal %s, which the host trust files never write", d.Version, strconv.QuoteToASCII(p))
			}
			all = append(all, p)
			if h.Status == directory.StatusActive {
				active = append(active, p)
			}
		}
	}
	slices.Sort(active)
	slices.Sort(all)
	return slices.Compact(active), slices.Compact(all), nil
}

// hostTrustState is host-trust.json: what this client last verified and
// wrote, the floors of the next run and every name it ever saw (sorted,
// unique, only growing). bundle_version and ops_key are the newest
// verified trust bundle's Version and OpsKey.Key.
type hostTrustState struct {
	Format           int      `json:"format"`
	InstallationID   string   `json:"installation_id"`
	BundleVersion    uint64   `json:"bundle_version"`
	OpsKey           string   `json:"ops_key"`
	DirectoryVersion uint64   `json:"directory_version"`
	DirectorySHA256  string   `json:"directory_sha256"`
	KRLVersion       uint64   `json:"krl_version"`
	Names            []string `json:"names"`
}

// errStateCorrupt is a state file this CLI cannot read.
var errStateCorrupt = errors.New("the host trust state is damaged")

// parseHostTrustState decodes a state strictly (trust.DecodeStrict:
// canonical bytes, no unknown field) and validates it.
func parseHostTrustState(data []byte) (*hostTrustState, error) {
	if len(data) > maxHostTrustState {
		return nil, fmt.Errorf("%w: %d bytes, above %d", errStateCorrupt, len(data), maxHostTrustState)
	}
	var st hostTrustState
	if err := trust.DecodeStrict(data, &st); err != nil {
		return nil, fmt.Errorf("%w: %w", errStateCorrupt, err)
	}
	if err := st.validate(); err != nil {
		return nil, err
	}
	return &st, nil
}

// validate checks a decoded state.
func (st *hostTrustState) validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errStateCorrupt, fmt.Sprintf(format, args...))
	}
	switch {
	case st.Format != 1:
		return bad("format %d", st.Format)
	case !trust.IsInstallationID(st.InstallationID):
		return bad("installation_id is not an installation ID")
	case st.BundleVersion < 1:
		return bad("bundle_version must be at least 1")
	case len(st.OpsKey) > maxHostTrustOpsKey:
		return bad("ops_key is longer than %d bytes", maxHostTrustOpsKey)
	case (st.DirectoryVersion == 0) != (st.DirectorySHA256 == ""):
		return bad("directory_version and directory_sha256 disagree")
	case st.DirectorySHA256 != "" && !isLowerHex64(st.DirectorySHA256):
		return bad("directory_sha256 is not 64 lowercase hex digits")
	case st.Names == nil:
		return bad("names must be an array")
	}
	if _, err := trust.ParseKey(st.OpsKey); err != nil {
		return bad("ops_key: %v", err)
	}
	for i, n := range st.Names {
		if !hostTrustName(n) {
			return bad("name %s", strconv.QuoteToASCII(n))
		}
		if i > 0 && st.Names[i-1] >= n {
			return bad("names are not sorted and unique")
		}
	}
	return nil
}

// isLowerHex64 reports whether s is 64 lowercase hex digits.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encode returns the state's canonical bytes.
func (st *hostTrustState) encode() ([]byte, error) {
	if st.Names == nil {
		st.Names = []string{}
	}
	return trust.CanonicalJSON(st)
}

// hostTrustStatePath returns <user config dir>/keyroster/host-trust.json.
func hostTrustStatePath() (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), hostTrustStateFile), nil
}

// readHostTrustState reads the state at path: nil and no error when
// there is none.
func readHostTrustState(path string) (*hostTrustState, error) {
	fh, err := os.Open(path) //nolint:gosec // G304: the CLI's own state file
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStateCorrupt, err)
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxHostTrustState+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errStateCorrupt, err)
	}
	return parseHostTrustState(data)
}

// hostTrustInput is what the writer verifies and writes from: the
// root-verified bundle and policy, the CAs to trust (hostTrustCAs; 03-12
// passes another set), the directory bytes and their signatures as the
// server sent them (nil: none), the KRL document (nil: none) and the
// time. DirMissing is the reason a missing directory is reported with.
type hostTrustInput struct {
	Bundle     *trust.Bundle
	Policy     *trust.Policy
	CAs        []trust.CAEntry
	Dir        []byte
	DirSigs    []byte
	KRL        *serverclient.KRLDocument
	Now        time.Time
	DirMissing string
}

// hostTrustResult is what a writer run did.
type hostTrustResult int

const (
	// hostTrustNone: nothing was written.
	hostTrustNone hostTrustResult = iota
	// hostTrustPartial: the KRL (and the state) only, or at the bound.
	hostTrustPartial
	// hostTrustFull: every file refreshed or already up to date.
	hostTrustFull
)

// parseHostTrustDirectory is directory.Parse; a test replaces it to feed
// the writer a document Parse would refuse.
var parseHostTrustDirectory = directory.Parse

// verifiedHostTrustDir is a directory the writer verified.
type verifiedHostTrustDir struct {
	dir         *directory.Directory
	sha         string
	active, all []string
}

// verifyHostTrustDirectory checks the directory of in against the
// root-verified policy (quorum), Parse, the strict installation rule
// (directory.CheckInstallation, not fetchVerifiedDirectory's lenient
// one) and the state's floor (an older version, or another SHA-256 at an
// equal version, is refused). It returns nil and the reason when the
// names cannot be refreshed.
func verifyHostTrustDirectory(in hostTrustInput, st *hostTrustState) (*verifiedHostTrustDir, string) {
	if len(in.Dir) == 0 || len(in.DirSigs) == 0 {
		if in.DirMissing == "" {
			return nil, "the server serves no directory"
		}
		return nil, in.DirMissing
	}
	if _, err := directory.VerifySignatures(in.Dir, in.DirSigs, in.Policy); err != nil {
		return nil, "the directory the server sent is not signed by the policy admins of your root-verified policy"
	}
	d, err := parseHostTrustDirectory(in.Dir)
	if err != nil {
		return nil, fmt.Sprintf("the directory the server sent is signed by the policy admins but does not validate here: %v", serverclient.PeerError(err))
	}
	if err := directory.CheckInstallation(d, in.Bundle.InstallationID); err != nil {
		return nil, fmt.Sprintf("directory version %d is bound to installation %s, not to %s, the installation of your root-verified trust bundle",
			d.Version, installationText(d.InstallationID), in.Bundle.InstallationID)
	}
	sha := trust.SHA256Hex(in.Dir)
	if st != nil {
		switch {
		case d.Version < st.DirectoryVersion:
			return nil, fmt.Sprintf("the server sent directory version %d, older than version %d this client already wrote", d.Version, st.DirectoryVersion)
		case d.Version == st.DirectoryVersion && sha != st.DirectorySHA256:
			return nil, fmt.Sprintf("the server sent directory version %d with another SHA-256 than the version %d this client already wrote", d.Version, d.Version)
		}
	}
	active, all, err := hostTrustNames(d)
	if err != nil {
		return nil, err.Error()
	}
	return &verifiedHostTrustDir{dir: d, sha: sha, active: active, all: all}, ""
}

// writeHostTrust is the one writer of the host trust files. It verifies
// everything first, then writes, in this order, the state, the KRL,
// keyroster_known_hosts and keyroster_ssh_config, each atomically, and
// prints its outcome line on stdout (warnings on stderr):
//
//   - the KRL is required: no document, a manifest that does not verify
//     under the bundle's ops key and installation ID with the floor
//     max(stored, 1) - 1 (an equal version passes, an older one does not),
//     or KRL bytes that do not parse strictly write nothing;
//   - a trust bundle older than the stored one freezes the CA lines and
//     the Host block, and its KRL is checked by the STORED ops key, never
//     the older bundle's; an equal one must carry the stored ops key;
//   - a directory that is missing, refused or older leaves the names
//     unrefreshed: with a state the state's KRL version and the KRL are
//     written (revocations only), without one nothing is.
func writeHostTrust(in hostTrustInput, stdout, stderr io.Writer) hostTrustResult {
	none := func(reason string) hostTrustResult {
		_, _ = fmt.Fprintf(stdout, "Host trust not refreshed: %s.\n", reason)
		return hostTrustNone
	}
	sshDir, err := userSSHDir()
	var lookup *homeLookupWarning
	switch {
	case errors.As(err, &lookup):
		_, _ = fmt.Fprintf(stderr, "Warning: %v.\n", lookup)
		sshDir = lookup.dir
	case err != nil:
		return none(err.Error())
	}
	statePath, err := hostTrustStatePath()
	if err != nil {
		return none(err.Error())
	}
	st, err := readHostTrustState(statePath)
	if err != nil {
		return none(fmt.Sprintf("%v (%s)", err, statePath))
	}
	b := in.Bundle
	if b == nil || b.InstallationID == "" {
		return none("the trust bundle in force has no installation ID, so no KRL can be verified")
	}

	// The trust bundle floor (T-03-347).
	krlBundle, older := b, false
	if st != nil {
		switch {
		case b.Version < st.BundleVersion:
			older = true
			kb := *b
			kb.OpsKey.Key = st.OpsKey
			krlBundle = &kb
			_, _ = fmt.Fprintf(stderr, "Warning: the server serves trust bundle version %d, older than version %d, which this client verified before "+
				"(a signer restore brings an older one back); the CA lines and the Host block are not refreshed, "+
				"and the KRL is checked with the ops key of version %d.\n", b.Version, st.BundleVersion, st.BundleVersion)
		case b.Version == st.BundleVersion && b.OpsKey.Key != st.OpsKey:
			return none(fmt.Sprintf("trust bundle version %d names another ops key than the version %d this client verified before", b.Version, b.Version))
		}
	}

	// The KRL, required.
	if in.KRL == nil {
		return none("the server serves no KRL")
	}
	var stored uint64
	if st != nil {
		stored = st.KRLVersion
	}
	m, err := krl.VerifyManifest(in.KRL.Manifest, in.KRL.Sig, in.KRL.KRL, krlBundle, b.InstallationID, max(stored, 1)-1)
	if err != nil {
		return none(fmt.Sprintf("the KRL the server serves does not verify against your root-pinned trust bundle: %v", serverclient.PeerError(err)))
	}
	if _, err := krl.Parse(in.KRL.KRL); err != nil {
		return none(fmt.Sprintf("the KRL the server serves (v%d) is signed but does not parse: %v", m.KRLVersion, err))
	}
	if issued, err := time.Parse(trust.TimeFormat, m.IssuedAt); err == nil && in.Now.Sub(issued) > hostTrustStale {
		_, _ = fmt.Fprintf(stderr, "Warning: the KRL the server serves (v%d) was issued at %s, %s ago; the server may be withholding newer revocations.\n",
			m.KRLVersion, m.IssuedAt, in.Now.Sub(issued).Round(time.Second))
	}

	// The directory, unless the bundle is older.
	var (
		vd     *verifiedHostTrustDir
		reason string
	)
	if older {
		reason = fmt.Sprintf("the server serves trust bundle version %d, older than version %d", b.Version, st.BundleVersion)
	} else {
		vd, reason = verifyHostTrustDirectory(in, st)
	}

	w := &hostTrustWriter{sshDir: sshDir, statePath: statePath}
	if vd == nil {
		// Revocations only, which needs a state to hold the floor.
		if st == nil {
			return none(reason)
		}
		next := *st
		next.KRLVersion = max(st.KRLVersion, m.KRLVersion)
		if err := w.write(&next, in.KRL.KRL, nil, nil); err != nil {
			return none(err.Error())
		}
		_, _ = fmt.Fprintf(stdout, "Host trust partly refreshed: revocations only (%s).\n", reason)
		return hostTrustPartial
	}

	next := &hostTrustState{Format: 1, InstallationID: b.InstallationID, BundleVersion: b.Version, OpsKey: b.OpsKey.Key,
		DirectoryVersion: vd.dir.Version, DirectorySHA256: vd.sha, KRLVersion: m.KRLVersion, Names: vd.all}
	if st != nil {
		// The merge: the names only grow, the versions never go down.
		next.Names = mergeNames(st.Names, vd.all)
		next.KRLVersion = max(st.KRLVersion, m.KRLVersion)
	}
	kh := knownHostsFile(in.CAs, vd.active, next)
	cfg := sshConfigFile(next.Names)
	if err := w.write(next, in.KRL.KRL, kh, cfg); err != nil {
		return none(err.Error())
	}
	_, _ = fmt.Fprintf(stdout, "Host trust refreshed (directory v%d, KRL v%d, %d names).\n", next.DirectoryVersion, next.KRLVersion, len(next.Names))
	return hostTrustFull
}

// mergeNames returns the sorted union of two sorted unique name lists.
func mergeNames(a, b []string) []string {
	out := append(append([]string{}, a...), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// knownHostsFile returns keyroster_known_hosts: the header, the
// informational version line and one @cert-authority line per CA, in the
// order given, over the active names (none when there are none).
func knownHostsFile(cas []trust.CAEntry, active []string, st *hostTrustState) []byte {
	var b strings.Builder
	b.WriteString(hostTrustHeader)
	fmt.Fprintf(&b, "# directory version %d (sha256 %s), trust bundle version %d, KRL version %d (informational; never read back)\n",
		st.DirectoryVersion, st.DirectorySHA256, st.BundleVersion, st.KRLVersion)
	if len(active) > 0 {
		names := strings.Join(active, ",")
		for _, ca := range cas {
			fmt.Fprintf(&b, "@cert-authority %s %s keyroster host CA generation %d\n", names, ca.Key, ca.Generation)
		}
	}
	return []byte(b.String())
}

// sshConfigFile returns keyroster_ssh_config: the header, the Include
// advice and, with any names, one Host block over all of them.
func sshConfigFile(names []string) []byte {
	var b strings.Builder
	b.WriteString(hostTrustHeader)
	b.WriteString("# Include it from ~/.ssh/config before the first Host or Match line.\n")
	if len(names) > 0 {
		b.WriteString("Host " + strings.Join(names, " ") + "\n")
		b.WriteString(hostTrustBlockOptions)
	}
	return []byte(b.String())
}

// hostTrustStep is one write of a run, by its name for hostTrustFault.
type hostTrustStep struct {
	name string
	do   func() error
}

// hostTrustWriter writes the state and the managed files.
type hostTrustWriter struct {
	sshDir, statePath string
}

// write writes the state, then the KRL, then (when non-nil) known-hosts
// and the config, calling hostTrustFault after each step. Unchanged
// bytes are not rewritten.
func (w *hostTrustWriter) write(st *hostTrustState, krlBytes, knownHosts, config []byte) error {
	state, err := st.encode()
	if err != nil {
		return err
	}
	writeState := func() error { return writeStateFile(w.statePath, state) }
	writeKRL := func() error { return w.managed(hostTrustKRLFile, krlBytes) }
	writeKnownHosts := func() error { return w.managed(hostTrustKnownHosts, knownHosts) }
	writeConfig := func() error { return w.managed(hostTrustSSHConfig, config) }
	steps := []hostTrustStep{{"state", writeState}, {"krl", writeKRL}}
	if knownHosts != nil {
		steps = append(steps, hostTrustStep{"known_hosts", writeKnownHosts}, hostTrustStep{"config", writeConfig})
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("writing the %s failed: %w; the next refresh starts over", s.name, err)
		}
		if hostTrustFault != nil {
			if err := hostTrustFault(s.name); err != nil {
				return err
			}
		}
	}
	return nil
}

// managed writes one managed file in ~/.ssh: ~/.ssh is created 0700 only
// when absent, the file goes through a temporary file in ~/.ssh, chmod
// 0644, fsync and rename (a symlink at the name is replaced, never
// followed), then the directory is fsynced (not on Windows).
func (w *hostTrustWriter) managed(name string, data []byte) error {
	if _, err := os.Lstat(w.sshDir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(w.sshDir, 0o700); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return replaceManagedFile(w.sshDir, name, data, 0o644)
}

// writeStateFile writes the state 0600 in its 0700 directory (saveConfig's
// pattern).
func writeStateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return replaceManagedFile(dir, filepath.Base(path), data, 0o600)
}

// replaceManagedFile atomically replaces dir/name with data at mode, unless it
// is a regular file that already holds exactly data.
func replaceManagedFile(dir, name string, data []byte, mode fs.FileMode) error {
	p := filepath.Join(dir, name)
	if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
		if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, data) { //nolint:gosec // G304: a managed file
			return nil
		}
	}
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir) //nolint:gosec // G304: the directory just written to
		if err != nil {
			return err
		}
		err = d.Sync()
		if cerr := d.Close(); err == nil {
			err = cerr
		}
		return err
	}
	return nil
}

// refreshHostTrust reads the KRL the server serves and hands it, with the
// directory the caller got (nil: none; missing names the reason), to
// writeHostTrust. known-hosts sync and keyroster login both call it.
func refreshHostTrust(ctx context.Context, c *serverclient.Client, b *trust.Bundle, pol *trust.Policy, dir, sigs []byte, missing string, stdout, stderr io.Writer) hostTrustResult {
	doc, err := c.GetKRL(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "Host trust not refreshed: the server's KRL could not be read: %v.\n", serverclient.PeerError(err))
		return hostTrustNone
	}
	now := time.Now()
	return writeHostTrust(hostTrustInput{Bundle: b, Policy: pol, CAs: hostTrustCAs(b, now), Dir: dir, DirSigs: sigs, KRL: doc, Now: now, DirMissing: missing}, stdout, stderr)
}

// runKnownHosts is keyroster known-hosts sync [--admin-key FP] (03-09b):
// the admin route of the installed directory and the KRL, verified and
// written by writeHostTrust. Exit 0 refreshed or unchanged, 3 partly
// refreshed, 1 nothing written.
func runKnownHosts(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "known-hosts: want a subcommand: sync")
		return errUsage
	}
	if args[0] != "sync" {
		_, _ = fmt.Fprintf(stderr, "known-hosts: unknown subcommand %q; want sync\n", args[0])
		return errUsage
	}
	fset := flag.NewFlagSet("known-hosts sync", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args[1:])
	if err != nil {
		return errUsage
	}
	if len(pos) != 0 {
		_, _ = fmt.Fprintln(stderr, "known-hosts sync: takes no arguments")
		return errUsage
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	bundle, pol, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return err
	}
	var ans serverclient.DirectoryAnswer
	if err := s.client.AdminJSON(ctx, http.MethodGet, serverclient.AdminDirectoryPath, nil, &ans, s.signer); err != nil {
		return adminError(err, s, pol)
	}
	var doc, sigs []byte
	if ans.Version > 0 {
		doc, sigs = ans.Directory, ans.Sigs
	}
	return hostTrustExit(refreshHostTrust(ctx, s.client, bundle, pol, doc, sigs, "the server serves no directory", stdout, stderr))
}

// hostTrustExit is known-hosts sync's exit for a writer result: nil (0)
// refreshed or unchanged, 3 partly refreshed, 1 nothing written.
func hostTrustExit(res hostTrustResult) error {
	switch res {
	case hostTrustFull:
		return nil
	case hostTrustPartial:
		return &exitError{code: 3, err: errors.New("host trust partly refreshed, as reported above")}
	default:
		return &exitError{code: 1, err: errors.New("host trust not refreshed, as reported above")}
	}
}
