//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// behindFile is the since record of bundle_behind in the applier's state
// directory (03-12c): the bundle version the accepted KRL manifest names
// and the first time it named one above the accepted bundle. The heartbeat's
// previous status cannot carry it, because the field is omitted during the
// grace.
const behindFile = "bundle-behind.json"

// maxBehindFile bounds the since record: 4 KiB.
const maxBehindFile = 4 << 10

// bundleBehindGrace is how long the accepted manifest may name a newer
// bundle before the host reports bundle_behind (owner decision, 2026-11-14).
// It is meant to cover one KRL republish period, the fetch poll and the
// applier's retry; that fit is not verified in a fleet.
const bundleBehindGrace = 2 * time.Hour

// behindDoc is the since record's document, strict canonical JSON.
type behindDoc struct {
	ManifestBundleVersion uint64 `json:"manifest_bundle_version"`
	Since                 string `json:"since"`
}

// bundleBehind is the heartbeat's bundle_behind for the accepted state st
// at now (03-12c): set once the KRL manifest st holds (signed by the ops
// key and accepted with its KRL) has named a bundle version above the
// accepted bundle's for bundleBehindGrace, nil otherwise. It is detection,
// not enforcement: the old key stays trusted while the host is behind.
//
// With write (a status build, under the apply lock) it keeps the since
// record: written when the manifest first names a newer bundle, rewritten
// with the same since when a still newer version is named, and removed once
// the manifest names no version above the accepted one. Without write (a
// check) it only reads. A missing or unreadable record counts as absent and
// only restarts the grace; it never fails the status.
func (e *engine) bundleBehind(st *state.Stored, now time.Time, write bool) *heartbeat.BundleBehind {
	var named uint64
	if st != nil && st.BundleVersion != 0 && len(st.KRLManifest) > 0 {
		if m, err := krl.ParseManifest(st.KRLManifest); err == nil {
			named = m.BundleVersion
		}
	}
	if st == nil || named <= st.BundleVersion {
		if write {
			if err := e.remove(e.l.State(behindFile)); err != nil {
				e.logf("WARNING %s: %v", behindFile, err)
			}
		}
		return nil
	}
	since := now.UTC().Truncate(time.Second)
	rec, _ := e.readBehind()
	if rec != nil {
		since, _ = time.Parse(time.RFC3339, rec.Since) // checked by readBehind
	}
	if write && (rec == nil || rec.ManifestBundleVersion != named) {
		if err := e.writeBehind(behindDoc{ManifestBundleVersion: named, Since: since.UTC().Format(trust.TimeFormat)}); err != nil {
			e.logf("WARNING %s: %v", behindFile, err)
		}
	}
	if now.Sub(since) < bundleBehindGrace {
		return nil
	}
	return &heartbeat.BundleBehind{ManifestBundleVersion: named, AcceptedVersion: st.BundleVersion,
		Since: since.UTC().Format(trust.TimeFormat), Reason: e.behindReason(st, named)}
}

// behindReason says, from persisted facts only, why bundle version named is
// not in force: unapplied when the unapplied record's state reaches it (it
// verified and cannot be applied); else, with a spool configured,
// not_accepted when the spool holds its complete document set
// (bundle-<N>.json and bundle-<N>.json.sigs: delivered, and this build did
// not accept it, a refused or held bundle, an older build refusing a draining
// entry included) and not_delivered when it does not; unknown when no spool
// is configured or it cannot be listed (the check command).
func (e *engine) behindReason(st *state.Stored, named uint64) string {
	if base, _, err := loadUnapplied(e.l, st); err == nil && base != nil && base.BundleVersion >= named {
		return "unapplied"
	}
	if e.cfg.Spool == "" {
		return "unknown"
	}
	fd, err := spool.OpenDir(e.cfg.Spool)
	if err != nil {
		return "unknown"
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := spool.ListDir(fd)
	if err != nil {
		return "unknown"
	}
	doc := "bundle-" + strconv.FormatUint(named, 10) + ".json"
	if slices.Contains(names, doc) && slices.Contains(names, doc+".sigs") {
		return "not_accepted"
	}
	return "not_delivered"
}

// readBehind reads the since record without following a symlink
// (spool.ReadFileAtInfo): nil, nil when it is missing; an error when it
// does not read, is not a 0600 regular file of the effective uid, is above
// 4 KiB, is not strict canonical JSON, names no version or holds a since
// that is not in trust's timestamp format.
func (e *engine) readBehind() (*behindDoc, error) {
	if e.stateFd < 0 {
		return nil, errors.New("the state directory is not open")
	}
	b, info, err := spool.ReadFileAtInfo(e.stateFd, behindFile, maxBehindFile)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case err != nil:
		return nil, err
	case info.Mode != 0o600 || int(info.UID) != os.Geteuid():
		return nil, fmt.Errorf("not a 0600 file of uid %d", os.Geteuid())
	}
	var r behindDoc
	if err := trust.DecodeStrict(b, &r); err != nil {
		return nil, err
	}
	if r.ManifestBundleVersion < 1 || trust.CheckTimestamp(r.Since) != nil {
		return nil, fmt.Errorf("manifest_bundle_version %d, since %q", r.ManifestBundleVersion, r.Since)
	}
	return &r, nil
}

// writeBehind writes the since record through e.writeState (atomic,
// fsynced, mode 0600).
func (e *engine) writeBehind(r behindDoc) error {
	b, err := trust.CanonicalJSON(r)
	if err != nil {
		return err
	}
	return e.writeState(behindFile, b)
}
