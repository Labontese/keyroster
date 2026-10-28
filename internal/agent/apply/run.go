//go:build linux

package apply

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/spool"
)

// DefaultInterval is how often keyroster-agent run looks at the spool, and
// DefaultRetry how long it waits before an apply that failed runs again
// on an unchanged spool.
const (
	DefaultInterval = 5 * time.Second
	DefaultRetry    = 60 * time.Second
)

// RunConfig is keyroster-agent run: Config for each apply (AllowAdoption
// is never set here, D-08: a Phase 2 takeover is a hand-run apply --once),
// the loop interval and the retry delay, and Out, where each apply that
// was not a no-op writes its report as one JSON line.
type RunConfig struct {
	Config
	Interval time.Duration
	Retry    time.Duration
	Out      func(r *Report, err error)
}

// Run is the applier's loop (03-07), until ctx ends. Each round:
//  1. the state directory, accepted/ and the outbox must be the applier's
//     own (CheckStateDirs, state_dir_unsafe); a round that fails it does
//     nothing else;
//  2. an enrollment request in the spool is answered (Enroll);
//  3. Apply runs when the spool holds documents and their names changed
//     since the last apply (a new version arrived), on the first round
//     (crash recovery), and again Retry after an apply that failed. While
//     an apply leaves newer versions in the spool than its capture read
//     (Report.SpoolMore) and moved forward, it runs again at once, at most
//     maxCatchUpApplies times a round (PR #71 review F9).
//
// Before approval the spool holds no document, so a round reads only its
// listing: it writes nothing and logs nothing. Errors are logged to
// cfg.Log and never end the loop.
func Run(ctx context.Context, rc RunConfig, l Layout) error {
	if rc.Interval <= 0 {
		rc.Interval = DefaultInterval
	}
	if rc.Retry <= 0 {
		rc.Retry = DefaultRetry
	}
	rc.AllowAdoption = false
	logf := func(format string, args ...any) {
		if rc.Log != nil {
			_, _ = fmt.Fprintf(rc.Log, "keyroster-agent run: "+format+"\n", args...)
		}
	}
	var (
		lastNames  string
		haveNames  bool
		catchUp    bool
		failedAt   time.Time
		lastErrMsg string
	)
	for {
		if err := CheckStateDirs(l); err != nil {
			if msg := err.Error(); msg != lastErrMsg {
				logf("ERROR %v", err)
				lastErrMsg = msg
			}
		} else {
			lastErrMsg = ""
			if wrote, err := Enroll(ctx, rc.Config, l); err != nil {
				logf("ERROR enrollment: %v", err)
			} else if wrote {
				logf("answered the fetcher's enrollment request (%s)", l.Outbox()+"/"+EnrollPoPFile)
			}
			names, err := spoolDocuments(rc.Spool)
			switch {
			case err != nil:
				logf("ERROR spool: %v", err)
			case names != "" && (!haveNames || names != lastNames || catchUp || (!failedAt.IsZero() && time.Since(failedAt) >= rc.Retry)):
				catchUp = false
				var prev *Report
				for i := 0; ; i++ {
					r, err := Apply(ctx, rc.Config, l)
					if rc.Out != nil && (err != nil || !r.NoOp) {
						rc.Out(r, err)
					}
					failedAt = time.Time{}
					if err != nil {
						logf("ERROR apply: %v", err)
						failedAt = time.Now()
					}
					lastNames, haveNames = names, true
					// PR #71 review F9: a capture reads at most
					// spool.MaxVersionsPerKind versions above what was
					// accepted. While the spool holds more and the last
					// apply moved forward, apply again: up to
					// maxCatchUpApplies times now, the rest next round.
					if err != nil || !r.SpoolMore || !advanced(prev, r) {
						break
					}
					if i+1 == maxCatchUpApplies {
						catchUp = true
						break
					}
					logf("applied up to bundle %d and directory %d; the spool holds newer versions, applying again", r.BundleVersion, r.DirectoryVersion)
					prev = r
				}
			}
		}
		t := time.NewTimer(rc.Interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// maxCatchUpApplies bounds the applies of one round while the spool holds
// more versions than one capture reads (Report.SpoolMore).
const maxCatchUpApplies = 16

// advanced reports whether the apply that wrote r moved the accepted
// bundle or directory version past prev's (any apply does, with no prev).
func advanced(prev, r *Report) bool {
	return prev == nil || r.BundleVersion > prev.BundleVersion || r.DirectoryVersion > prev.DirectoryVersion
}

// spoolDocuments is the sorted list of document names in the spool (every
// name but the enrollment hand-over's and the writers' temporary files),
// joined: what decides whether a new version arrived.
func spoolDocuments(dir string) (string, error) {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return "", err
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := spool.ListDir(fd)
	if err != nil {
		return "", err
	}
	names = slices.DeleteFunc(names, func(n string) bool {
		return strings.HasPrefix(n, ".") || n == EnrollRequestFile || n == IdentityFile
	})
	return strings.Join(names, "\n"), nil
}
