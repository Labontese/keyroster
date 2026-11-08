//go:build linux

package apply

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/agent/spool"
)

// DefaultInterval is how often keyroster-agent run looks at the spool, and
// DefaultRetry how long it waits before an apply that failed runs again
// on an unchanged spool. DefaultCheckEvery and DefaultCheckJitter are the
// drift check's period and its uniform jitter either way (AGENT-05: every
// 15 min +- 60 s, and after every apply).
const (
	DefaultInterval    = 5 * time.Second
	DefaultRetry       = 60 * time.Second
	DefaultCheckEvery  = 15 * time.Minute
	DefaultCheckJitter = 60 * time.Second
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
	// CheckEvery and CheckJitter are the drift check's period and jitter
	// (DefaultCheckEvery, DefaultCheckJitter when 0; tests shorten them).
	CheckEvery, CheckJitter time.Duration
	// Status, when set, receives every status Run writes (tests).
	Status func(s *heartbeat.Status)
	// HostCerts, when set, is called before every HostCerts run, and
	// Iteration at the end of every loop iteration (tests count them,
	// 03-09).
	HostCerts func()
	// ProbeCerts, when set, is called before every ProbeCerts run (03-10b).
	ProbeCerts func()
	Iteration  func()
}

// Run is the applier's loop (03-07), until ctx ends. Each round:
//
//  1. the state directory, accepted/ and the outbox must be the applier's
//     own (CheckStateDirs, state_dir_unsafe); a round that fails it does
//     nothing else;
//
//  2. an enrollment request in the spool is answered (Enroll);
//
//  3. Apply runs when the spool holds documents and their names changed
//     since the last apply (a new version arrived), on the first round
//     (crash recovery), and again Retry after an apply that failed. While
//     an apply leaves newer versions in the spool than its capture read
//     (Report.SpoolMore) and moved forward, it runs again at once, at most
//     maxCatchUpApplies times a round (PR #71 review F9).
//
//  4. the drift check (Check, AGENT-05) runs after every round that
//     applied, and every CheckEvery +- CheckJitter, in this goroutine, so
//     a check and an apply never overlap within run. Each check writes
//     the status (WriteStatus) with its result, a failed one with its
//     error (last_check.error, PR #72 review C16), and logs D-10's error
//     line when the KRL in force is 24 h old or older (LogKRLAge). An
//     apply writes the status itself (Apply). The first round writes the
//     status too, so an enrolled host that never applied reports
//     generation 0.
//
//  5. the host-certificate step (HostCerts, 03-09) runs after the apply
//     round when it is due: an Apply ran this round, the spool's host
//     certificate answers changed (by name, size and modification time),
//     the check ran, or the earliest time HostCerts returned has passed;
//     and once at start. Its error is logged as a host-certificate error,
//     never as an apply error.
//
//  6. the probe-certificate step (ProbeCerts, 03-10b) runs after it under
//     the same rule with its own trigger: the spool's probe answers (the
//     probecert- prefix, no spool document) and its own due time. Its error
//     is logged as a probe-certificate error, never as an apply error.
//
// Before approval the spool holds no document, so a round reads only its
// listing and writes nothing but the status at start. Errors are logged
// to cfg.Log and never end the loop.
func Run(ctx context.Context, rc RunConfig, l Layout) error {
	if rc.Interval <= 0 {
		rc.Interval = DefaultInterval
	}
	if rc.Retry <= 0 {
		rc.Retry = DefaultRetry
	}
	if rc.CheckEvery <= 0 {
		rc.CheckEvery = DefaultCheckEvery
	}
	if rc.CheckJitter < 0 || rc.CheckJitter >= rc.CheckEvery {
		rc.CheckJitter = 0
	} else if rc.CheckJitter == 0 && rc.CheckEvery == DefaultCheckEvery {
		rc.CheckJitter = DefaultCheckJitter
	}
	if rc.Clock == nil {
		rc.Clock = SystemClock{}
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
		started    bool
		nextCheck  time.Time
		lastStatus string
		// The host-certificate step's trigger (03-09).
		hostDue     time.Time
		hostAnswers string
		hostStarted bool
		// The probe certificate step's trigger (03-10b).
		probeDue     time.Time
		probeAnswers string
		probeStarted bool
	)
	status := func(u StatusUpdate) {
		s, err := WriteStatus(ctx, rc.Config, l, u)
		switch {
		case err != nil:
			if msg := err.Error(); msg != lastStatus {
				logf("ERROR status: %v", err)
				lastStatus = msg
			}
		case s != nil:
			lastStatus = ""
			if u.Checked {
				LogKRLAge(rc.Config, s)
			}
			if rc.Status != nil {
				rc.Status(s)
			}
		}
	}
	hostCerts := func() {
		if rc.HostCerts != nil {
			rc.HostCerts()
		}
		r, err := HostCerts(ctx, rc.Config, l)
		hostDue = time.Time{}
		if r != nil {
			hostDue = r.Due
		}
		if err != nil {
			logf("ERROR host certificates: %v", err)
			// Try again after the shortest back-off.
			hostDue = rc.Clock.Now().Add(time.Minute)
		}
	}
	probeCerts := func() {
		if rc.ProbeCerts != nil {
			rc.ProbeCerts()
		}
		r, err := ProbeCerts(ctx, rc.Config, l)
		probeDue = time.Time{}
		if r != nil {
			probeDue = r.Due
		}
		if err != nil {
			logf("ERROR probe certificates: %v", err)
			probeDue = rc.Clock.Now().Add(time.Minute)
		}
	}
	check := func() {
		nextCheck = rc.Clock.Now().Add(jitter(rc.CheckEvery, rc.CheckJitter))
		d, err := Check(ctx, rc.Config, l)
		switch {
		case errors.Is(err, ErrNotInstalled):
			return
		case err != nil:
			// The status says the check failed (for example sshd -T
			// refuses a broken sshd_config), instead of keeping the last
			// healthy one; the KRL's age is still logged (PR #72 review
			// C16).
			logf("ERROR drift check: %v", err)
			status(StatusUpdate{Checked: true, CheckErr: err})
			return
		case d.Drift():
			logf("ERROR drift: generation %d: %d setting, %d file and %d foreign findings (keyroster-agent check prints them)", d.Generation, len(d.Settings), len(d.Files), len(d.Foreign))
		}
		status(StatusUpdate{Checked: true, Drift: d})
	}
	for {
		if err := CheckStateDirs(l); err != nil {
			if msg := err.Error(); msg != lastErrMsg {
				logf("ERROR %v", err)
				lastErrMsg = msg
			}
		} else {
			lastErrMsg = ""
			if !started {
				started = true
				status(StatusUpdate{})
				check()
			}
			if wrote, err := Enroll(ctx, rc.Config, l); err != nil {
				logf("ERROR enrollment: %v", err)
			} else if wrote {
				logf("answered the fetcher's enrollment request (%s)", l.Outbox()+"/"+EnrollPoPFile)
			}
			names, err := spoolDocuments(rc.Spool)
			applied, checked := false, false
			switch {
			case err != nil:
				logf("ERROR spool: %v", err)
			case names != "" && (!haveNames || names != lastNames || catchUp || (!failedAt.IsZero() && time.Since(failedAt) >= rc.Retry)):
				catchUp = false
				// A check after the round's applies, below.
				nextCheck = time.Time{}
				var prev *Report
				applied = true
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
			if !rc.Clock.Now().Before(nextCheck) {
				check()
				checked = true
			}
			answers := hostCertAnswers(rc.Spool)
			if !hostStarted || applied || checked || answers != hostAnswers || (!hostDue.IsZero() && !rc.Clock.Now().Before(hostDue)) {
				hostStarted, hostAnswers = true, answers
				hostCerts()
			}
			pAnswers := spoolAnswers(rc.Spool, probecert.SpoolPrefix)
			if !probeStarted || applied || checked || pAnswers != probeAnswers || (!probeDue.IsZero() && !rc.Clock.Now().Before(probeDue)) {
				probeStarted, probeAnswers = true, pAnswers
				probeCerts()
			}
		}
		if rc.Iteration != nil {
			rc.Iteration()
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

// jitter is every plus a uniform offset in [-j, +j] from crypto/rand (j
// when the random source fails).
func jitter(every, j time.Duration) time.Duration {
	if j <= 0 {
		return every
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return every + j
	}
	n := int64(binary.BigEndian.Uint64(b[:]) % uint64(2*j+1)) //nolint:gosec // G115: below 2*j+1, which fits an int64
	return every + time.Duration(n) - j
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
		return strings.HasPrefix(n, ".") || n == EnrollRequestFile || n == IdentityFile || strings.HasPrefix(n, hostCertPrefix) || strings.HasPrefix(n, probecert.SpoolPrefix)
	})
	return strings.Join(names, "\n"), nil
}

// hostCertPrefix starts the spool's host certificate answers (03-09),
// which are no documents.
const hostCertPrefix = "hostcert-"

// hostCertAnswers is the digest of the spool's host certificate answers:
// each name with its size and modification time, so an answer replaced
// under the same name changes it.
func hostCertAnswers(dir string) string { return spoolAnswers(dir, hostCertPrefix) }

// spoolAnswers is the digest of the spool's answers whose names start with
// prefix (the host certificate ones, 03-09, and the probe ones, 03-10b).
func spoolAnswers(dir, prefix string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, d := range ents {
		if !strings.HasPrefix(d.Name(), prefix) {
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		fmt.Fprintf(&b, "%s %d %d\n", d.Name(), info.Size(), info.ModTime().UnixNano())
	}
	return b.String()
}
