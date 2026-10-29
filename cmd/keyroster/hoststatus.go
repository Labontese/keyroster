package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// statusFooter ends every keyroster host status table: convergence is the
// server's report of what each host said (T-03-51).
const statusFooter = "Reported by keyroster-server; run `keyroster-agent check` on a host to verify it there.\n"

// notYetPolled is how the CLI shows an agent the directory approves that
// has not polled since (03-08b owner decision D-R2).
const notYetPolled = "approved, not yet polled"

// recoveryCommand is what an operator runs on a host whose status says
// stuck: pending_state_unknown (03-05).
const recoveryCommand = "sudo keyroster-agent apply --once --recover-to-last-good"

// identityRotationShown is how long host status shows a host's identity
// rotation: an unexpected one means its identity key may be stolen
// (owner decision D-R1; docs/runbooks/host-setup.md "An unexpected
// identity rotation").
const identityRotationShown = 7 * 24 * time.Hour

// errBadHostsStatus refuses a hosts/status answer that does not check out;
// it never repeats the server's text.
var errBadHostsStatus = errors.New("the server's host status does not check out; refusing to show it")

// checkHostsStatus checks every row of the server's answer as the server
// checked the heartbeats before it stored them (heartbeat.ValidateHeartbeat),
// plus the names, identity, state and times: a compromised server or host
// can lie, but never put a byte outside printable ASCII on the admin's
// terminal (T-03-227).
func checkHostsStatus(a *serverclient.HostsStatusAnswer) error {
	for _, d := range [][2]any{{a.Current.Bundle, a.Current.BundleSHA256}, {a.Current.Directory, a.Current.DirectorySHA256}, {a.Current.KRL, a.Current.KRLSHA256}} {
		v, sum := d[0].(uint64), d[1].(string)
		if (v == 0) != (sum == "") || sum != "" && !enroll.IsSHA256Hex(sum) {
			return errBadHostsStatus
		}
	}
	for _, r := range a.Hosts {
		if !directory.ValidUserName(r.Name) || !directory.ValidUserName(r.ExpectedName) || !enroll.IsSHA256Hex(r.IdentitySPKISHA256) {
			return errBadHostsStatus
		}
		switch r.State {
		case serverclient.HostStateActive, serverclient.HostStateRemoved, serverclient.HostStateDisabled, serverclient.HostStateKeysChanged:
		default:
			return errBadHostsStatus
		}
		if r.IdentityRotations < 0 || (r.IdentityRotations == 0) != (r.IdentityRotatedAt == "") {
			return errBadHostsStatus
		}
		// Approved, not yet polled (03-08b owner decision D-R2): active in
		// the directory, and no heartbeat yet.
		if r.NotYetPolled && (r.State != serverclient.HostStateActive || r.Heartbeat != nil) {
			return errBadHostsStatus
		}
		for _, ts := range []string{r.LastSeen, r.ReceivedAt, r.IdentityRotatedAt} {
			if ts == "" {
				continue
			}
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				return errBadHostsStatus
			}
		}
		if r.ClockOffsetS > heartbeat.MaxClockOffset || r.ClockOffsetS < -heartbeat.MaxClockOffset {
			return errBadHostsStatus
		}
		if r.Heartbeat != nil {
			if err := heartbeat.ValidateHeartbeat(r.Heartbeat); err != nil {
				return fmt.Errorf("%w: host %s: %w", errBadHostsStatus, r.Name, err)
			}
		}
	}
	return nil
}

// safe is the CLI's second guard: every byte outside printable ASCII
// becomes '?' (the answer was checked already).
func safe(s string) string { return heartbeat.Sanitize(s, len(s)) }

// runHostStatus is keyroster host status [--json] [--admin-key FP]
// (03-08, AGENT-07): per host the directory approved once, when it was
// last seen and how old its stored status is (with status_stale), the
// bundle, directory and KRL versions it applied against the
// current ones, drift, its last apply with detail, a swap in progress, the
// stuck alert with its recovery command and the silent, krl_stale and
// clock_skew flags; and the header lines "bundle v<b> on <n>/<m> hosts",
// "directory v<d> on ...", "KRL v<k> on ...". A host counts as converged
// on a version only when its committed version matches and no swap is
// pending. A host removed or disabled in the directory that is still
// served shows that, never as waiting for approval (03-08 carry-over a).
func runHostStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host status", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	asJSON := fset.Bool("json", false, "print the server's answer as JSON (after the same checks)")
	if pos, err := parseInterspersed(fset, args); err != nil || len(pos) != 0 {
		return errUsage
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	_, pol, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return err
	}
	ans, err := fetchHostsStatus(ctx, s, pol)
	if err != nil {
		return err
	}
	if *asJSON {
		b, err := json.MarshalIndent(ans, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\n", b)
		return err
	}
	_, err = io.WriteString(stdout, renderHostsStatus(ans, time.Now()))
	return err
}

// fetchHostsStatus GETs hosts/status through the admin API and checks it
// (checkHostsStatus); pol is the verified policy for adminError.
func fetchHostsStatus(ctx context.Context, s *adminSession, pol *trust.Policy) (*serverclient.HostsStatusAnswer, error) {
	var ans serverclient.HostsStatusAnswer
	if err := s.client.AdminJSON(ctx, http.MethodGet, serverclient.AdminHostsStatusPath, nil, &ans, s.signer); err != nil {
		if refusal := hostAdminRefusal(err); refusal != nil {
			return nil, refusal
		}
		return nil, adminError(err, s, pol)
	}
	if err := checkHostsStatus(&ans); err != nil {
		return nil, err
	}
	return &ans, nil
}

// renderHostsStatus is host status's text output at now.
func renderHostsStatus(a *serverclient.HostsStatusAnswer, now time.Time) string {
	var b strings.Builder
	m := len(a.Hosts)
	var nb, nd, nk int
	cb, cd, ck := a.Current.Docs()
	for _, r := range a.Hosts {
		h := r.Heartbeat
		if h == nil || h.Status.Pending != nil {
			continue
		}
		if h.Status.Bundle == cb {
			nb++
		}
		if h.Status.Directory == cd {
			nd++
		}
		if h.Status.KRLDoc() == ck {
			nk++
		}
	}
	fmt.Fprintf(&b, "bundle v%d on %d/%d hosts\n", a.Current.Bundle, nb, m)
	fmt.Fprintf(&b, "directory v%d on %d/%d hosts\n", a.Current.Directory, nd, m)
	fmt.Fprintf(&b, "KRL v%d on %d/%d hosts\n", a.Current.KRL, nk, m)
	if m == 0 {
		b.WriteString("No approved host has reported yet.\n")
		b.WriteString(statusFooter)
		return b.String()
	}
	b.WriteString("\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOST\tDIRECTORY ENTRY\tLAST SEEN\tSTATUS\tBUNDLE\tDIRECTORY\tKRL\tGENERATION\tDRIFT\tLAST APPLY\tALERTS")
	var notes []string
	for _, r := range a.Hosts {
		entry := "active"
		switch {
		case r.NotYetPolled:
			entry = notYetPolled
		case r.State != serverclient.HostStateActive:
			entry = servedLine(r.State)
		}
		seen, status := "never", "none"
		if t, err := time.Parse(time.RFC3339, r.LastSeen); err == nil {
			seen = age(now.Sub(t)) + " ago"
		}
		// The stored status's age: LAST SEEN is any request, a re-posted
		// old status included (PR #72 review C2, C6).
		statusAge := time.Duration(0)
		if t, err := time.Parse(time.RFC3339, r.ReceivedAt); err == nil {
			statusAge = now.Sub(t)
			status = age(statusAge) + " ago"
		}
		var alerts []string
		if r.Silent {
			alerts = append(alerts, "silent")
		}
		if r.StatusStale {
			alerts = append(alerts, "status_stale")
			notes = append(notes, fmt.Sprintf("%s: status_stale: its status is %s old while the host is still seen: its applier writes none (on the host: systemctl status keyroster-agent)", r.Name, age(statusAge)))
		}
		bundle, dir, krl, gen, drift, last := "v0", "v0", "v0", "0", "-", "never applied"
		if h := r.Heartbeat; h != nil {
			st := h.Status
			bundle, dir, krl = mark(st.Bundle, cb), mark(st.Directory, cd), mark(st.KRLDoc(), ck)
			if st.Diverged(cb, cd, ck) {
				alerts = append(alerts, "diverged")
				notes = append(notes, fmt.Sprintf("%s: diverged: it reports a bundle, directory or KRL the server does not hold as current (above the current version, or the current number with other bytes, for example after a signer restore lost versions it had applied)", r.Name))
			}
			gen = fmt.Sprint(st.Generation)
			if c := st.LastCheck; c != nil {
				drift = "no"
				switch {
				case c.Error != "":
					drift = "failed"
					alerts = append(alerts, "check_failed")
					notes = append(notes, fmt.Sprintf("%s: check_failed: the last drift check failed: %s", r.Name, c.Error))
				case c.Drift:
					drift = "yes"
				}
			}
			if la := st.LastApply; la != nil {
				last = la.Result
				if la.Detail != "" {
					last += " (" + la.Detail + ")"
				}
				if la.Rollback {
					last += ", rollback"
				}
				if la.HostStatus != "" {
					last += ", " + la.HostStatus
				}
				if la.Error != "" {
					notes = append(notes, fmt.Sprintf("%s: last apply error: %s", r.Name, la.Error))
				}
			}
			if p := st.Pending; p != nil {
				alerts = append(alerts, "pending: "+p.Step)
			}
			if st.Stuck != "" {
				alerts = append(alerts, "stuck: "+st.Stuck)
				notes = append(notes, fmt.Sprintf("%s: stuck: %s; the host applies nothing, revocations included, until root runs `%s` there (docs/runbooks/host-setup.md \"Manual recovery\")",
					r.Name, st.Stuck, recoveryCommand))
			}
			if st.KRLStale {
				alerts = append(alerts, "krl_stale")
			}
			if r.SeqRegressed {
				alerts = append(alerts, "seq_regressed")
				notes = append(notes, fmt.Sprintf("%s: seq_regressed: its heartbeats carry a seq below the stored one (its state was reset after its clock ran ahead); the status shown is the stored one until its seq passes it", r.Name))
			}
			if st.FilesTruncated {
				alerts = append(alerts, "files_truncated")
			}
		}
		if r.ClockSkew {
			alerts = append(alerts, fmt.Sprintf("clock_skew (%+d s)", r.ClockOffsetS))
		}
		if t, err := time.Parse(time.RFC3339, r.IdentityRotatedAt); err == nil && now.Sub(t) <= identityRotationShown {
			alerts = append(alerts, "identity rotated "+age(now.Sub(t))+" ago")
		}
		if len(alerts) == 0 {
			alerts = []string{"-"}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", safe(r.Name), entry, seen, status, bundle, dir, krl, gen, drift, safe(last), safe(strings.Join(alerts, ", ")))
	}
	_ = tw.Flush()
	for _, n := range notes {
		b.WriteString(safe(n) + "\n")
	}
	b.WriteString("Versions marked * differ from the server's current ones (number or SHA-256); a host counts on a version only with no swap pending.\n")
	b.WriteString(statusFooter)
	return b.String()
}

// mark is d's version, with * when d is not cur (version or SHA-256).
func mark(d, cur heartbeat.Doc) string {
	s := fmt.Sprintf("v%d", d.Version)
	if d != cur {
		s += "*"
	}
	return s
}

// age is d rounded to whole seconds, minutes or hours.
func age(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < 2*time.Minute:
		return fmt.Sprintf("%ds", int(d/time.Second))
	case d < 2*time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%dh", int(d/time.Hour))
}
