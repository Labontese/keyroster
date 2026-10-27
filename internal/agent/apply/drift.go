//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/trust"
)

// ErrNotInstalled is a check on a host where current names no generation
// of the agent's: there is nothing installed to compare.
var ErrNotInstalled = errors.New("not_installed")

// SettingDrift is one sshd setting whose effective value is not the
// agent's: the keyword, the account of the sshd -T -C run ("" for the
// global sshd -T), and what the agent wants and sshd reports.
type SettingDrift struct {
	Keyword string `json:"keyword"`
	Account string `json:"account,omitempty"`
	Want    string `json:"want"`
	Got     string `json:"got"`
}

// FileDrift is one file of the generation current names whose SHA-256 is
// not its record's, or the drop-in when it is not the one the agent
// writes ("" for a file missing on that side).
type FileDrift struct {
	File       string `json:"file"`
	WantSHA256 string `json:"want_sha256"`
	GotSHA256  string `json:"got_sha256"`
}

// DriftReport is keyroster-agent check's output (AGENT-05): the
// generation current named when the check began, every setting and file
// drift, and the managed accounts sshd's AllowUsers, AllowGroups,
// DenyUsers or DenyGroups exclude (report only).
type DriftReport struct {
	Generation uint64         `json:"generation"`
	Settings   []SettingDrift `json:"settings"`
	Files      []FileDrift    `json:"files"`
	Excluded   []Finding      `json:"excluded,omitempty"`
	// Foreign are the trust settings in files sshd reads other than the
	// agent's drop-in, and the files of that configuration the agent
	// cannot read safely (configGraph, PR #68 review D-R3): drift.
	Foreign []Finding `json:"foreign,omitempty"`
	// LoginGraceObserved is false when an apply held the lock, so the
	// check left login_grace.json to that apply.
	LoginGraceObserved bool `json:"login_grace_observed"`
}

// Drift reports whether anything drifted.
func (r *DriftReport) Drift() bool {
	return len(r.Settings) > 0 || len(r.Files) > 0 || len(r.Foreign) > 0
}

// Check compares what sshd and the file system hold with what the agent
// installed (AGENT-05, T-03-34, T-03-38), and fixes nothing:
//
//   - current is resolved once (readlink); the generation directory it
//     names is re-hashed by that resolved path against
//     <state>/generations/<N>.json, so an apply that swaps current during
//     the check, even into an intermediate generation, cannot make it mix
//     two generations; a file missing, added or changed is a FileDrift,
//     and so is a drop-in whose bytes are not DropIn's;
//   - every file sshd reads (the whole Include graph, D-R3) is searched
//     for trust settings outside the agent's drop-in (Foreign), and
//     sshd -T must report no AuthorizedPrincipalsCommand;
//   - sshd -T must report the drop-in's three paths, and so must
//     sshd -T -C user=<account>,host=127.0.0.1,addr=127.0.0.1,laddr=<l>,lport=<p>
//     for every account that generation holds a principals file for (l
//     and p from the first loopback listener): a later Match block or an
//     earlier file is a SettingDrift;
//   - the sshd -T dump is passed to ObserveLoginGrace, so the swap wait's
//     LoginGraceTime bound is refreshed at every check (03-05), unless an
//     apply holds the lock (it observes for itself); an unbounded
//     LoginGraceTime is a SettingDrift of logingracetime.
//
// The record names the generation current names, whether that is
// last-good or RollbackTarget(current, last-good): neither is drift (03-05
// pre-merge review). An error is a tool error (exit 2), such as no
// generation of the agent's installed.
func Check(ctx context.Context, cfg Config, l Layout) (*DriftReport, error) {
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	for _, p := range []string{cfg.SSHD, cfg.SSHDConfig, l.Root, l.StateDir} {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%w: %q is not an absolute path", ErrConfig, p)
		}
	}
	if err := checkOwnDir(l.StateDir); err != nil {
		return nil, err
	}
	fd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: &Report{Errors: []string{}}, stateFd: fd}
	defer func() { _ = unix.Close(fd) }()

	cur, err := e.resolveLink(l.Current())
	if err != nil {
		return nil, err
	}
	if cur.kind != linkAgent {
		return nil, fmt.Errorf("%w: %s names no generation of this agent (%q)", ErrNotInstalled, l.Current(), cur.target)
	}
	if err := e.fault("check-resolved"); err != nil {
		return nil, err
	}
	r := &DriftReport{Generation: cur.n, Settings: []SettingDrift{}, Files: []FileDrift{}}
	rec, err := e.readRecord(cur.n)
	if err != nil {
		return nil, err
	}
	// By the resolved path, never through current again.
	g, err := readGeneration(l.Gen(cur.n))
	if err != nil {
		return nil, fmt.Errorf("generation %d: %w", cur.n, err)
	}
	for _, name := range fileNames(g, &Generation{Files: recordFiles(rec.Files)}) {
		want := rec.Files[name]
		got := ""
		if b, ok := g.Files[name]; ok {
			got = trust.SHA256Hex(b)
		}
		if want != got {
			r.Files = append(r.Files, FileDrift{File: filepath.Join(l.Gen(cur.n), name), WantSHA256: want, GotSHA256: got})
		}
	}

	// The drop-in is the agent's own file once a generation is installed
	// (D-R2, PR #68 review F15): bytes that differ from DropIn are drift,
	// even when sshd -T still reports the agent's three paths.
	if b, err := e.readDropIn(); err != nil {
		return nil, err
	} else if want := DropIn(l); !bytes.Equal(b, want) {
		got := ""
		if b != nil {
			got = trust.SHA256Hex(b)
		}
		r.Files = append(r.Files, FileDrift{File: l.DropIn(), WantSHA256: trust.SHA256Hex(want), GotSHA256: got})
	}
	dump, err := e.sshdDump(ctx, "")
	if err != nil {
		return nil, err
	}
	want := ourValues(l)
	for _, k := range trustKeywords {
		if got := dump.One(k); got != want[k] {
			r.Settings = append(r.Settings, SettingDrift{Keyword: k, Want: want[k], Got: got})
		}
	}
	if got := dump.One(principalsCommand); !isDefault(got) {
		r.Settings = append(r.Settings, SettingDrift{Keyword: principalsCommand, Want: "none", Got: got})
	}
	// Every trust setting in what sshd reads but the agent's drop-in
	// (D-R3); the Phase 2 runbook's own two lines, left by a takeover whose
	// removal is unfinished, are the takeover's (the agent's drop-in
	// shadows them).
	hits, problems := trustSettingHits(l, cfg.SSHDConfig, nil)
	r.Foreign = append(r.Foreign, problems...)
	for _, h := range hits {
		if h.File == l.Phase2DropIn() && (h.Text == phase2CALine || h.Text == phase2PrincipalsLine) {
			continue
		}
		r.Foreign = append(r.Foreign, Finding{Code: CodeForeignTrust, Refusal: true, File: h.File, Line: h.Line,
			Message: fmt.Sprintf("%s:%d sets %q; the agent never merges with or overrides another trust setting", h.File, h.Line, h.Text)})
	}
	grace, gerr := dump.LoginGrace()
	if gerr != nil {
		r.Settings = append(r.Settings, SettingDrift{Keyword: "logingracetime", Want: "a bounded value", Got: dump.One("logingracetime")})
	} else {
		unlock, held, err := e.tryLock()
		if err != nil {
			return nil, err
		}
		if !held {
			_, err := e.observeLoginGrace(grace, false)
			unlock()
			if err != nil {
				return nil, err
			}
			r.LoginGraceObserved = true
		}
	}

	var accounts []string
	for name := range rec.Files {
		if a, ok := strings.CutPrefix(name, PrincipalsDir+"/"); ok {
			accounts = append(accounts, a)
		}
	}
	slices.Sort(accounts)
	if len(accounts) == 0 {
		return r, nil
	}
	laddr, lport, err := firstLoopback(dump)
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		d, err := e.sshdDump(ctx, accountSpec(a, laddr, lport))
		if err != nil {
			return nil, err
		}
		for _, k := range trustKeywords {
			if got := d.One(k); got != want[k] {
				r.Settings = append(r.Settings, SettingDrift{Keyword: k, Account: a, Want: want[k], Got: got})
			}
		}
		if got := d.One(principalsCommand); !isDefault(got) {
			r.Settings = append(r.Settings, SettingDrift{Keyword: principalsCommand, Account: a, Want: "none", Got: got})
		}
		if why := Excluded(d, a, l.Root); why != "" {
			r.Excluded = append(r.Excluded, Finding{Code: CodeAccountExcluded, Account: a, Message: "account " + a + ": " + why})
		}
	}
	return r, nil
}

// recordFiles turns a record's file names into a Generation's keys, for
// fileNames.
func recordFiles(m map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for n := range m {
		out[n] = nil
	}
	return out
}
