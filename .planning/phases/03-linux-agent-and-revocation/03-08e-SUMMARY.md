---
phase: 03-linux-agent-and-revocation
plan: 08e
subsystem: agent
tags: [agent, fetch, spool, apply, preflight, phase2, krl, revocation, d-r2]
status: complete

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-08d: KRL-alone state and its fix round 1 (this plan's precondition: KRLAlone, NewPrincipalsRenderer)"
provides:
  - "spool: Cap, the read cap of every recognised spool name; Read takes its caps from it"
  - "fetch: ErrAnswerOverCap (state_item_over_cap) and checkCaps, run before writeState's first write: every bundle, policy, directory and KRL file against spool.Cap, and at most MaxAgentStatePerKind bundles and directories"
  - "fetch: healSpool, run at the start of every poll: removes recognised regular spool files above their cap, never following links; best effort, logged at warning level"
  - "apply: phase2Shadowed, the one Phase 2 leftover filter for Preflight, preflightApply and Check; foreignFindings' shadowed values, gated on an unfinished takeover"
  - "keyroster-agent apply: parseApply with run's path defaults (--state-dir /var/lib/keyroster-agent, --spool <state-dir>/spool)"
  - "tests: TestSpool/cap_is_what_read_enforces, nine TestFetch cases, five TestAdopt cases on a first-removal-crash fixture, TestApplyFlags"
  - "docs: host-setup.md fetcher paragraph, unfinished-takeover paragraph, state_item_over_cap Refusals row"
affects: [03-08f, 03-09, 03-10]

actuals:
  tokens: 31612
  tasks: 3
  commits: 6
plan_head_before: a70c661e5241a6f5374f4e81af40de6b2f8d8e7f
plan_head_after: 9fab51244fd6febfa415a5be4115c5b4d6084eb4

tech-stack:
  added: []
  patterns:
    - "The fetcher never spools what the applier's open contract refuses: one cap table (spool.Cap) serves both sides"
    - "A Phase 2 exemption only where activateDropIn's sshd -T check then proves the agent's values in force"

key-files:
  created:
    - cmd/keyroster-agent/apply_test.go
    - .planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md
  modified:
    - internal/agent/spool/spool.go
    - internal/agent/spool/spool_test.go
    - internal/agent/fetch/fetch.go
    - internal/agent/fetch/fetch_test.go
    - internal/agent/apply/preflight.go
    - internal/agent/apply/drift.go
    - internal/agent/apply/adopt_test.go
    - cmd/keyroster-agent/apply.go
    - docs/runbooks/host-setup.md
    - .planning/ROADMAP.md
    - .planning/STATE.md
    - .planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md (to 03-16-PLAN.md, the wave lines; 03-09 also depends_on and its precondition)

key-decisions:
  - "spool.Cap recognises a name only when its version parses as a uint64, exactly as Read does, so the heal never removes a file Read would never read"
  - "checkCaps refuses only recognised names above their cap; a name Cap does not recognise cannot occur in an answer that passed CheckSince (versions 0 are refused there)"
  - "The fetcher's warnings use the applier's text convention (a WARNING prefix through logf), with no new journald priority"
  - "honest_answers_fit_the_caps also pins tlog.MaxDocument = wire.MaxDirectory and tlog.MaxSigs = wire.MaxDirectorySigs (directory_install's bounds)"

requirements-completed: []

duration: 40min
completed: 2026-11-01
---

# Phase 3 Plan 08e: Agent spool and takeover Summary

**Neither the spool nor a cut-short takeover holds back a KRL any more:**
- The fetcher refuses a state answer before writing anything when either holds:
  - an item is above the cap the applier reads (`spool.Cap`);
  - it carries more than 16 versions of a kind.
- Every poll first removes oversize recognised spool files.
- The run loop repairs a drifted or missing `00-keyroster.conf` and installs newer KRLs while a Phase 2 takeover's removal is unfinished.
- `sudo keyroster-agent apply --once` runs without path flags.

PR: #77 (`p03/08e-agent-spool-and-takeover`), open without auto-merge.

CI on head 9fab512 (the code and the publish edits). Each workflow's run ID:
- CI: 41289564741 (build-test, lint, capslock, dependency-firewall, govulncheck, fuzz, cli-windows, cli-macos)
- e2e: 41289564802
- e2e-distro: 41289564782
- e2e-tpm: 41289564720
- e2e-pkcs11: 41289564756
- build-piv: 41289564776
- systemd-sandbox: 41289564721
- CodeQL: 41289564730
- pr-title: 41289564725
- pinned-actions: 41289564743

The final head, with this SUMMARY, runs the same workflows again.

## Commits

| Task | Commit | Message |
|------|--------|---------|
| 1 (tracer) | 5a2b4f8 | fix(agent): refuse state answers above the spool's read caps (F01) |
| 2 (F01) | 07170c4 | fix(agent): cap every spooled item and heal oversize spool files (F01) |
| 2 (F09) | bf6ecea | fix(agent): keep applying while a Phase 2 takeover's removal is unfinished (F09) |
| 3 | 9aa8a99 | fix(agent): give apply --once run's path defaults |
| 3 | 97f270a | docs(runbooks): say what the fetcher refuses and what an unfinished takeover still applies |
| 3 | 9fab512 | docs(03-08e): add the agent spool-and-takeover plan and shift later waves |
| 3 | (this) | docs(03-08e): complete agent spool-and-takeover plan |

## What changed

**F01.**
- `spool.Cap(name)` returns the cap for each name:
  - MaxBundle for bundles, policies and their signatures;
  - wire.MaxDirectory and wire.MaxDirectorySigs for directories and their signatures;
  - krl.MaxKRL, krl.MaxManifest and krl.MaxManifestSig for KRL files.
- `Read` reads every file through `readCapped`, which takes its cap from `Cap`.
- `writeState` calls `checkCaps` before its first write. checkCaps refuses with `state_item_over_cap`, naming the kind, version, file and size, when:
  - an answer holds more than `MaxAgentStatePerKind` bundles or directories; or
  - any file it would write (built as `writeState` builds it) is above `Cap`.
- `pollState` calls `healSpool` before it computes the cursor. healSpool walks the spool through `spool.OpenDir` and `ListDir`, then:
  - checks each recognised name with `fstatat(AT_SYMLINK_NOFOLLOW)`;
  - unlinks each regular file above its cap;
  - goes on past errors and returns them joined.
- pollState logs the removed names, and any error, at warning level, and polls on.
- dropAbove's comment now also says that a policy replaced by name is harmless, because the applier finds the accepted policy by SHA-256 first (`findPolicy`).

**F09.**
- `phase2Shadowed(l, hits, adoptPending)` drops the runbook's two lines in `50-keyroster.conf` from the hits. When it dropped any and a takeover plan exists, it returns the runbook's two values as `shadowed`. `foreignFindings` does not report a base `sshd -T` value equal to `shadowed[keyword]`.
- Preflight's installed branch uses the helper (with `readAdopt`), and keeps its Note.
- preflightApply's installed branch uses the helper when last-good is the agent's. Its other branches pass the hits unfiltered and nil.
- `Check` uses only `rest`. Its setting drift for the runbook's values stays reported.

**apply's path defaults.**
- `parseApply` is pure and models `runIdentity`'s flag block:
  - `--state-dir` defaults to `defaultStateDir`;
  - `--spool` "" means `Layout{StateDir}.Spool()`;
  - each must be absolute when given.
- applyUsage's first line is now `usage: keyroster-agent apply --once [--spool DIR] [--state-dir DIR] [--root DIR]`, and it gains the sentence `--spool defaults to <state-dir>/spool, --state-dir to /var/lib/keyroster-agent.`
- The `--spool` help string reads `(default <state-dir>/spool)`.

## RED evidence

All REDs were taken in WSL: Go 1.27.3 linux/amd64, uid 1000, `-race`, on a scratch copy of the tree.

**Task 1**, on origin/main's behaviour. `ErrAnswerOverCap` and a `spool.Cap` stub returning (0, false) were added first, and Read was not wired to the stub:
- `TestFetch/oversize_policy_answer_refused_nothing_written`: `an answer with an oversize policy 1: <nil>, want state_item_over_cap`; the spool gained bundle-2 and the oversize policy-1.json; `the applier's capture after the honest answer: spool_oversize: policy-1.json is 1048577 bytes, above 1048576`.
- `TestFetch/high_policy_version_oversize_refused`: the same at 18446744073709551615. Read then picks `policy-18446744073709551615.json` and refuses it with spool_oversize, which is F01 as described.
- `TestFetch/honest_answers_fit_the_caps`: every `spool.Cap(...) = 0, false`.
- `TestSpool/cap_is_what_read_enforces`: `Cap("bundle-1.json") = 0, false, want 1048576, true`.
- GREEN at once: `TestFetch/item_at_cap_written`, an adjacency guard (an at-cap policy was always written).

**Task 2**, on Task 1's head (5a2b4f8):
- `more_than_per_kind_refused`: 17 bundles accepted and written.
- `oversize_directory_and_krl_refused`: all five over-cap files (directory, directory sigs, KRL, manifest, manifest sig) were accepted and written.
- `poisoned_spool_file_removed_at_next_poll`: policy-1.json stays, no warning, and Read refuses with spool_oversize.
- `heal_error_logged_and_poll_continues`: no warning logged. Not skipped: uid 1000.
- `unfinished_removal_edited_dropin_run_loop_applies_krl` and `unfinished_removal_missing_dropin_run_loop_applies_krl`: `preflight refused: foreign_trust_setting: .../50-keyroster.conf:1 sets "TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub"` (and line 2).
- `unfinished_removal_foreign_line_still_refused`: RED, beyond the plan's prediction. The refusal named the runbook's own two lines beside the foreign one; the test requires every refusal to be the foreign line's.
- `missing_dropin_without_adoption_plan_still_refused`: RED, beyond the plan's prediction. Today the line refusals mark both keywords as named, so the `sshd -T` value refusal the test requires never appears.
- `preflight_command_agrees`: Preflight reported `sshd -T reports trustedusercakeys "/etc/ssh/keyroster_user_ca.pub"` for the edited drop-in, and both values for the missing one.
- GREEN at once: `heal_leaves_symlinks_and_unknown_names` (nothing removed anything yet) and `crash_during_removal_resumes` (unchanged).

**Task 3**, `TestApplyFlags` against parseApply with today's rules (a pure refactor of runApply first):
- `no_path_flag`, `state_dir_only` and `spool_only` returned a usage error (`apply: --spool must be an absolute path`, `apply: --state-dir must be an absolute path`).
- `-h` lacked the defaults sentence.
- `both`, the relative-path cases, `no_once` and `argument` were GREEN, as they should be.

## Mutants

Each mutant was applied to the scratch copy with a scripted exact replacement, run against its named test without `-race`, and restored from a backup. `cmp` against the working tree then confirmed every file byte for byte.

| Mutant | Named test | Result |
|--------|-----------|--------|
| preflightApply without the helper (`if false && lg.kind == linkAgent`) | `unfinished_removal_edited_dropin_run_loop_applies_krl` | killed (foreign_trust_setting on 50-keyroster.conf:1) |
| shadowed not gated on adoptPending (`if found {`) | `missing_dropin_without_adoption_plan_still_refused` | killed (`<nil>, want the sshd -T foreign_trust_setting`) |
| checkCaps removed from writeState | `oversize_policy_answer_refused_nothing_written` | killed |
| per-kind count removed | `more_than_per_kind_refused` | killed |
| healSpool removed from pollState | `poisoned_spool_file_removed_at_next_poll` | killed |
| Cap MaxBundle - 1 | `item_at_cap_written`; `cap_is_what_read_enforces` | killed by both |
| Cap MaxBundle + 1 | `cap_is_what_read_enforces`; tracer | killed by both. `item_at_cap_written` survives, as expected: a larger cap still writes an at-cap item |
| fixture crash moved to the third removal | the five F09 cases | the fixture's own starting-state check fails (`50-keyroster.conf false, CA file false`). See Deviations for what the F09 tests show with that check also dropped |

## Verification

- Task verifies, all PASS:
  - Task 1's `TestSpool|TestFetch`;
  - Task 2's `TestAdopt|TestPreflight|TestDrift|TestSpool|TestFetch`, with every named subtest and `crash_during_removal_resumes`;
  - Task 3's `TestApplyFlags`.
  - All ran with `-race -count=1` in WSL.
- The full local gate in WSL (Go 1.27.3) passed, fail=0:
  - `go test -race -count=1 ./...`: 34 packages ok, no FAIL and no DATA RACE.
  - Package times: internal/agent/apply 500.8 s, internal/agent/fetch 9.0 s, internal/agent/spool 4.0 s, cmd/keyroster-agent 2.0 s.
  - `go vet ./...`, plus `-tags e2e` and `-tags "e2e systemdsmoke"` on ./test/e2e/.
  - gofmt: the positive control (a misformatted file) was listed; the tree listed none.
  - golangci-lint v2.14.0: 0 issues for linux and for GOOS=windows.
  - capslock-check: no new pair (signer 92/92, agent 37/37, fetch 23/23).
  - dep-firewall, testonly-firewall and check-pinned-actions: clean.
  - check-pr-title: OK.
  - Cross builds for windows, darwin and freebsd: ok.
- Task 3's docs, dependency and wave verify passed:
  - `state_item_over_cap` appears 2 times in host-setup.md;
  - `unfinished_removal_edited_dropin_run_loop_applies_krl` appears once;
  - 03-09 has `depends_on: ["03-08e"]`;
  - 03-16 has `wave: 22`, origin/main's 21 + 1;
  - ROADMAP holds 03-08e-PLAN.md.
- Acceptance greps:
  - `func Cap(` 1;
  - non-comment `spool.Cap(` in fetch.go 2;
  - `func phase2Shadowed(` 1;
  - `phase2Shadowed(` in drift.go 1;
  - `defaultStateDir` in apply.go 2;
  - `(default <state-dir>/spool)` 1;
  - apply_test.go's first line `//go:build linux`;
  - attribution lines in commit messages 0.

**The `apply --once` mentions** (`grep -rn 'apply --once' docs/ internal/ cmd/ test/`; host-setup.md line numbers as on main, before this plan's insertions). Each falls into one of three kinds:
- **Works with the defaults:**
  - host-setup.md:889 (the code block) and 950, and the new F09 paragraph;
  - host-setup.md:1569 (step 4);
  - adopt.go:58 (adoptCommand);
  - preflight.go's trial Fix (`run sudo keyroster-agent apply --once`);
  - resetdir.go:90 (the pending hint).
- **Adds a mode flag only, and works with the defaults:**
  - host-setup.md:1225 and 1594 (`--recover-to-last-good`, `--dry-run`);
  - internal/agent/apply/apply.go:292 (the stuck log line);
  - cmd/keyroster/hoststatus.go:32 (recoveryCommand);
  - heartbeat.go:68 (a comment).
- **Prose, usage or test text:**
  - host-setup.md:598, 611 and 856 (table rows and prose) and 1581;
  - adopt.go:29, apply.go:125, run.go:34 and units.go:28/74 (comments);
  - cmd/keyroster-agent main.go:5, run.go:37 and apply.go:20/25/100;
  - adopt_test.go and apply_test.go comments;
  - test/distro and test/e2e: the invocations pass both flags (agent_apply_test.go:233, distro_test.go:304); the rest are comments.

No mention needed an edit.

## Deviations from Plan

1. **[Plan prediction] The third-removal mutant does not make the F09 REDs disappear.**
   - With the crash at the third removal and the fixture's 50-keyroster.conf check dropped, on the pre-F09 code, the line refusals (`50-keyroster.conf:1 sets ...`) disappear. Those are the defect the fixture targets.
   - Four F09 cases still fail. The cause is the fake `sshd -T`: installPhase2 keeps `h.run.after` at the runbook's values after 50-keyroster.conf is gone, a state a real sshd never shows.
   - The same mutant fails on the fixed code too, because the value exemption needs the runbook's lines present.
   - The first-removal crash is the only point where the files and the fake `sshd -T` agree, which is the fixture's reason. The harness was not changed.
   - Evidence: mutants-m6b-m7.txt and mutants-m7-fixed.txt in the scratch evidence directory.
2. **[Plan prediction] Two more REDs than the plan named:** `unfinished_removal_foreign_line_still_refused` and `missing_dropin_without_adoption_plan_still_refused` (see RED evidence). Each test asserts more than the bare refusal: that only the foreign line refuses, and that the refusal is the `sshd -T` value one. Both pass after the fix.
3. **[Reconciliation] `preflight_command_agrees` is one subtest over both variants (edited, missing)**, so its PASS line matches the plan's fails_when exactly.
4. **[Reconciliation] Publish edits mirror 03-08d's PR.**
   - The ROADMAP progress-table total also became 23 (14/23), as 03-08d moved it with the Plans line.
   - The tracking updates were applied by hand, mirroring 03-08d's docs commit:
     - the 03-08e row checked;
     - 15/23 executed;
     - completed_plans 50;
     - Plan 16 of 23;
     - a metrics row;
     - three decisions;
     - stopped_at and state_head.
   - The gsd state tools were not run, because they rewrite `.planning/state.json` and `config.json`, which stay untouched and unstaged.
5. **[Reconciliation] The guard held:** origin/main's 03-09 had `wave: 14` and `depends_on: ["03-08d"]`, and 03-10 to 03-16 had 15 to 21. The +1 edits used those values.
6. **[Addition] TestApplyFlags also covers `--once extra` (a stray argument) and `-h`**, which shows the defaults sentence.

## Deferred Issues

None from this plan.

The internal/agent/apply package takes about 500 s under `-race` in WSL, against `go test`'s default 10-minute per-binary timeout. 03-08d's 4096-principals-file cases cause it; this plan adds about 5 s.

## Threat model

- T-03-299 (F01, medium): mitigated by checkCaps (spool.Cap and the per-kind count) and healSpool. Tests are named above.
  - Residual: policy files no bundle names are never pruned (todo agent-spool-pruning).
  - Residual: a compromised fetcher remains T-03-225.
- T-03-298 (F09, low): mitigated by phase2Shadowed. The value exemption applies only while phase2-adopt.json exists, only on an installed host whose last-good is the agent's, and is proved by activateDropIn.
  - Residual: the run loop still cannot finish the removal; `apply --once` now runs without path flags.
- T-03-SC: no module was added, and the capslock baselines are unchanged.

No new network endpoint, auth path or trust-boundary schema change.

## Known Stubs

None.

## UNVERIFIED

- On a real host: the fetcher's refusal and heal, and the run loop applying during a cut-short takeover. No 03-16 drill provokes them. The runbook says so beside each text.
- e2e (containers, real sshd): CI only.

## TDD Gate Compliance

- Every behaviour change had its test RED first, on the code before the change (above).
- Task 1's stubs were symbol-only, so the REDs fail on behaviour, not on the build.
- Task 3 was refactored first, then RED, then GREEN.

## Self-Check: PASSED

- Files exist:
  - internal/agent/spool/spool.go (Cap);
  - internal/agent/fetch/fetch.go (checkCaps, healSpool, ErrAnswerOverCap);
  - internal/agent/apply/preflight.go (phase2Shadowed);
  - cmd/keyroster-agent/apply.go (parseApply);
  - cmd/keyroster-agent/apply_test.go;
  - the plan and this SUMMARY.
- Commits 5a2b4f8, 07170c4, bf6ecea, 9aa8a99, 97f270a and 9fab512 are ancestors of HEAD.
- The commit count from the ledger (a70c661..9fab512) is 6.
