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
    - internal/agent/fetch/prune_test.go (fix round 1)
    - .planning/phases/03-linux-agent-and-revocation/03-08e-PLAN.md
    - .planning/phases/03-linux-agent-and-revocation/03-08e-SUMMARY.md
  modified:
    - internal/agent/spool/spool.go
    - internal/agent/spool/spool_test.go
    - internal/agent/fetch/fetch.go
    - internal/agent/fetch/fetch_test.go
    - internal/agent/apply/configgraph.go (fix round 1)
    - .planning/todos/pending/2026-10-28-agent-spool-pruning.md (fix round 1)
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

- T-03-299 (F01, medium): mitigated by checkCaps (spool.Cap and the per-kind count), healSpool and, since fix round 1, pruneSpool. Tests are named above and in "Pre-merge review fix round 1".
  - Former residual, fixed in fix round 1 (D-1): policy files no bundle names were never pruned. pruneSpool now removes every policy no kept bundle names under its own version, and the spool stays within what it keeps plus one poll's answers.
  - Residual: the worst-case bound is about 845 MiB since fix round 2 (round 1: about 5.6 GiB), computed from the caps and not measured.
  - Residual: a prune can unlink an orphaned policy between the applier's listing and its open; that capture fails and the apply retries about 5 s later (fix round 2, "Known residual").
  - Residual: a compromised fetcher remains T-03-225.
- T-03-298 (F09, low): mitigated by phase2Shadowed. The value exemption applies only while phase2-adopt.json exists, only on an installed host whose last-good is the agent's, and is proved by activateDropIn.
  - Residual: the run loop still cannot finish the removal; `apply --once` now runs without path flags.
  - Fix round 1 (D-2): the line exemption also applies only while phase2-adopt.json exists, and only to the two lines at the top level of 50-keyroster.conf, outside any Match block.
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

## Pre-merge review fix round 1

The review ran at head `14c5a74` against base `a70c661` in security mode and stopped after the critic. Daniel decided D-1 and D-2 on 2026-11-01. One finding was refuted and needs no action: that the heal lines are logged "at warning level" although they carry no journald priority. The F01 and F09 paragraphs under "What changed" describe the state before this round.

### Owner decisions

- **D-1: policy files in the spool (findings [0] and [1], medium; both predate this PR), fixed as part of F01.** Fix round 2 changed the window to 64 and the bound to about 845 MiB; the 1024 figures in this bullet are round 1's. At the start of every poll, after healSpool, `pruneSpool` removes what the applier does not read. It works from the versions in `outbox/accepted.json`, taking zero for a kind with none, or when there is no file:
  - **Bundles and directories:** every version but the complete ones `spool.Keep` takes. That is Read's Floor rule (`pick`, now through `pickAbove`), with `keepAbove` (MaxRounds × MaxAgentStatePerKind = 1024) in place of 64 above a floor. So it keeps the newest version at or below the accepted one, and the lowest 1024 above it. Without a floor it is Read's own rule: the newest 64.
  - **KRLs:** every version but the newest complete one, which is the only one Read reads.
  - **Policies:** every version but those that pass two tests:
    - the document names its own version, as the server's do (`PolicyVersion` is the parsed policy's version);
    - a kept bundle names its SHA-256 (`policy_sha256`, the field `findPolicy` uses).

    A kept bundle that does not parse names no policy. A kept bundle that cannot be read at all (a symlink, which no answer writes) might name any policy, so then no policy goes.
  - **What is removed:** only regular files (fstatat without following a symlink). Symlinks, other non-regular files and unknown names stay, as healSpool leaves them.

  **The bound.**
  - At a poll's start, after the prune, the spool holds at most:
    - with a floor: 1025 bundle sets, 1025 directory sets, one policy set per kept bundle (the version rule leaves one name per document) and one KRL set;
    - without a floor: 64, 64, 64 and 1.
  - One poll then writes at most MaxRounds answers of at most MaxAgentStateResponse each: 64 × 8 MiB = 512 MiB of base64. The files they carry are smaller.
  - The read caps per set are:
    - MaxBundle, 1 MiB, for each bundle, policy and signature file;
    - 1 MiB + 64 KiB for a directory set;
    - 4 MiB + 4 KiB + 16 KiB for a KRL set.
  - So the spool holds at most about 1025 × 5.06 MiB + 4 MiB ≈ 5.1 GiB, plus 512 MiB: about 5.6 GiB in all. Without a floor it is about 0.3 GiB plus 512 MiB.
  - These figures are computed from the caps, not measured.
  - Before this round the spool had no bound: each poll could add up to 512 MiB under new names.

  **Why it holds.**
  - The kept bundles and directories are a superset of what any capture at the accepted floor reads.
  - They also cover what a pending swap reads: its floor is above the accepted one, and at most 64 versions above it.
  - The accepted bundle stays (the newest at or below the floor), so its policy stays too.
  - Without a floor, at most 64 policies are kept, and a floor-0 capture reads 64. So junk can no longer crowd out the honest policy.
  - On a fresh host, junk bundles, directories and KRLs above the honest versions go through dropAbove:
    - the applier writes `accepted.json` with zeros after every apply that took the lock, refused ones included. This is read from `Apply` in apply.go, which calls `WriteAccepted` after every locked apply that is not a dry run, whatever its error. UNVERIFIED by a test: `TestWriteAccepted` covers accepted versions only, and `fresh_host_junk_above_dropped` seeds the file by hand;
    - so the fetcher asks with since 0, and the server answers its current state;
    - dropAbove then removes what lies above that state (`fresh_host_junk_above_dropped`).

  **What stays the same.**
  - The applier's verification and Read's rules are unchanged. `pick` keeps its behaviour through `pickAbove`.
  - The todo 2026-10-28-agent-spool-pruning is covered as far as pruning goes. Two smaller items remain in it: skipping unchanged rewrites, and the repeated download from the accepted versions.
- **D-2: the Phase 2 line exemption (finding [2]), fixed.**
  - `parseConfig` marks every line after a Match line of its file `inMatch`.
  - `configGraph` marks a file `inMatch` when an Include line inside a Match block reaches it (on any visit), and passes that on to the files it includes.
  - `trustSettingHits` carries this as `settingHit.InMatch`.
  - `phase2Shadowed` drops the two runbook lines only when `adoptPending` is set and the hit is outside every Match block. `shadowed` is set exactly when it dropped a line.
  - `Check` now reads the plan (`readAdopt`), as Preflight and preflightApply do, so all three use the one rule.

  **Main's semantics change.** On main (a70c661), preflightApply passed the two lines unfiltered and refused them. Check and Preflight's installed branch dropped them by their text alone, with or without a plan. After this round, on an installed host with no `phase2-adopt.json`:
  - Check and Preflight report the lines as `foreign_trust_setting`, where main exempted them. In Check this is drift, logged at error level; in Preflight it is a refusal.
  - preflightApply refuses them, as main did.

  **Why this is safe for an installed host.**
  - finishAdoption removes `50-keyroster.conf` before the plan, which goes last. So whenever the agent itself leaves the file on disk, the plan is there too.
  - The lines exist without the plan only after a hand edit: someone re-creates the runbook lines, or removes the plan by hand. sshd still reads those lines, so reporting them is correct.
  - Check fixes nothing and blocks no apply.
  - preflightApply still runs only when the drop-in would change. So a host with an intact drop-in keeps installing KRLs while the drift check reports the lines.

### Fixes

| Finding | Commit | Test | RED and mutants (scratchpad `fix77-1/`) |
|---|---|---|---|
| D-1 (findings [0], [1]) | `989ae2e` | `TestSpoolPrune`: `spool_stays_bounded_across_polls`, `fresh_host_junk_policies_cannot_hide_the_honest_one`, `fresh_host_junk_bundles_below_cannot_hide_the_honest_policy`, `fresh_host_junk_above_dropped`, `prune_keeps_what_the_applier_reads`, `prune_leaves_symlinks_unknown_names_and_non_regular_files`, `prune_removes_no_policy_when_a_kept_bundle_cannot_be_read`, `honest_catch_up_keeps_one_polls_versions` | RED (`d1-red.txt`) on 14c5a74's fetcher, 5 subtests fail:<br>- between polls 3 and 8, policies grow from 49 to 129 and KRLs from 4 to 9;<br>- the floor-0 capture offers only the junk policies;<br>- the orphaned junk policy stays;<br>- every file the prune should remove stays.<br>The three guards pass on 14c5a74. So does dropAbove's part of `fresh_host_junk_above_dropped`, which shows dropAbove already covers junk above.<br>14 mutants killed (`d1-mutants.txt`; M3 and M13 rerun in `d2-mutants.txt`): the policy prune off; the own-version rule off; every KRL kept; the floor ignored for bundles; the floor ignored for directories; a window of 64 instead of 1024; floor 0 keeping 1024; the newest at or below the floor dropped; non-regular files removed; policies named by every bundle; an unreadable bundle naming nothing; the prune never called; dropAbove never called; incomplete sets kept |
| D-2 (finding [2]) | `c712f0b` | `TestAdopt/runbook_line_in_match_block_refused`, `runbook_file_included_in_match_block_refused` and `runbook_lines_without_adoption_plan_refused`, each at `apply`, `preflight` and `check` | RED (`d2-red-green.txt`), with the three D-2 sources taken from 14c5a74: all 9 subtests fail. The apply returns nil, and Preflight and Check report nothing. The changed `missing_dropin_without_adoption_plan_still_refused` fails too.<br>GREEN with the fix, together with the other F09 cases.<br>8 mutants killed (`d2-mutants.txt`, `d2-mutants-b.txt`): the filter ignoring Match context; the filter ignoring the plan; no line marked after a Match line; an Include inside a Match block not passed on; a later visit not recorded; Check, preflightApply and Preflight each exempting without a plan |
| [3] the units do not rewrite 00-keyroster.conf on their own | `a92224c` | n/a (docs) | n/a. The paragraph names `sudo keyroster-agent apply --once`. It labels two cases UNVERIFIED: the hand run's repair with nothing new to install, and the units' rewrite with only a newer bundle or directory |
| split [0] the phase2_adoption_pending row | `14fbec1` | n/a (docs) | n/a |
| This section, the threat rows, the todo, deferred-items.md | `83a5764` | n/a | n/a |
| Follow-up: sshd's per-file Match scope cited, the trial and refused-edit repairs in the cut-short state labelled UNVERIFIED | `8de2d28` | n/a (a comment and docs) | n/a. Source: servconf.c's Include case runs `*activep = oactive` after each file a glob matches (portable 10.2p1) |
| This update of the section | (this) | n/a | n/a |

### Deviations

1. **[Fixture] honestSpool's bundle now names its policy.**
   - It was `"b"` with policy `"p"`, a pair no applier can have accepted.
   - With the prune, three TestFetch cases failed: `oversize_policy_answer_refused_nothing_written`, `high_policy_version_oversize_refused` and `more_than_per_kind_refused`. A bundle that does not parse names no policy, so policy-1 went.
   - The bundle now holds the `policy_sha256` of a policy document that names version 1. No assertion changed.
   - The alternative was to treat a kept bundle that does not parse as naming any policy. That would let a compromised server turn the policy prune off with junk bundle bodies, and the growth would have no bound again.
2. **[Assertion] `missing_dropin_without_adoption_plan_still_refused` now expects the refusal of the runbook's TrustedUserCAKeys line, not the sshd -T value refusal.**
   - With no plan, the line is a hit. foreignFindings reports an sshd -T value only for a keyword that no line names (unchanged since main).
   - The test still requires a foreign_trust_setting refusal in the same state.
   - Main's preflightApply passed the hits unfiltered, so `named` suppressed the value finding there too: in this state main refused with this same line refusal. The old assertion matched only 14c5a74's text-only exemption.
3. **[Test design] The apply subtests edit 00-keyroster.conf by appending a comment.**
   - On an installed host whose drop-in is intact, preflightApply returns early (D-R2, as on main). So a first RED run with an intact drop-in did not test the apply site.
   - The comment leaves the agent's values in force, so only the runbook's line can refuse.
   - With the trust-line edit the existing cases use, 14c5a74 already refused the no-plan case through the sshd -T value.
4. **[Scope] An Include inside a Match block counts as inside the block.**
   - sshd reads every line of a file that such an Include reaches as part of the block.
   - The spec names Match blocks in 50-keyroster.conf. This round also covers this path, with its own test and two mutants.

### Gate and CI

- **Windows (Go 1.27.1):** gofmt and `GOOS=linux go vet` after each change. Every RED run, GREEN run and mutant ran in WSL (Go 1.27.3) on copies of the working tree outside the repository.
- **The local gate in WSL, on a `git archive` copy of `14fbec1` outside the repository.** It ran twice:
  - **First run:** failed on `internal/signer` `TestSignerRestore/restore_older_db` (`signer unavailable: clock_regression`). The fix round changed nothing under internal/signer. The test passed 10 runs of 10 alone under `-race` (`signer-restore-rerun.txt`). It is recorded in deferred-items.md beside the earlier `clock_regression` entry. Every other step of that run passed.
  - **Rerun: exit 0 (`GATE PASSED`).** Each of these passed:
    - gofmt, with its positive control;
    - go mod verify, the static build, and the CLI cross-compiles for windows, darwin and freebsd;
    - `go vet`: plain, `e2e`, and `e2e systemdsmoke`;
    - `CGO_ENABLED=1 go test -race -count=1 ./...`: 34 packages ok, with no data race;
    - golangci-lint: 0 issues for linux, windows and darwin;
    - capslock: 23 pairs, equal to the baseline;
    - dep-firewall;
    - testonly-firewall, in 6 combinations;
    - check-pinned-actions: 47.
  - **Package times under `-race`, first run then rerun:**
    - internal/agent/apply: 380 s and 354 s;
    - internal/agent/fetch: 28 s and 28 s;
    - internal/agent/spool: 4 s and 6 s.
- **After the gate:** `83a5764` and `8de2d28` change only docs and one Go comment. gofmt and `GOOS=linux go vet` ran on them on Windows.
- **CI:** the required checks on the head that carries this section are in the handback.

### UNVERIFIED after this round

- D-1's byte bound: computed from the caps, never measured.
- The fresh-host heal assumes the applier has written `accepted.json` once. It writes it after every apply that took the lock, refused ones included. If a host's applier never gets that far (no pins.json, or sshd -T failing), the fetcher keeps asking from the spool's newest versions, and junk above them stays until the applier does.
- Two cut-short-takeover cases, as the runbook says:
  - the hand run's repair of a drifted or missing 00-keyroster.conf with no new signed state;
  - the units' rewrite when only a newer bundle or directory arrives.
- The trial and refused-edit repairs in the cut-short state: tested only on an installed host without a takeover (`TestDropInRepair/noop_apply_replaces_trial_on_installed_host`, `dropin_sshd_refuses_repaired_by_noop_run`).
- sshd's per-file Match scope: read in portable 10.2p1's servconf.c only, not in 9.2p1, and not observed on a running sshd.
- On a real host: the prune, the Match-block refusals and the cut-short takeover. No 03-16 drill provokes them.

## Pre-merge review fix round 2

A narrow check ran at head `ee1bda1` (wf_28c335a5-a91) and found nothing blocking. Daniel decided on 2026-11-01:
- Q1: the prune window is 64, not 1024.
- Q2 to Q4 stand as built in round 1: the two changed existing tests, an Include inside a Match block counting as inside, and the spool-pruning todo staying open for its two remaining items.

Two lows from the check were fixed as well.

### Q1: the read window

- `spool.Keep(vs, floor)` is now exactly Read's rule (`pick`). `pickAbove` and the fetcher's `keepAbove` are gone, so spool.go differs from the PR's base only by `Keep`.
- The prune keeps the accepted version and the lowest `spool.MaxVersionsPerKind` (64) above it, or the newest 64 with none accepted. That is what the applier's next capture reads.
- A host more than 64 versions behind reads to the window's end. The next poll fetches the rest again, because it asks from the accepted versions.

**The bound, recomputed.**
- After the prune, at most 65 bundle, 65 policy and 65 directory sets and one KRL set stay: 65 × (2 + 2 + 1.0625) MiB + 4.02 MiB ≈ 333 MiB.
- One poll adds at most 64 × 8 MiB = 512 MiB.
- That is about 845 MiB in all, and about 840 MiB with nothing accepted.
- These are computed from the caps, not measured. The code comment, the runbook, T-03-299 (here and in the PLAN) and the todo say the same. Round 1's 1024 figures above are superseded.

### Fixes

| Fix | Commit | Test | RED | Mutants (scratchpad `fix77-2/`) |
|---|---|---|---|---|
| Q1: the read window | `8c749cb` | `TestSpoolPrune/honest_catch_up_refetches_past_the_read_window` (replaces `honest_catch_up_keeps_one_polls_versions`); the bound in `spool_stays_bounded_across_polls` uses the 64 window | Against round 1's 1024 window: the host read to bundle 200 after the rate-limited poll, where the 64 window stops it at 129 (`q1-red.txt`) | 3 killed (`q1-mutants.txt`): every version kept, round 1's 1024 window, the floor ignored |
| Check reads the takeover plan before it scans the configuration (low) | `72748aa` | `TestAdopt/check_during_finished_removal_reports_no_runbook_line`, through a new `check-plan-read` fault point between the two reads, at which the test removes 50-keyroster.conf and then the plan | Two RED runs (`f2-red.txt`). Without the fault point the test fails as "does not test". With the old order and the fault point (the swap mutant), Check reports both runbook lines after they are gone | The swap mutant, killed (the second RED run) |
| The runbook: what the hand run does to lines added to 50-keyroster.conf (low) | `fefb2aa` | `TestAdopt/hand_run_removes_runbook_file_with_every_line` (pins existing behaviour, so it is green on `ee1bda1`; `f3-test.txt`) | n/a (docs) | n/a |
| This section and the threat rows | (this) | n/a | n/a | n/a |

**Check's order.** keyroster-agent check takes no apply lock, so a hand run can finish a takeover while a check runs. finishAdoption removes 50-keyroster.conf before the plan. Check now reads the plan first:
- a plan found then may exempt lines the scan no longer finds;
- no plan means the file is gone already.

Before, a plan removed between the scan and the read made check report runbook lines that were already gone. Preflight and preflightApply hold the apply lock, so no finishAdoption runs between their two reads.

**The hand run.**
- The units' apply refuses these lines when it would rewrite 00-keyroster.conf. The hand run `apply --once` does not check them while the plan is there.
- It rewrites 00-keyroster.conf through repairDropIn, without the foreign-trust preflight. It then removes 50-keyroster.conf with every line in it, a foreign line and a Match block included. Its copy in `phase2/` goes once the removal succeeds.
- The runbook now tells the operator to remove or move any added line first.
- The new test covers the hand run's repair of an edited drop-in with nothing new to install, so that case is no longer UNVERIFIED. A missing drop-in in that case still is.

### Known residual

The prune can unlink a policy file between the applier's listing of the spool and its open of that file, when the policy has become orphaned. That capture then fails with ENOENT, and the apply retries about 5 s later. It is carried as a known residual and not fixed here.

### Gate and CI

- **The local gate in WSL, on a `git archive` copy of `fefb2aa` (the last code commit), outside the repository:** exit 0, `GATE PASSED` on the first run (`gate-fefb2aa.txt`).
  - gofmt, with its positive control; go mod verify; the static build and the CLI cross-compiles;
  - `go vet`: plain, `e2e`, and `e2e systemdsmoke`;
  - `CGO_ENABLED=1 go test -race -count=1 ./...`: 34 packages ok, with no data race. internal/agent/apply took 282 s, internal/agent/fetch 28 s and internal/agent/spool 4 s;
  - golangci-lint: 0 issues for linux, windows and darwin;
  - capslock: 23 pairs, equal to the baseline; dep-firewall; testonly-firewall in 6 combinations; check-pinned-actions: 47.
- **CI:** the required checks on the head that carries this section are in the handback.

### UNVERIFIED after this round

- The bound of about 845 MiB: computed from the caps, never measured.
- Round 1's other items stand, except that the hand run's repair of an edited drop-in with nothing new to install is now tested. The repair of a missing one is not.
