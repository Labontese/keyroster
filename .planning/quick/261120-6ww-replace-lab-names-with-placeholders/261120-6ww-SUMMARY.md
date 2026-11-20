---
phase: quick-261120-6ww
plan: 01
subsystem: planning-docs
tags: [docs, privacy, placeholders, planning]
status: complete
requires: []
provides: ["planning records and two docs without the owner's lab machine names or local paths"]
affects: []
key-files:
  created:
    - .planning/quick/261120-6ww-replace-lab-names-with-placeholders/261120-6ww-PLAN.md
    - .planning/quick/261120-6ww-replace-lab-names-with-placeholders/261120-6ww-SUMMARY.md
  modified:
    - ".planning/** (69 files; see the PLAN's files_modified)"
    - .planning/phases/03-linux-agent-and-revocation/03-12e2-SUMMARY.md
    - docs/runbooks/host-setup.md
    - docs/security/needs-hardware.md
decisions:
  - "Replace by kind, line for line: the placeholders are the owner's workstation / owner-workstation, the owner's laptop / owner-laptop, the homelab server / homelab-server, srvadmin, KR_SERVER_SINCE, journal-kr-server.txt and homelab-server.tailnet.ts.net."
  - "Leave the account name used as test data in internal/directory and test/vectors alone: it sits in pinned format vectors, so renaming it is a code change."
  - "Do not rewrite git history. Earlier commits still hold the old text."
requirements: []
metrics:
  completed: 2026-11-20
actuals:
  tokens: 30470
  tasks: 1
  commits: 3
plan_head_before: 2ed959f
plan_head_after: c51a70d
---

# Quick 261120-6ww Plan 01: replace lab names with placeholders Summary

Planning records and two docs no longer name the owner's development machine, laptop and home server, the server's login account and tailnet name, or absolute paths under the owner's user directory. They carry neutral placeholders instead, line for line. 72 files, 421 added and 419 removed lines in total (the two lines more are the 03-12e2 SUMMARY correction below). The three commits of the work are 17503f8 (the plan), a299461 (the 71 files) and c51a70d (the 03-12e2 SUMMARY); the commit that records this SUMMARY follows them, so `commits: 3` counts the work before this record.

## What was replaced

- The development machine's name became "the owner's workstation" (`owner-workstation` where an identifier is needed).
- The laptop's ssh alias became `owner-laptop`; "the laptop" stays where it was already used.
- The home server's name and its login account became "the homelab server" / `homelab-server` and `srvadmin` (also `/etc/ssh/principals/srvadmin`). The names derived from it became `KR_SERVER_SINCE` and `journal-kr-server.txt`, and its tailnet name `homelab-server.tailnet.ts.net`.
- Absolute local links became repo-relative links (20 distinct targets in 02-REVIEWS.md, all existing). Other local paths became `~/...`, `/home/<user>` or a description.
- The AI session's scratch directory is now called a scratch directory.

Scope: `.planning/**` plus `docs/runbooks/host-setup.md` (one line) and `docs/security/needs-hardware.md` (9 lines). No Go file, test vector, script or workflow changed. ROADMAP.md and STATE.md changed only inside sentences: no count, check box, table value, `Plan: N of M` or stopped_at moved.

## The 03-12e2 SUMMARY correction

Its "Pre-merge review" paragraph first said "Sonnet skeptics" and "confirmed by independent skeptics". One batched Sonnet skeptic judged all ten review results: it confirmed seven, which are four distinct review items, and refuted three. The paragraph now says so (+3/-1). An "After the merge" paragraph records the squash merge (2ed959f), the CI runs of the final head 0c3de1f, and that over five heads the rotation lanes' `go test` took 525.296 s to 534.027 s with 464 to 469 logins and no failed login.

## Consequences

- Commands and outputs quoted in executed plans and SUMMARYs now show placeholders, not the text that was typed or printed at the time.
- The plans that have not run yet (03-15, 03-16) use the placeholder aliases; their reconcile maps them to the real hosts from the owner's private notes.
- Git history is unchanged, so earlier commits still hold the old text.

## Deliberately not changed

- The account name used as test data in the Go tests of internal/directory and in test/vectors (pinned format vectors; renaming it is a code change), and the one planning line that quotes that fixture, `.planning/phases/02-passkey-login-mvp/02-01-PLAN.md:384`.
- The Windows per-user roaming-data environment variable where it is the product's Windows config location.
- The project's signer-VM ssh alias.
- One YAML key of the gaps block in 02-VERIFICATION.md keeps its name; its value was cleaned.

## Two notes

- `.planning/phases/02-passkey-login-mvp/02-08-PLAN.md:158`, an executed plan's check, now greps for the shorter word `scratch`.
- `.planning/research/PITFALLS.md:515` holds a Win32-OpenSSH preview release version (it ends in `p2`); it is a version string and not an address.

## How it went

Five rewriting agents worked on disjoint file groups. Three independent checks followed: a pattern scan with a structure check, a read of every hunk, and the Go tests and CI-equivalent checks. One fixing pass closed what they found. The checks raised 21 problems, among them two doubled articles, four lines with a local home path that the first search pattern had missed, and two lines that had been left with a private name for a wrong reason. All were fixed.

## Verification

The scan uses the non-comment lines of the owner's two private pattern files, written to temp files (the plan's verify command):

- The added lines of the diff against 2ed959f give no hit in either pattern file (case-sensitive and case-insensitive). Re-run at c51a70d, before this SUMMARY was written: empty.
- `git grep -n -I -i -E -f <case-insensitive patterns> -- .planning docs` prints only `02-01-PLAN.md:384` and 8 lines whose only hit is the product's Windows roaming-data variable (three in 02-06-PLAN.md, and one each in 02-06-SUMMARY.md, 02-REVIEWS.md, 03-02-PLAN.md, 03-02-SUMMARY.md and docs/runbooks/server-install.md), 9 lines in all.
- `git diff --numstat`: added equals deleted for 71 of the 72 files; the exception is the 03-12e2 SUMMARY (+3/-1). The quick-task record adds its own lines.
- `go test -count=1 ./cmd/keyroster/` ok (111.7 s; the runbook tests that read host-setup.md). `go test` of internal/tlog, internal/wire, internal/custodytext and internal/directory ok; `go vet` of those packages clean.
- internal/agent/apply is Linux-only and reads host-setup.md in TestProbeHoldReasonsDocumented, so it could not run on Windows. Its 18 pinned reasons were checked by hand, no `probe_held` line changed, and CI runs it.
- `git diff --check` clean, no CR byte, every rewritten link resolves, table cell counts unchanged.

## Deviations from Plan

None - plan executed exactly as written. The quick-task id `6ww` follows the way `/gsd-quick` makes ids (two-second blocks since midnight, base 36, three characters).

## Known Stubs

None.
