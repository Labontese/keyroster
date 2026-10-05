---
phase: 01-trust-core
plan: 04
subsystem: ci
tags: [github-actions, e2e, openssh, sshd, fuzzing, rulesets, required-checks, actions-cache]

requires:
  - phase: 01-02
    provides: "keyroster-signer + keyroster ca issue, test/e2e harness (non-root sshd, ssh-agent, signer helpers), TestIssueAcceptedBySSHD, scripts/build-openssh.sh"
  - phase: 01-16
    provides: "Four seeded fuzz targets (FuzzParseIssueRequest, FuzzReadFrame, FuzzParseKeyID, FuzzValidatePrincipals); agent backend that skips certificate entries"
  - phase: 01-01
    provides: "main-integrity ruleset as code, scripts/apply-rulesets.sh (owner-run), integration_id 15368 convention, keyroster-bot, scripts/gh-as-bot.sh, scripts/merge-gate.sh"
  - phase: 01-03
    provides: "selected-actions allowlist + sha_pinning_required, pinned-actions check"
provides:
  - "E2E workflow: checks e2e (9.5p1) and e2e (10.5p1), OpenSSH built from SHA-256-pinned, GPG-verified tarballs, cached by version + build-script hash, sshd logs uploaded on failure"
  - "TestSSHDRejects: principal not listed, untrusted CA, expired, not yet valid, no local/remote port forwarding, no agent forwarding, PTY allowed, each with a control"
  - "TestSignerRefuses: no/empty/wildcard/comma/whitespace/uppercase principal, certificate as --pubkey, RSA-2048, serve pinned to a certificate in the agent"
  - "scripts/fuzz.sh and CI job fuzz (30 s per target; fails on zero targets or an unlistable package)"
  - "main-integrity.json requires e2e (9.5p1), e2e (10.5p1) and fuzz; CONTRIBUTING documents them and the 9.5p2 gap"
affects: [01-05, 01-07, 01-13, 01-15, every later PR (three more required checks)]

actuals:
  tokens: 6500
  tasks: 2
  commits: 3
plan_head_before: e1e61227995133ee5ecaaf69626107598bd78407
plan_head_after: 310c7750aa00bfb52c02380496e3961613e28067

tech-stack:
  added: [actions/cache v6.1.0, actions/upload-artifact v7.0.1 (both GitHub-owned, SHA-pinned)]
  patterns:
    - "Each authentication refusal in e2e runs against its own sshd: OpenSSH >= 9.8 PerSourcePenalties drops a source after repeated failures, and 9.5p1 does not know the option, so it cannot be switched off portably"
    - "Each sshd refusal has a control that changes only the certificate (ssh-keygen -s oracle with permissive or cleared extensions), so a refusal cannot come from a broken setup or a vacuous client invocation"
    - "Matrix values reach run: steps only through env (OPENSSH_VERSION), never by ${{ }} interpolation"

key-files:
  created:
    - .github/workflows/e2e.yml
    - test/e2e/negative_test.go
    - scripts/fuzz.sh
  modified:
    - .github/workflows/ci.yml
    - .github/rulesets/main-integrity.json
    - CONTRIBUTING.md
    - README.md

key-decisions:
  - "The ruleset change is applied by the owner from the PR branch after the three checks reported green on this PR and before approval (plan order, Pitfall 10), so this PR itself shows that the new contexts resolve; CONTRIBUTING records this as the exception to 'apply after merge'. Claude never runs apply-rulesets.sh (no admin, no owner-token writes)"
  - "The plan's '-L 0:127.0.0.1:9 -o ExitOnForwardFailure=yes' case was replaced: ssh rejects '-L 0:...' as a bad specification before connecting, so it would pass without reaching sshd. Local forwarding is checked with -W (sshd logs 'refused local port forward', client sees 'administratively prohibited'), remote forwarding with -R 0:... + ExitOnForwardFailure"
  - "Agent forwarding runs ssh with SSH_AUTH_SOCK pointing at a client agent plus -A (new helper sshWithAgent); -o ForwardAgent=<path> made ssh send no agent request in testing, which would make the refusal vacuous. harness_test.go stays unchanged"
  - "No signer or CLI defect surfaced: every TestSignerRefuses case is refused with its specific reason (bad_principal / bad_subject_key / usage error, or 'pinned CA key not present' at serve start)"

patterns-established:
  - "A new required check goes: workflow on the PR -> green on the PR -> ruleset JSON commit -> owner applies from the PR branch -> approval"

requirements-completed: [CA-02, CA-05, CA-06, CA-07, CA-08, REPO-01, REPO-02]

coverage:
  - id: D1
    description: "e2e (9.5p1) and e2e (10.5p1) build verified OpenSSH and run the whole e2e suite on GitHub's runners; TestIssueAcceptedBySSHD passes on both"
    requirement: CA-08
    verification:
      - kind: integration
        ref: "PR #5 runs 37269006141 (first, uncached) and 37269881022 (cached): job logs contain '--- PASS: TestIssueAcceptedBySSHD' for both matrix jobs"
        status: pass
    human_judgment: false
  - id: D2
    description: "Real sshd 9.5p1 and 10.5p1 reject a principal not listed, an untrusted CA, expired and not-yet-valid certificates, refuse local and remote port forwarding and agent forwarding for the signer's certificate, and allocate a PTY"
    requirement: CA-05
    verification:
      - kind: integration
        ref: "bash scripts/linux.sh with KEYROSTER_OPENSSH_PREFIX=openssh-9.5p1 and openssh-10.5p1: go test -tags e2e -count=1 -v ./test/e2e/... -> --- PASS: TestSSHDRejects (all 13 subtests) on both; CI run 37269881022 -> --- PASS: TestSSHDRejects on both"
        status: pass
    human_judgment: false
  - id: D3
    description: "keyroster ca issue refuses missing, empty, wildcard, comma-joined, whitespace-padded and uppercase principals, a certificate as --pubkey and RSA-2048, writes no certificate file, and the signer serves the next request; serve refuses to start when the pinned fingerprint names a certificate in the agent"
    requirement: CA-07
    verification:
      - kind: integration
        ref: "go test -tags e2e ./test/e2e/... -> --- PASS: TestSignerRefuses (9 subtests) on 9.5p1 and 10.5p1, locally and in CI run 37269881022"
        status: pass
    human_judgment: false
  - id: D4
    description: "scripts/fuzz.sh runs every fuzz target and fails on a failing target, on a package that cannot be listed, and when zero targets ran; CI job fuzz runs it at 30 s"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "bash scripts/linux.sh 'FUZZTIME=5s bash scripts/fuzz.sh' -> 'fuzz: all 4 targets passed'; scratch module without targets -> exit 1 'zero fuzz targets ran'; scratch module with a failing target -> exit 1 with corpus path; CI fuzz job 111634427069 -> 'all 4 targets passed (30s each)'"
        status: pass
    human_judgment: false
  - id: D5
    description: "Every uses: in e2e.yml and ci.yml is pinned to a full commit SHA with a version comment; permissions {} at top level, contents: read per job, persist-credentials: false"
    requirement: REPO-02
    verification:
      - kind: other
        ref: "! grep -E 'uses:' .github/workflows/e2e.yml | grep -v -E '@[0-9a-f]{40} # v' -> exit 0; bash scripts/check-pinned-actions.sh -> all 22 pinned; CI pinned-actions pass"
        status: pass
    human_judgment: false
  - id: D6
    description: "main-integrity requires build-test, lint, govulncheck, pr-title, e2e (9.5p1), e2e (10.5p1) and fuzz on main"
    requirement: REPO-01
    verification:
      - kind: other
        ref: ".github/rulesets/main-integrity.json lists exactly the seven contexts (integration_id 15368; the new check runs report app id 15368). Live state: gh api repos/Labontese/keyroster/rules/branches/main, checked after the owner runs scripts/apply-rulesets.sh at the merge gate"
        status: deferred
    human_judgment: true
    rationale: "Applying a ruleset needs admin rights; the owner runs scripts/apply-rulesets.sh at the Task 3 checkpoint, after this SUMMARY is written, and the continuation verifies it read-only through the rules API"
  - id: D7
    description: "CI is not presented as Windows OpenSSH 9.5p2 coverage: e2e.yml's header and CONTRIBUTING name portable 9.5p1 as the closest upstream code and plan 01-15's manual Windows check as the 9.5p2 evidence"
    requirement: CA-08
    verification: []
    human_judgment: true
    rationale: "Wording judgment (prohibition with verification: judgment); the owner reviews it in the PR"
  - id: D8
    description: "PR #5 is green on every check and waits for the owner at the merge gate"
    requirement: REPO-01
    verification:
      - kind: other
        ref: "scripts/gh-as-bot.sh pr checks p01/04-e2e-ci --watch on 310c775: all 11 checks pass"
        status: pass
    human_judgment: true
    rationale: "The ruleset application, the owner's approval and the squash merge happen at the Task 3 blocking-human merge gate, after this SUMMARY is written"

duration: 23min
completed: 2026-10-05
status: complete
---

# Phase 1 Plan 04: E2E and Fuzz CI Summary

**The signer's issuance path now runs in CI against real sshd built from verified portable OpenSSH 9.5p1 and 10.5p1. Both versions also reject every sshd negative case (principal, untrusted CA, expired, not yet valid, forwarding, agent), each paired with a control that succeeds. The CLI and signer refuse bad principals, certificate subjects and RSA-2048 without writing a file. A fuzz job runs all four targets for 30 s each. `e2e (9.5p1)`, `e2e (10.5p1)` and `fuzz` were green on PR #5 before they were added to the `main-integrity` JSON; the owner applies that JSON at the merge gate.**

## Performance

- **Duration:** 23 min
- **Started:** 2026-10-05T05:41:22Z
- **Completed:** 2026-10-05T06:04:15Z
- **Tasks:** 2 of 3 executed before the merge gate (Task 3 is the owner's ruleset application and approval)
- **Files modified:** 7 (3 created, 4 modified), 529 insertions, 5 deletions

## Accomplishments

- **Task 1 (tracer):** `.github/workflows/e2e.yml` and the E2E badge. On the first push both matrix jobs built OpenSSH from scratch and passed `TestIssueAcceptedBySSHD`. The tracer feedback gate (`end-of-phase`, automated-only verify) re-checked the PR before Task 2 started: green, so expansion continued.
- **Task 2:** `test/e2e/negative_test.go` (`TestSSHDRejects`, `TestSignerRefuses`), `scripts/fuzz.sh`, CI job `fuzz`, the three new contexts in `main-integrity.json`, and the required-check list plus the 9.5p2 note in CONTRIBUTING.md. All three new checks were green on the PR (head `9c1ef6b`) before the ruleset commit `310c775`. All 11 checks are green on `310c775`.

## PR

- **PR #5** `ci(e2e): run the issuance e2e suite against OpenSSH 9.5p1 and 10.5p1 and require it` (https://github.com/Labontese/keyroster/pull/5), branch `p01/04-e2e-ci`, opened by keyroster-bot.
- **Auto-merge is not enabled.** The bot's `gh pr merge --auto --squash` was denied by the local permission classifier ("Merge Without Review"). After approving, the owner enables auto-merge (squash) or squash-merges in the GitHub UI.
- The three implementation commits show `verified: true` (keyroster-bot signature, GitHub API).

## Recorded Facts

| Item | Value |
|---|---|
| OpenSSH build in CI, no cache (run 37269006141) | 9.5p1: 41 s; 10.5p1: 30 s (step "Build OpenSSH (verified tarball)") |
| OpenSSH build in CI, cache hit (run 37269881022) | under 1 s for both (`using cached OpenSSH`); cache restore 1-2 s |
| e2e suite in CI (cached run) | 9.5p1: 28 s step, `ok ... 25.6s`; 10.5p1: 28 s step, `ok ... 25.3s` |
| OpenSSH 9.5p1 build in WSL (Daniel-PC) | 3 min 26 s |
| Cache key | `openssh-Linux-<version>-<sha256 of scripts/build-openssh.sh>` |
| Runner OpenSSL | 3.0.13 (Ubuntu 24.04); no extra packages needed |
| Fuzz job | 2 min 41 s; 4 targets × 30 s, all passed |
| Final required-check list (main-integrity.json) | `build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)`, `fuzz` (integration_id 15368) |
| Signer/CLI defects exposed by the negative cases | none |
| `go.mod` / `go.sum` | unchanged (no module added) |

## Task Commits

1. **Task 1: E2E workflow and badge (tracer).** `28507a2` (ci)
2. **Task 2: negative cases and fuzz job.** `9c1ef6b` (test); **required checks and CONTRIBUTING.** `310c775` (ci)
3. **Task 3: merge gate.** No commit (the owner applies the ruleset and approves; GitHub squash-merges)

**Plan metadata:** the `docs(01-04): complete e2e CI plan` commit on the same PR branch.

## Files Created/Modified

- `.github/workflows/e2e.yml`: E2E workflow (matrix 9.5p1/10.5p1, cache, log upload on failure)
- `test/e2e/negative_test.go`: `TestSSHDRejects`, `TestSignerRefuses`, helpers `newCAEnv`, `newUserKey`, `oracleCert`, `sshWithAgent`, `runKeyroster`
- `scripts/fuzz.sh`: runs every fuzz target, fails on zero targets
- `.github/workflows/ci.yml`: job `fuzz`
- `.github/rulesets/main-integrity.json`: three new required contexts
- `CONTRIBUTING.md`: required-check table, 9.5p2 note, ruleset rollout rule for new checks
- `README.md`: E2E badge

## Decisions Made

See `key-decisions` above.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug in the plan's test spec] `-L 0:127.0.0.1:9` never reaches sshd**
- **Found during:** Task 2
- **Issue:** ssh exits 255 with "Bad local forwarding specification '0:127.0.0.1:9'" before connecting, so the planned assertion would pass whatever sshd did.
- **Fix:** `no_local_port_forwarding` uses `-W 127.0.0.1:<sshd port>` (a direct-tcpip channel, refused by sshd with "administratively prohibited"). `no_remote_port_forwarding` uses `-R 0:127.0.0.1:9 -o ExitOnForwardFailure=yes` ("remote port forwarding failed"). Both have controls with a permissive oracle certificate that succeed.
- **Files modified:** test/e2e/negative_test.go
- **Committed in:** `9c1ef6b`

**2. [Rule 3 - Blocking] OpenSSH 10.x PerSourcePenalties dropped later connections**
- **Found during:** Task 2 (first local run against 10.5p1)
- **Issue:** After four failed authentications, sshd 10.5p1 penalised 127.0.0.1 and dropped every later connection ("kex_exchange_identification: Connection reset"). `PerSourcePenalties no` would make sshd 9.5p1 fail `sshd -t`.
- **Fix:** each authentication refusal gets its own sshd with the default config. The cases that authenticate share one sshd.
- **Files modified:** test/e2e/negative_test.go
- **Committed in:** `9c1ef6b`

**3. [Rule 1 - Vacuous test] Agent forwarding needed a real client agent**
- **Found during:** Task 2
- **Issue:** `sshLogin` clears `SSH_AUTH_SOCK`, so `-A` forwarded nothing and `test -z "$SSH_AUTH_SOCK"` passed vacuously. The control case caught this. `-o ForwardAgent=<path>` also sent no agent request.
- **Fix:** new helper `sshWithAgent` (same arguments as `sshLogin`, `SSH_AUTH_SOCK` set to a client agent), used with `-A`. `harness_test.go` is unchanged.
- **Files modified:** test/e2e/negative_test.go
- **Committed in:** `9c1ef6b`

**4. [Rule 2 - Missing critical] fuzz.sh fails when a package cannot be listed**
- **Found during:** Task 2
- **Issue:** `go test -list ... | grep || true` would hide a compile failure and silently drop that package's targets.
- **Fix:** a failing `go test -list` counts as a failure.
- **Files modified:** scripts/fuzz.sh
- **Committed in:** `9c1ef6b`

**5. [Permission gate] Ruleset not applied by Claude; auto-merge not enabled**
- **Found during:** Task 1 (auto-merge) and Task 2 (ruleset)
- **Issue:** `apply-rulesets.sh` needs admin rights (owner token, which Claude must not use for writes). The bot's `gh pr merge --auto --squash` was denied by the permission classifier.
- **Handling:** both are handed to the owner in the Task 3 checkpoint (ruleset before approval, auto-merge or squash merge by the owner). CONTRIBUTING documents the ruleset order.

### Additions beyond the plan

- Controls in `TestSSHDRejects` (`control_*` subtests): the signer certificate logs in, and an ssh-keygen certificate with forwarding extensions forwards ports and the agent. A certificate with cleared extensions gets no PTY.
- `TestSignerRefuses/empty_principal` (`--principal ""`) next to `no_principal` (flag absent), to cover both readings of "no principal".

---

**Total deviations:** 4 auto-fixed (2 Rule 1, 1 Rule 2, 1 Rule 3) plus 1 permission gate. **Impact:** the tests assert more than the plan specified and none of them can pass vacuously. No scope creep, and no module was added.

## Issues Encountered

- The first `pr create` + `pr merge --auto` call was denied as a whole. The PR was then created alone. Auto-merge stays with the owner.
- OpenSSH 10.1+ creates the forwarded agent socket under `~/.ssh/agent/`, not `/tmp`. The tests only check whether `SSH_AUTH_SOCK` is set.

## User Setup Required

At the merge gate the owner runs `bash scripts/apply-rulesets.sh` (from the `p01/04-e2e-ci` checkout) before approving.

## Next Phase Readiness

- After the merge gate, every PR needs `e2e (9.5p1)`, `e2e (10.5p1)` and `fuzz`. Open PRs based on an older `main` (for example Dependabot) need a rebase to get the new workflow.
- Plan 01-07 (which removes the skeleton pin flags) migrates the e2e helpers. `newCAEnv`/`startSigner` are the call sites to update.
- Plan 01-15 supplies the Windows OpenSSH 9.5p2 evidence that CI does not provide.

## Self-Check: PASSED

- Files present: `.github/workflows/e2e.yml`, `test/e2e/negative_test.go`, `scripts/fuzz.sh`, `.github/workflows/ci.yml`, `.github/rulesets/main-integrity.json`, `CONTRIBUTING.md`, `README.md` (`git diff --name-only e1e6122..310c775`).
- Commits present on `origin/p01/04-e2e-ci`: `28507a2`, `9c1ef6b`, `310c775`, all verified. `git rev-list --count e1e6122..HEAD` = 3 before the docs commit.
- Acceptance: e2e.yml has `permissions: {}`, `persist-credentials: false`, matrix exactly `9.5p1`/`10.5p1`, and `${{ matrix.openssh }}` only on `name:`/`env:` lines. README has `pre-alpha` in its first 15 lines and the e2e badge. negative_test.go has `TestSSHDRejects` and `TestSignerRefuses` with named subtests. CONTRIBUTING lists the three checks and the 01-15 note. main-integrity.json lists exactly the seven contexts.
- Pending at the gate: the rules API check for the three contexts (after the owner applies the ruleset).
