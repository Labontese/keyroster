---
phase: 02-passkey-login-mvp
plan: 09
subsystem: auth
tags: [directory, sshsig, admin-api, enrollment, passkey, quorum, mirror]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-01 directory document (Parse, Validate, CheckPolicy, VerifySignatures); 02-03 signer InstallDirectory/GetDirectory; 02-04 audit verify of directory_install leaves; 02-06 server core (signerAPI seam, currentStatus, dropStatus, fakeSigner); 02-07 admin API (requireAdminLimit, signed admin message); 02-08 registration and pending credentials (PendingAnswer, PendingState)"
provides:
  - "One directory edit pipeline (cmd/keyroster/dirpipe.go): fetchVerifiedDirectory, editDirectory, confirmSign, stdinIsTerminal"
  - "keyroster user approve/list/disable/enable and keyroster directory show/sign/install"
  - "Server directory mirror currentDirectory (fail-closed, one status cache) replacing 02-07's dirCache"
  - "GET/POST /api/v1/admin/directory and GET /api/v1/admin/users, the install forwarded under pendingMu with the credential_not_pending check and self-healing DeleteBound"
  - "signerAPI.InstallDirectory with socketSigner and fakeSigner (forced and chain modes, loseAnswer, hold hook)"
  - "internal/directory.Diff and AlgName"
  - "docs/runbooks/enroll-user.md"
affects: [02-10, 02-11, 02-12, 02-13, phase-4-directory-binding]

actuals:
  tokens: 49800
  tasks: 2
  commits: 5
plan_head_before: 961421e284368e667fef78b1b88e331002b4fc41
plan_head_after: d7a62182576bbac7540759dd690e87fd322ae264

tech-stack:
  added: []
  patterns:
    - "Every directory edit goes through editDirectory: trust against root pins, base against policy admins (signatures before parsing), successor, Validate, CheckPolicy, diff, confirmSign, SSHSIG, install or proposal"
    - "One serverclient.Client and one agent signer per admin command (adminSession), so the custody banner prints once"
    - "currentDirectory is the only reader of the installed directory in internal/server"
    - "pendingMu is the outermost lock; install steps 1-5 and the reinvite path's lookups and write run under it"
    - "CLI tests count only SSHSIG sign requests under keyroster/directory/v1 (countingAgent), since every admin API request is a sign request too"

key-files:
  created:
    - internal/directory/diff.go
    - internal/directory/diff_test.go
    - internal/server/directory.go
    - internal/server/directory_test.go
    - cmd/keyroster/dirpipe.go
    - cmd/keyroster/directory.go
    - cmd/keyroster/dirpipe_test.go
    - test/e2e/approve_test.go
    - docs/runbooks/enroll-user.md
  modified:
    - internal/server/signer.go
    - internal/server/server.go
    - internal/server/admin.go
    - internal/server/enroll.go
    - internal/server/server_test.go
    - internal/server/admin_test.go
    - internal/serverdb/db.go
    - internal/serverdb/db_test.go
    - internal/serverclient/admin.go
    - cmd/keyroster/user.go
    - cmd/keyroster/commands.go
    - test/e2e/server_test.go

key-decisions:
  - "The mirror replaces 02-07's version-and-hash dirCache: enroll and user add read the directory through currentDirectory too, so there is one fail-closed accessor (a Status at version 0 now makes no signer read)"
  - "fetchVerifiedDirectory verifies the served directory's signatures against the policy admins before it parses the bytes, and refuses a version that disagrees with the parsed document or a version 0 answer that carries bytes"
  - "keyroster user list prints the users of the verified directory with CLI-computed fingerprints; the server's own users list is never printed, because a fingerprint there is text the server chose (T-02-93)"
  - "Without --out at a quorum above 1, the proposal goes to keyroster-directory-v<N> in the working directory, checked before anything is signed"
  - "directory sign refuses an admin who already signed; a second signature by one admin counts once at the signer"

patterns-established:
  - "Directory pipeline: verify, build, validate, diff, confirm, sign, install or propose"
  - "Server install: base, newlyBound/bound, pending check, forward, dropStatus, DeleteBound, all under pendingMu"

requirements-completed: []  # AUTH-01 completes in 02-13 after a real-browser registration; KEY-02 was completed in 02-04 (plan <output>)

coverage:
  - id: D1
    description: "An admin binds a registered passkey with user approve --fingerprint through a verified, diffed, SSH-signed directory version that the server forwards and the signer installs; the first admin enrolls the same way; audit verify counts the installs"
    requirement: AUTH-01
    verification:
      - kind: e2e
        ref: "test/e2e/approve_test.go#TestEnrollApproveEndToEnd"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/dirpipe_test.go#TestDirectoryPipeline"
        status: pass
    human_judgment: false
  - id: D2
    description: "AUTH-01 edges: adjacency (duplicate credential across users refused before signing), empty (no pending passkey, unknown fingerprint, active user without credential), idempotency (approve_twice), concurrency (no lost update)"
    requirement: AUTH-01
    verification:
      - kind: unit
        ref: "cmd/keyroster/dirpipe_test.go#TestDirectoryPipeline/duplicate_credential_across_users_not_signed|no_pending_credential|unknown_fingerprint|active_user_without_credential_not_signed"
        status: pass
      - kind: e2e
        ref: "test/e2e/approve_test.go#TestEnrollApproveEndToEnd/approve_twice"
        status: pass
      - kind: e2e
        ref: "test/e2e/approve_test.go#TestApproveConflictNoLostUpdate"
        status: pass
    human_judgment: false
  - id: D3
    description: "Quorum above 1: proposal written with 1 of 2 signatures, install refused by the signer, directory sign confirm rule (--yes, terminal prompt), same admin counts once, co-signed proposal installs"
    verification:
      - kind: e2e
        ref: "test/e2e/approve_test.go#TestApproveQuorumTwo"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/dirpipe_test.go#TestDirectorySignConfirm"
        status: pass
    human_judgment: false
  - id: D4
    description: "Server mirror fails closed and follows the status SHA-256; an install through the server is read by the very next request; the install route's body limit fits the signer's frame and no more"
    verification:
      - kind: unit
        ref: "internal/server/directory_test.go#TestDirectoryMirror"
        status: pass
      - kind: unit
        ref: "internal/server/directory_test.go#TestDirectoryInstallBodyLimit"
        status: pass
    human_judgment: false
  - id: D5
    description: "Install ordering and cleanup: a reinvite waits for a running install, a proposal written before a reinvite is refused (credential_not_pending), cleanup heals an orphan and never touches another user's or an open invite's state, and a failed cleanup still reports the install"
    verification:
      - kind: unit
        ref: "internal/server/admin_test.go#TestDirectoryInstallPending"
        status: pass
      - kind: unit
        ref: "internal/server/admin_test.go#TestDirectoryInstallCleanup"
        status: pass
      - kind: e2e
        ref: "test/e2e/approve_test.go#TestApproveProposalAfterReinvite"
        status: pass
    human_judgment: false
  - id: D6
    description: "Enrollment runbook (docs/runbooks/enroll-user.md): out-of-band fingerprint comparison, quorum, stale and discarded proposals, look before you retry, residual risk"
    verification: []
    human_judgment: true
    rationale: "Runbook clarity and fitness for an operator is a judgment; only the presence of the required statements is checked by grep"

duration: about 40 min
completed: 2026-10-21
status: complete
---

# Phase 2 Plan 09: Approve Summary

**`keyroster user approve NAME --fingerprint FP` binds a registered passkey through an admin-signed directory version. The CLI verifies the trust bundle and the installed base, then diffs, confirms and SSH-signs the new version. The server forwards it under `pendingMu` with a `credential_not_pending` check, a fail-closed mirror and self-healing cleanup. The first admin enrolls the same way as any user.**

## Performance

- **Duration:** about 40 min of wall-clock execution (2026-10-21T17:41:19Z to about 18:20Z), not counting the earlier planning and review rounds
- **Tasks:** 2 of 3 executed. Task 3 is the owner's merge gate, which this executor does not run.
- **Files modified:** 21 outside `.planning`

## Delivery

- **Branch:** `p02/09-approve`, created from origin/main `ada1283`. It carries the orchestrator's `961421e docs(phase-02): mark 02-08 complete ...`.
- Before the push, `git fetch origin` showed origin/main still at `ada1283`, so no rebase was needed.
- **PR:** keyroster-bot opens it after the one push that carries this SUMMARY. Title: `feat(cli): approve passkeys into an admin-signed directory`. The PR number and the check results go in the merge-gate checkpoint. They do not exist before the push (same as 02-06 to 02-08).
- **Auto-merge is not enabled.** This is an environment rule: the orchestrator enables auto-merge after its own pre-merge review. The plan's "PR is open with auto-merge" line is therefore deliberately unmet.

## The pipeline (cmd/keyroster/dirpipe.go)

1. **`fetchVerifiedDirectory`** is the one fetch-and-verify step.
   - It runs `Trust` against the saved root pins, then `GET /api/v1/admin/directory`, a body-less signed GET.
   - For a version above 0, it runs `directory.VerifySignatures` against the root-verified policy's admins (the quorum must be met), and only then `directory.Parse`.
   - It refuses a reported version that is not the parsed one, and a version 0 answer that carries bytes.
   - Its result is never nil with a nil error, and `Policy` is always set. "Nothing installed" is exactly `Version == 0` with a nil `Dir`.
2. **The successor.** `next` is a deep copy of the base, or a new genesis (version 1, all-zero prev), with version + 1 and prev = SHA-256 of the base bytes. Then: `mutate`, `Sort`, `Validate`, `CheckPolicy`. An edit that changes nothing is refused.
3. **Diff and confirmation.** It prints `directory.Diff`, the base, and the new SHA-256. Then `confirmSign`:
   - `--yes` reads nothing;
   - on a terminal it asks `Sign directory version N? [y/N]` and accepts only y or yes;
   - without a terminal it refuses.
   The confirmation comes after the diff and before any agent request.
4. **Signature.** SSHSIG under `keyroster/directory/v1`, with the admin key in ssh-agent (`--admin-key` or `admin_key`).
5. **Install or proposal.**
   - At quorum 1 without `--out`, it POSTs to the server, which forwards to the signer.
   - Otherwise it writes a proposal directory.
   - On success it prints the version and the SHA-256 the CLI computed itself, and the server's answer must match them.

## Proposal layout

- `DIR/directory.json`: the canonical bytes.
- `DIR/directory.json.sigs`: armored SSHSIG blocks, separated by newlines (the root sign convention, appended with `appendSignature`).
- `DIR/base.sha256`: a note for admins (`<sha256> (version N)` or `none (genesis)`). It is never read.
- `directory sign` and `directory install` read only the first two files.
- The default `DIR` (quorum above 1, no `--out`) is `keyroster-directory-v<N>` in the working directory. It must not exist, and this is checked before signing.

## Endpoints

| Route | Wrapped like | Answers |
|---|---|---|
| `GET /api/v1/admin/directory` | `rateLimited(adminLimit)` + `requireAdmin` | 200 `{"version","directory","sigs","authorized"}` (base64 std); 503 `signer unavailable` when the mirror cannot serve the Status's version |
| `POST /api/v1/admin/directory` | `rateLimited(adminLimit)` + `requireAdminLimit(maxDirectoryInstallBody)` (1 485 824 bytes, derived from `wire.MaxDirectoryFrame`) | 200 `{"version","sha256","leaf_index"}`; 400 `malformed request` / `directory_invalid`; 403 `directory_quorum_not_met` / `directory_exceeds_policy`; 409 `directory_version_chain` / `credential_not_pending`; 413; 503 `signer unavailable` (base unavailable, signer undecided, or transport error with unknown outcome) |
| `GET /api/v1/admin/users` | `rateLimited(adminLimit)` + `requireAdmin` | 200 `{"directory_version","users":[{"name","status","credentials":[{"fingerprint","alg","synced"}]}],"pending":[{"name","invite_expires_at","invite_used","credentials"}]}` |

## AUTH-01 edge evidence

- **Adjacency.** `duplicate_credential_across_users_not_signed`: bob's pending passkey carries alice's bound credential ID. `Validate` refuses ("bound more than once"). No directory sign request reaches the agent and nothing is posted.
- **Empty.**
  - `no_pending_credential` covers the pending route's 404 and an open invite with no passkey.
  - `unknown_fingerprint` and `active_user_without_credential_not_signed` (`user enable` of a credential-less user) are refused before signing.
  - `approve_without_fingerprint_exits_2` (unit) and its e2e twin exit 2 and list the fingerprints.
- **Idempotency.** e2e `approve_twice` exits non-zero with `no pending credential`, and the signer's directory stays at version 2.
- **Concurrency.** e2e `TestApproveConflictNoLostUpdate`:
  1. proposals A and B are built from one base;
  2. A installs;
  3. B is refused with `directory changed since it was read` and `re-run the command that produced it`;
  4. re-running B's approval gives version 2 with both carol and dave.

## Task Commits

1. **Task 1 (tracer): end-to-end approval.** `f80c755` (feat).
   - Tracer gate: interactive, end-of-phase, automated-only verify. `TestEnrollApproveEndToEnd|TestRegisterPasskeyPending` (WSL, OpenSSH 10.5p1) and `go test ./internal/directory/... ./cmd/keyroster/...` passed before the commit, and capslock (91/91), dep-firewall and testonly-firewall were green.
   - Logged: "Tracer verified end-to-end — expanding".
2. **Task 2 (tdd="true"): edge cases, co-signing, unit tests, runbook.**
   - `d839f04` (test): every test of the plan's Task 2 list plus `TestDirectoryInstallRefusals`, `TestDeleteBound`, `TestDiff` and `TestDirectoryPeerText`. RED for the user list fix.
   - `e905786` (fix): `user list` prints from the verified directory (GREEN).
   - `8c2044e` (chore): gosec G101 annotation on the `credential_not_pending` reason code.
   - `d7a6218` (docs): `docs/runbooks/enroll-user.md`.
3. **Task 3, merge gate.** Not attempted. It is the owner's `checkpoint:human-action` (`gate="blocking-human"`).

**Plan metadata:** `docs(02-09): complete approve plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 2; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED** (`d839f04`): `TestDirectoryPeerText/list_ignores_server_fingerprints` and the `user list` assertion of `TestDirectoryPipeline/approve_disable_enable_round_trip` failed on `f80c755`'s `cmd/keyroster/user.go`.
  - The first test printed the server's user `mallory` with a fingerprint equal to the attacker's root pin.
  - The second found no users, because the fake server's users list is empty.
  - Semantic assessment: the target tests ran and failed on the planned assertion (server-chosen text printed, verified users missing), not on build, setup or fixture errors. Go output is not a format `tdd-red-evidence` parses (01 decision), so the evidence is recorded here.
- **GREEN** (`e905786`): both tests pass.
- **Tests written after Task 1's code.** For these, the bite was shown with mutants. Each mutant was applied with a script, run against the named test, and restored; `git status` was clean afterwards.
  - Server mutants, all killed:
    - the reinvite path without `pendingMu`: `reinvite_waits_for_running_install` (the reinvite answered 201 while the install was held);
    - no `dropStatus` after the install: `install_then_immediate_edit_sees_new_base`;
    - `DeleteBound` matching the ID only: `orphan_pending_cleaned_on_next_install` (erin's X deleted);
    - cleanup with newlyBound only: the same test (dave's orphan left);
    - no pending check: `install_refuses_credential_no_longer_pending` (200);
    - no `dropStatus` on a mirror mismatch: `mirror_sha_mismatch_refused`;
    - the held entry served on a GetDirectory failure: `mirror_refresh_failure_fails_closed`;
    - the install route on the default `maxAdminBody`: `at_signer_cap_forwarded` (413);
    - a cleanup failure answered 500: `cleanup_failure_still_reports_install`.
  - CLI mutants, all killed:
    - `confirmSign` always consenting: `TestDirectorySignConfirm`;
    - a non-admin signature skipped: `directory_sign_refuses_non_admin_sig`;
    - signature verification skipped: `directory_sign_refuses_tampered_doc`;
    - the base not verified: `fake_base_refused`;
    - no prev check: the stale tests;
    - the stale message saying "re-run this command": the stale tests;
    - no `Validate` before signing: `duplicate_credential_across_users_not_signed` and `active_user_without_credential_not_signed`;
    - the install answer not checked: `install_answer_mismatch`;
    - approve's 404 not mapped: `no_pending_credential`.
  - One mutant first survived. Removing only `s.mirror.entry = nil` changes nothing observable, because a failed read never served the held entry. It was replaced by the real fail-open mutant (serve the held entry on a GetDirectory failure), which the test kills.

## Verification run

- **Windows (go1.27.3):**
  - `gofmt -l .` printed nothing.
  - `go vet ./...`, `GOOS=linux go vet ./...`, `GOOS=darwin go vet ./...` and `go vet -tags e2e ./test/e2e/` are clean.
  - `go test -count=1 ./...` passed, all 21 packages with tests (internal/winagent included, 40 s).
  - `go test -count=1 -v -run TestDirectorySignConfirm ./cmd/keyroster/...` shows both PASS lines.
- **WSL (scripts/linux.sh, script files under the scratchpad):**
  - The targeted `-race -v -run "TestDirectoryMirror|TestDirectoryInstallBodyLimit|TestDirectoryInstallPending" ./internal/server/...` shows every required PASS line, with no DATA RACE and no timeout.
  - `go test -race -count=1 ./...` exited 0.
  - `go vet ./...` and the e2e vet are clean; `gofmt` (the GOROOT one) is empty.
  - golangci-lint v2.14.0: the first run found 3 issues (gosec G115 and ineffassign in `dirpipe_test.go`, gosec G101 false positive on the reason-code constant). Fixed in `d839f04` and `8c2044e`; the second run reports 0 issues.
  - `scripts/capslock-check.sh`: 91 pairs, baseline 91, unchanged (`internal/directory` gained `diff.go`). `scripts/dep-firewall.sh` and `scripts/testonly-firewall.sh` are clean.
- **e2e in WSL (OpenSSH 10.5p1):**
  - `TestEnrollApproveEndToEnd`, `TestApproveConflictNoLostUpdate`, `TestApproveQuorumTwo` and `TestApproveProposalAfterReinvite` all PASS.
  - The other server-facing e2e tests were run at HEAD and pass: `TestUserAddInvite`, `TestRegisterPasskeyPending`, `TestServerInitEndToEnd`, `TestServerSIGHUPDuringStartup`, `TestServerRefusesStart`, `TestLoginRefusals`, `TestLoginSignerEndToEnd` and `TestAuditLoginAcrossPolicyChange`.
  - Not run locally: the rest of the e2e suite, the 9.5p1 lane, govulncheck and the macOS/Windows CI lanes. CI runs them; the results are in the checkpoint.
- Every commit of `961421e..HEAD` carries an SSH signature (`gpgsig` header checked on each).

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Deferred-items rows addressed to 02-09 (each marked "Status for 02-09: resolved" in deferred-items.md)

1. **Verify-before-body (02-07 pre-merge, owner decision D2).**
   - The install route uses `requireAdminLimit(maxDirectoryInstallBody, ...)`, and its doc comment states the real order: a declared Content-Length over the limit gets 413 before any signature work, with the nonce unused; a body sent without a length is read only after Verify.
   - The plan's "before authentication" and T-02-36 wording is not repeated.
   - `over_route_limit_413_no_signer_call` sends its bodies with a length, so the unsigned copy also gets 413. It asserts the nonce is unused by using it again successfully.
2. **The changed admin message (origin and signed body-digest header).**
   - All new GETs pass a nil input to `AdminJSON`, so there is no body and the signature covers the digest of the empty body.
   - The server tests build requests with `signedReq`.
3. **No global limiter on the admin route class.** The three routes are wrapped like their siblings, with the per-client bucket only. The 02-10 part of that row stays open.
4. **PendingAnswer and the invariant.**
   - `user approve` decodes `serverclient.PendingAnswer`, validates `.Invite` and every `.Credentials` entry (`checkPendingInvite`, `checkPendingCredential`), and refuses `errBadPendingAnswer` when "used exactly when one passkey is pending" does not hold.
   - `DeleteBound` keeps that invariant. It deletes a pending credential only for the binding's own user, then the account in the same transaction once it is empty and its invite is used or expired. `TestDeleteBound` covers this, including the open-invite clause on a state forced by SQL.
5. **e2e step 5 and the idempotency path.**
   - Step 5 now expects exit 1 with `admin1 has no pending enrollment`. 02-08's wording is unchanged.
   - `user approve` maps the pending route's 404 `not pending` to its own "no pending credential for NAME", so `approve_twice` holds.
6. **02-07 D4 handover.** `reinvite_directory_user` and `reinvite_directory_user_with_pending_row` now also assert that the fake signer's InstallDirectory count is 0. Their old "directory changed" assertions could not fail.

### Auto-fixed issues and interpretations

7. **[Rule 1, consistency] The mirror replaces 02-07's `dirCache`.**
   - The plan makes `currentDirectory` the accessor "every reader goes through". 02-07's `installedDirectory`, with its version-and-hash cache, was a second cache, and it served a fresh read that did not match the Status.
   - `handleAddUser` and enroll begin/finish now read through `currentDirectory`. A Status at version 0 now makes no signer read.
   - Three 02-07 tests assumed a read at version 0 and were adjusted to install a directory or report a matching SHA-256 first: `add_creates_pending_account_and_invite`, `concurrent_add_same_name/held` and `unparsable_directory_fails_closed`. Their intent is unchanged. `directory_cache` and `directory_cache_follows_status` pass unchanged.
8. **[Rule 2, T-02-93] `user list` prints the verified directory.**
   - The plan had `user list` print the GET users answer. A fingerprint in that answer is text the server chose, and the test shows that an attacker's root pin passes a format check.
   - `user list` now calls `fetchVerifiedDirectory` and computes fingerprints itself. It takes only the pending accounts from the route, with every field validated.
   - The route keeps the planned shape. e2e step 5 still reaches it.
   - RED `d839f04`, GREEN `e905786`.
9. **[Interpretation] `fetchVerifiedDirectory(ctx, *adminSession)`** instead of `(ctx, env cliEnv, adminKey string)`. cmd/keyroster has no `cliEnv` type. One Client and signer per command keeps the KEY-06 banner to one print; `software_custody_banner_once` covers `user approve`.
10. **[Interpretation, T-02-93 pattern] Signatures before parsing.** The plan lists Parse, then VerifySignatures. The CLI verifies the signatures over the exact bytes first, as the signer does. It also checks the reported version against the parsed one, and that a version 0 answer is empty.
11. **[Rule 3] `exitError` in cmd/keyroster/commands.go.** `dispatch` printed the command list for every exit 2. `user approve` without `--fingerprint` needs exit 2 with only its own message.
12. **[Rule 3] Files outside files_modified.**
    - The request and answer types and paths in internal/serverclient/admin.go, shared by the server and the CLI.
    - `serverdb.ListPending`, for the users route.
    - `serverOpts.AdminQuorum` in test/e2e/server_test.go.
    - `DeleteBound` and `PendingCredentialUser` take a `ctx` like every other accessor.
13. **[Interpretation] The default proposal directory** (see "Proposal layout"), and the refusal of a second signature by the same admin in `directory sign`. e2e `same_admin_counts_once` also shows that a hand-assembled `.sigs` file with one admin's block twice is refused by the signer at install.
14. **[Interpretation] The install handler checks the field sizes against the signer's message caps** (`wire.MaxDirectory`, `wire.MaxDirectorySigs`) and answers 400 `malformed request`. Without the check, `socketSigner` cannot frame such a request and it would surface as 503. This is not a second body limit: the route's one body limit is still `maxDirectoryInstallBody`.
15. **[Interpretation] Signer refusals of class unavailable or internal** (`state_unavailable`, `trust_changed`) answer 503 `signer unavailable`. The plan maps only 409, 403 and 400.
16. **[Rule 2] `DeleteBound` also deletes the registration sessions** of each account it deletes.
17. **[Test infrastructure]**
    - `fakeSigner` chain mode derives Status (version, SHA-256, authorized) from the held bytes. Without this the immediate-edit tests could not converge.
    - New helpers: `statusNow`, `setChain`, `setInstall`, `setLoseAnswer`, `heldDirectory` and `lastInstallRequest`.
    - The CLI's `countingAgent` counts only directory signatures.
18. **[Scope] Tests beyond the plan's list:**
    - server: `TestDirectoryInstallRefusals` and `TestDeleteBound`;
    - CLI: `approve_disable_enable_round_trip`, `quorum_two_writes_proposal`, `approve_without_fingerprint_exits_2` and `TestDirectoryPeerText` (padded 404 and 409, a forged fingerprint, a forged pending name, ignored server fingerprints, an install answer mismatch, banner once);
    - diff: `TestDiff`.
19. **[Rule 1, lint]** gosec G115 and ineffassign in the new test, and a gosec G101 false positive on the reason-code constant (annotated, not renamed: the name is the wire value's).

### Environment overrides

20. Auto-merge not enabled; one push; the PR number and the check results go in the merge-gate checkpoint. ROADMAP is not marked complete. `requirements-completed: []` and no `requirements.mark-complete` call, as the plan's `<output>` says.

**Total deviations:** 20. That is 6 deferred-row resolutions, 2 Rule 1 fixes (the mirror, lint), 2 Rule 2 additions (`user list`, session cleanup), 2 Rule 3 blockers, 6 interpretations, 1 scope item and 1 environment override.

**Impact on plan:**
- No new module and no capslock change.
- Every security property the plan names is pinned by a test that bites. *Corrected in the pre-merge review:* T-02-43 was not pinned on the edit path. The `confirmSign` mutant above changed the shared helper, which only `directory sign` exercised. The call site in `editDirectory` and the diff-before-sign order survived mutation. `TestEditConfirm` now pins them (see "Pre-merge review fixes").
- The one design change with an outward effect: `user list` prints the verified directory instead of the server's users.

## Relation to the phase-4 todo (bind admin-signed directories to a deployment)

Not fixed here, and not made worse.
- The directory format and namespace are unchanged.
- The server forwards admin-signed versions unchanged.
- The CLI only signs versions it built on a base it verified for the root-pinned deployment it talks to.

The exposure the todo describes remains. A genesis proposal signed for deployment A, with admins shared with B, could be installed at a fresh deployment B:
- through `directory install DIR`;
- through any socket peer of B's signer.

There is one incidental narrowing. Through B's server such a proposal is refused with `credential_not_pending` unless its credentials happen to be pending for the same users at B. That check is not a deployment binding and is not claimed as one. A compromised server, or direct socket access, still bypasses it.

## Issues Encountered

- **Bash heredocs with Python.** `\n` inside Go string literals turned into real newlines once in a Python heredoc edit, and an apostrophe broke a heredoc; both were caught by gofmt and vet and fixed with the Edit tool. 02-08 recorded the same issue.
- **A test helper bug.** `buildDir` used `d, d.Version, d.Prev = p, ...`. Go evaluates `d.Version` on the old `d`. Found by the stale-proposal tests and fixed before the commit.

## Not exercised (UNVERIFIED)

- **Whether a re-registration on the same authenticator after a reinvite replaces a passkey already bound there.** The pending row gets a new user handle when an install wins, and `reinvite_waits_for_running_install` asserts that. The authenticator side is authenticator behaviour, and no real authenticator ran.
- **The real signer receiving a full-size directory through the server.** The server side runs in `at_signer_cap_forwarded`. The signer's frame acceptance rests on 02-03's `install_exactly_max_directory_frame`.
- **`stdinIsTerminal` against a real terminal.** The tests replace the variable, and the e2e runs without a terminal. In the e2e, only `directory sign` takes the refusal path; no e2e command reaches the prompt. *Corrected in the pre-merge review:* this line used to imply that both signing commands were covered. At review time `user approve`, `disable` and `enable` had neither their refusal path nor their prompt path tested. `TestEditConfirm` now covers both against the fake server.
- **HTTP/2 buffering on the larger install route.** It is derived from 02-07's measurement (the D6 todo), not measured here.
- **Registration in a real browser** (02-13).
- **CI-only:** govulncheck, the e2e 9.5p1 lane, the rest of the e2e suite and the macOS/Windows lanes. They are reported in the checkpoint.

## Known Stubs

None. Every command and route is wired to real data; the proposal's `base.sha256` is a deliberate note, never read.

## Threat Flags

None beyond the plan's threat model.
- The three routes are T-02-42..46, T-02-99, T-02-101 and T-02-119.
- The `user list` change narrows T-02-93's surface.

## User Setup Required

None.

## Next Phase Readiness

- **02-10:** sign-in and `withSession` read the directory through `currentDirectory` (fail-closed, follows Status). The admin route class keeps its per-client limiter only; 02-10's own route class is its business.
- **02-11:** role, group and host-group commands call `editDirectory` with a `mutate`, and `host principals` calls `fetchVerifiedDirectory`. Version 0 means nil `Dir`.
- **02-12:** the directory a login is checked against is the signer's, not the server mirror's.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in `key-files.created` exists.
- Commits `f80c755`, `d839f04`, `e905786`, `8c2044e` and `d7a6218` are ancestors of HEAD and SSH-signed.
- Task 1 and Task 2 acceptance greps and named cases were re-run and pass:
  - `requireAdminLimit(` count 1, `signerclient` imported only in signer.go, two `dropStatus()` calls in directory.go;
  - `pendingMu` locked in directory.go and admin.go, one field;
  - `pending_cleanup_failed`, `id = ? AND user_name = ?`, `invite_used_us IS NOT NULL`;
  - `confirmSign(` in directory.go, and `fetchVerifiedDirectory` 3 times in directory.go;
  - the 11 dirpipe case names, the runbook statements, and `look before you retry` exactly once.
- No private network detail in any file this plan changed (grep for 100.x, 10.x, 192.168.x, tailnet names: none).

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-21 (before the merge gate)*

## Pre-merge review fixes

Review of PR #49 at `3f67e3c`. Every finding below was confirmed by both skeptics, unless marked split. Fixed on 2026-10-22, one commit per finding (overlapping findings share one), each with a test shown to fail before the fix, or for a test-only finding, a mutant shown to survive before and to be killed after.

### Owner decisions (2026-10-21, Daniel, through the orchestrator; replies verbatim)

- **F1, install confirmation:** "Ärligt nu, kvitto i fas 4 (Rekommenderas)".
  - In this PR: honest wording, a check on the signer host, threat rows, and the todo [2026-10-21-cli-verifies-directory-install-receipts](../../todos/pending/2026-10-21-cli-verifies-directory-install-receipts.md) (blocker, Phase 4).
  - Phase 4: a signer-signed receipt.
- **F2, the executor's five unsettled choices:** "Godkänn alla fem (Rekommenderas)". They are now owner-approved deviations:
  1. `user list` prints the verified directory with fingerprints the CLI computes itself (deviation 8);
  2. `currentDirectory`, one fail-closed mirror, replaces 02-07's `dirCache` (deviation 7);
  3. the default proposal directory is `keyroster-directory-v<N>` at quorum above 1 without `--out` (deviation 13);
  4. `directory sign` refuses an admin who already signed (deviation 13);
  5. 503 `signer unavailable` for unavailable or internal refusals, and 400 `malformed request` for fields over the signer's caps (deviations 14 and 15).
- **F3, recovery after an admin-set or quorum change:** "Blocker för fas 4 (Rekommenderas)".
  - No code change, because the refusal is T-02-42, and phase-2 tooling cannot reach the state (`root successor-policy` changes only the RP).
  - Todo: [2026-10-21-recover-directory-after-admin-set-change](../../todos/pending/2026-10-21-recover-directory-after-admin-set-change.md) (blocker, Phase 4).

### Fixed

| Finding | Commit | Test |
|---|---|---|
| The CLI cannot tell an admin-signed version from an installed one (approval-integrity, medium) | `7dac758` | `TestDirectoryPipeline/fetch_no_directory_installed`, `approve_disable_enable_round_trip` and `quorum_two_writes_proposal` pin the wording of `reportInstalled`, `directory show` and `user list`. The tests do not compile against the old code. e2e assertions follow. Runbook "Confirm on the signer host", plus the todo and STATE line |
| A compromised server can withhold or delay any install, even a disable (signer-install, medium) | `7dac758` (same fix) | the same. The CLI prints the log leaf so it can be compared with an export |
| Diff renders a credential without its ID or backup_eligible (low) | `9278a9b` | `TestDiff/credential_id_or_flag_change_visible` covers an ID-only change, an ID that differs only in its last character, and a backup_eligible-only change. Before the fix it printed two identical lines. The ID is shown as a 128-bit SHA-256 digest, not a prefix, because an attacker chooses the new ID |
| Cleanup after an accepted install runs on the request context (low) | `5dd3a45` | `TestDirectoryInstallPending/cleanup_survives_client_hangup`. Before the fix: 1 pending row, and `pending_cleanup_failed ... context canceled` |
| The install pending check matches only ID and user, not the key (low) | `64e4fe7` | `TestDirectoryInstallCleanup/install_refuses_reused_id_with_other_key`; before the fix it answered 200. `TestDeleteBound/same_id_other_key_untouched` kills the old `WHERE id = ? AND user_name = ?` |
| A retry after a lost install answer calls the proposal stale (cli, low) | `c34c2f3` | `TestDirectoryPipeline/proposal_already_served` (install exits 0 "nothing to do"; sign refuses without discard advice) |
| `directory install` reports the proposal's own base after a 409 (cli, low) | `c34c2f3` | `stale_proposal_install_message` now asserts "based on version 1, but the server serves version 2" on the 409 path. The old call (`staleProposal(p, vd.Version)`) fails it with "version 1 ... version 1" |
| Stale message wrong after a mid-flight 409, and misdiagnoses an already installed proposal (plan-tests, low) | `c34c2f3` | both of the above. The runbook gains a "Proposal already served" paragraph |
| T-02-43 is not pinned on the edit path (medium) | `8c28cc0` | `TestEditConfirm`, plus a diff-before-prompt check in `TestDirectorySignConfirm`. It kills all three of the reviewer's mutants: `confirmSign(true, ...)` in `editDirectory`, and `printChanges` moved after `sshsig.Sign` in `editDirectory` and in `directory sign` |
| No test pins dropStatus after a transport error from InstallDirectory (low) | `27e8bce` | `orphan_pending_cleaned_on_next_install` GETs at the same instant after the lost answer. It kills the conditional-drop mutant ("version 1; want ... version 2") |
| No test covers user approve appending a passkey to a directory user (low) | `ec489e9` | `TestDirectoryPipeline/approve_appends_passkey_to_directory_user`. It kills the replace-the-slice mutant |
| enroll-user.md claims the e2e tests run every command (low) | `ea93811` | doc only. The note lists the commands the four e2e tests run, and labels `user disable`, `user enable`, `directory show` and the interactive prompt UNVERIFIED end to end |
| Directory free text can carry terminal escape sequences (critic, orchestrator note) | `6c1fa0c` | `TestDiff/extension_control_bytes_escaped` and `TestDirectoryPeerText/show_escapes_extension_control_bytes`. Before the fix the output held a raw 0x1b. The second test fails again under a no-escape mutant |

### Documented, not fixed in code

| Finding | Commit | Reason |
|---|---|---|
| fetchVerifiedDirectory has no bundle or policy version floor, so a removed admin key plus a compromised server can forge a "verified" view (critic, medium) | `8cbcfe9` | Owner decision F1 puts the high-water marks into the Phase 4 receipts todo. The finding's own note assigns the floor in `Trust` to 02-06. This PR adds the runbook residual and a threat row (below) |
| Once a successor policy changes the admin set, no CLI path can install the re-signed directory (plan-tests, medium), and both split findings on the same mechanism | `e142c53` | Owner decision F3 is a Phase 4 blocker; this PR adds the todo and the STATE.md line. The split findings were checked against the code: the mechanism holds, and is covered by F3 |

### Threat rows added (accept/document)

| ID | Category | Component | Severity | Disposition | Residual |
|---|---|---|---|---|---|
| R-02-09-1 | Tampering / Repudiation | server to CLI: install answer and directory reads | medium | accept, document | The server withholds or delays an install, including `user disable`, or serves a signed but uninstalled version as installed. The CLI words installs and views as the server's word, and the runbook confirms every revocation on the signer host (`export-log` and `audit verify`, `directory installs N`). This stays a residual until the CLI verifies a signer-signed install receipt (checkpoint and inclusion proof; todo 2026-10-21-cli-verifies-directory-install-receipts, Phase 4) |
| R-02-09-2 | Spoofing | served trust bundle and policy | medium | accept, document | The server serves an older root-signed policy, so a removed admin key it still names makes a forged directory show as verified. The signer is not affected. This stays a residual until the CLI keeps bundle, policy and directory high-water marks (same todo) |

### Verification

- `gofmt -l` printed nothing.
- `go vet ./...` passed on Windows, `GOOS=linux` and `GOOS=darwin`, also with `-tags e2e ./test/e2e/`.
- `go test -count=1` passed on the touched packages (cmd/keyroster, internal/directory, internal/server, internal/serverdb), and `go test -count=1 ./...` passed once on Windows.
- In WSL with OpenSSH 10.5p1, these e2e tests passed: `TestEnrollApproveEndToEnd`, `TestApproveConflictNoLostUpdate`, `TestApproveQuorumTwo` and `TestApproveProposalAfterReinvite`.
- `-race` was not run: no cgo on the Windows toolchain.
- Not run: the rest of the e2e suite and the CI-only lanes.
