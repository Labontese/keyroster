---
phase: 02-passkey-login-mvp
plan: 10
subsystem: auth
tags: [webauthn, passkey, sign-in, session, web-ui, rate-limit]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-03 internal/webauthn.VerifyAssertion (the signer's verifier); 02-06 server core (currentStatus, signerUnavailable, secure, fakeSigner, logBuffer); 02-07 bounded LRU limiter and clientKey; 02-08 app.js ceremony pattern; 02-09 currentDirectory mirror, dropStatus on install, keyroster directory install and user disable/enable"
provides:
  - "GET /login, POST /api/v1/web/login/begin and /finish: username-first passkey sign-in against the installed directory"
  - "withSession, POST /logout and the __Host-keyroster-session cookie (opaque 32-byte ID, SHA-256 at rest, 1 h idle, 12 h absolute)"
  - "GET /account: the signed-in user's own roles, principals, TTL cap, directory version and passkeys, read only"
  - "serverdb CreateChallenge, TakeChallenge, CreateSession, TouchSession, DeleteSession; migration 0003_web.sql"
  - "Sign-in route class in Limits: per client with a global backstop, and a bounded per-username limiter"
  - "e2e TestWebSignInEndToEnd"
affects: [02-12, 02-13, 02-14, UI-02, AUTH-02, UI-01]

actuals:
  tokens: 28300
  tasks: 2
  commits: 3
plan_head_before: 9c9d4c15d10397fc7c05a568510e5397875dc427
plan_head_after: e811c5341458d137780284f298c94167558b1298

tech-stack:
  added: []
  patterns:
    - "Sign-in reads signer state only through currentStatus and currentDirectory; begin, finish and withSession check the user's status and credential binding straight from the directory view, never from pending tables"
    - "withSession hands the directory view it checked to the handler, so the check and the page see one version"
    - "One log line per sign-in event: msg \"web sign-in\" with event, reason, user and client; a name that fails the user-name rule is logged as an empty user"
    - "Sign-in routes apply their limiters inline (not rateLimited), so a 429 is one sign-in log line"

key-files:
  created:
    - internal/serverdb/migrations/0003_web.sql
    - internal/server/weblogin.go
    - internal/server/session.go
    - internal/server/account.go
    - internal/server/web/templates/login.html
    - internal/server/web/templates/account.html
    - internal/server/weblogin_test.go
    - internal/server/session_test.go
    - test/e2e/websignin_test.go
  modified:
    - internal/serverdb/db.go
    - internal/serverdb/db_test.go
    - internal/server/server.go
    - internal/server/ratelimit.go
    - internal/server/render.go
    - internal/server/web/static/app.js
    - internal/server/web/templates/index.html

key-decisions:
  - "The sign-in section is <section id=\"kr-login\">, not <main>: base.html already wraps every page in <main> (enroll.html does the same)"
  - "CreateSession takes idle and absolute and purges expired sessions in its transaction; CreateChallenge purges expired challenges"
  - "Session cookie value: unpadded base64url of 32 random bytes; the server stores SHA-256 of the 32 raw bytes; a cookie that does not decode to exactly 32 bytes is no session and is cleared"
  - "One per-username bucket (10/min, burst 10) is shared by begin and finish; finish charges it after TakeChallenge, keyed on the stored user, so a limited finish has consumed its challenge"
  - "Every refused finish is 401 sign-in failed, including a malformed or oversized body; a malformed begin body is 400 malformed request; server-side failures are 500"

patterns-established:
  - "Sign-in: per-client limit, body cap, name rule, per-user limit, directory, active-and-bound check, verify, session"
  - "Session check per request: TouchSession (one conditional UPDATE ... RETURNING), currentDirectory (503 keeps the row), active and cred_id bound (else delete)"

requirements-completed: []  # AUTH-02 completes in 02-14 after a real-browser sign-in (plan <output>); UI-01 pages added, browser run in 02-13/02-14

coverage:
  - id: D1
    description: "A user bound in the installed directory signs in with that passkey (begin from directory credentials, assertion verified by internal/webauthn against the directory credential, the policy RP and origins), gets the __Host- cookie with every flag, sees role, principal and fingerprint on /account, and logout ends the session"
    requirement: AUTH-02
    verification:
      - kind: e2e
        ref: "test/e2e/websignin_test.go#TestWebSignInEndToEnd"
        status: pass
      - kind: unit
        ref: "internal/server/weblogin_test.go#TestSignInFinish/signs_in"
        status: pass
    human_judgment: false
  - id: D2
    description: "Pending, unapproved, disabled, unknown and invalid names get the identical begin 404; refused finishes (wrong, replayed or expired challenge, other user's credential, UV clear, wrong origin, other RP, flipped signature, type create) get 401 with no session row"
    requirement: AUTH-02
    verification:
      - kind: unit
        ref: "internal/server/weblogin_test.go#TestSignInBegin"
        status: pass
      - kind: unit
        ref: "internal/server/weblogin_test.go#TestSignInFinish"
        status: pass
    human_judgment: false
  - id: D3
    description: "Sessions: idle and absolute expiry in one conditional statement with no revival, ended on disable or credential removal, kept on a role change, kept with a 503 while the signer is unavailable, stored as SHA-256 only, cross-site logout refused"
    requirement: AUTH-02
    verification:
      - kind: unit
        ref: "internal/server/session_test.go#TestSession"
        status: pass
      - kind: e2e
        ref: "test/e2e/websignin_test.go#TestWebSignInEndToEnd/disabled_user"
        status: pass
    human_judgment: false
  - id: D4
    description: "Rate limits and logging: per-username 429, bounded per-username map keyed only on valid names, finish keyed on the challenge's user, global backstop; one log line per sign-in event with no session ID, hash or challenge"
    verification:
      - kind: unit
        ref: "internal/server/weblogin_test.go#TestSignInLimits"
        status: pass
      - kind: unit
        ref: "internal/server/weblogin_test.go#TestSignInLog/signin_log_has_no_secrets"
        status: pass
    human_judgment: false
  - id: D5
    description: "The app.js sign-in ceremony in a real browser (feature detection, navigator.credentials.get, error text through textContent)"
    requirement: UI-01
    verification: []
    human_judgment: true
    rationale: "No browser runs in this plan; app.js is only syntax-checked (node --check) and grep-checked. UNVERIFIED until 02-13/02-14."

duration: about 40 min
completed: 2026-10-22
status: complete
---

# Phase 2 Plan 10: Web Sign-in Summary

**A user whose passkey is bound in the installed, admin-signed directory signs in to the web UI with it. The server verifies the assertion with the signer's own `internal/webauthn` verifier against the directory credential, opens an opaque `__Host-` session stored only as its SHA-256, and `/account` shows that user's roles, principals, TTL cap and passkeys, read only. Every session request re-checks the directory: a disable or a removed credential ends the session, and a signer outage answers 503 without logging the user out.**

## Performance

- **Duration:** about 40 min of wall-clock execution (2026-10-22T05:30:50Z to about 06:10Z)
- **Tasks:** 2 of 3 executed. Task 3 is the owner's merge gate, which this executor does not run.
- **Files modified:** 16 outside `.planning`

## Delivery

- **Branch:** `p02/10-web-signin`, created from origin/main `3120e25`. It carries the orchestrator's `9c9d4c1 docs(phase-02): mark 02-09 complete ...`.
- Before the push, `git fetch origin` showed origin/main still at `3120e25`, so no rebase was needed.
- **PR:** keyroster-bot opens it after the one push that carries this SUMMARY. Title: `feat(server): passkey sign-in and read-only account page`. The PR number and the check results go in the merge-gate checkpoint; they do not exist before the push (same as 02-06 to 02-09).
- **Auto-merge is not enabled.** This is an environment rule: the orchestrator enables auto-merge after its own pre-merge review. The plan's "PR is open with auto-merge" line is therefore deliberately unmet.

## Routes

| Route | Wrapping | Answers |
|---|---|---|
| `GET /login` | none (like `GET /`) | 200 login page with the KEY-06 banner; 503 error page when the status cannot be read |
| `POST /api/v1/web/login/begin` `{"user"}` | sign-in limiters inline; CrossOriginProtection | 200 `{"challenge_id","publicKey":{"challenge","allowCredentials":[{"type":"public-key","id"}],"rpId","userVerification":"required","timeout":60000}}`; 404 `no usable passkey for this user` (identical for unknown, invited, unapproved, disabled, invalid names, nothing installed); 400 `malformed request`; 429 `rate limited`; 503 `signer unavailable` |
| `POST /api/v1/web/login/finish` `{"challenge_id","credential_id","authenticator_data","client_data_json","signature"}` | the same | 200 `{"redirect":"/account"}` with the cookie; 401 `sign-in failed` for every refusal; 429; 503 |
| `GET /account` | `withSession` | 200 own account page; 303 to /login without a usable session; 503 error page when the directory cannot be read (session kept) |
| `POST /logout` | CrossOriginProtection | 303 to /login, row deleted, cookie cleared; 403 cross-origin; works during a signer outage |

## Session parameters

- Cookie `__Host-keyroster-session=<43 chars>; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict`, no Domain. Logout and an invalid session send the same cookie with `Max-Age=0`.
- The ID is 32 bytes from `crypto/rand`, unpadded base64url. The `sessions` row holds `SHA-256(raw 32 bytes)`, the user, the opening credential's ID, `created_us` and `last_seen_us`.
- Idle 1 h, absolute 12 h, enforced by `TouchSession`'s one statement: `UPDATE sessions SET last_seen_us = max(last_seen_us, :now) WHERE id_hash = :hash AND :now - last_seen_us <= :idle AND :now - created_us <= :absolute RETURNING user_name, cred_id`. No match deletes the row.
- Per request, after TouchSession: `currentDirectory` (503 error page, row kept, on failure), then the user must be active and `cred_id` bound to that user, otherwise the row is deleted (`session_ended` log line).
- Challenges: 32 random bytes under a random 32-byte ID, 120 s, consumed by `DELETE ... RETURNING`; the browser timeout is 60 s.

## Rate limits

| Limiter | Rate | Burst | Key |
|---|---|---|---|
| `signInLimit` (begin and finish) | 20/min | 10 | `clientKey` (RemoteAddr, IPv6 by /64) |
| its global backstop | 200/min | 100 | all clients |
| `signInUserLimit` (begin and finish, one bucket) | 10/min | 10 | user name and `clientKey` together (`signInUserKey`, pre-merge review G1): at begin only a name that passes `^[a-z0-9][a-z0-9._-]{0,63}$`; at finish the name stored with the challenge |

Both are configurable through `Limits` (`SignInPerMinute`, `SignInBurst`, `SignInUserPerMinute`, `SignInUserBurst`). The per-username map is a second instance of 02-07's bounded LRU map (10 000 entries, 10 min idle eviction).

## Logging

One line per event, message `web sign-in`, with exactly `event`, `reason`, `user` and `client` (the RemoteAddr IP):

| event | reasons |
|---|---|
| `signin_ok` | `ok` |
| `signin_refused` (finish) | `body_too_large`, `malformed`, `challenge_not_found`, `directory_not_authorized`, `user_not_active`, `credential_not_bound`, `assertion_*` (one per internal/webauthn sentinel), `signer_unavailable`, `internal_error` |
| `begin_refused` | `no_usable_passkey`, `directory_not_authorized`, `malformed`, `body_too_large`, `signer_unavailable`, `internal_error` |
| `rate_limited` | `per_client`, `per_user` |
| `logout` | `ok`, `no_session` |
| `session_ended` | `directory_not_authorized`, `user_not_active`, `credential_not_bound` |

No line holds the session ID, its hash, a challenge, a challenge ID or assertion bytes. Web sign-in stays out of the signer's Merkle log.

## Task Commits

1. **Task 1 (tracer): end-to-end sign-in.** `395dda5` (feat).
   - Tracer gate: interactive, end-of-phase, automated-only verify. `TestWebSignInEndToEnd|TestEnrollApproveEndToEnd` (WSL, OpenSSH 10.5p1) passed before the commit, and golangci-lint (after two fixes), capslock (91/91), dep-firewall and testonly-firewall were green.
   - Logged: "Tracer verified end-to-end — expanding".
2. **Task 2 (tdd="true"): refusal matrix.**
   - `906938f` (test): weblogin_test.go, session_test.go, serverdb `TestWebSignInRows`, and the e2e `disabled_user` control.
   - `e811c53` (test): `TestSession/custody_banner_on_signin_pages` (KEY-06 banner on GET /login and GET /account under software custody).
3. **Task 3, merge gate.** Not attempted. It is the owner's `checkpoint:human-action` (`gate="blocking-human"`).

**Plan metadata:** `docs(02-10): complete web-signin plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 2; workflow.tdd_mode is false, so the gate sequence is advisory)

- **No RED commit.** Task 1 (the tracer) wrote the code first, and every Task 2 test passed on `395dda5` at its first run. A passing test alone proves nothing, so each key property was shown to bite with a mutant. Each mutant was applied by a script, run against the named test and restored; `git status` showed only the then-untracked test files afterwards.
- **Mutants, all killed:**

| Mutant | Killed by |
|---|---|
| withSession skips the active-and-bound check | `credential_unbound_ends_session` (200), `disabled_user_ends_session` (500 from the page builder, a second line of defence) |
| withSession deletes the row on a directory error | `signer_unavailable_fails_closed` (0 rows) |
| TouchSession without the DELETE on no match | `touch_after_expiry_does_not_revive` (1 row left, revived later) |
| TouchSession without the absolute condition | `absolute_expiry` (200 at 12 h 1 min) |
| TouchSession without the idle condition | `idle_expiry` (200 at 61 min) |
| begin without the user-name rule | `username_limiter_bounded` ("Alice" logged and keyed) |
| begin without the per-username limiter | `eleventh_begin_for_one_user_429` |
| finish without the per-username limiter | `finish_keyed_on_challenge_user` |
| begin ignores the user's status | `disabled_user_uniform_404` |
| the cookie value logged | `signin_log_has_no_secrets` |
| the session hash logged | `signin_log_has_no_secrets` |
| SameSite=Lax | `signs_in` |
| the raw ID stored and looked up | `stored_hash_only` |
| finish checks the binding but not the status | `disabled_between_begin_and_finish_refused` |
| /account built without the custody banner | `custody_banner_on_signin_pages` |
| /login built without the custody banner | `custody_banner_on_signin_pages` |

## Verification run

- **Windows (go1.27.3):** `gofmt -l .` empty; `go vet ./...`, `GOOS=linux go vet ./...`, `GOOS=darwin go vet ./...` and `go vet -tags e2e ./test/e2e/` clean; `go test -count=1 ./...` passed (all packages, internal/winagent included).
- **WSL (scripts/linux.sh, script files under the scratchpad):**
  - Task 2 verify 1: `go test -race -count=1 -v -run "SignIn|Session|Logout|Begin|Finish" ./internal/server/...` exit 0, 72 PASS lines (at `e811c53`), no FAIL, no DATA RACE; `signer_unavailable_fails_closed`, `credential_unbound_ends_session`, `touch_after_expiry_does_not_revive`, `username_limiter_bounded` and `signin_log_has_no_secrets` all appear.
  - Task 2 verify 2, re-run in full at `e811c53`: `go test -race -count=1 ./...` exit 0; `go vet ./...` and the e2e vet clean; `$(go env GOROOT)/bin/gofmt -l .` empty, run from a script file (the plan's inline `test -z "$(gofmt -l .)"` checks nothing through scripts/linux.sh, deferred-items row of 02-01); golangci-lint v2.14.0 on `./...`: 3 issues found across the two tasks (gosec G101 on the reason code `credential_not_bound`, annotated; revive redefines-builtin `clear`, renamed; gosec G101 on a test constant named `noPasskey404`, renamed), then 0 at `e811c53`; `scripts/capslock-check.sh` 91 pairs, baseline 91; `scripts/dep-firewall.sh` and `scripts/testonly-firewall.sh` clean.
- **e2e in WSL (OpenSSH 10.5p1):** the full suite ran: 29 top-level tests PASS, including `TestWebSignInEndToEnd` (with `disabled_user`) and every approve, enroll, login and audit test. `TestSSHDRejects/pty_allowed` failed under the hosts wrapper (below) and passed on a rerun without it, as in 02-07.
  - WSL's resolver did not answer `keyroster.localhost` this session (02-07 saw the same). The e2e ran under a scratch script that bind-mounts a copy of `/etc/hosts` with the name in a private mount namespace and maps back to the caller's uid in a nested user namespace. It is not committed. CI resolves the name natively, so CI's lanes are the authoritative run.
- Not run locally: the 9.5p1 lane, govulncheck and the macOS/Windows CI lanes. CI runs them; the results are in the checkpoint.
- Every commit of `9c9d4c1..HEAD` carries an SSH signature (checked at the Self-Check).

## Decisions Made

See `key-decisions` in the frontmatter, and the open choices under the deviations.

## Deviations from Plan

### Deferred-items rows addressed to 02-10

1. **02-07 (pre-merge review, for 02-09 and 02-10): sign-in keeps its own route class with 02-07's global backstop.** Done as planned: `signInLimit` per client 20/min burst 10 with a global bucket of 200/min burst 100, and `signInUserLimit` per user name 10/min burst 10 with none. `TestSignInLimits/global_backstop` pins the backstop. The row is marked "Status for 02-10: resolved" in deferred-items.md.
2. The 02-01 gofmt-in-WSL row is not addressed to 02-10 and is not fixed here; this plan ran the GOROOT gofmt from a script file instead (Verification run).

### Choices the plan left open (listed for the owner's veto)

3. **`<section id="kr-login">` instead of `<main id="kr-login">`.** base.html already wraps every page's content in `<main>`, and a nested `<main>` is invalid HTML. enroll.html uses a section the same way. The data attributes, the username input, the button and the `role="alert"` element are as planned; the input sits in a form whose submit handler runs the ceremony.
4. **Body caps:** begin 1 KiB, finish 16 KiB. A malformed or oversized begin is 400 `malformed request` (before any name is known); every refused finish, a malformed or oversized body included, is the plan's 401 `sign-in failed`. Server-side failures (the database) are 500 `internal error`, not 401.
5. **Per-username burst 10**, derived from "the 11th begin within a minute gets 429". One bucket per name serves both begin and finish, so a complete sign-in costs two tokens (five sign-ins a minute per user).
6. **Where expired rows go.** `CreateChallenge` deletes expired challenges in its transaction. `CreateSession` takes `idle` and `absolute` (the plan's signature is `CreateSession(hash, user, credID, now)`) and deletes sessions past either limit in its transaction. Without this, rows of sessions nobody uses again would stay forever.
7. **A finish refused by the per-username limiter has already consumed its challenge**: the limiter is keyed on the user stored with the challenge, which only TakeChallenge reveals.
8. **Cookie hashing** is over the 32 raw bytes, not over the base64url string. A cookie value that does not decode to exactly 32 bytes is treated as no session and never looked up.
9. **An invalid, unknown or expired cookie** gets the 303 to /login plus a `Max-Age=0` cookie.
10. **`DeleteSession` returns the user name**, for the logout log line. Logout needs no signer state, so it works during an outage; a database error on logout is 500 "You are not signed out yet".
11. **Logging details:** the plan's event names, plus `begin_refused`, `signin_refused` and `session_ended` as events with reason codes (table above). `client` is the RemoteAddr IP, not the /64 limiter key. A per-client 429 is logged with an empty user, because the body has not been read.
12. **Begin 404s and 401s carry no custody header**, so the uniform refusals are identical in headers as well as body.
13. **Account page wording:** TTLs as `3600 s (1h0m0s)`, the cap labelled "Longest certificate", "none: no roles yet" and "No roles yet." when the user holds no role, each passkey with its algorithm. index.html links to /login and /account.

### Auto-fixed issues

14. **[Rule 1, test] html/template escapes `+` as `&#43;`.** The e2e and unit tests compare the account page's text after `html.UnescapeString`; the first e2e run failed on a fingerprint with a `+`.
15. **[Rule 1, lint]** gosec G101 on the reason-code constant (annotated, as 02-09 did), revive redefines-builtin (`clear` renamed), gosec G101 on a test constant (renamed).
16. **[Rule 3] `TestOpen/migration_applies_once`** expected schema version 2; it now expects 3.

### Scope: tests beyond the plan's list

17. Server: `custody_banner_on_signin_pages`, `options_from_directory`, `unknown_user_uniform_404`, `nothing_installed_uniform_404`, `malformed_body_400`, `unknown_challenge_refused`, `malformed_refused`, `challenge_used_by_refused_finish`, `disabled_between_begin_and_finish_refused`, `per_client_limit`, `global_backstop`, `finish_keyed_on_challenge_user`, `account_shows_own_data_only`, `ttl_cap_is_user_ca_cap`, `no_roles_yet`, `credential_moved_to_other_user_ends_session`, `directory_read_failure_fails_closed`, `unknown_cookie_redirects`, `logout`, `logout_during_outage`, `login_page`, and `TestSignInNotAuthority` (a session cookie on admin routes still gets the uniform 401, T-02-51). serverdb: `TestWebSignInRows` (purges, take once, delete once).

### Environment overrides

18. Auto-merge not enabled; one push; the PR number and check results go in the merge-gate checkpoint. ROADMAP is not marked complete. `requirements-completed: []` and no `requirements.mark-complete` call, as the plan's `<output>` says.

**Total deviations:** 18: 1 deferred-row resolution and 1 deferred-row note, 11 open choices, 3 auto-fixes, 1 scope item, 1 environment override.

**Impact on plan:** no new module, no capslock change, no change to internal/directory, internal/webauthn or any 02-11 file. The plan's `CreateSession` signature gained two parameters.

## Threat model notes

- **T-02-51 (web session as authority):** no handler outside withSession and logout reads the cookie; `TestSignInNotAuthority` shows the admin routes ignore it.
- **T-02-91 residuals, as planned:** a disable or credential removal installed on the signer socket directly takes effect within the 5 s status window; a disable then re-enable with the same credential and no request between leaves the session alive. Through the server, each takes effect on the next request (e2e `disabled_user`, no sleep, polling or retry).
- **T-02-50 (enumeration):** the begin 404 is identical in body and headers for every non-usable name, but its timing is not uniform: an invalid name answers before the directory is read. Usernames are not secret here (plan's flagged assumption).
- The two new unauthenticated JSON routes have the same HTTP/2 buffering exposure as 02-08's enroll routes (receive windows before the handler's cap): the Phase 6 todo `2026-10-20-cap-server-connections-and-memory.md`. Not measured here (UNVERIFIED).

## Relation to the phase-4 todos

Not made worse. Sign-in reads only the installed directory through the existing mirror and adds no signer call, no directory format change and no install path.

## Issues Encountered

- **WSL resolver** (above): the namespace wrapper; its pty side effect needed one rerun.
- **Python heredoc newlines** turned `\n` in Go string literals into real newlines once (02-08 and 02-09 recorded the same); fixed and caught by vet.

## Not exercised (UNVERIFIED)

- **The app.js sign-in ceremony in a real browser:** feature detection, `navigator.credentials.get` with the begin options, the base64url conversions, the error text through `textContent`, and `location.assign`. It is syntax-checked with `node --check` and grep-checked (no `innerHTML`). It stays UNVERIFIED until 02-13/02-14.
- **Real authenticators:** the e2e and unit tests use the soft authenticator; a platform or roaming authenticator's assertion (clientDataJSON with extra members, other flags) has not been signed in with.
- **HTTP/2 buffering on the sign-in routes** (Threat model notes).
- **CI-only:** govulncheck, the e2e 9.5p1 lane and the macOS/Windows lanes; reported in the checkpoint.

## Known Stubs

None. Every route reads the installed directory and the state database.

## Threat Flags

None beyond the plan's threat model: the five routes, the cookie and the two tables are T-02-47..51, T-02-90..92 and T-02-94.

## User Setup Required

None.

## Next Phase Readiness

- **02-12:** the login approval page can reuse `withSession` if it wants a signed-in user, but a session must never stand in for the per-request assertion the signer verifies.
- **02-13/02-14:** run app.js's sign-in in a real browser; AUTH-02 completes there.
- **UI-02 (later phase):** last sign-in time, a session list and revocation (02-10-F16, deferred).
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in `key-files.created` exists.
- Commits `395dda5`, `906938f` and `e811c53` are ancestors of HEAD and carry an SSH signature (`gpgsig` header checked on each; `git rev-list --count 9c9d4c1..e811c53` is 3).
- Task 1 acceptance greps re-run and pass: `signerclient.InstallDirectory` in websignin_test.go (comments excluded) 0; `id_hash` in 0003_web.sql 2; `cred_id` 2; the one `RETURNING user_name, cred_id` TouchSession statement in db.go; the non-passkey route grep prints nothing; `kr-login` setup in app.js with feature detection before the submit handler; `innerHTML` (comments excluded) 0; `webauthn.VerifyAssertion` in weblogin.go.
- Task 2 named cases present: the six weblogin cases under `TestSignInBegin`/`TestSignInFinish`, `username_limiter_bounded` and `signin_log_has_no_secrets` under `TestSignInLimits`/`TestSignInLog`, and the nine session cases under `TestSession`.
- No private network detail in any file this plan changed (grep for 100.x, 10.x, 192.168.x, host and tailnet names: none).

## Pre-merge review fixes

Review of PR 50 at `ed27fba`. Eight confirmed findings, three distinct defects, three fix commits. Each fix's test was run before the fix and failed, then passed after it.

**Owner decisions (2026-10-22, Daniel, via the orchestrator), verbatim:**

- **G1**, per-username sign-in limit: "Per användare + klient (Rekommenderas)". The per-username bucket is keyed on the user name and the client key together; the per-client limiter and the global backstop are unchanged.
- **G2**, the executor's other open choices: "Godkänn (Rekommenderas)". Choices 3, 4 and 6 to 12 under "Choices the plan left open" are recorded as owner-approved deviations. Two are superseded by these fixes rather than approved as they stood: choice 5 ("one bucket per name") is now one bucket per name and client, and choice 13 (the label "Longest certificate") is reworded below.

**Fixed:**

- `e915e48` fix(02-10): key the per-username sign-in limit on user and client. Covers "Unauthenticated per-username lockout: a single IP can keep any user from signing in indefinitely" (medium), "An unauthenticated client can lock any known user out of web sign-in by draining the per-username limiter" (low) and "Per-username sign-in bucket lets one client lock a named user out of web sign-in" (low, which named 02-12 L196 as the owner of the limiter decision; G1 decided it here). Begin keys `signInUserLimit` on `signInUserKey(name, r)` and finish on `signInUserKey(storedUser, r)`: the name, a space (which the user-name rule excludes) and `clientKey`. Test: `TestSignInLimits/other_client_not_locked_out` (an attacker at 203.0.113.9 drains alice's bucket within its per-client limit; alice still signs in from another address; the attacker's next begin is 429 `per_user`). Before the fix it failed with `begin alice = 429 ... "reason":"per_user"`. `eleventh_begin_for_one_user_429` and `finish_keyed_on_challenge_user` now drain from one client. deferred-items.md gains a row for 02-12, whose L196 and L517 inherit the limiter for the CLI login routes and must use the same (user, client) keying.
- `f1d195b` fix(02-10): refuse web sign-in under a directory the signer does not authorize. Covers "Web sign-in and sessions ignore the signer's DirectoryAuthorized flag: an unauthorized directory still decides who can sign in" (low), "Web sign-in and /account ignore DirectoryAuthorized: they authenticate against, and show access from, a directory the signer has refused" (medium) and "Web sign-in and /account accept a directory the signer marks unauthorized (DirectoryAuthorized=false)" (medium). `activeUser` holds no user of a view whose `authorized` is false, and `boundCredential` refuses such a view first with the new closed reason `directory_not_authorized`. Begin answers the uniform 404, finish the uniform 401, and withSession deletes the session row, clears the cookie and redirects to /login, each logged with `directory_not_authorized`; /account can no longer be built from such a view. Nothing installed (version 0) still logs `no_usable_passkey`. Tests: `TestSignInBegin/directory_not_authorized_uniform_404`, `TestSignInFinish/directory_not_authorized_refused`, `TestSession/directory_not_authorized_ends_session`, `TestSession/account_page_refuses_unauthorized_view`; all four failed before the fix (begin 200 with options, finish 200 with the redirect, /account 200, the page built). `fakeSigner` gains an `unauthorized` switch for chain mode.
- `af4941f` fix(02-10): state truthfully what the account page's certificate lengths mean. Covers "Account page 'Longest certificate' understates the real cap: it is the minimum over all roles, but a login may request a subset of roles" (low) and "/account 'Longest certificate' understates access when the user holds several roles (login can select a subset with --role)" (low). The summary row reads "Longest certificate with all your roles"; the roles table's column, now headed "Longest certificate", shows each role's max TTL capped by the user CA's, which is what a login for that role alone gets (signer `ttlCap`); a sentence under the table says a login for only some roles gets the shortest of their values. Doc comments on `accountPage.TTLCap` and `accountRole.MaxTTL` say the same. Test: `TestSession/ttl_cap_is_user_ca_cap` pins the label, the per-role values (dev 7200 s, long 43200 s under a 43200 s user CA cap) and the sentence, and that the uncapped 86400 s is not shown. It failed before the fix on the label; a temporary mutant that dropped the per-role cap failed it on the `long` row, then was restored.

**Skipped:** none.

**CodeQL #13 (go/log-injection, weblogin.go:125, the `logSignIn` call):** no code change; a false positive. Every `user` passed to `logSignIn` is empty, a name that passed `directory.ValidUserName` (`^[a-z0-9][a-z0-9._-]{0,63}$`, no control characters), or a database value written only from such a name: the challenge's user (CreateChallenge runs after the rule and the active-user check), the session's user (CreateSession takes the challenge's user) and DeleteSession's user. A name that fails the rule is logged as empty. `client` is `netip` output. keyroster-server logs through `slog.NewJSONHandler`, which escapes control characters in any case.

**Threat model note (targeted lockout, an extension of T-02-90):** an unauthenticated client can now drain only its own (user, client) buckets, so it cannot lock another client out of a user's sign-in. Residual, accepted: an attacker with many source addresses gets more sign-in attempts per user, bounded by the per-client limit per address and the global backstop (200/min); each attempt still needs a passkey assertion over a single-use challenge. The per-username map is still the bounded LRU map (10 000 entries), now of (user, client) pairs, so a flood of pairs evicts older ones as before.

**Verification (Windows, go1.27.3):** `gofmt -l .` empty; `go vet ./...`, `GOOS=linux go vet ./...`, `GOOS=darwin go vet ./...` and `go vet -tags e2e ./test/e2e/` clean; `go test -count=1 ./internal/server/` passed; `go test ./...` passed (all packages). `-race` was not run (no cgo on this host). The e2e (`TestWebSignInEndToEnd`, which checks /account for "3600 s") was not run locally: it needs `KEYROSTER_OPENSSH_PREFIX`; CI's e2e lanes run it. golangci-lint was not run locally. The PR's auto-merge was left off.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-22 (before the merge gate)*
