---
phase: 02-passkey-login-mvp
plan: 12
subsystem: auth
tags: [login, webauthn, passkey, pkce, loopback, ssh-agent, winagent, audit-export]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-01..02-05 signer LoginIssue (assertion over the request digest, D-08 grant, kr2 key IDs, login_issue leaves); 02-02 winagent (Serve, Ensure, VerifyServerOwner, OpenSSHSpelling) and the A3 line; 02-06 signerAPI seam and currentStatus; 02-07 limiter, clientKey, requestOrigin; 02-09 currentDirectory; 02-10 signInUserKey, readSignInBody, decodeStrict, verifyReason; 02-11 roles and the principals renderer"
provides:
  - "GET /api/v1/login/options, POST /api/v1/login/begin, GET /login/{id}, POST /api/v1/login/{id}/assertion, POST /api/v1/login/{id}/redeem"
  - "login_sessions table (migration 0004) with CreateLogin (reaper), Login, ApproveLogin, RedeemLogin (the single conditional burn)"
  - "signerAPI.Login on socketSigner and fakeSigner"
  - "keyroster login [--role R]... [--ttl D] [--no-browser]; connectLoginAgent (Unix: SSH_AUTH_SOCK; Windows: winagent.Ensure)"
  - "audit export decodes login_issue and directory_install leaves"
  - "e2e TestLoginEndToEnd with login_lifetime_expiry, two_concurrent_logins, unapproved_login_mints_nothing, signer_refusal_after_approval"
affects: [02-13, 02-14, AUTH-03, AUTH-04, PLAT-05, UI-01]

tech-stack:
  added: []
  patterns:
    - "Mint at redemption: the redeem handler is the only caller of s.signer.Login; every check that can fail runs before the one conditional UPDATE that burns the code"
    - "The CLI trusts nothing from the server: options are checked against the directory name rules and the root-signed policy's user CA cap, the begin answer is rebuilt from checked parts, the certificate is verified (signature included) against the root-pinned user CA with one reading of the clock"
    - "Login limiters are their own class with the sign-in values and a bucket per route: per client once per request, per (user, client) once the user is known"

key-files:
  created:
    - internal/serverdb/migrations/0004_login.sql
    - internal/server/login.go
    - internal/server/login_test.go
    - internal/server/web/templates/login_approve.html
    - cmd/keyroster/login.go
    - cmd/keyroster/loopback.go
    - cmd/keyroster/loginagent_unix.go
    - cmd/keyroster/loginagent_windows.go
    - cmd/keyroster/browser_linux.go
    - cmd/keyroster/browser_darwin.go
    - cmd/keyroster/browser_windows.go
    - cmd/keyroster/browser_other.go
    - cmd/keyroster/login_test.go
    - cmd/keyroster/login_unix_test.go
    - cmd/keyroster/login_windows_test.go
    - internal/audit/export_test.go
    - test/e2e/login_test.go
  modified:
    - internal/serverdb/db.go
    - internal/serverdb/db_test.go
    - internal/server/server.go
    - internal/server/signer.go
    - internal/server/server_test.go
    - internal/server/ratelimit.go
    - internal/server/render.go
    - internal/server/web/static/app.js
    - internal/audit/export.go
    - .github/workflows/e2e.yml
    - docs/runbooks/enroll-user.md

key-decisions:
  - "Login limiters: own instances (loginLimit, loginUserLimit) with the sign-in values, keyed per route; per client charged once per request, per user keyed on signInUserKey (02-10 G1)"
  - "The CLI measures clock skew in whole seconds on both sides (server_time - local Unix seconds)"
  - "keyroster login refuses a TTL below 2 minutes so the certificate can still have 60 s left on arrival"
  - "Windows prints only the host-scoped Host/IdentityAgent block (owner decision 2026-10-17), not -o IdentityAgent"
  - "The CLI prints a signer refusal detail in full only from the signer's closed list; any other 403 text only as a PeerError excerpt"

patterns-established:
  - "CLI login fake server (cmd/keyroster/login_test.go loginServer): a root-signed bundle whose user CA the test holds, driven like a browser"
  - "Per-OS startLoginTestAgent: real ssh-agent on Unix (KEYROSTER_REQUIRE_SSH_AGENT), winagent.Serve on a random test pipe on Windows"

requirements-completed: []  # AUTH-04 and UI-01 are decided in 02-14; AUTH-03 and PLAT-05 stay open while macOS is UNVERIFIED (plan <output>)

actuals:
  tokens: 45000
  tasks: 2
  commits: 8
plan_head_before: 71ff8be54f778a8a50ec8bd7de220162e30788b5
plan_head_after: e67ac2b

duration: about 65 min
completed: 2026-10-22
status: complete
---

# Phase 2 Plan 12: CLI Login Summary

**`keyroster login` makes an ephemeral Ed25519 key, prints its fingerprint, and runs a browser-loopback login with PKCE S256 and a state. The approval page shows the fingerprint the server computes from the stored request bytes, the passkey signs SHA-256 of those bytes, and the server asks the signer for a certificate only when the CLI redeems the single-use code with its verifier. The CLI accepts the certificate only from the root-pinned user CA (signature verified), for its own key, with exactly the requested principals and a kr2 key ID naming the user and request. It adds it to the agent with a lifetime equal to the remaining validity: OpenSSH ssh-agent via SSH_AUTH_SOCK on Linux and macOS, keyroster's own agent on Windows. A real sshd accepts the login through the agent.**

## Performance

- **Duration:** about 65 min of wall-clock execution (2026-10-22T12:22Z to about 13:30Z).
- **Tasks:** 2 of 3 executed. Task 3 is the owner's merge gate, which this executor does not run.
- **Files:** 28 outside `.planning`.

## Delivery

- **Branch:** `p02/12-cli-login`, created from origin/main `33aece6`. It keeps the orchestrator's unpushed `71ff8be docs(phase-02): mark 02-11 complete ...`.
- At the SUMMARY, `git fetch origin` showed origin/main still at `33aece6`, so no rebase was needed.
- **PR:** keyroster-bot opens it after the one push that carries this SUMMARY. Title: `feat(cli): keyroster login with passkey approval and ssh-agent lifetime`. The PR number and check results go in the merge-gate checkpoint; they do not exist before the push (as in 02-10 and 02-11).
- **Auto-merge is not enabled.** This is an environment rule: the plan's "enable auto-merge" step is deliberately unmet.

## API and page contract

| Route | Limits | Answers |
|---|---|---|
| `GET /api/v1/login/options?user=NAME` | per client; per (user, client) after the name rule | 200 `{"server_time","user","ca_max_ttl_seconds","roles":[{"name","principals","max_ttl_seconds","extensions"}]}` from `directory.Authorize` per role, custody header; uniform 404 `no usable passkey for this user`; `roles: []` for a user without a role |
| `POST /api/v1/login/begin` `{"request","code_challenge","code_challenge_method","state","redirect_port"}` | per client; per (subject, client) after the name rule | 200 `{"login_id","approval_url","expires_at"}`; uniform 404 for an unusable subject; 400 `malformed request` (evidence present, bad bytes, method not S256, challenge or state not 43 base64url characters, port outside 1024-65535); 400 `the request time is more than 120 s from the server's clock` |
| `GET /login/{id}` | per client | 200 approval page; the uniform 404 error page for an unknown, expired, approved or redeemed login |
| `POST /api/v1/login/{id}/assertion` | per client; per (stored user, client) | 200 `{"redirect":"http://127.0.0.1:<stored port>/callback?code=<code>&state=<stored state>"}`; every refusal 401 `{"error":"approval failed"}` |
| `POST /api/v1/login/{id}/redeem` `{"code","code_verifier"}` | per client; per (stored user, client) | 200 `{"certificate":"<std base64>"}`; 403 `{"error":"<signer detail>"}` for a signer refusal; every other failure 400 `{"error":"login not redeemable"}`; 503 when the signer status cannot be read (code not burnt) |

- **Timing:** begin window ±120 s around CreatedAt; the session expires at CreatedAt + 240 s; a code is valid for min(now + 120 s, CreatedAt + 290 s); the CLI waits until `expires_at − skew + 5 s`.
- **Approval page** (`login_approve.html`): `<section id="kr-approve" data-assertion data-expires data-options>`. It shows the fingerprint (from the stored request's subject key), the warning "Approve only if your terminal shows exactly this fingerprint. If you did not just run keyroster login, close this page.", the user, the roles (or "all your roles"), each principal, the TTL, the expiry and a countdown. It also has the `role="alert"` element and the KEY-06 banner. The `data-options` challenge is base64url(Digest()), allowCredentials holds the user's directory credentials, and userVerification is required.
- **app.js `#kr-approve`:** it feature-detects on load, and the countdown only informs. `navigator.credentials.get` runs only in the Approve click handler, and errors go through textContent. Navigation uses `window.location.assign(resp.redirect)`; `127.0.0.1` never appears in app.js.
- **Logging:** one line per event, message `cli login`, with `event`, `reason`, `user`, `login_id` and `client`. An assertion refusal also writes a `cli login assertion refused` line with the verifier sentinel, plus `authenticator_data_len` and `authenticator_flags` for authenticator-data refusals. No line holds a code, a verifier or a state.

## CLI certificate checks

On one `now` read after the redeem, the certificate must:
- be a user certificate whose SignatureKey is the active user CA of the root-verified bundle;
- pass `ssh.CertChecker.CheckCert`, which verifies the signature and the validity at `now`;
- have the ephemeral key as its Key;
- have ValidPrincipals equal to the request's principals;
- have a key ID that is kr2 with `ca=user`, `sub=<user>` and `req=<hex request ID>`;
- span at most TTL + 300 s;
- have at least 60 s left, where remaining = ValidBefore − ceil(now).

The agent add is `AddedKey{PrivateKey, Certificate, LifetimeSecs: remaining, Comment: KeyId}`. The listing must then hold the certificate blob. If the agent refuses the constrained add, login fails with no retry. A failed redeem (HTTP error, 400, 403, lost answer) ends with `login not completed: ...; run keyroster login again`, also with no retry.

## Cross-OS flow test (configuration; CI results go in the checkpoint)

| Job | Runs `TestLoginFlowFakeServer` with |
|---|---|
| build-test (Linux, `-race`, `KEYROSTER_REQUIRE_SSH_AGENT=1`) | a real OpenSSH `ssh-agent -D -a <sock>`; the default Unix `connectLoginAgent` |
| cli-macos (`KEYROSTER_REQUIRE_SSH_AGENT=1`) | the same, with the macOS ssh-agent |
| cli-windows | in-process `winagent.Serve` on `\\.\pipe\keyroster-test-<16 random bytes hex>`; `connectLoginAgent` replaced by a dial that requires `winagent.VerifyServerOwner` |

Locally: it passed on the Windows development host (Windows adapter, test pipe) and in WSL (real ssh-agent, switch set).

## A3 and the expiry record

- **A3 line applied:** `A3: moved to 02-14` (02-02-SUMMARY). No gcr check ships and there is no `gcr_socket_refused` test. gcr-ssh-agent is **UNVERIFIED until 02-14**; enroll-user.md says to use OpenSSH ssh-agent.
- **login_lifetime_expiry matched on fingerprint and key ID.** For both logins, the fingerprint the CLI printed and its `Key ID:` appear on the same `ssh-add -l` line (OpenSSH 10.5p1 prints the plain key's fingerprint for the `ED25519-CERT` entry). This is informational for 02-14, which matches on the key ID.

## Task Commits

1. **Task 1 (tracer):** `99e9cbf` feat(02-12): keyroster login through passkey approval and loopback redeem.
   - Tracer gate: interactive, `end-of-phase`, automated-only verify.
   - `TestLoginEndToEnd` (WSL, OpenSSH 10.5p1) passed before the commit, and the CLI cross-builds for windows, darwin, linux and freebsd.
   - Logged: "Tracer verified end-to-end — expanding".
2. **Task 2:**
   - `845d75c` fix(02-12): measure the login clock skew in whole seconds
   - `45eaded` test(02-12): login refusal matrix, cross-OS CLI flow and e2e subtests
   - `c761283` feat(02-12): decode login_issue and directory_install leaves in the export
   - `2c4d71a` ci(02-12): run the e2e suite with a 20 minute timeout
   - `62388d1` docs(02-12): logging in and the fingerprint residual in enroll-user
   - `a9d6a67` fix(02-12): charge the login per-client limit once per request
   - `e67ac2b` test(02-12): keyroster login peer text and custody banner
3. **Task 3, merge gate:** not attempted. It is the owner's `checkpoint:human-action` (`gate="blocking-human"`).

**Plan metadata:** `docs(02-12): complete cli-login plan` (this file, STATE.md, deferred-items.md and the corrected line of 02-12-PLAN.md).

## TDD record (workflow.tdd_mode is false, so the gate sequence is advisory)

There is no RED commit: Task 1, the tracer, wrote the code first. The one exception is the per-client double charge (`a9d6a67`). Its test `per_client_charged_once` was written first and failed on the old code, with begin #6 getting 429.

Each key property was shown to bite with a mutant, applied by a script, run against the named tests and then restored. The CLI mutants ran against the committed `login.go` at `845d75c`/HEAD. An earlier run restored with `git checkout` onto the pre-fix file, so it was discarded and repeated. Mutants that first failed to build were rewritten until they built, and only those runs are counted.

| Mutant | Killed by |
|---|---|
| redeem without the PKCE compare | `wrong_verifier`, `signer_not_called_on_refusal` |
| redeem without the verifier-format check | `bad_verifier_format` (log reason `verifier_format`) |
| redeem without the handler's code-expiry check | `code_expired` (log reason `expired`) |
| redeem burns the code before the checks | `redeems_with_stored_assertion`, `wrong_code` |
| redeem without the status read before the burn | `redeems_with_stored_assertion`, `wrong_code` |
| assertion without the handler's deadline check | `assertion_after_deadline_refused` (log reason) |
| page without the expiry check | `expired_or_redeemed_page_refused` |
| code without the CreatedAt + 290 s cap | `code_capped_by_signer_window` |
| page options challenge not the digest | `page_shows_stored_fingerprint` |
| redirect from a different port | `expired_or_redeemed_page_refused`, `assertion_after_deadline_refused` |
| per-user key on the name only | `other_client_not_locked_out` |
| per-client bucket shared across routes | `client_buckets_per_route` |
| CLI without CheckCert (signature) | `cert_bad_signature_refused` |
| CLI without the CA key compare | `cert_other_ca_refused` |
| CLI without the key compare | `cert_other_key_refused` |
| CLI without the principals compare | `cert_extra_principal_refused` |
| CLI without the key-ID subject check | `cert_other_user_refused` |
| CLI span check + 5 s | `cert_span_ttl_301_refused` |
| CLI remaining check − 2 s | `cert_59s_remaining_refused` |
| CLI retries the add without the lifetime | `constrained_add_refused_no_retry` |
| CLI accepts any listing entry | `listing_without_cert_refused` |
| CLI deadline without the skew | `callback_deadline_uses_server_expiry` |
| CLI lifetime + 400 s | `lifetime_within_remaining_validity` |
| CLI skew limit + 1 s | `clock_skew_refused` |
| CLI accepts any approval URL origin | `begin_answer_checked` |
| CLI retries the redeem | `redeem_failure_tells_rerun/connection_closed` |

Not counted: the page-fingerprint-from-another-field mutant did not build. The e2e and `page_shows_stored_fingerprint` assert the fingerprint verbatim.

## Verification run

- **Windows (go1.27.3):**
  - `gofmt -l .` empty;
  - `go vet ./...` with GOOS windows, linux and darwin;
  - `go test -count=1 ./...` passed;
  - `TestLoginFlowFakeServer -v` passed, not skipped (Windows adapter on a test pipe);
  - `CGO_ENABLED=0 GOOS=windows|darwin|linux|freebsd go build ./cmd/keyroster` passed.
- **WSL (scripts/linux.sh, script files in the session scratchpad):**
  - `go test -race -count=1 ./...` exit 0, no DATA RACE. It ran at the Task 2 test commit, and `./internal/server/` and `./cmd/keyroster/` ran again at HEAD.
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/` clean; `$(go env GOROOT)/bin/gofmt -l .` empty.
  - golangci-lint v2.14.0: 0 issues with GOOS linux, windows and darwin, at HEAD. The first run found 5 test-file issues (bodyclose, revive unused-parameter), which were fixed.
  - `scripts/capslock-check.sh`: 91 pairs, baseline 91 (the export change added no capability). `scripts/dep-firewall.sh` and `scripts/testonly-firewall.sh` clean.
  - `TestDecodeLoginIssue` passed.
  - The plan's failing-branch command, run verbatim, exits 0. With `KEYROSTER_REQUIRE_SSH_AGENT=1 PATH=/nonexistent`, the test binary prints "ssh-agent not found and KEYROSTER_REQUIRE_SSH_AGENT=1".
  - With a real ssh-agent and the switch set, `TestLoginFlowFakeServer` and `TestLoginAgentUnix/ssh_auth_sock_unset_refused` passed.
- **e2e in WSL (OpenSSH 10.5p1), `-run TestLogin -timeout 20m`, at HEAD:**
  - `TestLoginEndToEnd` passed with `login_lifetime_expiry` (124.7 s), `two_concurrent_logins`, `unapproved_login_mints_nothing` and `signer_refusal_after_approval`. In the last, the CLI printed `refused by the signer: role_not_granted; run keyroster login again`.
  - `TestLoginRefusals` and `TestLoginSignerEndToEnd` (02-04) passed.
  - The full e2e suite (`-run .`) at HEAD under the same wrapper: every test passed except `TestSSHDRejects/pty_allowed`, which passed on a rerun without the hosts wrapper. That is the side effect of the wrapper that 02-07 and 02-10 recorded; that test does not involve keyroster login.
  - WSL's resolver does not answer `keyroster.localhost`. As in 02-07..02-11, the run used the uncommitted scratch wrapper that bind-mounts a private `/etc/hosts`.
- **Not run locally:** the 9.5p1 e2e lane, govulncheck, and the macOS and Windows CI lanes. CI runs them; the results go in the checkpoint.

## Deviations from Plan

### Deferred-items rows addressed to 02-12

1. **02-03 (fingerprint claim), resolved by wording.**
   - The must_haves truth at 02-12-PLAN.md line 48 said "a server showing a false fingerprint gets a signer refusal". That holds against page tampering on an honest server, not against a compromised server.
   - Corrected text: the authenticator signs only the challenge, so a compromised server can show the CLI key's fingerprint while the challenge covers its own key. The signer then issues for that key. The CLI's own-key check keeps that certificate out of the agent, and the issuance is logged with the other key's `key_fingerprint`. The residual is T-02-60.
   - enroll-user.md "Residual risk" says the same, and no shipped text claims a refusal.
   - No redesign: closing this would need the authenticator to sign displayed data, which WebAuthn does not offer.
2. **02-10 (per-username limiter on (user, client)), resolved.**
   - Login keys its per-user limit with `signInUserKey`, after the name rule at options and begin, and on the stored user at assertion and redeem.
   - Test: `TestLoginLimits/other_client_not_locked_out`.
3. **02-07 part (c) (requestOrigin on a login route), applied.** `approval_url` uses `requestOrigin`, and the CLI accepts only the configured server's origin or a root-signed policy origin.
4. **02-07 route-class rows:** the login routes are their own class with the 02-10 values and keep the global backstop on the per-client limiter.
5. **02-06 (negative cache, `init --force` keeping fields), reviewed.** 02-12 touches neither the status cache nor the config format. Both questions stay open for the owner.
6. **Not addressed (not 02-12's):**
   - the 02-01 gofmt-in-WSL row: this plan ran the GOROOT gofmt from a script file;
   - the 02-03 `TestCheckLogAgainstLiveSigner` flake row: it did not occur in this plan's runs, and this plan does not touch issuance;
   - the 02-05 capslock row: the count is unchanged.

### Auto-fixed issues

7. **[Rule 1] Clock skew read in fractional time** (`845d75c`). The server time is whole seconds, so `time.Unix(server_time).Sub(now).Truncate(s)` read 61 s of skew as 60 s and started the login. Now both sides are whole seconds. Found by `clock_skew_refused`.
8. **[Rule 1] The per-client login limit was charged twice on begin, assertion and redeem** (`a9d6a67`, found in the pre-completion review). The effective limit was 10/min burst 5, not the stated 20/min burst 10. It is now split into `loginClientAllow` (once per request) and `loginUserAllow`. Tests: `per_client_charged_once` (red before the fix) and `client_buckets_per_route`.
9. **[Rule 3] `TestOpen/migration_applies_once`** expected schema version 3; it now expects 4 (`internal/serverdb/db_test.go`, outside files_modified).
10. **[Rule 2] Files outside files_modified:**
    - `internal/server/ratelimit.go`: a doc sentence on the login class.
    - `internal/server/render.go`: the `login_approve` page name and the `pageData.Login` field.
    - `internal/server/login_test.go` also holds `TestLoginOptions`, `TestLoginLimits` and the banner case.
11. **[Rule 2] Tests beyond the plan's list:**
    - server: `authenticator_data_refusal_logs_length_and_flags`, `signer_unavailable_keeps_code`, `signer_error_is_uniform_400`, `log_has_no_secrets`, `custody_banner_on_approval_page`;
    - CLI: `cert_bad_signature_refused`, `begin_answer_checked`, `listing_without_cert_refused`, `TestLoginPeerText` (options error with ESC/CR, a begin URL with control characters not echoed, an unknown 403 detail only as an excerpt, the software-custody banner);
    - export: `garbage_cert_keeps_serial`.

### Environment overrides and owner decisions applied

12. **Windows output:** only the host-scoped `Host <your keyroster hosts>` / `IdentityAgent //./pipe/keyroster-agent-<SID>` block, per the owner decision of 2026-10-17. Step 11's `-o IdentityAgent=` form is not printed.
13. Auto-merge not enabled; one push; ROADMAP not marked complete; no `requirements.mark-complete` call (`requirements-completed: []` per the plan's output section).

### Test design notes

14. **`two_concurrent_logins`:** the e2e cannot read B's PKCE verifier out of CLI process B. So it posts A's code with a foreign verifier to B's redeem while B is still pending (400), and A then still redeems. `cross_login_code` in the server unit tests covers A's code with B's verifier on an approved B.
15. **`login_lifetime_expiry`** reads the 2 m certificate's ValidBefore from the decoded export (`valid_before`), not from the CLI's local-time "Valid until" line.

### Choices the plan left open (listed for the owner's veto)

16. The login routes have **their own limiter instances with a bucket per route**: one per route and client, and one per route, user and client. A single bucket for all five routes would let one ordinary login (5 requests) use half the burst. So each route gets 20/min burst 10 per client, and 10/min burst 10 per (user, client) on the four API routes.
17. **`serverdb.Login(ctx, id)`** takes no `now`: it returns the row whatever its expiry, and each handler applies its own deadline. `created_us` stores the request's CreatedAt.
18. **TTL floor of 2 minutes** for `keyroster login`: a shorter certificate could not have 60 s left after the approval. A role whose cap is under 2 min cannot be used for login.
19. **Skew is measured in whole seconds** (server_time − local Unix seconds), so a skew of exactly 60 s is accepted and 61 s refused.
20. **Options for a user without roles** answer 200 with `roles: []`, and the CLI says "<user> holds no role on this server; ask an admin to grant one".
21. **A begin outside ±120 s** gets its own 400 text, "the request time is more than 120 s from the server's clock", not `malformed request`.
22. **Signer refusal details** are printed in full only from a closed list of the signer's login refusals. Any other 403 text is shown only as a PeerError excerpt.
23. **Output split:** progress (fingerprint, principals, approval URL, warnings) goes to stderr. The result (`Logged in as ...`, `Serial:`, `Key ID:`, `Valid until:`, the Windows block) goes to stdout.
24. **Loopback:** a second valid callback after the first gets 400, the server also sets `Referrer-Policy: no-referrer`, and a malformed code gets 400. The answer page carries `Cache-Control: no-store`.
25. **Only the certificate identity** is added to the agent (`AddedKey` with Certificate), not a separate plain-key entry. `ssh-add -l` shows one `ED25519-CERT` line per login.
26. **The approval page's expiry** is shown in UTC (`15:04:05 UTC`). The countdown uses the browser's clock and only informs; it does not disable the button.
27. **Approval-URL check in the CLI:** https, no user, query or fragment, path exactly `/login/<32 hex>`, an origin equal to the configured server or a root-signed policy origin, and `expires_at` within 600 s of `server_time`.
28. **`ca_max_ttl_seconds`** must equal the root-verified policy's user CA cap, or the CLI refuses the options.

**Total deviations:** 28: 6 deferred-row items, 5 auto-fixes and scope items, 2 environment items, 2 test-design notes, 13 open choices.

**Impact on plan:** no new module and no capslock change. The signer is untouched apart from the export decode it links, which uses only packages it already linked.

## Threat model notes

- **T-02-56/T-02-60:** see deviation 1. The honest wording is in the plan, enroll-user.md and this SUMMARY.
- **T-02-57/T-02-58/T-02-59:** PKCE and state checks, the loopback Host check and a redirect built only from the stored port and state. The server tests and `TestLoopback` cover them.
- **T-02-105/T-02-106:** the limiter values are now as stated (deviation 8).
- **T-02-108:** a lost redeem answer is not retried (`redeem_failure_tells_rerun`).
- The five new unauthenticated routes have the same HTTP/2 buffering exposure as 02-08's and 02-10's routes (receive windows before the handler's body caps). That belongs to the Phase 6 todo `2026-10-20-cap-server-connections-and-memory.md`. It was not measured here (UNVERIFIED).

## Relation to the phase-4/6 todos

Not made worse. Login reads only the installed directory through the existing mirror, and its one signer call is the existing `TypeLoginIssueRequest`. There is no directory format change and no install path, and no new trust is placed in the server: the CLI verifies every certificate against the root-pinned user CA.

## Not exercised (UNVERIFIED)

- **The approval page's script in a real browser:**
  - feature detection, `navigator.credentials.get`, the countdown and `window.location.assign`;
  - the judgment-tier prohibition that WebAuthn starts only from the Approve click.

  This was checked by reading the `#kr-approve` code and `node --check`; no test runs it. UNVERIFIED until 02-14.
- **The browser opener** (xdg-open, open, rundll32): every test uses `--no-browser`. UNVERIFIED until 02-14.
- **The default Windows `connectLoginAgent`** (os.Executable, then winagent.Ensure starting a detached keyroster agent from `keyroster login`): the tests point the hook at a test pipe. Ensure itself is tested in 02-02. UNVERIFIED until 02-14 Task 2.
- **gcr-ssh-agent:** A3 moved to 02-14, and no check shipped.
- **The macOS browser leg:** there is no Mac (D-16).
- **Real authenticators:** only the soft authenticator ran.
- **The skip branch of `startLoginTestAgent`** (no ssh-agent, switch unset): run by no command.
- **CI-only:** the e2e 9.5p1 lane, govulncheck, cli-macos and cli-windows (results in the checkpoint).

## Known Stubs

None.

## Threat Flags

None beyond the plan's threat model: the five routes, the table and the loopback are T-02-56..64 and T-02-105..108.

## User Setup Required

None.

## Next Phase Readiness

- **02-13/02-14:**
  - run the approval page and the opener in real browsers;
  - run the Windows Ensure path from `keyroster login`;
  - run the A3 probe;
  - match listings on the key ID (decided in this plan's e2e).
- This plan is blocked on the owner's merge gate for its PR.

## Self-Check: PASSED

- Every file in `key-files.created` exists.
- Commits `99e9cbf`, `845d75c`, `45eaded`, `c761283`, `2c4d71a`, `62388d1`, `a9d6a67` and `e67ac2b` are ancestors of HEAD and carry an SSH signature (`gpgsig` checked on each); `git rev-list --count 71ff8be..e67ac2b` is 8.
- Task 1 acceptance greps pass:
  - one `signer.Login(` line in login.go;
  - only signer.go imports signerclient;
  - two `Login(ctx context.Context, req *wire.LoginIssueRequest)` lines in signer.go and one non-comment `signerclient.Login(`;
  - one `type fakeSigner struct`;
  - `127.0.0.1` count 0 in app.js;
  - `defer clear(priv)` directly after `ed25519.GenerateKey`;
  - one non-comment `winagent.Ensure(` and the two-value `exe, err := os.Executable()`;
  - `connectLoginAgent` in loginagent_unix.go.
- Task 2 acceptance:
  - every named server and CLI case is present;
  - one `func startLoginTestAgent` per OS file, `connectLoginAgent = ` and `VerifyServerOwner` in login_windows_test.go;
  - `KEYROSTER_REQUIRE_SSH_AGENT` 3 non-comment lines in login_unix_test.go and ≥2 in ci.yml;
  - exactly one `-timeout 20m` in e2e.yml.
- No private network detail in any changed file (grep for 10.x, 100.x, 192.168.x, host and account names: none).

## Pre-merge review fixes

These fix the verified findings of the pre-merge review of PR 52 (head `1753113`). Each code fix has a test that failed before the fix and passes after it. Each test-only finding was proven by a mutation: the checked line was broken, the suite failed, and the line was restored.

**Owner decision 2026-10-22:** the 13 open choices (deviations 16-28) are approved as owner-approved deviations ("Godkänn (Rekommenderas)"). Three of them are adjusted below:
- **Choice 16:** each route now also has its own global backstop.
- **Choices 18 and 19:** the 2-minute floor now holds at any accepted skew, and the skew is now read from a local time taken before the options request.

**Fixed:**
- **Per-route global backstop** (server login.go:130; medium). Commit `89eb62d`, fix(server).
  - Before: the five login routes shared one global backstop sized for one bucket per client.
  - Now each route has its own limiter (`newLoginLimits`), with a backstop of `globalFactor` × the per-client values. The per-client and per-(user, client) buckets are unchanged.
  - Tests in `TestLoginLimits`:
    - `junk_on_every_route_leaves_others_open`: 2 addresses × 5 routes × 10 junk requests, then a third client's options and begin get 200.
    - `route_backstop_applies_per_route`: 10 addresses drain the options backstop, so an 11th address's options gets 429 while its begin gets 200.
  - Both failed before the fix (429).
- **Login certificate roles, extensions and critical options** (CLI login.go:514; the SPLIT finding, fixed per the orchestrator note). Commit `ab3ab1f`, fix(cli).
  - The key ID must name exactly the plan's roles: the `--role` subset, or every role of the options, sorted like the signer's grant.
  - The extensions must be exactly the requested ones plus the root-signed user CA profile's defaults.
  - A critical option is refused by name before CertChecker runs.
  - New table cases:
    - `cert_extra_role_refused`;
    - `cert_unrequested_role_refused` (`--role ops`, certificate names dev+ops);
    - `cert_extra_extension_refused`;
    - `cert_critical_option_refused`.
  - The control `role_extensions_accepted` shows that a role granting `permit-agent-forwarding` still logs in.
  - All four refusal cases failed before the fix. The critical-option case was already refused before, but only with CertChecker's vaguer "CA signature or validity" text.
  - The fake now issues the honest roles and extensions the way the signer does.
- **Skew in the remaining validity and the agent lifetime** (CLI login.go:520 and :524, two duplicate findings, both low). Commit `2d0d65b`, fix(cli).
  - `checkLoginCert` now reads the server's clock as local + measured skew + 1 s, to cover the whole-second truncation. It uses that clock for CertChecker, the 60 s floor and the agent lifetime.
  - The skew is measured from a local reading taken before the options request, so it errs toward a shorter lifetime.
  - Test `two_minute_login_at_accepted_skew`: a `--ttl 2m` login whose certificate is minted 2 s before the check, at skew -60, 0 and +60 s. It requires success and a lifetime of at least 60 s and at most what the certificate has left on the server's clock.
  - Before the fix, -60 s was refused with "less than 60 s left", and +60 s gave a lifetime of 2m58s against 1m58s left.
  - enroll-user.md now states the lifetime rule.
- **Options validation untested** (CLI login.go:335/340). Commit `c12326c`, test(cli).
  - `options_checked` has 11 cases: other user, `server_time` 0, a CA cap other than the policy's, too many roles, a bad role name, a zero role TTL, no principals, a principal with ESC, a principal with CR, a bad extension, and a duplicate role.
  - Each case requires `errBadLoginOptions`, no begin, no agent add, and none of the text on stderr.
  - Mutants killed: line 335 changed to `if false {` (4 cases fail), and line 340 reduced to `if r.MaxTTLSeconds == 0 {` (4 cases fail).
- **checkBegin's https and expiry checks untested** (CLI login.go:434). Commit `ef3b2fc`, test(cli).
  - `begin_answer_fields_checked` covers: an http URL on the configured host, a query, a fragment, user info, another login's path, `expires_at` equal to the server time, and `expires_at` at +601 s. The control is +600 s, which is offered.
  - Mutants killed: dropping the expiry bound (2 cases fail) and dropping `u.Scheme != "https"` (`http_scheme` fails).
- **Server begin state format untested** (server login.go:350). Commit `385c7e2`, test(server).
  - `bad_state_refused_nothing_stored` covers a 42-character state and a state containing `&`, `+`, `#` or `=` padding. It requires the malformed-request 400 and an unchanged `login_sessions` row count.
  - Mutant killed: removing `|| !pkceRE.MatchString(in.State)`.

**Judged, no code change:**
- **CodeQL #14 (server login.go:118, `logLogin`):** every logged value is constrained, so this is a false positive.
  - `event` and `reason` are constants.
  - `user` is "", a name that passed `directory.ValidUserName`, or the stored `l.User`, which begin wrote only after that check.
  - `login_id` is "" until it passes `loginIDRE` (32 lowercase hex), or it is the server-made ID.
  - `client` is `remoteIP`, a parsed `netip` address.
  - The server logs through `slog.NewJSONHandler`, which escapes control characters anyway.
- **CodeQL #15 (server login.go:767, `loginInternal`):** a false positive.
  - `event` is a constant.
  - `err` is an internal error from the database, the RNG or `directory.Authorize`, and Authorize quotes names with `%q`.
  - The JSON handler escapes the value.

**Skipped:** none.

**Checks:**
- `gofmt -l .` printed nothing.
- `go vet ./...` passed natively (windows) and with `GOOS=linux` and `GOOS=darwin`. `GOOS=linux go vet -tags e2e ./test/e2e/` also passed.
- `go test -count=1 ./cmd/keyroster/ ./internal/server/` and `go test ./...` passed.
- `-race` was not run: there is no cgo toolchain here. The e2e lane is CI-only.
