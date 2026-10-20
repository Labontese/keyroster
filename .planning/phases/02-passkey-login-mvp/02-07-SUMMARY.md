---
phase: 02-passkey-login-mvp
plan: 07
subsystem: server
tags: [server, admin-api, sshsig, invites, rate-limit, serverdb, sqlite, cli, auth-01, ui-01]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-06: keyroster-server (signerAPI seam, fakeSigner, currentStatus, secure headers, custody header), serverclient (pinned client, PeerError, ConnectError), keyroster init and Config; 02-03: signerclient.GetDirectory; 02-01: directory document"
provides:
  - "internal/adminauth: Namespace keyroster/admin-api/v1, HeaderTime/HeaderNonce/HeaderSignature, MaxSkew, Message, Sign, Verify (distinct Err values)"
  - "internal/serverdb: Open, CreatePendingUser (ErrExists), ReplaceInvite, PendingUser, PendingUserByInvite, UseNonce (ErrNonceUsed); migration 0001_server.sql (pending_users, admin_nonces); nothing in it is authority"
  - "server: requireAdmin / requireAdminLimit (maxAdminBody, 413 before verify), nonceRetention, POST /api/v1/admin/users, requestOrigin, GET /enroll/{token}, per-client + global rate limits (Limits), GetDirectory on the signer seam with a version/hash-keyed cache, Config.DB and Config.Limits"
  - "serverclient: AdminJSON (signs URL.RequestURI(), clock hint on 401), AdminUsersPath, AddUserRequest/AddUserResponse, AdminErrPending/AdminErrInDirectory, HTTPError (APIErrorIs), ErrAdminAuth, ErrAdminBodyTooLarge"
  - "keyroster user add NAME [--reinvite] [--admin-key]; keyroster-server serve --state-dir; unit StateDirectory"
  - "directory.ValidUserName (exported name rule)"
affects: [02-08, 02-09, 02-10, 02-11, 02-12, 02-13, AUTH-01, UI-01]

actuals:
  tokens: 37000   # chars/4 over the added lines of the code, test, deploy and docs diff (147924 chars); planning docs excluded
  tasks: 2        # Tasks 1-2 executed; Task 3 is the owner merge gate
  commits: 5      # git rev-list --count plan_head_before..HEAD at SUMMARY write; this docs commit follows
plan_head_before: 2cfdcd3aa340ea8b0499286d7c6530dfab3cce20
plan_head_after: 1b61c5bfd72f5dcaad023d155cae5509c49677c4

tech-stack:
  added: ["golang.org/x/time v0.16.0 (rate; owner-locked in STACK.md; server and CLI graph only, absent from the signer graph)"]
  patterns:
    - "Admin requests are authenticated per request by SSHSIG over the raw request-target; the server keeps no admin list of its own, only the root-signed policy from the signer's Status"
    - "Server-chosen text in a CLI success answer (the invite URL, the expiry) is parsed as structured data and rebuilt, never printed as received"
    - "A refusal the CLI must render is matched exactly against an exported constant (APIErrorIs); the server's text appears only as a PeerError excerpt"

key-files:
  created:
    - internal/adminauth/adminauth.go
    - internal/adminauth/adminauth_test.go
    - internal/adminauth/fuzz_test.go
    - internal/serverdb/db.go
    - internal/serverdb/migrate.go
    - internal/serverdb/migrations/0001_server.sql
    - internal/serverdb/db_test.go
    - internal/server/admin.go
    - internal/server/invite.go
    - internal/server/ratelimit.go
    - internal/server/admin_test.go
    - internal/server/web/templates/enroll.html
    - internal/serverclient/admin.go
    - internal/serverclient/admin_test.go
    - cmd/keyroster/user.go
    - cmd/keyroster/user_test.go
    - cmd/keyroster/fuzz_user_test.go
    - test/e2e/enroll_test.go
  modified:
    - go.mod
    - go.sum
    - internal/server/server.go
    - internal/server/signer.go
    - internal/server/render.go
    - internal/server/server_test.go
    - internal/serverclient/client.go
    - internal/serverclient/client_test.go
    - internal/serverclient/fuzz_test.go
    - internal/directory/directory.go
    - cmd/keyroster-server/serve.go
    - deploy/systemd/keyroster-server.service
    - docs/runbooks/server-install.md
    - test/e2e/server_test.go

key-decisions:
  - "The admin-api/v1 signed message is keyroster/admin-api/v1\\nMETHOD\\nraw request-target\\nhex sha256(body)\\nunix seconds\\n32-hex nonce\\n, SSHSIG under the same namespace; the signature header is standard base64 of the armored SSHSIG"
  - "The CLI parses the server's invite_url as an origin (ParseServerURL) + /enroll/ + 43 base64url characters and prints the rebuilt URL; it does not check that the origin is one of the policy's origins (it does not fetch the trust document for user add). Superseded by the pre-merge fixes (062a59e): user add verifies the trust document and requires a policy origin"
  - "Pre-merge fixes: the admin message covers the canonical server origin and the body digest (sent in Keyroster-Admin-Body-SHA256); the server verifies against an exactly matched policy origin before its handler reads any body; the admin route has no global rate-limit bucket"
  - "ParseServerURL now requires a letter-digit-hyphen DNS host and a non-empty port, so neither a server URL nor an invite URL can carry a shell metacharacter (found by FuzzParseInviteURL)"
  - "The server reads the installed directory per user add through GetDirectory and caches the user list only while the Status reports the same directory version and SHA-256"
  - "A timed-out *net.OpError keeps Go's own text in ConnectError (the 02-06 round 4 deferred item)"

patterns-established:
  - "requireAdminLimit: limit while reading, then Status, then Verify on r.RequestURI, then UseNonce, then re-attach the verified body"
  - "Rate limiting keys on RemoteAddr only (IPv6 by /64), with an LRU-bounded per-client map and a global backstop per route class"

requirements-completed: []  # AUTH-01 completes in 02-13; UI-01 continues in later plans (plan <output>)

coverage:
  - id: D1
    description: "keyroster user add creates a pending account through the SSHSIG admin API and prints the invite URL, the user's keyroster init line (always with --tls-root-file keyroster-tls-root.pem) and the pinned TLS root PEM; the printed line runs unchanged for the user in a fresh config; the invite page greets the user; the signer's directory stays at version 0; a second add is refused already pending; a non-admin key gets admin authentication failed while the admin's add succeeds"
    requirement: AUTH-01
    verification:
      - kind: e2e
        ref: "test/e2e/enroll_test.go#TestUserAddInvite (WSL, sshd 10.5p1 and 9.5p1, with keyroster.localhost mapped in a private mount namespace; see Issues)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Admin authentication: every refusal of adminauth.Verify is a distinct error; the server answers each with the identical 401 body and a specific log line; nonces are single-use (serial, parallel, after a purge); the signed path is the raw request-target; the handler reads exactly the signed body; a body over the route's limit gets 413 before any verification and consumes no nonce"
    verification:
      - kind: unit
        ref: "internal/adminauth/adminauth_test.go#TestVerify; internal/server/admin_test.go#TestAdminAuth; FuzzVerify (20 s)"
        status: pass
    human_judgment: false
  - id: D3
    description: "POST /api/v1/admin/users: name rule (400), directory name (409 already in directory), pending name (409 already pending), held and parallel concurrent adds (one 201, one 409, one row), reinvite replaces the token and keeps the handle, reinvite of a directory user (with and without a pending row), invite origin per Host, directory cache follows the Status, an unparsable directory fails closed"
    requirement: AUTH-01
    verification:
      - kind: unit
        ref: "internal/server/admin_test.go#TestAdminUsers; internal/serverdb/db_test.go#TestCreatePendingUserConflict, TestPendingUserInvite, TestUseNonce, TestOpen"
        status: pass
    human_judgment: false
  - id: D4
    description: "Invite page GET /enroll/{token}: greets the user with the RP ID and expiry, no script, Referrer-Policy no-referrer and all security headers; unknown, malformed, replaced and expired tokens get one uniform 404; the token never appears in the log"
    requirement: UI-01
    verification:
      - kind: unit
        ref: "internal/server/admin_test.go#TestInvitePage"
        status: pass
    human_judgment: true
    rationale: "No browser has rendered the page; its wording and layout are for the owner to judge (UNVERIFIED in a browser)"
  - id: D5
    description: "Rate limits: per-client buckets keyed by RemoteAddr (IPv6 /64, X-Forwarded-For ignored), global backstop, 429 with Retry-After, map bounded at 10 000 entries, idle eviction"
    verification:
      - kind: unit
        ref: "internal/server/admin_test.go#TestRateLimit"
        status: pass
    human_judgment: false
  - id: D6
    description: "CLI and client: AdminJSON signs the sent request-target; 401/413/429 in the CLI's own words with a clock hint above 60 s; 409 rendered from exact constants; forged or padded invite URL, expiry, 401 and 409 bodies never reach the terminal beyond a PeerError excerpt; the custody banner prints once"
    verification:
      - kind: unit
        ref: "internal/serverclient/admin_test.go#TestAdminJSONSigns, TestAdminJSONClockSkewHint, TestAdminJSONRefusals; cmd/keyroster/user_test.go#TestUserAdd, TestUserAddPeerText; FuzzParseInviteURL, FuzzParseServerURL (20-30 s)"
        status: pass
    human_judgment: false
  - id: D7
    description: "keyroster-server serve --state-dir and the unit's StateDirectory=keyroster-server (0700)"
    verification:
      - kind: other
        ref: "systemd-analyze verify (systemd 255, WSL): no unit error; e2e servers start with --state-dir"
        status: pass
    human_judgment: true
    rationale: "The unit has not run on a host; StateDirectory under ProtectSystem=strict is UNVERIFIED until 02-13"

duration: 5h40m (wall clock, including an interrupted session)
completed: 2026-10-20
status: complete
---

# Phase 2 Plan 07: Admin API Summary

**Admins now start an enrollment with `keyroster user add alice`: an SSHSIG-signed admin API (keyroster/admin-api/v1, policy admin keys only, single-use nonces) creates a pending account with a hashed 24 h invite, the CLI prints the invite URL, the user's ready-to-run `keyroster init` line and the pinned TLS root, and nothing about it reaches the signer: the directory stays unchanged until an admin signs a credential in (02-09).**

## Performance

- **Started:** 2026-10-20T05:25Z. **SUMMARY written:** 2026-10-20T11:05Z. The executor session was interrupted once and resumed.
- **Tasks:** Tasks 1 (tracer) and 2 (TDD, tests and publish) executed. Task 3 is the owner's merge gate.
- **Files:** 34 code, test, deploy and docs files.

## Delivery

- **Branch:** `p02/07-admin-api`, from origin/main `731f950`, carrying the orchestrator's `2cfdcd3 docs(phase-02): mark 02-06 complete ...`.
- **PR:** opened by keyroster-bot after the single push that carries this SUMMARY. Title `feat(server): admin-signed API and invites for enrollment`. The PR number and the check results go in the merge-gate checkpoint (Delivery Protocol step 4, as in 02-06).
- **Auto-merge is not enabled** (environment rule: the orchestrator enables it after its own pre-merge review). The plan's "PR is open with auto-merge" acceptance line is therefore deliberately unmet.

## The admin-api/v1 contract

> **Superseded by the pre-merge fixes** (see "Pre-merge review fixes" at the end). The message now also carries the origin on line 2. The body digest travels in `Keyroster-Admin-Body-SHA256`, and the server's handler verifies before it reads the body. The admin route has no global rate-limit bucket. The contract below is the one this plan first shipped.

Signed message (every line ends in `\n`):

```
keyroster/admin-api/v1
<METHOD>
<raw request-target: path and query exactly as sent>
<hex SHA-256 of the body>
<Unix seconds, decimal>
<nonce: 32 lowercase hex digits>
```

- SSHSIG (sha512) under the namespace `keyroster/admin-api/v1`, by a key that equals an admin key of the root-signed policy in the signer's Status (fingerprint and exact key).
- Headers: `Keyroster-Admin-Time`, `Keyroster-Admin-Nonce`, `Keyroster-Admin-Signature` (standard base64 of the armored SSHSIG).
- Window: the timestamp may differ from the server clock by at most 120 s (inclusive). A used nonce is kept `nonceRetention` = 2 × 120 s + 1 s = 241 s after its first use.
- The client signs `req.URL.RequestURI()` of the request it sends; the server verifies against `r.RequestURI`.

## Endpoints

| Route | Auth | Answers |
|---|---|---|
| `POST /api/v1/admin/users` `{"name","reinvite"}` | requireAdmin (body limit `maxAdminBody` = 1 MiB + 64 KiB) | 201 `{"name","invite_url","expires_at"}`; 400 `invalid user name` / `malformed request`; 401 `admin authentication failed` (uniform); 409 `already pending` / `already in directory`; 413 `request body too large`; 429 `rate limited`; 503 `signer unavailable` |
| `GET /enroll/{token}` | the 43-character token (SHA-256 stored) | 200 invite page; 404 uniform "Invite not valid"; 429 page; 503 page |

`invite_url` = `requestOrigin(r, policy origins)` + `/enroll/` + token: the policy origin equal to `https://` + Host (`:443` removed), otherwise the first sorted origin.

## Rate limits

| Class | Per client | Global backstop | Retry-After |
|---|---|---|---|
| Admin API | 60/min, burst 20 | none since the pre-merge fixes (was 600/min, burst 200) | 1 s |
| Invite pages | 30/min, burst 10 | 300/min, burst 100 | 2 s |

Key: host of `r.RemoteAddr` only (IPv4 and IPv4-mapped as the address, other IPv6 by /64; `X-Forwarded-For` and `Forwarded` ignored). The per-client map holds at most 10 000 entries (LRU) and drops entries idle for 10 min. `server.Config.Limits` overrides the per-client values; zero fields take the defaults.

## Accomplishments

- **internal/adminauth** (stdlib, sshsig, trust; not in the signer graph): `Message`, `Sign` (new nonce per call), `Verify` with ten distinct refusals (`ErrMissingHeaders`, `ErrBadTime`, `ErrStale`, `ErrFuture`, `ErrBadNonce`, `ErrBadSignature`, `ErrNotAdmin`, `ErrNamespace`, `ErrMismatch`, `ErrBadPolicy`).
- **internal/serverdb** mirrors signerdb (WAL, synchronous FULL, one connection, `PRAGMA user_version`, newer schema refused, file 0600). `CreatePendingUser` maps the `pending_users.name` primary-key conflict (SQLite 1555) to `ErrExists`; other unique conflicts stay plain errors. `UseNonce` purges rows expired at `now` and inserts in one transaction.
- **Server.** `requireAdminLimit` order: bounded read (413), Status (503), `Verify` on `r.RequestURI` with the policy's admins (401), `UseNonce` (401 on replay), verified body re-attached, admin name in the context. `handleAddUser` reads pending_users first, then the installed directory, and decides with the pending check first. The 201 carries `Keyroster-Custody`.
- **Signer seam.** `GetDirectory` added to `signerAPI`, `socketSigner` and `fakeSigner` (settable reply, counter, `enter("GetDirectory")`); signer.go stays the only importer of signerclient.
- **CLI.** `keyroster user add NAME [--reinvite] [--admin-key SHA256:...]` (flags anywhere): local name check, config check (every value of the init line re-validated), admin key from the flag or `admin_key`, found in ssh-agent by fingerprint and used through `agentSigner`. Output: `Invite for NAME: URL`, the expiry, exactly one `keyroster init --server ... --tls-root-file keyroster-tls-root.pem --tls-pin ... --root-pin ... --threshold N --user NAME` line, the root PEM, and the out-of-band instruction.
- **Deploy.** `serve --state-dir` (default `/var/lib/keyroster-server`, created 0700, `server.db`); the unit adds `--state-dir`, `StateDirectory=keyroster-server`, `StateDirectoryMode=0700`; server-install.md says what the directory holds.

## Task Commits

1. **Task 1, tracer.** `4b01080` (feat). Tracer gate (interactive, end-of-phase, automated-only verify): the e2e verify (`TestUserAddInvite|TestServerInitEndToEnd`, sshd 10.5p1) and the `-race` verify passed in WSL on the tree that became 4b01080; execution continued to Task 2.
2. **Task 2, TDD.** `eb3aa0f` (test: the refusal matrix), `f060546` (fix: the deferred ConnectError item), `a54cbb5` (fix: DNS host names, fuzz targets), `1b61c5b` (test: lint fixes).
3. **Task 3, merge gate.** Not attempted; the owner's `checkpoint:human-action`.

**Plan metadata:** `docs(02-07): complete admin-api plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 2; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED: unexpected green, recorded honestly.** The Task 1 tracer built the code, so every planned Task 2 test passed on its first run except for mistakes in the tests themselves (a wrong timestamp constant and a wrong expected URL, both fixed in the test). There was no failing-test commit before an implementation commit for the planned behaviour. The classifier was not run: it has no Go adapter.
- **Bite evidence instead.** 22 production mutants, each applied to a copy, run against the named test, and restored byte for byte (`ALL RESTORED` checked after every run). All counted mutants were killed:

  | Mutant | Killed by |
  |---|---|
  | `nonceRetention = MaxSkew` | `TestAdminAuth/nonce_replay_after_cleanup` |
  | ErrExists not mapped to 409 | `TestAdminUsers/concurrent_add_same_name/held` |
  | PK code test uses UNIQUE (2067) | `TestCreatePendingUserConflict` |
  | size gate after Verify | `TestAdminAuth/body_over_limit_413_before_verify` |
  | `r.URL.Path` instead of `r.RequestURI` | `TestAdminAuth/encoded_path_variant_401` |
  | verified body not re-attached | `TestAdminAuth/handler_sees_signed_body` |
  | nonce not consumed | `TestAdminAuth/nonce_replay` |
  | directory branch before the pending row on reinvite | `TestAdminUsers/reinvite_directory_user_with_pending_row` |
  | X-Forwarded-For read | `TestRateLimit/forwarded_for_ignored` |
  | IPv6 keyed by /128 | `TestRateLimit/ipv6_same_64_shares_bucket` |
  | no global limiter | `TestRateLimit/global_backstop_429` |
  | no LRU bound | `TestRateLimit/limiter_map_bounded` |
  | invite expiry not checked | `TestInvitePage/expired_token_404` |
  | cache used for any directory version | `TestAdminUsers/directory_cache_follows_status` (added for this mutant) |
  | cache never used | `TestAdminUsers/directory_cache` |
  | invite token not validated | `TestUserAddPeerText/invite_token_carries_pin` (added: the first run of this mutant survived) |
  | CLI prints the server's 409 text | `TestUserAdd/already_pending` |
  | clock hint threshold 0 | `TestAdminJSONClockSkewHint/no_hint_within_60s` |
  | client signs `URL.Path` | `TestAdminJSONSigns` |
  | no DNS-name check (CLI / client) | `TestUserAddPeerText/invite_url_shell_host`, `TestParseServerURL` |
  | empty port accepted | `TestParseServerURL` |
  | op timeout pass-through removed | `TestConnectErrorOpTimeout` (RED before f060546's fix) |

  One mutant was not counted at first: printing the received invite URL instead of the rebuilt one survived. The reason given here was that every accepted URL already equals its rebuilt form apart from a harmless empty fragment marker. That was untrue: an upper-case scheme also differed, and since the pre-merge fixes so do an upper-case host, a trailing dot and `:443`. The pre-merge fixes added a kill test, `TestUserAddPeerText/invite_url_printed_rebuilt` (264efc8), which fails under this mutant.

## Verification run

| Check | Where | Result |
|---|---|---|
| Task 1 verify 1: e2e `TestUserAddInvite\|TestServerInitEndToEnd`, sshd 10.5p1 | WSL (namespace hosts entry, see Issues) | PASS, all 6 subtests of TestUserAddInvite |
| Task 1 verify 2: `go test -race` adminauth, serverdb, server, cmd/keyroster | WSL | PASS, 0 DATA RACE |
| Task 1 acceptance greps (namespace, signer graph `GOOS=linux` = 0, GetDirectory and the single signerclient importer, invite_hash and no invite_token, RequestURI in both files and no URL.Path, requireAdminLimit, maxAdminBody, nonceRetention, ErrExists, SQLITE_CONSTRAINT_PRIMARYKEY) | Windows | all PASS |
| Task 2 verify 1: `go test -count=1 -v -run 'Verify\|Admin\|Invite\|Nonce\|RateLimit\|UserAdd\|PendingUser'` | Windows | PASS; TestAdminJSONClockSkewHint, TestCreatePendingUserConflict, /body_over_limit_413_before_verify, /nonce_replay_after_cleanup, /concurrent_add_same_name all in the PASS lines; 0 FAIL |
| Task 2 verify 2: `go test -race ./...` (on a54cbb5; adminauth and server again on 1b61c5b), `go vet` (linux, windows, darwin, `-tags e2e`), GOROOT gofmt, golangci-lint v2.14.0 (linux, windows, darwin: 0 issues on 1b61c5b), capslock-check (91/91, unchanged), dep-firewall, testonly-firewall | WSL | all pass. The first lint run found 3 issues in the new tests; fixed in 1b61c5b |
| govulncheck `./...` (linux) | WSL | 0 vulnerabilities affecting the code (1 in a required module, not called). The windows and darwin runs failed in WSL with `exec format error` (the tool was built for the target GOOS); they run in CI |
| `scripts/fuzz.sh` FUZZTIME=5s | WSL | all 26 targets passed; FuzzVerify, FuzzParseInviteURL, FuzzParseServerURL also 20-30 s each on Windows |
| systemd-analyze verify keyroster-server.service | WSL, systemd 255 | no unit error (only the executable-bit notice of the temp copy) |
| Full e2e, sshd 10.5p1 | WSL, namespace | 23 PASS, 1 FAIL: `TestSSHDRejects/pty_allowed`, which fails because the namespace wrapper breaks pty allocation; rerun without the wrapper: PASS |
| Full e2e, sshd 9.5p1 | WSL, namespace | 22 PASS, 2 FAIL: the same pty case, and `TestLoginRefusals` with `clock_regression` (the known serial-clock flake class); both PASS on rerun without the wrapper |
| `go test -count=1 ./...` | Windows | PASS, 21 packages |
| Task 2 verify 3 and 4 (SUMMARY on the pushed head, required checks) | GitHub | after the push; reported in the merge-gate checkpoint |

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Environment overrides

1. **Auto-merge not enabled, one push only, PR number in the checkpoint** (environment rules). The plan's Task 2 action and acceptance ask for auto-merge and two pushes.
2. **`requirements-completed: []`, no `requirements.mark-complete`, ROADMAP not updated** (plan `<output>` and environment).

### Auto-fixed issues and interpretations

3. **[Rule 3] `internal/directory.ValidUserName` exported.** The plan asks for the directory user-name rule; it was unexported. One function, used by the directory's own validation, the server and the CLI. File not in files_modified.
4. **[Rule 3] Every e2e server start passes `--state-dir`** (test/e2e/server_test.go), because the default `/var/lib/keyroster-server` is not writable in tests.
5. **[Interpretation] serverdb methods take a `context.Context` first**, like signerdb's reads; otherwise the signatures are the plan's.
6. **[Interpretation] The wire types and route of the admin API live in serverclient** (`AdminUsersPath`, `AddUserRequest`, `AddUserResponse`, the two 409 texts), as 02-06 did for the trust document, so the CLI never links internal/server.
7. **[Rule 2, T-02-93] Server-chosen text in user add.** `invite_url` is parsed as structured data (ParseServerURL origin, `/enroll/`, 43 base64url characters, nothing else) and printed rebuilt; `expires_at` is parsed as RFC 3339 and reprinted in UTC; 401/413/429 are the CLI's own words; 409 is matched exactly. `TestUserAddPeerText` covers padded and forged URLs, expiry, 401 and 409 bodies in the TestPeerTextCannotForgeAdvice style.
8. **[Rule 1, found by fuzzing] ParseServerURL accepted non-DNS hosts and an empty port.** `FuzzParseInviteURL` found `https://!/enroll/...` and `https://host:/enroll/...` accepted. url.Parse admits RFC 3986 sub-delimiters (`!$&'()*+,;=`) in a host, so a server could have put `$(...)` or `;` into the printed invite URL, and an admin could have put them into the printed init line. ParseServerURL now requires letter-digit-hyphen labels and a non-empty port. This also applies to `keyroster init --server`. Commit a54cbb5.
9. **[Rule 2, project rule: every parser fuzzed]** `FuzzVerify` (adminauth) and `FuzzParseInviteURL` (CLI); FuzzParseServerURL checks the host form.
10. **[Rule 2] `HTTPError` in serverclient.** A non-2xx answer other than 503 is now an `*HTTPError` with the status code; its `Error()` text is byte-identical to before (TestPeerTextCannotForgeAdvice and the custody tests pass unchanged).
11. **[Deferred item, resolved] ConnectError keeps Go's text for a timed-out network operation** (f060546): the 02-06 round 4 item in deferred-items.md, assigned to the next plan that edits internal/serverclient. A `*net.OpError` whose `Timeout()` is true now prints Go's own text (address, operation, `i/o timeout`); net/http's timeout error and `context.DeadlineExceeded` keep the CLI's wording. `TestConnectErrorOpTimeout` fails without the fix. The deferred-items row is marked resolved by 02-07.
12. **[Directive] Directory cache.** As the 02-06 SUMMARY asked: the user list is cached only while the Status reports the same directory version and the SHA-256 the server computed over the bytes; a mismatched read is used but not cached; a directory that does not parse gives 503, never "no such user".
13. **[Scope] Extra tests** beyond the plan's list: `signer_unavailable_503`, `unknown_field_400`, `directory_cache`, `directory_cache_follows_status`, `unparsable_directory_fails_closed`, `ipv4_and_mapped_share_bucket`, `idle_entries_evicted`, `TestAdminJSONSigns`, `TestAdminJSONRefusals`, `TestPendingUserInvite`, `TestUseNonce`, `software_custody_banner_once`, `reinvite_flag_sent`, `bad_name_refused_locally`.
14. **[Scope] server-install.md** names the state directory and says nothing in it is authority.

**Total deviations:** 14 (2 environment overrides, 2 blocking fixes, 2 interpretations, 1 bug found by fuzzing, 4 Rule 2 additions, 1 resolved deferred item, 1 directive, 2 scope items).

**Impact on plan:** one new module, golang.org/x/time v0.16.0, as planned (owner-locked). The signer graph is unchanged: `GOOS=linux go list -deps ./cmd/keyroster-signer` has no adminauth, serverdb or x/time, capslock stays 91/91 and dep-firewall is clean.

## Issues Encountered

- **WSL no longer resolves `keyroster.localhost`.** 02-06 recorded native resolution; this session WSL's DNS answered "no such host", which also failed the existing TestServerInitEndToEnd. Without editing the system's /etc/hosts, the e2e ran under a script (`.git/gsd-tmp/p07ns.sh`, not committed) that bind-mounts a copy of /etc/hosts with the name added in a private mount namespace and maps back to the caller's uid. That wrapper breaks pty allocation (TestSSHDRejects/pty_allowed), so the two failing tests were rerun without it and passed. CI resolves the name natively (02-06), so CI's e2e lanes are the authoritative run.
- **Git Bash expands `$(go env GOROOT)`** before WSL sees it; every WSL command with `$` ran from a script file (as in 02-06).
- The executor session was interrupted once (a shell failure after the first gate run); work resumed on the same branch with nothing lost.

## Not exercised (UNVERIFIED)

- **A browser loading the invite page.** Headers and content are asserted in unit and e2e tests; rendering in a browser is UNVERIFIED.
- **The unit on a host**: `StateDirectory=keyroster-server` under `ProtectSystem=strict`, the directory's ownership and mode as created by systemd. UNVERIFIED until 02-13.
- **The real signer's GetDirectory with an installed directory through the server.** The e2e has only directory version 0; a non-empty installed directory reaches the handler only through fakeSigner in this plan (02-09 installs one).
- **The admin agent on Windows** (inbox agent pipe) for `user add`: the CLI tests use an in-memory keyring; no Windows agent was used.
- **govulncheck for windows and darwin** ran only in CI (local runs failed with exec format error).
- **CI on the pushed head**: reported in the merge-gate checkpoint.

## Known Stubs

None. The invite page has no registration ceremony by plan (02-08 adds it); it says so to the user.

## Threat Flags

None beyond the plan's threat model: the admin route is T-02-32/33/36/95, the invite page T-02-34/96, the state DB T-02-35, x/time T-02-SC. The ParseServerURL tightening (Deviation 8) narrows input, it adds no surface.

## User Setup Required

None for CI. A server install picks up the state directory from the unit.

## Next Phase Readiness

- **02-08** extends `PendingUserByInvite` (invite_used_us) and `ReplaceInvite`, adds the registration script to enroll.html, and uses `requireAdmin` for its pending route. Server tests can raise rate limits with `newTestServerLimits` / `Config.Limits`.
- **02-09** adds `pendingMu` around reinvite and the install, `InstallDirectory` on the seam, `requireAdminLimit(maxDirectoryInstallBody, ...)`, and calls `dropStatus()`; the directory cache needs no change (it follows the Status).
- **02-12** reuses `requestOrigin` for approval_url.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in key-files.created exists; commits 4b01080, eb3aa0f, f060546, a54cbb5 and 1b61c5b are ancestors of HEAD.
- Task 1 and Task 2 acceptance greps and named-case checks re-run and pass; the PR acceptance (open, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-20 (before the merge gate)*

## Pre-merge review fixes

These fix the verified findings of the pre-merge review of PR 45 at b880289, under the owner's decisions D1 to D6 of 2026-10-20. The commits sit on top of b880289, signed as keyroster-bot. For each mutant named below, the test was run against the mutant and the code was then restored.

### Fixed

- **The admin signature did not bind the deployment** (confirmed, low; owner decision D1). Fixed in af7a2e5, which builds on c4e8264. A request signed for one deployment no longer verifies at another that trusts the same admin key.
  - The signed message now covers the canonical origin of the CLI's server URL.
  - The server verifies only against a root-verified policy origin. It matches that origin exactly from the Host header, with `:443` stripped and no fallback. A request for an origin the policy does not name gets the uniform 401 and consumes no nonce.
  - Tests:
    - `TestAdminAuth/cross_deployment_replay_401_nonce_unused`. Before the fix it was 204 and the nonce was consumed.
    - `TestAdminAuth/origin_matched_exactly`. The mutant that falls back like `requestOrigin` fails it.
    - The `other_deployment_origin` and `host_not_a_policy_origin` cases in `TestAdminAuth/uniform_401_body`.
    - `TestVerify/other_deployment_origin_refused`.
    - `TestAdminJSONSigns`: a non-canonical config still signs the canonical origin.
  - Why the origin is derived from Host rather than stated by the client in a header:
    - It is the origin the request actually reached.
    - It needs no new header to parse.
    - A client-stated origin would still need the same membership check, plus a rule for when it disagrees with Host.
    - It is `requestOrigin` without its fallback.
- **ParseServerURL did not normalize** (confirmed, low). Fixed in c4e8264.
  - ParseServerURL lowercases the host, strips one trailing dot (stripped, not refused) and drops an explicit `:443`.
  - `loadConfig` canonicalizes a server URL saved in an earlier form, so the printed init line and the signed origin are canonical.
  - Tests:
    - `TestParseServerURL`, canonical table. It failed before the fix.
    - `TestUserAdd/non_canonical_saved_server`. Before the fix it refused with "the saved config has no valid server URL".
- **Unauthenticated clients could make the admin route hold large request bodies** (split finding; owner decision D2). Fixed in af7a2e5 and b8a54cb.
  - The body's SHA-256 travels in `Keyroster-Admin-Body-SHA256`. It must be exactly 64 lowercase hex digits; any other form is refused. It is signed together with D1's origin in one change to the message, and the namespace stays `keyroster/admin-api/v1`.
  - `requireAdminLimit` now runs in this order:
    1. the per-client limiter;
    2. the declared Content-Length check (413);
    3. Status (503);
    4. the exact policy origin;
    5. `adminauth.Verify` over the headers;
    6. the body read through `MaxBytesReader` (413);
    7. `adminauth.CheckBody` (401);
    8. `UseNonce`.
  - The admin route class has no global bucket any more (b8a54cb).
  - Tests:
    - `TestAdminAuth/unauthenticated_body_never_read`. Before the fix the server read 1 114 113 bytes of an unsigned body. The read-before-verify mutant fails it.
    - `body_digest_mismatch_401_nonce_unused`.
    - The `missing_digest`, `malformed_digest` and `digest_changed` cases.
    - `body_over_limit_413_before_verify`, for a declared length.
    - `streamed_body_over_limit_413_after_verify`, with the nonce unused.
    - `TestRateLimit/admin_valid_request_not_refused_by_others`. It sends 250 unsigned or junk-signed requests from distinct client keys, with stalling `maxAdminBody` bodies; half of them name the real admin key. The handler reads none of the bodies, and a valid add gets 201 meanwhile. Before b8a54cb the valid add got 429.
    - `TestVerify` digest cases. `FuzzVerify` now fuzzes the origin and the digest.
- **Deferred-items row resolved by 02-07 overclaimed** (confirmed, low; TLS handshake). Fixed in f354c27.
  - net/http's fixed text `net/http: TLS handshake timeout` now prints "the TLS handshake with <host> timed out".
  - The ConnectError comment no longer claims that a handshake read is an OpError. The dial and DNS cases are labelled as tested with synthetic errors only (UNVERIFIED), and the deferred-items row is narrowed to match.
  - Test: `TestConnectErrorTLSHandshakeTimeout`, against a real server that reads the ClientHello and stalls. Before the fix it printed "timed out talking to localhost".
- **The limiter check order was not pinned** (confirmed, low). Fixed in ab591ff. Test: `TestRateLimit/client_bucket_checked_before_global`, on the invite route. The global-first mutant fails it.
- **"Invite token never logged" was not pinned on the 429 path** (confirmed, low). Fixed in 2862326. Test: `TestRateLimit/invite_token_not_logged_on_429`, which rate-limits a real invite URL. The mutant that logs `r.URL.Path` fails it.
- **A GetDirectory error was not pinned to fail closed** (confirmed, low). Fixed in 51323f1. Test: `TestAdminUsers/directory_read_error_fails_closed`, which expects 503 and no pending row. The error-to-empty-map mutant answers 201 and fails it.
- **checkInviteConfig was never exercised** (confirmed, low). Fixed in a91c099. Test: `TestUserAdd/bad_saved_config_refused`, seven cases: a root pin with metacharacters, a malformed root pin, threshold 0, a threshold above the pin count, a bad TLS pin, a TLS root that is not PEM, and a server URL with a path. Each is refused in checkInviteConfig's own words, with no request sent. The mutant that skips the call and the mutant that drops the root-pin check both fail it.
- **The SUMMARY's near-equivalent-mutant note was incomplete** (confirmed, info). Fixed in 264efc8, which adds the kill test `TestUserAddPeerText/invite_url_printed_rebuilt` (an `HTTPS://`, upper-case host, `:443` and trailing `#` invite must print the rebuilt URL). The TDD record above is reworded; the print-raw mutant fails the test.
- **A reinvite of a name in neither place was untested at the server** (confirmed, info). Fixed in d1e2d01. Test: `TestAdminUsers/reinvite_unknown_name_is_plain_add`. The 404 mutant fails it.
- **user add printed an invite URL whose origin the server chose freely** (split finding, low as the owner rated it). Fixed in 062a59e.
  - user add verifies the trust document with the saved root pins and threshold before it creates the account.
  - It prints the invite only when the invite's canonical origin is one of the verified policy's webauthn origins. There is no hostname-equality fallback.
  - Otherwise it refuses without repeating the URL. A policy without a WebAuthn RP is refused before any admin request.
  - The test server now serves a root-signed trust document whose policy names `https://keyroster.example`.
  - Tests:
    - The `TestUserAddPeerText` cases `invite_url_foreign_origin`, `invite_url_server_url_not_in_policy` and `invite_url_policy_host_other_port`. All three exited 0 before the fix; the mutant that skips the membership check fails them.
    - `TestUserAdd/policy_without_relying_party_refused`.
- **Docs.**
  - 6114886: the runbook says an admin's `--server` must be a policy origin.
  - 590fb8d: the D6 todo, `.planning/todos/pending/2026-10-20-cap-server-connections-and-memory.md` (severity minor, Phase 6, server). The memory figures in it are a skeptic's measurements, UNVERIFIED on a host.
  - b6925bc: deferred-items rows for later plan text that assumes the old order, the old message layout or the admin global backstop (02-09 L51, L182, L183, L320, L469 and L497; 02-08 L236 and 02-09 L193 and L210 for the empty-body digest of a GET; 02-10 L178).

### Skipped, no code change

- **D3, CodeQL.** keyroster-bot dismissed the go/log-injection alerts #8 to #11 (internal/server/admin.go:197, 218, 223) as false positives on 2026-10-20. #8 to #10 log `req.Name`, which ValidUserName checks before any log call. #11 logs `req.Reinvite`, a bool. The logger is slog's JSONHandler. No code was changed to quiet CodeQL. The log calls added or moved here log only fixed reason strings, the verified admin name and adminauth's error text. That error text is the same Verify reason as at b880289, and it can carry escaped fields from the SSHSIG parse, quoted by internal/sshsig: the namespace, the hash algorithm, the signature format or the key type. The Host header, the digest, URLs and tokens are never logged; `uniform_401_body` asserts that neither the digest nor the foreign host appears in the log.
- **D4.** The "signer's directory changed" assertions in the reinvite tests (`reinvite_directory_user*`) cannot fail. 02-09 owns this, because it adds InstallDirectory to the seam.
- **D5, refuted by both skeptics.** No CLI range check on the invite expiry (cmd/keyroster/user.go, the expiry parse).
- **D5, refuted by both skeptics.** No tightening of the mode of an existing server.db or state directory (internal/serverdb/db.go:49).
- **The phase-4 blocker todo stays open.** `.planning/todos/pending/2026-10-16-bind-admin-signed-directories-to-a-deployment.md` covers admin-signed directories. D1 binds the admin API only, not directories.

### Deviations from the plan's must_haves (PLAN not edited)

1. **Body limit.** `maxAdminBody` is unchanged at 1 MiB + 64 KiB. It now bounds only the body of a request whose signature has verified. The handler never reads or buffers an unauthenticated body. What net/http itself reads of it depends on the protocol. Over HTTP/1.1 it may discard up to 256 KiB of it after the refusal, and a stalled body holds the connection until ReadTimeout (30 s in serve.go). Over HTTP/2, which keyroster-server negotiates by default, it buffers the stream's DATA in memory, whether or not the handler reads, up to the receive windows (by default 1 MiB per stream and 1 MiB per connection), frees that buffer when the handler returns and then resets the stream; there is no 256 KiB drain.
2. **`body_over_limit_413_before_verify`.** It holds for a declared Content-Length: 413 before any signature work, nonce unused. A body sent without a length is read only after Verify. If that body is oversized and the request verified, it gets 413 with the nonce unused. If the request did not verify, it gets the uniform 401 and the handler does not read the body (net/http may still discard up to 256 KiB of it over HTTP/1.1, or buffer up to the receive windows of it over HTTP/2 until the handler returns).
3. **The admin global limiter is removed.** The admin route keeps the per-client bucket in front of everything; the invite route keeps its global backstop unchanged.
   - Why removal rather than keeping a global bucket only for requests that fail verification: a bucket charged after a failed Verify bounds nothing the per-client bucket does not already bound, and one charged before Verify would refuse valid admins too. Removal is the only choice that provably never refuses a valid admin because of traffic from other client keys. A client that shares the admin's client key (the same IPv4 address behind NAT, or the same IPv6 /64) can still use up the admin's per-client bucket. That is an accepted residual of keeping the per-client bucket.
   - `newLimiter(..., 0, 0)` means "no global bucket".
4. **503 order.** Status is read before the body, so a 503 comes before any body read.
5. **Server URL.** An admin's server URL must be a policy origin; any other gets the uniform 401. `requestOrigin`'s fallback is no longer reachable on an admin route. user add makes one more request, GET `/api/v1/trust`, before the admin POST.
6. **T-02-36, rewritten.**
   - **Admin route.** Pre-auth work is a header parse plus at most one signature check, done only when the presented key is a policy admin, and it is bounded per client. The handler never reads or buffers an unauthenticated body. What net/http reads of it depends on the protocol.
     - Over HTTP/1.1, net/http may discard up to 256 KiB of it after the refusal, and a stalled body holds the connection until ReadTimeout (30 s in serve.go). Nothing is buffered.
     - Over HTTP/2, which keyroster-server negotiates by default, net/http buffers the stream's DATA in memory whether or not the handler reads. The receive windows bound it: by default 1 MiB per stream (`MaxReceiveBufferPerStream`) and 1 MiB per connection (`MaxReceiveBufferPerConnection`). The buffer is freed when the handler returns, and the stream is then reset. The admin 401 returns without waiting for the body, so the buffer is short-lived and D2's memory goal holds for this route. An independent check with serve.go's exact `http.Server` settings measured a 4 MiB POST to a handler that held 1.5 s without reading: net/http read 1 053 797 bytes from the connection over h2, and 2 785 over HTTP/1.1.
     - UNVERIFIED: how long other routes' handlers can run, and so hold the h2 buffer, and how long an h2 connection whose body stalled stays open after the reset. Both belong to the D6 todo.
   - **Invite route.** It keeps the global backstop. The accepted residual, from a skeptic's simulation against the real limiter code with realistic timing, is partial delay from about 10 to 16 full-rate client keys, and near-total denial from about 128 or more keys (or one IPv6 /56 or wider).
   - **Remaining admin-route residuals.**
     - There is no cap across many client keys on the CPU spent on headers and signature checks.
     - A client that shares the admin's client key (the same IPv4 address, or the same IPv6 /64) can use up the admin's per-client bucket.
     - The nonce is consumed only after the digest matches. So a holder of a valid header set for this origin, inside MaxSkew, can drive concurrent body reads, each bounded by the limit. Only the admin, or the server itself, holds such a set.
     - Idle connections are the cheaper memory path, and stalled admin-route bodies hold connections the same way. Both are recorded in the D6 todo for Phase 6.

### Verification

- `gofmt -l .` printed nothing. `go vet ./...`, `GOOS=linux go vet ./...` and `GOOS=darwin go vet ./...` are clean.
- `go test -count=1` passes for cmd/keyroster, internal/adminauth, internal/server and internal/serverclient.
- `go test ./...` timed out on the first run in internal/winagent, at `TestAgent/ensure_retries_once_on_closing_agent`, a package these fixes do not touch. Every package passed on the second run.
- Fuzzing found no failure: `FuzzVerify` for 30 s, `FuzzParseServerURL` for 20 s, `FuzzParseInviteURL` for 20 s.
- e2e ran in WSL (OpenSSH 10.5p1) from a git-archive scratch copy of b6925bc, whose code is the pushed code; the copy was deleted afterwards. `TestUserAddInvite`, `TestServerInitEndToEnd`, `TestServerSIGHUPDuringStartup` and `TestServerRefusesStart` pass. keyroster.localhost resolved natively. The other e2e tests and the 9.5p1 lane were not run locally; CI runs them.
- `-race` was not run: the Windows toolchain has no cgo.

### Still UNVERIFIED

- Real dial and DNS timeouts. Only synthetic `net.OpError` values test them.
- The connection and memory figures in the D6 todo on a real host.

### Follow-up check of c69db17

An independent check of the PR at c69db17 found three more non-blocking problems. Two are fixed below. The third was skipped in that round and is now handled by a diagnosis (0b3f77e).

- **c69db17, the orchestrator's lint fix.** `stallingReader.Read` names its unused parameter `_`, for revive's unused-parameter rule. It is test-only and changes no behaviour.
- **requestOrigin's fallback had no test** (low). Fixed in d108bef.
  - af7a2e5 had rewritten the only test of the fallback to expect 401. With that, replacing `return sorted[0]` by `return "https://attacker.example"` passed the whole internal/server suite. 02-12 reuses requestOrigin for the approval URL on an unauthenticated route (T-02-96).
  - Test: `TestRequestOrigin`, with an unsorted origin list. It checks the exact Host match, including the `:443` strip. Eleven Hosts that are not a policy origin (among them CRLF, `[::1]:443`, upper case, a trailing dot and an empty Host) must give the first sorted origin, always a member of the list. An empty or nil list must give "".
  - Mutants: the attacker-origin mutant passes the rest of the suite (`-skip TestRequestOrigin`) and fails TestRequestOrigin. TestRequestOrigin also fails against `return origins[0]`, the mutant without the `:443` strip, and one that returns a foreign origin for an empty list; each of these three was run against TestRequestOrigin only. Each mutant was restored, and `git diff --exit-code` was clean afterwards.
- **"No unauthenticated admin body is ever read" overclaimed** (low). Fixed in 38b9bd5. This is a wording change only, with no test.
  - The claim holds for the handler: it never reads or buffers an unauthenticated body. It does not hold for the real net/http server. Over HTTP/1.1, net/http may read and discard up to 256 KiB of the unread body when the refusal is written (`maxPostHandlerReadBytes`), and a stalled body holds the connection until ReadTimeout (30 s in serve.go). This round described HTTP/1.1 only; the HTTP/2 wording is corrected in the follow-up check of ddc07d6 below.
  - The reworded places:
    - the requireAdminLimit doc;
    - the Limits doc;
    - three test comments;
    - the key decision and the contract note above;
    - `admin_valid_request_not_refused_by_others`;
    - Deviations 1, 2 and 6 (T-02-36);
    - the 02-09 deferred-items row, items 2 and 3.
  - The D6 todo now records stalled admin-route bodies as part of the connection exposure, with the check's figures (httptest server, byte-counting listener). No code was added: `Connection: close` was measured and does not stop the drain.
- **user add does not check its own server URL against the verified policy** (info). Skipped in this round. Handled in the follow-up check of ddc07d6 below, by 0b3f77e, as a diagnosis rather than a refusal (an owner-level choice, made by the orchestrator).
  - What 0b3f77e does. The admin request is still sent. When it fails with the uniform 401 (`serverclient.ErrAdminAuth`) and the canonical `client.Server()` is not one of the verified policy's webauthn origins, user add appends the cause and the policy's origins, then its own advice last (T-02-93). The origins are root-verified values in their validated canonical form, never text from the server's answer. AdminJSON's text, with its clock hint, stays in front.
  - Why not refuse before sending. A refusal test does work on the existing harness: its policy names only `https://keyroster.example`, and the fake server runs at `https://localhost:PORT`. What breaks is every case that reaches the admin request: the passing cases, and also the 409 refusals (already_pending, already_in_directory) and the forged-invite refusals. Trust policy validation requires an RP ID with at least two labels and origins of exactly `https://<rp_id>[:port]`, so no policy can name the fake server's URL. A probe of the refuse-before-send variant on top of 0b3f77e failed 19 existing subtests: 6 in TestUserAdd and 13 in TestUserAddPeerText, plus the new diagnosis test. The independent check reproduced 18 (12 in TestUserAddPeerText) with a refusal that ends in the CLI's own advice, because padded_401 then passes. The count depends on the refusal's wording. The probe was removed afterwards, and `git diff --exit-code` was clean.
  - Keeping those 19 cases passing would need the fake server at a policy origin. That means either `keyroster.localhost` resolving on every CI lane (UNVERIFIED on cli-macos; it resolves on this Windows host and in WSL) or a test dial hook in internal/serverclient. The server already enforces the origin.
  - The earlier wording of this record was partly inaccurate. It said the suggested test setup "cannot be built", that the check would affect "every user add test" and that a dial hook "would change a library API". In fact the refusal test can be built, the cases that break are the 18 or 19 existing subtests that reach the admin request (depending on the refusal's wording), and serverclient is an internal package, not a library API.

Verification of this round:
- `gofmt -l .` printed nothing.
- `go vet ./...`, `GOOS=linux go vet ./...` and `GOOS=darwin go vet ./...` are clean.
- `go test -count=1 ./internal/server` passes.
- `go test ./...`: every other package passed on the first run (replayed from cache on the second). internal/winagent timed out on the first run, again at `TestAgent/ensure_retries_once_on_closing_agent`, and passed on the second.
- golangci-lint v2.14.0 (WSL) reports 0 issues on internal/server.
- `-race` was not run: the Windows toolchain has no cgo.

### Follow-up check of ddc07d6

An independent check of the PR at ddc07d6 found two more non-blocking problems and an inaccurate record. All three are fixed below.

- **The body wording covered HTTP/1.1 only** (low). Fixed in 1759056. This is a wording change only, with no test and no behaviour change.
  - keyroster-server negotiates HTTP/2 by default: serve.go calls `ServeTLS` with a TLS 1.3 config and sets no `TLSNextProto` or `Protocols`. Over h2 net/http's `processData` writes an open stream's DATA into a memory buffer whether or not the handler reads. The receive windows bound it: `MaxReceiveBufferPerStream` and `MaxReceiveBufferPerConnection`, both 1 MiB by default (Go 1.27.2, `net/http/internal/http2/config.go:55,60`). `runHandler` closes the request body when the handler returns, which frees the buffer, and the stream is then reset. Over h2 there is no 256 KiB drain.
  - The check measured this with serve.go's exact `http.Server` settings. It sent a 4 MiB POST to a handler that held 1.5 s without reading: net/http read 1 053 797 bytes from the connection over h2, and 2 785 over HTTP/1.1. The admin route answers without reading the body, after at most one signer Status refresh (requireAdminLimit calls currentStatus before the origin check and Verify; statusTimeout is 3 s and a failed refresh is not cached) and one signature check. Its h2 buffer is therefore held for at most about 3 s per request, and D2 still holds. That hold time is derived from the code, not measured: UNVERIFIED.
  - The reworded places:
    - the requireAdminLimit doc;
    - the Limits doc;
    - Deviations 1, 2 and 6 (T-02-36) and the c69db17 record above;
    - the 02-09 deferred-items row;
    - the D6 todo. Its measured figures are now marked as HTTP/1.1. It adds h2's receive windows to the exposure analysis, and a Phase 6 option to lower them through `http.Server.HTTP2`.
  - UNVERIFIED and recorded in the D6 todo:
    - how long other routes' handlers can hold the h2 buffer;
    - how long an h2 connection with a stalled body stays open after the reset;
    - the memory of an idle h2 connection;
    - what smaller windows would cost a verified admin's upload.
- **user add printed only "admin authentication failed" at a server URL that is not a policy origin** (info). Fixed in 0b3f77e.
  - `adminOriginDiagnosis` is a pure function. When the error is `serverclient.ErrAdminAuth` and the canonical `client.Server()` is not one of the verified policy's webauthn origins, it appends the cause, the origins and the CLI's own advice, which comes last. Otherwise it returns the error unchanged. AdminJSON's text, with the clock hint, stays in front. The request is still sent; see the corrected record in the c69db17 section for why.
  - Tests:
    - `TestAdminOriginDiagnosis`. Its three cases cover a server URL that is not a policy origin (the clock hint survives), each policy origin (the error is unchanged), and another error or nil (unchanged).
    - `TestUserAdd/server_url_not_policy_origin_diagnosed`, on the newUserAddEnv harness. The fake server answers the admin POST with 401, and the policy names only `https://keyroster.example`. The test asserts the diagnosis, the named origin, the advice last and that one admin request was sent.
    - `TestUserAddPeerText/padded_401` now expects the diagnosis's advice as the CLI's last words, because its fake server is not at a policy origin. Its meaning is unchanged: the CLI's own words come last, and the padded server text stays contained.
  - Mutants:
    - Without the call (`return userAddError(name, err)`), `server_url_not_policy_origin_diagnosed` and `padded_401` fail.
    - Without the membership check, `TestAdminOriginDiagnosis/policy_origin_unchanged` fails.
    - Both mutants were restored.
- **The c69db17 record of the skipped server URL check was partly inaccurate** (low). Fixed in 33e29b1. This is a wording change only.

Verification of this round:
- `gofmt -l .` printed nothing.
- `go vet ./...`, `GOOS=linux go vet ./...` and `GOOS=darwin go vet ./...` are clean.
- `go test -count=1 ./cmd/keyroster ./internal/server` passes.
- `go test ./...` passed on the first run.
- golangci-lint v2.14.0 (WSL, via scripts/linux.sh) reports 0 issues on cmd/keyroster and internal/server. Its first run flagged two `!=` error comparisons in the new unit test (errorlint), and they were changed to `errors.Is` plus a text comparison.
- `-race` was not run: the Windows toolchain has no cgo.
