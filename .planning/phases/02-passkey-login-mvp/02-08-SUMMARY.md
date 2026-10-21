---
phase: 02-passkey-login-mvp
plan: 08
subsystem: server
tags: [server, webauthn, go-webauthn, registration, passkey, invites, serverdb, sqlite, cli, auth-01, ui-01, d-17]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-07: requireAdmin with the exact-origin admin message, pending_users with hashed invites, PendingUserByInvite, ReplaceInvite, GET /enroll/{token}, the invite limiter, keyroster user add; 02-06: signerAPI/fakeSigner, currentStatus, secure headers, custody header, serverclient; 02-03: internal/webauthn verifier and its mutation matrix; 02-01: webauthntest, the directory credential form (alg + SPKI DER)"
provides:
  - "go-webauthn v0.18.2 in keyroster-server only, owner-reviewed (Task 1), with the four owner hardening measures H1-H4"
  - "POST /api/v1/enroll/{token}/begin and /finish: attestation none only (refined by E1: a packed self-attestation of the pass-through shape is registered as none), UV required, EdDSA/ES256/RS256 offered; per-ceremony sessions consumed once; one pending credential per invite and per user"
  - "serverdb migration 0002 (registration_sessions, pending_credentials, invite_used_us) and CreateRegistrationSession, ConsumeRegistrationSession, BindPendingCredential, PendingCredentials, PendingCredentialExists, InviteUsed; extended PendingUserByInvite and ReplaceInvite"
  - "credential.go spkiFromCOSE: COSE key to alg + SPKI DER, accepted only by internal/webauthn.ParsePublicKey"
  - "internal/webauthn.ParsePublicKey: RS256 modulus 2048-4096 bits and e = 65537 (H2), shared by server, directory and signer"
  - "GET /api/v1/admin/users/{name}/pending (requireAdmin) and keyroster user pending NAME, which re-derives the fingerprint"
  - "invite page with data-begin/data-finish and one embedded static/app.js running navigator.credentials.create"
  - "servertest.Register (soft attestation-none registration), webauthntest Sign and WithAuthDataSuffix"
  - "TestWebAuthnOracle: internal/webauthn vs go-webauthn with bothRefuse and strictOnly"
  - "dep-firewall bans github.com/go-webauthn, github.com/fxamacker/cbor, github.com/golang-jwt for the signer; depguard denies github.com/go-webauthn in signer packages"
affects: [02-09, 02-10, 02-12, 02-13, AUTH-01, UI-01]

actuals:
  tokens: 34000   # chars/4 over the added lines of the code, test and script diff (136333 chars, go.sum and planning docs excluded)
  tasks: 2        # Tasks 2 and 3 executed; Task 1 (owner review) was resolved by the orchestrator before this run; Task 4 is the merge gate
  commits: 9      # git rev-list --count plan_head_before..plan_head_after (9b15533..949b713); the docs commit 62de5c9 follows
plan_head_before: 9b15533258b14a85a7334c58afe99b63d3b25485
plan_head_after: 949b713ad6987a5ad832d485b7c5fa3de97e509c

tech-stack:
  added:
    - "github.com/go-webauthn/webauthn v0.18.2 (owner-locked, reviewed with its transitive modules 2026-10-21; keyroster-server only)"
    - "transitive, server only: github.com/go-webauthn/x v0.3.1, github.com/fxamacker/cbor/v2 v2.9.4, github.com/x448/float16 v0.8.4, github.com/golang-jwt/jwt/v5 v5.3.1, github.com/go-viper/mapstructure/v2 v2.5.0, github.com/tinylib/msgp v1.6.4, github.com/philhofer/fwd v1.2.0; graph only: stretchr/testify v1.12.1, go.uber.org/mock v0.6.0, go.yaml.in/yaml/v3 v3.0.5"
  patterns:
    - "Third-party parsing is narrowed before it runs: finish looks the invite up before go-webauthn parses the body, and refuses every attestation format but none (a packed self-attestation of the pass-through shape is re-encoded as none, E1) before go-webauthn could reach a format verifier"
    - "Every key the server stores passes the signer's own ParsePublicKey, so server, directory and signer accept the same keys"
    - "Registration sessions are rows the server wrote, keyed by (invite hash, challenge), consumed with DELETE ... RETURNING; the client never holds session bytes"
    - "Every non-2xx answer of a route writes one log line through one helper with a closed attribute set and a closed list of reason codes"

key-files:
  created:
    - internal/server/enroll.go
    - internal/server/credential.go
    - internal/server/servertest/softreg.go
    - internal/server/web/static/app.js
    - internal/serverdb/migrations/0002_registration.sql
    - internal/server/enroll_test.go
    - internal/server/webauthn_oracle_test.go
    - internal/server/fuzz_credential_test.go
    - cmd/keyroster/user_pending_test.go
  modified:
    - go.mod
    - go.sum
    - internal/server/server.go
    - internal/server/admin.go
    - internal/server/invite.go
    - internal/server/render.go
    - internal/server/web/templates/enroll.html
    - internal/server/web/static/app.css
    - internal/server/web/embed.go
    - internal/serverdb/db.go
    - internal/serverclient/admin.go
    - internal/webauthn/verify.go
    - internal/webauthn/webauthntest/soft.go
    - cmd/keyroster/user.go
    - test/e2e/enroll_test.go
    - test/e2e/server_test.go
    - scripts/dep-firewall.sh
    - .golangci.yml

key-decisions:
  - "Owner, 2026-10-21: go-webauthn v0.18.2 and its 10 other modules approved together with hardening H1-H4 (verbatim reply: \"Godkänn + härdning (Rekommenderas)\")"
  - "H1 (refined by E1 below): finish refuses every attestation format except none right after parsing, before the session is consumed (reason unsupported_attestation, client answer \"unsupported attestation\"); the client's fmt is never logged"
  - "E1, owner, 2026-10-21 (pre-merge review; verbatim reply: Behandla som \"none\" (Rekommenderas)): H1 refined. A packed self-attestation of exactly the shape W3C WebAuthn L3 5.1.3 tells a client to forward under attestation none (attStmt exactly {alg, sig}, alg an integer equal to the credential key's COSE alg and offered, sig a byte string, AAGUID 16 zero bytes) is re-encoded as {fmt: none, attStmt: {}} with webauthncbor and parsed again by go-webauthn, so it registers; its self-signature is not verified (no cryptography on a client-chosen key at registration; the signer proves possession at every login). Every other attestation stays refused as under H1, and no verifier but none's runs"
  - "H2: RS256 credential keys are accepted only with a 2048-4096-bit modulus and e = 65537, enforced in internal/webauthn.ParsePublicKey for registration, directory install and login"
  - "H3: begin reads at most 1 KiB and finish 64 KiB before any parsing; a declared length over the limit is refused unread, a streamed body as soon as it passes the limit (413, reason body_too_large)"
  - "H4: no FIDO metadata provider, no AAGUID filtering, no cross-origin, go-webauthn's own session expiry off; session data stored as server-written JSON in registration_sessions only"
  - "The finish order is invite lookup, parse, fmt gate (with the E1 rewrite), session consumption, go-webauthn verification, SPKI conversion, duplicate checks, bind. The invite lookup comes first (pre-merge review) so only a live invite reaches go-webauthn's parser, and before consumption so a used invite leaves the other ceremony's session untouched"
  - "The registration section is a <section id=\"kr-enroll\"> with the data attributes, not a second <main>: base.html already wraps the content in <main>"

patterns-established:
  - "Counting seam: a test-binary init() replaces go-webauthn's attestation-format registry entries with counters, which proves the verifiers are never reached"
  - "Limits on unauthenticated JSON routes: Content-Length check, then http.MaxBytesReader, then parsing"

requirements-completed: []  # AUTH-01 completes in 02-13; UI-01 continues in later plans (plan <output>)

coverage:
  - id: D1
    description: "An invited user registers a passkey through begin, a soft ES256 authenticator and finish; keyroster user pending shows the admin the same fingerprint byte for byte; the invite is then used up (uniform 404); the signer directory stays at version 0"
    requirement: AUTH-01
    verification:
      - kind: e2e
        ref: "test/e2e/enroll_test.go#TestRegisterPasskeyPending (WSL, OpenSSH 10.5p1 and 9.5p1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Registration refusals with nothing written and the invite unused: UV/UP clear, wrong rpIdHash, origin and type, a challenge of another session or none, an expired session, a session used by a failed finish, ES384, RSA-1024, an EC key labelled RS256, BS without BE, a malformed body, a credential ID pending for another user or in the installed directory, an expired invite; single use and replay; BE/BS recorded; canonical pending id"
    requirement: AUTH-01
    verification:
      - kind: unit
        ref: "internal/server/enroll_test.go#TestEnrollRefusals, TestEnrollRecordsCredential, TestEnrollRegister"
        status: pass
    human_judgment: false
  - id: D3
    description: "Invite lifecycle under -race: 8 concurrent ceremonies give exactly one credential, a second ceremony after use is refused, reinvites discard the old ceremony and the unapproved credential, 16 open sessions per invite, a used invite's page and begin give the never-issued token's 404"
    verification:
      - kind: unit
        ref: "internal/server/enroll_test.go#TestEnrollInviteLifecycle (WSL, -race)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Begin offers exactly EdDSA, ES256, RS256, attestation none, UV required, resident key preferred, and excludes the user's directory credentials; every refusal writes one enroll refused line with route, reason, user and err and no token, hash, challenge or credential material"
    verification:
      - kind: unit
        ref: "internal/server/enroll_test.go#TestEnrollBeginOptions, TestEnrollRefusalLog"
        status: pass
    human_judgment: false
  - id: D5
    description: "Owner hardening H1-H4 and E1: non-none attestation refused before any verifier runs (counting seam), packed self-attestation of the pass-through shape registered as none (E1), RSA bounds at server and signer verifier, body caps declared and streamed, metadata disabled"
    verification:
      - kind: unit
        ref: "internal/server/enroll_test.go#TestEnrollAttestationFormats, TestEnrollRSABounds, TestEnrollBodyLimits, TestEnrollWebAuthnConfig; internal/webauthn/verify_test.go#TestWebAuthnRSABounds"
        status: pass
    human_judgment: false
  - id: D6
    description: "Differential oracle over the listed vectors (the whole 02-03 matrix plus extras): the disagreements are exactly strictOnly and the documented oursOnly list (tokenBinding shapes and case-variant member names, where internal/webauthn follows the spec); any other vector accepted by internal/webauthn and refused by go-webauthn fails the test"
    verification:
      - kind: unit
        ref: "internal/server/webauthn_oracle_test.go#TestWebAuthnOracle"
        status: pass
    human_judgment: false
  - id: D7
    description: "keyroster user pending: body-less signed GET, fingerprint re-derived from a validated SPKI, server text contained (T-02-93); user add --reinvite says what was discarded"
    verification:
      - kind: unit
        ref: "cmd/keyroster/user_pending_test.go#TestUserPending (incl. software_custody_banner_once, KEY-06), TestUserPendingPeerText, TestUserAddReinviteText; FuzzCheckPendingCredential (30 s; its seeds reached acceptance only after the pre-merge review, see there)"
        status: pass
    human_judgment: false
  - id: D8
    description: "go-webauthn, fxamacker/cbor and golang-jwt never enter the signer graph"
    verification:
      - kind: other
        ref: "scripts/dep-firewall.sh, scripts/capslock-check.sh (91/91), depguard; a temporary go-webauthn import in internal/webauthn made dep-firewall and depguard fail"
        status: pass
    human_judgment: false
  - id: D9
    description: "The registration page in a real browser: navigator.credentials.create with a real authenticator, the feature detection, the error and result display"
    requirement: UI-01
    verification: []
    human_judgment: true
    rationale: "Browser-only behaviour; no browser ran app.js in this plan (UNVERIFIED until 02-13)"

duration: about 1h (2026-10-21, from about 04:00Z)
completed: 2026-10-21
status: complete
---

# Phase 2 Plan 08: Passkey Registration Summary

**An invited user now registers a passkey on the invite page: one embedded app.js runs `navigator.credentials.create`, go-webauthn v0.18.2 (server only, owner-reviewed) verifies an attestation-none registration, and the server keeps the key as a pending `alg` + SPKI DER credential whose `SHA256:` fingerprint the user reads to the admin and `keyroster user pending` shows identically. The four owner hardening measures are in place: only attestation none reaches go-webauthn's verifier, RS256 keys are bounded to 2048-4096 bits and e = 65537 in the verifier the signer shares, the enroll bodies are capped before parsing, and FIDO metadata stays off. Nothing reaches the signer: the credential grants nothing until 02-09's admin-signed directory binds it.**

## Performance

- **Started:** about 2026-10-21T04:00Z. **SUMMARY written:** 2026-10-21T05:00Z.
- **Tasks:** Task 1 was resolved by the orchestrator before this run (below). Tasks 2 (tracer) and 3 (TDD, tests, bans) executed. Task 4 is the owner's merge gate, not attempted.
- **Files:** 31 code, test and script files.

## Task 1: owner dependency review (recorded)

The orchestrator prepared the review exactly as Task 1's `<what-built>` prescribes, in a throwaway worktree of origin/main 52b99c4 in the session scratchpad, without touching the plan branch. Each added module was audited for identity, sumdb and tag integrity, licence, a code scan of the linked packages, OSV, vulndb and govulncheck, and maintenance.

| Module | Version | Linked into keyroster-server | Licence | Audit verdict |
|---|---|---|---|---|
| github.com/go-webauthn/webauthn | v0.18.2 | yes: metadata, protocol, protocol/webauthncbor, protocol/webauthncose, webauthn | BSD-3-Clause | concern: no upper bound on RSA credential keys in v0.18.2 (fixed upstream in #805/#809/#813, unreleased); VerifyAttestation runs any fmt the client sends |
| github.com/go-webauthn/x | v0.3.1 | yes: crypto/secp256k1, crypto/secp256k1/ecdsa, encoding/asn1, revoke | BSD-3-Clause (in-tree forks: ISC, BSD-2-Clause, Go BSD) | concern: forks verified against decred, Go and cfssl originals; revoke fetches URLs from certificates if FIDO metadata were enabled; bus factor 1 |
| github.com/fxamacker/cbor/v2 | v2.9.4 | yes: cbor/v2 | MIT | concern: single maintainer; v2.9.6 exists (12 bug fixes); v2.9.4 approvable |
| github.com/x448/float16 | v0.8.4 | yes | MIT | ok (no Origin record: 2020 module; verified against GitHub otherwise) |
| github.com/golang-jwt/jwt/v5 | v5.3.1 | yes: jwt/v5 | MIT | concern: reachable through android-safetynet attestation from client input; bus factor about 2 |
| github.com/go-viper/mapstructure/v2 | v2.5.0 | yes: mapstructure/v2, internal/errors | MIT | concern: blessed fork of archived mitchellh/mapstructure; used only on signature-verified data (SafetyNet, FIDO metadata); single maintainer, quiet 9 months |
| github.com/tinylib/msgp | v1.6.4 | yes: msgp | MIT | concern: never reads browser data; crafted msgp bytes can crash a reader, so session data must only be read back from what the server itself wrote |
| github.com/philhofer/fwd | v1.2.0 | yes | MIT | concern: Peek/Next allocate what the input asks for; same rule as msgp |
| github.com/stretchr/testify | v1.12.1 | no (module graph only, go-webauthn's tests) | MIT | ok |
| go.uber.org/mock | v0.6.0 | no (graph only) | Apache-2.0 | ok |
| go.yaml.in/yaml/v3 | v3.0.5 | no (graph only, via testify) | MIT AND Apache-2.0 | ok |

Checks for every module (from the review): the go.sum h1 lines equal sum.golang.org; the Origin VCS hash equals the upstream tag's commit (float16 has no Origin record); `go mod verify` passes; the keyroster-signer package list (CGO_ENABLED=0 GOOS=linux) is unchanged; github.com/google/go-tpm stays at v0.9.9-0.20260124013517-8f8f42cba0de; no known vulnerability in any added module at the selected version (vulndb's older advisories for mapstructure, fixed in 2.3.0 and 2.4.0, and jwt/v5, fixed in 5.2.2, predate the selected versions). govulncheck reported GO-2026-6809, which is in the go1.27.2 standard library (crypto/x509), fixed in go1.27.3, and comes from no added module.

**Owner's reply (verbatim), 2026-10-21.** Question: "Godkänner du de 11 modulerna för 02-08, och ska planen härdas mot svagheterna ovan?" Reply: **"Godkänn + härdning (Rekommenderas)"**. The owner approved all 11 modules together with four hardening measures (H1-H4, below).

**Task 1's automated checks, re-run on the plan branch before the first `go get`:** `git worktree list --porcelain` shows no scratchpad worktree (PASS); `git diff --quiet origin/main -- go.mod go.sum` exits 0 (PASS); the precondition `git cat-file -e origin/main:.planning/phases/02-passkey-login-mvp/02-07-SUMMARY.md` exits 0 (PASS).

**After `go get` and `go mod tidy` (Task 2):** `go list -m all` is identical to the module set the owner reviewed (the review's `after-followup-list-m-all.txt`); go.mod gained 1 direct and 7 indirect requirement lines, as the review predicted; go.sum differs from the review's only by the h1 lines of testify, mock and yaml/v3, which equal the sum.golang.org values in the review's cross-check; `go mod verify` passes. **go-tpm check:** `go list -m github.com/google/go-tpm` printed `v0.9.9-0.20260124013517-8f8f42cba0de` before and after (RESEARCH A7). The signer's non-stdlib package list (`CGO_ENABLED=0 GOOS=linux go list -deps ./cmd/keyroster-signer`, 65 packages) is identical to the review's baseline.

## Delivery

- **Branch:** `p02/08-registration`, created from origin/main `52b99c4` with the orchestrator's `docs(phase-02): mark 02-07 complete ...`. Before the push, origin/main had moved to `0ecc48e build(go): pin the toolchain to go1.27.3 for GO-2026-6809 (#47)`, so the branch was rebased onto it. go.mod merged cleanly (the toolchain line is main's, the requirements this plan's); `.planning/STATE.md` conflicted and was resolved as the Delivery Protocol says: main's version with this plan's entries re-applied (the quick task's row is kept). Every rebased commit carries an SSH signature (checked on each). origin/main then moved again, to `2ac2e7f test(directory): time Authorize against Validate as the fastest of five runs (#46)`, and the orchestrator rebased the branch a second time, onto 2ac2e7f (#46 and #47). **The hashes in this file are those of the PR's history on 2ac2e7f** (the orchestrator commit is `9b15533`, the plan's commits `55d901a`..`949b713`, this file's commit `62de5c9`). Runs recorded on earlier hashes are named by those hashes and marked as such: their plan code equals the PR's (`git diff 837befc 949b713 -- . ':!.planning'` and `git diff e0914a4 62de5c9 -- . ':!.planning'` show only #46's internal/directory/directory_test.go).
- **PR:** opened by keyroster-bot with `scripts/gh-as-bot.sh pr create` after the one push that carries this SUMMARY, title `feat(server): passkey registration through invites with pending credentials`. The PR number and the check results go in the merge-gate checkpoint (as in 02-06 and 02-07: they do not exist before the single push).
- **Auto-merge is not enabled** (environment rule: the orchestrator enables it after its own pre-merge review). The plan's "PR is open with auto-merge" acceptance line is therefore deliberately unmet.
- **GO-2026-6809:** after the rebase the toolchain is go1.27.3 (#47), so the govulncheck failure that every PR had since 2026-10-21 should not recur on this one.

## Endpoints

| Route | Wrapped like | Answers |
|---|---|---|
| `POST /api/v1/enroll/{token}/begin` | `GET /enroll/{token}` (invite limiter, JSON) | 200 creation options `{"publicKey":{...}}`; 404 `invite not valid`; 413 `request body too large` (over 1 KiB); 429 too many registrations in progress (16 open sessions) or rate limited; 500 `internal error`; 503 `signer unavailable` |
| `POST /api/v1/enroll/{token}/finish` | same | 200 `{"fingerprint","algorithm","synced"}`; 400 `malformed registration`, `unsupported attestation`, the session text (expired or already used), `the passkey registration could not be verified`, `unsupported credential`; 404 `invite not valid`; 409 `this passkey is already registered`; 413 (over 64 KiB); 500; 503 |
| `GET /api/v1/admin/users/{name}/pending` | `POST /api/v1/admin/users` (per-client admin limiter, requireAdmin; pinned by `TestAdminPendingRoute` since the pre-merge review) | 200 `{"invite":{"state":"open"\|"expired"\|"used","expires_at"},"credentials":[{"id","alg","spki","fingerprint","backup_eligible","backed_up","registered_at"}]}` (a bare array before the pre-merge review); 400 invalid user name; 401 uniform; 404 `not pending`; 500; 503 |

`enroll refused` reason codes (closed list): `invite_not_valid`, `too_many_sessions`, `bad_request`, `session_not_found`, `verify_failed`, `unsupported_credential`, `duplicate_credential`, `signer_unavailable`, `internal_error`, plus `unsupported_attestation` (H1) and `body_too_large` (H3). Level error for `signer_unavailable` and `internal_error`, info otherwise.

## The oracle's strictOnly list (TestWebAuthnOracle)

go-webauthn was called with the production settings: `ParsedCredentialAssertionData.Verify` with UV and UP required, `allowCrossOrigin=false`, explicit top-origin mode, DER ECDSA signatures, no appid, the same RP and origin. For EdDSA, ES256 and RS256 alike:

- **Both accept:** `valid`, `extra_client_data_member`.
- **Both refuse:** `signature_bit_flip`, `wrong_challenge`, `wrong_origin`, `wrong_rp_id_hash`, `uv_clear`, `up_clear`, `wrong_type`, `cross_origin_true`, `top_origin_present`, `padded_challenge`, `non_canonical_challenge`, `trailing_client_data`.
- **strictOnly (go-webauthn accepts, internal/webauthn deliberately refuses):**
  - `at_set_with_attested_data`: the signer accepts only the 37-byte authenticatorData with AT and ED clear, so it never parses CBOR (D-17);
  - `ed_set_with_extension`: no extension is requested at login, and refusing the flag keeps CBOR out of the signer;
  - `duplicate_type_member`: encoding/json in go-webauthn keeps the last duplicate member; the signer's token walk refuses any duplicate, so one clientDataJSON cannot be read two ways.
- **Accepted by internal/webauthn and refused by go-webauthn:** none among the vectors above. The pre-merge review added the rest of the 02-03 matrix and further vectors; see "Pre-merge review fixes" for the full lists and the six documented ours-only vectors.

The plan predicted crossOrigin true and topOrigin present in strictOnly. With the production setting `allowCrossOrigin=false`, go-webauthn refuses both itself (protocol/client.go), so the runs put them in both-refuse. Cross-origin was not switched on to make the list match.

## Accomplishments

- **Registration (Task 2, tracer).** Migration 0002 and the serverdb accessors; begin and finish in enroll.go with `WithCredentialParameters(CredentialParametersRecommendedL3())`, `WithExclusions` from the installed directory, server-side JSON sessions; spkiFromCOSE; the pending admin route; the invite page's data attributes and app.js; `keyroster user pending`; the reinvite text; `servertest.Register`; `TestRegisterPasskeyPending`.
- **Tests and hardening (Task 3).** The plan's refusal, options, log and lifecycle tests; the oracle; H1-H4 with RED tests where the behaviour was new; CLI peer-text tests; two fuzz targets; the dependency bans.

## Task Commits

1. **Task 2, tracer.** `55d901a` (feat; `08be165` before the rebases). Tracer gate (interactive, end-of-phase, automated-only verify): the e2e verify (`TestRegisterPasskeyPending|TestUserAddInvite`, OpenSSH 10.5p1, WSL) and `dep-firewall` + `capslock-check` passed on the tree that became 08be165; execution continued to Task 3.
2. **Task 3, TDD.** In order (the hash before the rebases in brackets):
   - `15dd014` [dcc4f79] (test): the plan's refusal, options, log and lifecycle tests, the oracle, and the RED tests for H1, H2 and H3 (H4 pinned);
   - `40d2fd2` [cee9e4c] (feat): H2, the RSA bounds in internal/webauthn;
   - `c0c1190` [0222ad9] (feat): H1 and H3 in enroll.go, with three tests added alongside (below);
   - `7686e46` [53517e4] (test): `keyroster user pending` and the reinvite text;
   - `277373e` [38a5036] (chore): the dependency bans;
   - `30b8be4` [818fd56] (test): a gosec G115 fix in a test;
   - `084fa81` [f7a5e5e] (test): the two fuzz targets;
   - `949b713` [837befc] (test): the KEY-06 custody banner on `keyroster user pending`.
3. **Task 4, merge gate.** Not attempted; the owner's `checkpoint:human-action`.

**Plan metadata:** `62de5c9` `docs(02-08): complete registration plan` (this file, STATE.md, deferred-items.md).

## TDD record (Task 3; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED, valid, for the new hardening behaviour** (`15dd014`, before any H1-H3 code). The GSD classifier was not run: it has no Go adapter. The semantic assessment below is from the go test output, kept in the scratchpad (`exec-0208/red-h2.txt`, `exec-0208/red-h1h3h4.txt`):
  - H2, `TestWebAuthnRSABounds`: exactly the H2 cases failed, each on its planned assertion (`ParsePublicKey = <nil>, want ErrPublicKey` for 4097, 8192 and 65536 bits, e=3, e=65539, e=2^31-1; `VerifyAssertion ... want ErrSignature wrapping ErrPublicKey` at login for 8192 and 65536 bits). 1024, 2047, 2048, 3072 and 4096 passed, as they should. Go's own x509 code refused none of the H2 cases: every bound is keyroster's. (The subtest times include generating an RSA-2048 key, so they are no measurement of the verification cost; the owner review's figures are.)
  - H1, `TestEnrollAttestationFormats`: all seven formats failed on the planned assertion (400 with "the passkey registration could not be verified" from go-webauthn's verifier path, want "unsupported attestation").
  - H3, `TestEnrollBodyLimits`: the four over-limit cases failed on the planned assertion (200, want 413); the at-limit cases passed.
  - The tests compiled against `reasonUnsupportedAttestation`, `reasonBodyTooLarge`, `maxEnrollBeginBody` and `maxEnrollFinishBody`, which the RED commit declares as names only, so the failures are assertion failures, not build failures.
- **Unexpected green, recorded honestly.** The plan's own Task 3 behaviour (refusals, options, log, lifecycle, oracle) passed on its first run apart from two test mistakes (below), because the Task 2 tracer had built it. H4's `TestEnrollWebAuthnConfig` was green from the start: it pins a configuration that never had a provider. Bite evidence instead:
- **GREEN.** `40d2fd2` made `TestWebAuthnRSABounds` pass; `c0c1190` made `TestEnrollAttestationFormats` and `TestEnrollBodyLimits` pass. No REFACTOR commit.
- **Mutants.** Each was applied to the file, run against the named test, and the file restored byte for byte (checked by SHA-256 after every run; `ALL RESTORED`):

  | Mutant | Killed by |
  |---|---|
  | H1: fmt gate off | `TestEnrollAttestationFormats` ("go-webauthn ran an attestation verifier 1 times": the counting seam fired) |
  | H2: no upper bound or exponent check | `TestWebAuthnRSABounds`, and at the server `TestEnrollRSABounds` (200 for 4097+ bits) |
  | H3: no Content-Length check | `TestEnrollBodyLimits/declared_over_limit_not_read` (413, but 1025 bytes read) |
  | H3: no MaxBytesReader | `TestEnrollBodyLimits` (200 for the streamed over-limit bodies) |
  | H4: an MDS provider set | `TestEnrollWebAuthnConfig/metadata_disabled` |
  | no `WithCredentialParameters` | `TestEnrollBeginOptions/begin_options_exact` (the library's ten algorithms) |
  | bind UPDATE without `invite_used_us IS NULL` | `TestEnrollInviteLifecycle/invite_concurrent_finish` (a 409 instead of the uniform 404); scheduling-dependent, so the pre-merge review added the deterministic `TestBindPendingCredential` (serverdb) |
  | invite lookup without `invite_used_us IS NULL` | `TestEnrollInviteLifecycle/used_invite_page_and_begin_404` |
  | ReplaceInvite keeps `invite_used_us` | `TestEnrollInviteLifecycle/reinvite_after_used_invite_allows_register` |
  | internal/webauthn accepts UV clear | `TestWebAuthnOracle` (accepted by ours, refused by go-webauthn) |
  | session read with SELECT instead of DELETE ... RETURNING | survived the first set of tests (the invite lookup refuses a replay first); killed after `session_single_use_after_failed_finish` was added |
  | no installed-directory duplicate check | `TestEnrollRefusals/credential_id_in_directory_refused` |
  | CLI: no fingerprint comparison | `TestUserPendingPeerText` |
  | CLI: no ParsePublicKey on the SPKI | `TestUserPendingPeerText` |
  | CLI: no reinvite text | `TestUserAddReinviteText` |
  | AdminJSON marshals nil as `null` | `TestUserPending` (4 body bytes on the GET) |
  | CLI prints the server's fingerprint field | survived: equivalent while the comparison is in place (the printed value must equal the computed one) |
  | a go-webauthn import in internal/webauthn | `dep-firewall.sh` exit 1 (BANNED lines) and depguard (`signer-no-network`, D-17) |

## Verification run

| Check | Where | Result |
|---|---|---|
| Task 2 verify 1: e2e `TestRegisterPasskeyPending\|TestUserAddInvite`, OpenSSH 10.5p1 | WSL | PASS (tracer gate) |
| Task 2 verify 2: `dep-firewall.sh && capslock-check.sh` | WSL | PASS, capslock 91/91 |
| Task 2 acceptance greps (signer graph 0, server graph 5 go-webauthn/webauthn packages, ./cmd/... test helpers 0, PendingUserByInvite in invite.go and enroll.go, data-begin 1, `<script>` 0, app.js src 1, RETURNING x2, `invite_used_us IS NULL` x2 statements, the unique index, the BE CHECK, PublicKeyCredential detection, innerHTML 0, WithCredentialParameters with CredentialParametersRecommendedL3, `func logEnrollRefusal`, one `"enroll refused"`), all with `GOOS=linux` where the plan says so | Windows | all PASS |
| Task 3 verify 1: `go test -race -count=1 -timeout 5m -v -run "Register\|Enroll\|Oracle" ./internal/server/...` | WSL, on 38a5036 and again on 837befc (pre-rebase hashes; now 277373e and 949b713) | PASS both times, 0 FAIL, 0 DATA RACE; the four required PASS lines present (invite_concurrent_finish, used_invite_page_and_begin_404, begin_options_exact, refusal_logged_with_reason) |
| Task 3 verify 2: `go test -race -count=1 ./...`, `go vet ./...`, `go vet -tags e2e ./test/e2e/`, GOROOT gofmt (from a script file, so not vacuous), golangci-lint v2.14.0 (linux, windows, darwin), capslock-check, dep-firewall, testonly-firewall | WSL, on 38a5036 (pre-rebase; now 277373e) | all pass. The first lint run found one gosec G115 in a test, fixed in `818fd56` (now `30b8be4`); lint then 0 issues on the changed packages in all three GOOS |
| Head 837befc (pre-rebase; now 949b713): `go test -race -count=1` of internal/server, serverdb, serverclient, webauthn and cmd/keyroster; GOROOT gofmt; golangci-lint `./...` (linux) | WSL | all pass, 0 issues. The commits after 38a5036 change only tests (818fd56, f7a5e5e, 837befc; now 30b8be4, 084fa81, 949b713) |
| Full e2e, OpenSSH 10.5p1 | WSL, on 818fd56 (pre-rebase; now 30b8be4; later commits change only unit tests and fuzz targets) | 25 PASS, 0 FAIL (keyroster.localhost resolved natively this time) |
| e2e `TestRegisterPasskeyPending\|TestUserAddInvite`, OpenSSH 9.5p1 | WSL, on 818fd56 (pre-rebase; now 30b8be4) | PASS |
| `go test -count=1 ./...` | Windows, on 38a5036 (pre-rebase; now 277373e) | PASS (internal/winagent did not time out this run) |
| Fuzz `FuzzSPKIFromCOSE`, `FuzzCheckPendingCredential`, 30 s each | Windows | no failure |
| `go mod verify`; module set vs the owner-reviewed set; signer package list vs the review baseline | Windows | identical |
| After the first rebase, onto 0ecc48e (go1.27.3), on e0914a4's code (its plan code equals the PR's; the PR's base 2ac2e7f adds only #46's directory_test.go): Task 3 verify 1 under `-race` (the four required PASS lines), `go test -race -count=1` of internal/server, serverdb, serverclient, webauthn, directory, signer and cmd/keyroster, dep-firewall, capslock (91/91), e2e `TestRegisterPasskeyPending\|TestUserAddInvite` (10.5p1); on Windows `go test` of the touched packages, `go mod verify`, the module set and the go-tpm version | WSL and Windows, go1.27.3 | all pass; module set identical to the reviewed one; go-tpm v0.9.9-0.20260124013517-8f8f42cba0de |
| govulncheck | not run locally | CI only |
| Task 3 verify 3 and 4 (SUMMARY on the pushed head, required checks) | GitHub | after the push; reported in the merge-gate checkpoint |

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Owner hardening (in scope by the owner's decision of 2026-10-21)

1. **[H1] Attestation none only, before verification (refined by E1).** `handleEnrollFinish` checks `parsed.Response.AttestationObject.Format == "none"` right after `ParseCredentialCreationResponseBytes`, before the invite lookup and the session consumption, with nothing written: 400 `{"error":"unsupported attestation"}`, reason `unsupported_attestation`, logged err the fixed text "attestation format is not none" (the client's fmt is never logged). Test: `TestEnrollAttestationFormats` with packed self-attestation (ES256 and RS256, signed by the credential key), tpm, android-safetynet, fido-u2f, apple and an unknown format. Proof that go-webauthn's verifiers are never reached: a test-binary `init()` replaces every non-none entry of go-webauthn's attestation registry (`protocol.RegisterAttestationFormat`) with a counter; the counter stays 0, and the gate-off mutant makes it fire. The test also shows the session was not consumed (the same ceremony then finishes with attestation none). Commit `c0c1190` (RED in `15dd014`). **Refined at the pre-merge review by owner decision E1** (commit `e5b2c6d`): a packed self-attestation of the pass-through shape is re-encoded as none and registers; the gate now runs after the invite lookup (`e7ba144`).
2. **[H2] RSA bounds in the shared verifier.** `internal/webauthn.ParsePublicKey` accepts RS256 only with a 2048-4096-bit modulus and e = 65537. It is the function the server (spkiFromCOSE), the directory validation and the signer's login verification call, so the bound holds at registration, at directory install and at login. RS256 stays offered. Tests: `TestWebAuthnRSABounds` (1024, 2047, 2048, 3072, 4096, 4097, 8192, 65536 bits, e=3, e=65539, e=2^31-1, and login with 8192 and 65536 bits refused as ErrPublicKey before any signature work) and `TestEnrollRSABounds` at the server (1024, 2048, 4096, 4097, 8192, 65536, e=3, e=65539; refusals are `unsupported_credential`). The signer side still passes capslock (91/91, unchanged) and dep-firewall. Commit `40d2fd2` (RED in `15dd014`); `TestEnrollRSABounds` came with `c0c1190` and bites under the H2 mutant.
3. **[H3] Body caps before parsing.** begin 1 KiB (it reads no input; app.js sends no body), finish 64 KiB (an attestation-none finish is a few KiB even with a 1023-byte credential ID and an RSA-4096 key, base64url-encoded). A declared Content-Length over the limit is refused before a byte is read; a streamed body through `http.MaxBytesReader`. 413 `{"error":"request body too large"}`, reason `body_too_large`, nothing written, no session consumed. Tests: `TestEnrollBodyLimits` (declared and streamed, over and at the limit, both routes, `declared_over_limit_not_read`, session still usable afterwards, no session stored by a refused begin). Commit `c0c1190` (RED in `15dd014`).
4. **[H4] FIDO metadata disabled.** `webauthnConfig` sets no `MDS`, no `Filtering`, no cross-origin, no top or opaque origins and leaves `Timeouts.Registration.Enforce` off (go-webauthn reads time.Now; the session row's expiry under the server clock is the authority). Sessions are JSON the server wrote into `registration_sessions` and read back only from there; begin answers only `publicKey` (and an omitted `mediation`). Test: `TestEnrollWebAuthnConfig` (`metadata_disabled`, `sessions_server_side_only`); green from the start, the MDS mutant fails it. go-webauthn/x's revoke package is linked but reachable only through metadata validation, which never runs with `MDS == nil` (read in `protocol/attestation.go`: `if mds == nil { return nil }` before `ValidateMetadataWithAuthenticatorData`).

### Environment overrides

5. **Auto-merge not enabled, one push only, PR number and check results in the checkpoint** (environment rules). The plan's Task 3 action and acceptance ask for auto-merge and two pushes.
6. **`requirements-completed: []`, no `requirements.mark-complete`, ROADMAP not updated** (plan `<output>` and environment).
7. **Task 1 was executed by the orchestrator** before this run; this plan records its result and re-ran its automated checks.

### Auto-fixed issues and interpretations

8. **[Rule 3, deferred row for 02-08] `serverclient.AdminJSON` sends no body for a nil input** and signs the SHA-256 of the empty body. Needed for the body-less admin GET (the 02-07 pre-merge row). serverclient is not in files_modified. The deferred row is marked resolved for 02-08.
9. **[Rule 3] e2e harness `requestBody`.** `test/e2e/server_test.go`'s `request` now delegates to `requestBody`, so the e2e can POST begin and finish. Not in files_modified.
10. **[Rule 3] webauthntest gains `Sign` and `WithAuthDataSuffix`** (test-only package): packed self-attestation for H1 and the AT/ED vectors of the oracle. Not in files_modified.
11. **[Interpretation] The registration block is a `<section id="kr-enroll" data-begin data-finish>`, not `<main>`:** base.html already wraps every page's content in `<main>`, and a second one would be invalid HTML. The acceptance greps hold.
12. **[Interpretation] Finish order.** The plan lists parse, consume, verify. The invite lookup (which supplies CreateCredential's user) runs before the consumption, and the H1 gate right after parsing. A finish on a used invite therefore gets the uniform 404 without touching its own session, which `finish_after_invite_used_refused` expects. **Changed at the pre-merge review** (`e7ba144`): the invite lookup now runs before the body is parsed, so an unknown, used or expired token gets the uniform 404 before go-webauthn's parser or the H1 gate sees anything.
13. **[Interpretation] Session status code.** The plan gives no status for `session_not_found`; it is 400 with a fixed "expired or already used; reload the page" text.
14. **[Rule 1, found by a test] An EC2 key labelled RS256 passes go-webauthn.** `rs256_label_on_ec_key_refused` showed that go-webauthn v0.18.2 checks only the algorithm number at an attestation-none registration; keyroster's own conversion refuses the key (`unsupported_credential`). The test expects that; a deferred-items row records the library behaviour.
15. **[Rule 1, test mistakes] Two test mistakes** in the first run of the Task 3 tests: the wrong reason expected for the EC-labelled-RS256 case (item 14), and the default invite limiter answering 429 inside `refusal_logged_with_reason` (that test now raises the limit, as the lifecycle tests do).
16. **[Rule 2, project rule: every parser fuzzed]** `FuzzSPKIFromCOSE` and `FuzzCheckPendingCredential` (`084fa81`).
17. **[Rule 2, T-02-93 and KEY-06] `keyroster user pending`** shows the custody banner once (`software_custody_banner_once`, `949b713`) and validates every field of the server's list (canonical base64url ID of 1-1023 bytes, canonical standard-base64 SPKI accepted by ParsePublicKey for its algorithm, the server's fingerprint equal to the computed one, BS only with BE, RFC 3339 time) and prints only the re-derived values; a 401 at a server URL that is not a policy origin gets 02-07's diagnosis, from the root-verified policy only. `TestUserPendingPeerText` covers forged and foreign fingerprints, padded fields, RSA-1024, an unknown algorithm, padded 404 and 401 bodies.
18. **[Scope] Tests beyond the plan's list:** `wrong_type_refused`, `unknown_challenge_refused`, `session_single_use_after_failed_finish`, `rs256_label_on_ec_key_refused`, `bs_without_be_refused`, `malformed_body_refused`, `exclude_credentials_from_directory`, `backup_flags_recorded`, the at-limit body cases, the oracle's extra vectors (`extra_client_data_member`, `padded_challenge`, `non_canonical_challenge`, `trailing_client_data`, `duplicate_type_member`), and `TestUserAddReinviteText`.
19. **[Existing test updated] `TestInvitePage/valid_invite`** asserted that the invite page carries no script. It now asserts exactly one script, `<script src="/static/app.js" defer></script>`, no inline script, and the data attributes with the token. The "Passkey registration on this page comes in a later release" sentence is gone from the page.

**Total deviations:** 19 (4 owner hardening measures, 3 environment overrides, 3 blocking fixes, 3 interpretations, 2 library or test findings under Rule 1, 2 Rule 2 additions, 1 scope item, 1 updated test).

**Impact on plan:** the module set is exactly the owner-reviewed one; the signer's dependency graph and capslock baseline are unchanged; H1-H4 narrow what go-webauthn sees and what any keyroster component accepts.

## Threat model notes

- **T-02-37 (attestation and CBOR parsing), narrowed by H1 and H3.** go-webauthn still parses the creation response and its CBOR on the server (bounded to 64 KiB), but only an attestation of format none reaches its verification. The packed, TPM (go-tpm), android-key, SafetyNet (golang-jwt, mapstructure), fido-u2f, apple and compound verifiers, with their x509 chain building, never see client input. The result is re-validated as SPKI by internal/webauthn; the signer never parses CBOR (dep-firewall and depguard bans). **Pre-merge review:** go-webauthn's parser now runs only for a live invite's holder (`e7ba144`); a packed self-attestation of the pass-through shape is re-encoded as none before go-webauthn verifies it (E1, `e5b2c6d`), and its self-signature is deliberately not verified: verifying it would be cryptography on a client-chosen key at registration and would prove nothing keyroster relies on (D-05), while the signer checks possession of the private key at every login.
- **T-02-40 (weak credential algorithms), extended by H2.** Only EdDSA, ES256 (P-256) and RS256 are offered (`WithCredentialParameters`, `begin_options_exact`) and accepted. RS256 now means a 2048-4096-bit modulus with e = 65537, in the one verifier the server, directory and signer share: a huge key can no longer make each login verification expensive, and an exotic exponent is refused everywhere.
- **T-02-39 (replay of sessions and invites).** A session is consumed once with DELETE ... RETURNING, also by a finish that fails verification (`session_single_use_after_failed_finish`); 5-minute expiry under the server clock; the invite is used only by the conditional UPDATE; credential IDs are unique against pending credentials and the installed directory.
- **T-02-97 and T-02-98** as planned: `invite_concurrent_finish` (8 ceremonies, one credential, under -race) and the two reinvite tests.
- **T-02-140 (the enroll refused log line).** One helper, a closed attribute set, fixed client answers; `refusal_logged_with_reason` checks six answers and the absence of tokens, token hashes (hex and four base64 forms), challenges, credential IDs, SPKIs (three base64 forms), attestation objects and clientDataJSON in the whole log. **Pre-merge review:** the premise that go-webauthn's Error() carries no request data was wrong (its Details quote unsolicited client extension names); the line now logs only the library-declared Type of a go-webauthn error or a fixed text (`e24ecf4`, `client_text_never_logged`).
- **New surface, mitigated: unauthenticated request bodies (H3).** The handlers read at most 1 KiB and 64 KiB; HTTP/2's receive-window buffering is the 02-07 D6 exposure (deferred-items row, UNVERIFIED for these routes).
- **New surface, mitigated: outbound fetches (H4).** No metadata provider is configured, so go-webauthn/x's revoke package, linked into the server, never fetches a CRL or OCSP URL.
- **T-02-38 (compromised server swaps the credential)** stays accepted as planned: the out-of-band fingerprint comparison catches a stolen invite on an honest server, not a compromised server; binding still needs an admin signature (02-09).

## Issues Encountered

- **The Bash tool refused some heredocs** that contained Go source with apostrophes ("unexpected EOF while looking for matching `'`"), and Python edits through heredocs turned `\n` escapes into newlines once. Larger Go edits were therefore made with the Edit and Write tools. No effect on the code.
- keyroster.localhost resolved natively in WSL this session (02-07 had needed a namespace wrapper), so the full e2e ran without it.

## Not exercised (UNVERIFIED)

- **app.js in a real browser, UNVERIFIED until 02-13:** `navigator.credentials.create` with a real authenticator, the base64url handling of a real browser's ArrayBuffers, the passkey feature detection and the error and result display. Only `node --check` (syntax) ran, and the e2e fetched the file.
- **Unsolicited client extension outputs:** go-webauthn's default policy refuses an extension output that was not requested. Whether a real browser or password manager adds one at registration is UNVERIFIED. Since the pre-merge review such a refusal no longer puts the client's extension names in the log.
- **Pre-merge review branches no test reaches:** `webauthnCause`'s fixed text for an error that is not a go-webauthn `*protocol.Error` (`errWebAuthnOther`, e.g. a raw CBOR error from CreateCredential) and for a `*protocol.Error` whose Type the library does not declare; `asNoneAttestation`'s error return. Every refusal the tests drive is a `*protocol.Error` of a declared Type, and the re-encode and re-parse of authData go-webauthn already parsed never failed.
- **Which authenticators send packed self-attestation under attestation none (E1):** the owner's note names OpenSK default builds, and Chromium and Firefox forward the shape; no real authenticator or browser ran here, so this is UNVERIFIED. The tests use soft authenticators only.
- **Re-registering on the same authenticator after a reinvite replaces the orphaned passkey there** (the pending row keeps its user handle): authenticator behaviour, not exercised.
- **HTTP/2 buffering on the enroll routes**: derived from 02-07's measurement, not measured here.
- **govulncheck** and the windows/darwin CI lanes ran only in CI (after the push).
- **The full e2e and the full `-race ./...` under go1.27.3**: both ran before the rebase, under go1.27.2; after it, only the touched packages, the registration e2e and the firewalls ran locally. CI runs the rest.
- **CI on the pushed head**: reported in the merge-gate checkpoint.

## Known Stubs

None. The registration page is complete for this plan; the account stays unusable until 02-09 binds the credential, by design (AUTH-01, D-03).

## Threat Flags

None beyond the threat model and the notes above: the two new unauthenticated routes and the new admin route are in the plan's threat register (T-02-37, T-02-39, T-02-97, T-02-98, T-02-140), and the body and outbound-fetch surfaces are mitigated by H3 and H4.

## User Setup Required

None.

## Next Phase Readiness

- **02-09** binds a pending credential with an admin-signed directory: it reads `serverdb.PendingCredentials` (alg + SPKI DER + BE/BS, canonical ID), refuses an install that newly binds a credential which is not pending for that user (`credential_not_pending`), and can call `AdminJSON` with a nil input for its GETs. The pending admin route answers an object since the pre-merge review: `serverclient.PendingAnswer` (`invite` state and expiry, `credentials`), so `keyroster user approve` reads `.Credentials`.
- **02-10/02-12** inherit the app.js pattern (feature detection, one try/catch, textContent only) and the body-cap and one-log-helper patterns.
- **02-13** runs app.js in a real browser.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in key-files.created exists. Commits 55d901a, 15dd014, 40d2fd2, c0c1190, 7686e46, 277373e, 30b8be4, 084fa81 and 949b713 (the PR's history on 2ac2e7f, re-checked at the pre-merge review with `git rev-list 2ac2e7f..62de5c9`) are ancestors of the PR head, and every commit of this plan carries an SSH signature (`gpgsig` header checked on each). The hashes before the rebases (08be165..837befc) are no longer in the PR's history.
- The Task 2 and Task 3 acceptance greps and named cases were re-run on f7a5e5e (pre-rebase, now 084fa81; 837befc, now 949b713, changes one CLI test only) and pass: signer graph 0, server graph 5, test helpers in ./cmd/... 0, the template counts, RETURNING and `invite_used_us IS NULL`, innerHTML 0, the one logEnrollRefusal and one "enroll refused", go-webauthn in dep-firewall, `strictOnly` and `TestWebAuthnOracle`, and all fifteen named subtests. The PR acceptance (open, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.
- No private network detail in any file this plan changed (grep for tailnet names and 100.x/10.x/192.168.x addresses: none).

## Pre-merge review fixes

The orchestrator's pre-merge review of PR 48 (head `62de5c9`) confirmed 12 findings, 9 distinct issues (the log, H1/E1 and pending-route-test findings each came from two lenses), and split one more; the owner decided the H1/D-05 question as **E1** (verbatim reply: "Behandla som \"none\" (Rekommenderas)"). Every finding below was fixed, one commit each, on top of `62de5c9`; none was skipped. Each test was shown to fail before the fix (or, for a test that could not bite, its rewrite was shown to bite under a mutant of the checked code, restored afterwards with `git checkout` and checked clean).

**Fixed:**

- **finish ran go-webauthn's parser and the H1 gate before the invite lookup** (hardening) - `e7ba144`. Test `TestEnrollFinishInviteFirst`: malformed, non-JSON, packed, tpm and none bodies on a never-issued, a used and an expired token all answer the uniform 404 `invite_not_valid` with the counting seam at 0. Before: 400 `malformed registration` / `unsupported attestation`.
- **Client-chosen extension output names reached the enroll refused line** (web, and its plan-tests duplicate) - `e24ecf4`. `webauthnCause` logs only the Type of a go-webauthn `*protocol.Error`, checked against the Types the library declares, or a fixed text; the logEnrollRefusal doc comment says so. Test `TestEnrollRefusalLog/client_text_never_logged` (a 20 KB unsolicited `clientExtensionResults` name plus `credProps`: the marker never reaches the log, `err` is `go-webauthn: invalid_request`, every line stays under 512 bytes; new `servertest.WithClientExtensionResults`). Before: the whole name was logged. The fallback for a non-`*protocol.Error` (`errWebAuthnOther`) and for an undeclared Type is not reached by any test (UNVERIFIED, below). spkiFromCOSE's errors were checked too and left alone: its first decode masks CBOR errors to a fixed `Unsupported Public Key Type`, so a duplicate-key test against it could not bite.
- **H1 refused the packed self-attestation a conforming client forwards under attestation none** (web, and its plan-tests duplicate; owner decision E1) - `e5b2c6d` (and `36b1d7c`, a revive unused-parameter fix in its test). `isPackedSelfAttestation` and `asNoneAttestation` in enroll.go: exactly fmt packed, attStmt {alg, sig} and nothing else, alg an int64 equal to the COSE key's alg and one of EdDSA/ES256/RS256, sig a non-empty byte string, AAGUID 16 zero bytes; re-encoded with webauthncbor as {fmt: none, attStmt: {}, authData} and parsed again by go-webauthn (`CredentialCreationResponse.Parse`) after the invite lookup and before session consumption. The self-signature is not verified (see Threat model notes). Test `TestEnrollAttestationFormats`: `packed_self_registers` (EdDSA, ES256, RS256: 200, the authenticator's fingerprint, pending entry, counting seam 0) and 17 refused shapes (packed with x5c, an extra key, ecdaaKeyId, no sig, a text sig, a text alg, an alg mismatch, an unoffered alg agreed by key and statement, a non-zero AAGUID; tpm, tpm with the self shape, android-key, android-safetynet, fido-u2f, apple, compound, unknown), each with nothing written and the session still usable. `asNoneAttestation`'s error return (a re-encode or re-parse failure of authData go-webauthn just parsed) is not reached by any test (UNVERIFIED, below). Before: `packed_self_registers` got 400 `unsupported attestation`. Mutants, all killed: rewrite removed; shape accepted without the rewrite (the seam fired); gate removed (the seam fired for tpm and the others); any packed rewritten; and each shape condition dropped (attStmt size, AAGUID, offered alg, key-alg equality, sig type).
- **No test covered the pending admin route's wrapping** (cli, and its plan-tests duplicate) - `1606a1e`. Test `TestAdminPendingRoute` through the full handler: unsigned (also for an unknown name), another deployment's origin, a body-digest mismatch, a non-admin key and a signature for another name's path each get the uniform 401 with no `pending credentials listed` line; the signed control gets 200; the 20th signed request after one add gets 429. Mutants killed: requireAdmin dropped (unsigned got `200`), rateLimited dropped (burst+1 got 200).
- **FuzzCheckPendingCredential never reached acceptance** (cli) - `036030e`. Seeds are real EdDSA, ES256 and RS256 keys with their computed fingerprints (each seed checked to be accepted before fuzzing), one with BS set and BE clear, and a `recompute` flag that fingerprints the fuzzed SPKI. A 20 s run (`-fuzz '^FuzzCheckPendingCredential$' -fuzztime 20s`, Windows): 1,341,496 executions, no failure. Mutant "no BS-implies-BE check": the new seeds fail (`accepted {... backupEligible:false backedUp:true ...}`); the old target passed under it.
- **user pending said an expired invite was still open** (cli) - `61bbe6f`. The pending route answers `{"invite":{"state","expires_at"},"credentials":[...]}` (`serverclient.PendingAnswer`): open, expired at the invite lookup's boundary (`expires_us <= now` under the server clock), used (wins over expired). The CLI accepts only the three states and an RFC 3339 time, says them in its own words and puts the `--reinvite` advice last. Tests `TestPendingInviteState` (open, a microsecond before, at the expiry with begin 404, reinvite, used, used after expiry) and `TestUserPending/invite_expired`, `invite_used_none_pending`, `none_registered_yet`, plus four peer-text refusals of the invite fields in `TestUserPendingPeerText`. Before: the old handler answered a bare array and the old CLI printed "has an open invite". Mutants killed: never expired, the boundary off by one, never used, CLI ignores the state, CLI skips the state check.
- **user pending's 404 advice failed for a user already in the directory** (cli) - `a5bc29f`. The message says there is no pending enrollment and gives both commands: `keyroster user add NAME` for a new user, `keyroster user add NAME --reinvite` for a user already in the directory (advice last). Test `TestUserPending/not_pending`; before: "carol is not pending ... Use keyroster user add carol to invite them". `padded_404` still passes. 02-09's e2e step 5 ("`user pending admin1` reports none") still meets this exit-1 path after approval: that is 02-09's to reconcile with this wording.
- **The differential oracle omitted 02-03 mutations, and D6 overclaimed** (plan-tests) - `c383df4`. Added to bothRefuse: auth_data_36_bytes, auth_data_38_bytes, at/ed flag without data, invalid_utf8, cross_origin_string_false, origin_http_scheme, origin_other_host, origin_extra_port, type_not_string, client_data_not_an_object; to strictOnly: duplicate_type_same_value. A new exact `oursOnly` class with its reasons: token_binding_bogus_status, token_binding_no_status, token_binding_string, case_variant_origin_member, case_variant_challenge_member, case_variant_type_member (internal/webauthn follows the spec; go-webauthn over-reads; the signature covers clientDataJSON, so nothing is exploitable). D6 is restated over the listed vectors. Bite: the internal/webauthn mutants that accept an extra port or an http origin pass the old vector set and fail the new one; the uv_clear mutant is still killed. A mutant accepting a 38-byte authenticatorData survives the oracle (the signature check still refuses it, so the outcome is unchanged); `TestWebAuthnMutationMatrix` pins that sentinel.
- **(split) BindPendingCredential's conditional UPDATE was guarded only by a scheduling-dependent test** (plan-tests) - judged real and fixed: `716fdcc`. Test `TestBindPendingCredential` (serverdb): a second bind on one invite, a bind on a replaced invite and one at the expiry get ErrInviteNotValid with nothing written and `invite_used_us` unchanged; another user's credential ID and a second credential for one user (invite reset by SQL so only the index stands) get ErrDuplicateCredential with the UPDATE rolled back. Mutants killed: bind ignores `invite_used_us`, inclusive expiry, non-unique one-per-user index (which survived every test before).
- **The SUMMARY was stale after the rebase onto 2ac2e7f** (plan-tests) - `1b38748`: plan heads `9b15533`/`949b713`, the task, TDD and deviation hashes, the Self-Check, the Delivery text, and go.mod's 1 direct and 7 indirect lines. Pre-rebase runs keep their hashes, labelled as such.

**Skipped:** none.

**Verification of the fixes** (Windows, go1.27.3): on `716fdcc` and again on `36b1d7c` (this commit's parent), `gofmt -l .` empty; `go vet ./...`, `GOOS=linux go vet ./...`, `GOOS=darwin go vet ./...` and `go vet -tags e2e ./test/e2e/` clean; `go test -count=1` of internal/server, serverdb, serverclient and cmd/keyroster pass; `go test ./...` passes on `716fdcc` (all 21 packages with tests; `36b1d7c` changes one test helper and its package was re-run); `scripts/dep-firewall.sh` exit 0 and `scripts/testonly-firewall.sh` clean; `go list -deps` shows 0 go-webauthn/cbor/jwt packages in keyroster-signer and keyroster (linux). **Not run:** `-race` (no cgo on this Windows host), the e2e suite (only compiled), golangci-lint (not installed locally), capslock; CI runs them on the pushed head. Every commit carries an SSH signature: the `gpgsig` header is on all 23 commits of 2ac2e7f..HEAD, this one included (`git log --pretty=raw` counted against `git rev-list --count` after this commit).

**Second round (on `510403d`, one finding, low):** the pending route read the account, `invite_used_us` and the credentials in three statements, so a reinvite committing between them answered "used, no credential" and the CLI advised a reinvite that would replace the invite just sent. Fixed: `f4a1d36` (`serverdb.PendingState` reads all three in one transaction and the handler builds its answer only from it; `TestPendingState` starts a reinvite and a registration between the reads through a `DB` test hook that waits for an event, the write's commit or its wait for the one connection, not a timing; the mutant without the transaction gives "used true with 0 credentials" and "used false with 1", the finding exactly) and `9717334` (the CLI refuses used with no passkey and open/expired with one, and the used-no-passkey reinvite text is gone, superseding that part of `61bbe6f` above: its `invite_used_none_pending` is now `invite_used_none_pending_refused`; that test and three `TestUserPendingPeerText` rows fail on the previous CLI); two 02-09 rows in deferred-items.md, `0c62b5f`. The handler's use of `PendingState` is pinned by the code, not by a server-level test (the hook is unexported). Verification (go1.27.3): `gofmt -l .` empty, `go vet` (windows, linux, darwin, `-tags e2e`) clean, `go test ./...` passes on Windows; in WSL on a `git archive` copy, `go test -race` of serverdb, server and cmd/keyroster and `-race -count=20 -run TestPendingState` pass and golangci-lint v2.14.0 reports 0 issues. Not run: the e2e suite, govulncheck, capslock and the firewall scripts (CI). The `gpgsig` header is on all 4 commits of `510403d..HEAD`.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-21 (before the merge gate)*
