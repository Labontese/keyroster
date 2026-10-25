---
phase: 03-linux-agent-and-revocation
plan: 01
subsystem: revocation
tags: [krl, revocation, installation-id, sshsig, sshd, signer, tlog]

requires:
  - phase: 02-passkey-login-mvp
    provides: admin SSHSIG API, signer socket and wire framing, audit log kinds 1-8, e2e harness with real sshd
provides:
  - trust.Bundle installation_id (D-04, random-128) and root sign --installation-id new
  - internal/krl (deterministic PROTOCOL.krl encoder, ops-signed manifest, size bounds)
  - keyroster revoke serial through POST /api/v1/admin/revoke to the signer
  - signer revoke + krl_publish in one transaction; GET /api/v1/krl
  - tlog kinds revoke (9) and krl_publish (10)
  - proof that sshd re-reads RevokedKeys after a rename(2) swap with no reload
affects: [03-03, 03-04, 03-05, 03-07, 03-11, 03-12, 03-13, 03-15, 03-16]

actuals:
  tokens: 57401
  tasks: 3
  commits: 3
plan_head_before: 27f3ea2e0995c132c519396a75af158ef4076bc0
plan_head_after: d263deea5a227f7a58ded895fb6a59a78175046c

tech-stack:
  added: []
  patterns:
    - "Own KRL encoder, verified against ssh-keygen -Q as the oracle"
    - "Per-call HTTP response limit in serverclient (send takes the limit)"
    - "One clock reading per revocation, feeding freshness, ResolvedAtSeconds, both leaf times and the manifest's issued_at"

key-files:
  created:
    - internal/krl/krl.go
    - internal/krl/manifest.go
    - internal/wire/revoke.go
    - internal/signerdb/migrations/0005_revocation.sql
    - internal/signerdb/revocation.go
    - internal/signer/revoke.go
    - internal/signer/krl.go
    - internal/server/revoke.go
    - cmd/keyroster/revoke.go
    - test/e2e/revoke_test.go
    - docs/runbooks/revoke.md
  modified:
    - internal/trust/bundle.go
    - internal/trust/verify.go
    - internal/trust/successor.go
    - cmd/keyroster/root.go
    - internal/tlog/leaf.go
    - internal/wire/frame.go
    - internal/signer/signer.go
    - internal/signer/logstate.go
    - internal/signer/refusal.go
    - internal/signer/server.go
    - internal/signer/evidence.go
    - internal/signer/trust.go
    - internal/signerdb/log.go
    - internal/signerclient/client.go
    - internal/server/server.go
    - internal/server/signer.go
    - internal/serverclient/admin.go
    - internal/serverclient/client.go
    - test/e2e/bootstrap_test.go
    - test/e2e/server_test.go
    - .golangci.yml

key-decisions:
  - "D-04 is random-128 with a lenient transition (owner, 2026-10-24)"
  - "One policy admin authorizes a revocation, whatever admin_quorum says"
  - "No KRL is published while the bundle in force has no installation ID (krl_no_installation_id)"
  - "doctor (CheckTrust) also checks the KRL state against the log, matching serve"

patterns-established:
  - "A new signed format ships with a golden vector under test/vectors and a strict decoder whose errors wrap the package's malformed sentinel"
  - "A KRL leaves the signer only after the transaction holding its revoke and krl_publish leaves committed"

requirements-completed: []

coverage:
  - id: D1
    description: "Trust bundles carry installation_id (32 lowercase hex), successors keep it or add it once, root sign draws it only for a new out-dir"
    requirement: "REVOKE-03"
    verification:
      - kind: unit
        ref: "internal/trust/installation_test.go#TestInstallationIDFormat"
        status: pass
      - kind: unit
        ref: "internal/trust/installation_test.go#TestInstallationIDSuccessor"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestRootSignAccumulates"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestRootSignInstallationID"
        status: pass
    human_judgment: false
  - id: D2
    description: "internal/krl writes PROTOCOL.krl serial sections that ssh-keygen -Q agrees with (adjacency, duplicates, order, empty set, size bound)"
    requirement: "REVOKE-02"
    verification:
      - kind: unit
        ref: "internal/krl/krl_test.go#TestEncode"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestEncodeSizeBound"
        status: pass
      - kind: integration
        ref: "internal/krl/oracle_test.go#TestOracleSSHKeygenKRL"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestKRLGoldenVector"
        status: pass
    human_judgment: false
  - id: D3
    description: "The manifest binds a KRL to the installation, version and SHA-256 under the ops key; VerifyManifest refuses every other key, namespace, installation, version and byte"
    requirement: "REVOKE-03"
    verification:
      - kind: unit
        ref: "internal/krl/krl_test.go#TestVerifyManifest"
        status: pass
      - kind: unit
        ref: "internal/krl/krl_test.go#TestManifestSizeBounds"
        status: pass
    human_judgment: false
  - id: D4
    description: "Signer revocation: one admin authorizes; replay, non-admin, wrong namespace, unknown serial, role mismatch, no installation ID and an oversize KRL are refused and change nothing; one clock reading; restart and doctor checks"
    requirement: "REVOKE-01"
    verification:
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevoke"
        status: pass
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevokeClock"
        status: pass
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevokeKRLTooLarge"
        status: pass
      - kind: unit
        ref: "internal/signer/revoke_test.go#TestRevokeRestart"
        status: pass
    human_judgment: false
  - id: D5
    description: "keyroster revoke serial through keyroster-server to the signer; GET /api/v1/krl; real sshd refuses the revoked certificate after a file swap with no reload, the control still logs in, same PID"
    requirement: "REVOKE-03"
    verification:
      - kind: e2e
        ref: "test/e2e/revoke_test.go#TestRevokeSerialEndToEnd (local WSL, OpenSSH 10.5p1 and 9.5p1)"
        status: pass
      - kind: unit
        ref: "internal/server/revoke_test.go#TestRevokeRoute"
        status: pass
      - kind: unit
        ref: "internal/serverclient/client_test.go#TestGetKRLResponseBound"
        status: pass
      - kind: unit
        ref: "internal/wire/wire_test.go#TestKRLFrameBound"
        status: pass
    human_judgment: false
  - id: D6
    description: "Wire and log formats pinned: RevokeRequest, revoke and krl_publish leaves; audit verify refuses kinds 9 and 10 until 03-03"
    verification:
      - kind: unit
        ref: "internal/wire/wire_test.go#TestRevokeRequestSigningVector"
        status: pass
      - kind: unit
        ref: "internal/tlog/leaf_test.go#TestRevokeLeafVector"
        status: pass
      - kind: unit
        ref: "internal/tlog/leaf_test.go#TestKRLPublishLeafVector"
        status: pass
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyKindsWithoutChecks"
        status: pass
    human_judgment: false
  - id: D7
    description: "Revoke runbook (D-20)"
    verification: []
    human_judgment: true
    rationale: "A runbook's clarity and its labels need a human reader; its homelab steps are UNVERIFIED until 03-16"

duration: 62min
completed: 2026-10-24
status: complete
---

# Phase 3 Plan 01: Revoke Tracer Summary

**An admin revokes a certificate by serial with `keyroster revoke serial`. keyroster-server forwards the request to the network-less signer. The signer publishes a KRL written by our own PROTOCOL.krl encoder, with an ops-signed manifest bound to the bundle's new installation ID. Real sshd refuses the certificate once the KRL file is swapped in, with no reload.**

## Owner's D-04 answer (Task 1, resolved before this run)

Copied from `$HOME/keyroster-ceremony/phase3/d04-answer.txt`, three lines:

```
random-128
Ägarens ordagranna svar (AskUserQuestion, 2026-10-24): "random-128 (Recommended)"
Claudes beskrivning av alternativet (inte ägarens ord): slumpat 128-bitars ID, 32 hex-tecken i gemener, som root sign väljer vid genesis eller som en efterföljare lägger till en gång; lenient övergång: kataloger utan ID gäller för inloggning på signern men accepteras aldrig av en agent.
```

- Line 2 is the owner's verbatim wording, which is only the option label he picked.
- Line 3 is Claude's description of that option, not the owner's words.

What 03-01 implemented from it:
- The regex is `^[0-9a-f]{32}$`.
- The successor rule: a successor keeps the previous bundle's ID, or adds one when the previous bundle has none. A successor that changes or drops the ID is refused with ErrVersionChain.
- The transition rule is LENIENT. 03-04 implements the directory side.

## Performance

- **Duration:** about 62 min
- **Started:** 2026-10-24T18:51:10Z
- **Completed:** 2026-10-24T19:53Z (before the PR; CI and the merge gate follow)
- **Tasks:** 3 (Task 1 resolved beforehand; Tasks 2 and 3 executed; Task 4 is the merge gate)
- **Files modified:** 52

## Accomplishments

- **Installation ID (D-04).**
  - `trust.Bundle` gains `installation_id` (omitempty, the last field). Every bundle under test/vectors re-encodes byte-identically, and `"installation_id":""` is refused as non-canonical.
  - `root sign` gives every genesis bundle an ID and prints `installation id: <id> (new in this version)`. `--installation-id new` adds one to a successor of a bundle without an ID.
  - The ID is drawn only when the out-dir holds no bundle yet, so the signatures of several roots accumulate on one bundle, also after the out-dir is copied to another machine.
- **internal/krl.**
  - A deterministic encoder: one certificate section per CA key, ordered by the key's wire bytes; the single serials in one 0x20 list placed first; every run of two or more serials as a 0x21 range. It never writes a signature section, an extension or a bitmap.
  - The canonical manifest with its SSHSIG under `keyroster/krl/v1`, and `VerifyManifest`, which has one sentinel per refusal.
  - The F12 bounds: `MaxKRL` 4 MiB, `MaxManifest` 4 KiB, `MaxManifestSig` 16 KiB, and `MaxKRLResponse` = 5 620 744 bytes.
- **Revocation path.**
  - `keyroster revoke serial SERIAL [--ca] [--reason] [--admin-key]` sends the request to `POST /api/v1/admin/revoke`. The server forwards the RevokeRequest unchanged.
  - In one transaction the signer verifies one policy admin's SSHSIG, records the revocation row, the revoke leaf and the request ID, rebuilds the KRL from the whole revocation table, signs the manifest with the ops key, stores the KRL state and appends the krl_publish leaf.
  - `GET /api/v1/krl` serves the result with `Cache-Control: no-store`, under its own rate class (60/min, burst 30, with a global backstop).
- **sshd re-reads RevokedKeys with no reload.** In TestRevokeSerialEndToEnd, `current -> gen/2` is renamed over `current -> gen/1`. A is then refused with sshd's log line `Authentication key ED25519-CERT ... revoked by file .../current/revoked.krl`. B still logs in, and the sshd PID is the same. This settles the STATE blocker, which is now removed. It ran locally on OpenSSH 10.5p1 and 9.5p1.

## Task Commits

1. **Task 1: D-04 checkpoint.** Resolved by the owner before this run, so no commit.
2. **Task 2 (tracer): revoke by serial into an installation-bound KRL.** `79ccd94` (feat).
3. **Task 3: unit coverage, vectors, gates and runbook.**
   - `b641b8f` (test). Tests and golden vectors. TestRevokeRestart's doctor assertion is RED here.
   - `d263dee` (feat). Doctor KRL check, depguard entry and runbook.

**Plan metadata:** the `docs(03-01): complete revoke-tracer plan` commit that carries this file.

## Wire, log and refusal reference

- **Wire types:** `TypeRevokeRequest` 0x06, `TypeGetKRL` 0x07, `TypeRevokeResponse` 0x86, `TypeGetKRLResponse` 0x87.
  - `MaxKRLFrame` = 4 MiB + 64 KiB, for GetKRLResponse only. RequestCaps is unchanged.
  - `RevokeRequest.CARole` is the `wire.CARole` enum, written as one byte. `TargetSerial` = 1, and any other target is refused.
- **Leaf kinds:** `revoke` 9 (with `ResolvedAtSeconds`) and `krl_publish` 10.
- **Tables (migration 0005):** `revocation`, `krl_state` and `revoke_request`.
- **New refusal details:**

  | Detail | Class |
  |---|---|
  | `unknown_serial`, `ca_role_mismatch` | malformed |
  | `krl_no_installation_id`, `krl_too_large`, `ops_key_unavailable` | unavailable |
  | `duplicate_request` | existing class, reused for a replayed revoke |
  | `krl_state_not_logged` | not a refusal: serve and doctor refuse to start |

- **Golden vectors:**
  - `test/vectors/krl_manifest_v1.json`
  - `test/vectors/krl_serials_v1.hex` (starts with `5353484b524c0a00`)
  - `test/vectors/revoke_request_signing_v1.hex` (starts with the domain tag)
  - `test/vectors/leaf_revoke_v1.hex`
  - `test/vectors/leaf_krl_publish_v1.hex`
- **Capslock pairs added:** none. `scripts/capslock-check.sh` reports 91 (package, capability) pairs against a baseline of 91, so `--update` was not run. `scripts/dep-firewall.sh` passes unchanged.
- **Interim audit note:** from this plan's merge until 03-03 merges, `keyroster audit verify` refuses a log at its first revoke or krl_publish entry with `audit: entry N (revoke|krl_publish): not verifiable by this version`. Two new cases of `TestVerifyKindsWithoutChecks` pin this. internal/audit/verify.go is unchanged: `git diff origin/main` on it and on internal/wire/issue.go is empty.

## What ran and what did not

**Ran (2026-10-24):**
- **Windows unit tests:** `go test` of trust, krl (the ssh-keygen oracle included, with Git's ssh-keygen), wire, audit, serverclient and cmd/keyroster.
- **Fuzzing:** `FuzzDecodeLeaf` for 20 s, PASS.
- **Linux full gate (WSL):**
  - `go test -race ./...`, PASS (the krl oracle with Ubuntu's ssh-keygen included).
  - `go vet`, plus vet with the e2e tag, and gofmt.
  - golangci-lint: 0 issues.
  - capslock: no new pairs. dep-firewall: OK.
  - `go.mod` and `go.sum` are unchanged.
- **e2e on 10.5p1:** the full e2e suite.
  - Every test passed except `TestSSHDRejects/pty_allowed`, which fails only inside the local namespace workaround (see Issues) and passes when run outside it.
  - The doctor, audit, rotation, trust-flow and revoke e2e tests were run again after Task 3's doctor change. All passed.
- **e2e on 9.5p1:** `TestRevokeSerialEndToEnd`, PASS.
- **Mutants**, each killed, each restored:
  - a fresh ID drawn in prepareBundle's existing-bundle branch (killed: TestRootSignAccumulates, 4 subtests);
  - no 0x20 list (TestEncode);
  - no dedupe (TestEncode);
  - GetKRL read under maxResponse (TestGetKRLResponseBound);
  - CheckTrust without the KRL check (TestRevokeRestart);
  - the revoke quorum taken from admin_quorum (TestRevoke);
  - a second clock reading for ResolvedAtSeconds (TestRevokeClock).

**Not run here:**
- **CI.** CI (both e2e matrix lanes, 9.5p1 and 10.5p1, cli-windows and cli-macos) runs on the PR. Its results go in the merge-gate return, not in this file.
- **The e2e_pkcs11 and e2e_tpm build tags.** Their files compile against the changed bootstrap helper but were not executed.
- **The homelab's bundles v1 to v3.** They are not in the repository, so "the homelab's v1-v3 re-encode byte-identically" is UNVERIFIED here. Only the test/vectors bundle was checked. Every homelab step is UNVERIFIED until 03-16.
- **The CLI's text for `krl_no_installation_id` and `krl_too_large` over HTTP.** It is UNVERIFIED end to end. The CLI prints "signer unavailable" with a hint to read the signer's log, because a 503 carries no reason.

## Decisions Made

- **One admin revokes.** One policy admin's evidence authorizes a revocation whatever `admin_quorum` says. Revocation is the fail-safe direction, and the plan specifies it.
- **No KRL without an installation ID.** The signer refuses `krl_no_installation_id` before any state changes when the bundle in force has no installation ID. Revocation therefore needs a bundle signed after this plan: the homelab gets one with the v4 ceremony (03-15).
- **The doctor checks the KRL state too (Rule 2).** `CheckTrust` now compares the stored KRL state with the last krl_publish entry, so a database that serve refuses (`krl_state_not_logged`) is not reported healthy.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical] doctor parity for the KRL state**
- **Found during:** Task 3 (raised in the advisor review)
- **Issue:** `serve` refused a KRL state that the log does not record, but `CheckTrust`, which `keyroster-signer doctor` uses, did not check it, although its doc says it mirrors serve.
- **Fix:** `signerdb.LogSnapshot` carries the KRL state. `CheckTrust` tracks the last krl_publish body and calls `checkKRLLogged`.
- **Files modified:** internal/signerdb/log.go, internal/signer/logstate.go
- **Verification:** TestRevokeRestart. RED in `b641b8f`: "CheckTrust with a tampered KRL state: <nil>, want krl_state_not_logged". GREEN in `d263dee`.
- **Committed in:** d263dee

**2. [Rule 3 - Blocking] files outside the plan's list**
- **Found during:** Task 2
- **Issue:** The planned changes could not be built or tested without touching files the plan does not list.
- **Fix:**
  - `trust.BuildSuccessor` takes the installation ID (internal/trust/successor.go and its test call sites).
  - The signer's trust state opens the ops key (internal/signer/trust.go).
  - Admin evidence verification is shared by issue and revoke (internal/signer/evidence.go).
  - `trust.CheckTimestamp` is exported for the manifest's issued_at.
  - A `StoppableSigner` option for the e2e server env (test/e2e/server_test.go).
  - An installation-ID field on the signer test fixture.
  - Revocation tests in a new internal/signer/revoke_test.go, as the plan names no file for the signer table.
- **Committed in:** 79ccd94, b641b8f

**3. [Rule 1 - Bug] unknown-kind test used kind 9**
- **Found during:** Task 2
- **Issue:** `TestDecodeLeafStrict` used kind 9 as its unknown kind, but 9 is now `revoke`.
- **Fix:** It uses `KindKRLPublish + 1`.
- **Committed in:** 79ccd94

**4. [Plan detail] no edit to harness_test.go**
- **Issue:** harness_test.go says later plans do not edit it, and `startSSHD` returns neither sshd's PidFile nor its log.
- **Fix:** revoke_test.go has its own `startSSHDWithLog`, built from the same `sshdConfigTemplate`.

**5. [Plan detail] key link `krl.Encode` in revoke.go**
- **Issue:** The plan's own action text puts `krl.Encode` in `publishKRLLocked` (internal/signer/krl.go).
- **Fix:** Revoke's doc comment names `krl.Encode` where it is called, so the key-link grep holds for the call path and not for a call in revoke.go itself.

---

**Total deviations:** 5. Of these, 3 were auto-fixed (Rules 1, 2 and 3) and 2 are plan details.
**Impact on plan:** No scope creep. No new module.

## TDD Gate Compliance

- **Order.** Task 3 is `tdd="true"`, but the tracer (Task 2) had already implemented the behaviour before any Task 3 test existed. So most Task 3 tests passed on their first run. RED was not faked.
- **Evidence instead.** Seven mutants, each killed by the named test (listed under "What ran"), show that the tests check the behaviour they name.
- **The one genuine RED.** The doctor KRL check: target `TestRevokeSerialEndToEnd`'s sibling `TestRevokeRestart`, run with internal/signer/logstate.go and internal/signerdb/log.go at Task 2's state. It failed on the planned assertion, "CheckTrust with a tampered KRL state: <nil>, want krl_state_not_logged", with exit 1, not on a build or setup error. It went GREEN after `d263dee`.
- **The classifier was not used.** Go's test output is not one of the formats `gsd-tools check tdd-red-evidence` reads, and `workflow.tdd_mode` is off.
- **Commit order:** `test(03-01)` b641b8f, then `feat(03-01)` d263dee.

## Issues Encountered

**WSL no longer resolves `keyroster.localhost`.** Phase 2 recorded that it did.
- **Workaround:** the e2e ran in `unshare --user --map-current-user --mount` with a bind-mounted /etc/hosts entry, as the same uid and with no capabilities. The script was not committed.
- **Side effect:** in that namespace, `TestSSHDRejects/pty_allowed` cannot allocate a pty. It passes outside the namespace.
- **Tracking:** logged in deferred-items.md.

## Known Stubs

None. No keyroster command fetches and verifies a KRL for a hand install yet. That is future scope (the agent, 03-05 to 03-07), not a stub, and the runbook says so.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: new unauthenticated endpoint | internal/server/revoke.go | `GET /api/v1/krl` serves the KRL to any TLS client. This is in the threat model (T-03-08, accepted; own rate class). |

## User Setup Required

None.

## Next Phase Readiness

- **03-03** adds the audit verify rules for kinds 9 and 10, revocation by key ID, key and subject, and the strict KRL parser. It should also correct the stale comment in internal/audit/verify.go (deferred-items.md).
- **03-04** binds directories to the installation ID (lenient transition).
- **03-07** reuses `krl.MaxKRLResponse` and `krl.VerifyManifest` for the agent.
- **The homelab** refuses every revocation until a bundle with an installation ID is installed (the v4 ceremony, 03-15).

## Self-Check: PASSED

- **Files:** every created file listed above exists, including the five vectors under test/vectors, docs/runbooks/revoke.md and test/e2e/revoke_test.go.
- **Commits:** 79ccd94, b641b8f and d263dee are ancestors of HEAD.
- **Acceptance greps:**
  - The installation_id tag is on the last Bundle field.
  - Both namespaces are present.
  - The verify.go and issue.go diff against origin/main is empty.
  - 4 `case KindRevoke|KindKRLPublish` lines.
  - `MaxKRLResponse` is defined and used in GetKRL, and `maxResponse = 4 << 20` is unchanged.
  - `CARole CARole` is the field type, and `ResolvedAtSeconds` is set in the signer.
  - `revoke_request` table, and one `NewInstallationID(` call site.
  - `k <= KindKRLPublish` in the fuzz test, and internal/krl in .golangci.yml.
  - UNVERIFIED appears 5 times in the runbook.

## Pre-merge review fixes

PR #58, findings the review upheld. Each code fix has a test that failed before the fix and passes after it.

- **CLI reported the server's unsigned revoke answer as fact** (two findings, one defect): f6bc33d. Test: `TestRevokeSerialConfirm`; its seven refusal cases fail when the confirmation is bypassed. The CLI now labels the answer as the server's report and refuses answers the signer never gives. The served KRL manifest must verify against the root-pinned bundle and installation ID, with at least the reported version and krl_publish entry. Not done: checking that the KRL lists the serial needs `krl.Parse` (03-03), and no plan owns this check in the CLI.
- **Revocation table not reconciled with the revoke leaves** (two findings, one defect): 1e5843e. Test: `TestRevocationsNotLogged` (row deleted, inserted, changed; serve and CheckLog). It fails with the check disabled. `TestRevokeKRLTooLarge` now adds its rows in the revocation's own transaction, through a trigger. Not done: a guard at publish time against rows changed while the signer runs.
- **s.krl stale after a failed COMMIT that still reached disk**: e6b8bdc. Test: `TestRevokeFailedCommitReloadsKRL`. The directory cache has the same older pattern and is out of scope.
- **Unauthenticated GET /api/v1/krl waited on s.mu and held signer slots**: eb18e2b. Test: `TestGetKRLDoesNotWaitForMu`. Not done: caching the KRL on the server or limiting concurrent signer calls.
- **`--ca host` said hosts enforce the revocation**: 94728e6. Test: `TestRevokeSerialConfirm/enforcement_by_role`. The runbook describes the host case and labels it UNVERIFIED until 03-09.
- **Runbook gave the wrong error for a non-admin key; refusal texts untested**: b7b1b57. Test: `TestRevokeRefusalText`; the 403 case fails on the old text. Each row is labelled as run against a stub server and UNVERIFIED end to end. 0782fcc is a lint-only follow-up.
- **"Every refusal is in the audit log"** (split): 21856d2. Docs only, no test.
- **Installation-ID upgrade path shown as working but never run end to end** (split): 9da2d70. Docs only, no test; the runbook labels it UNVERIFIED and names 03-15 and 03-16.
- **DecodeRevokeBody accepted kind-inconsistent entries** (split): 01ee30a, for the serial kind only. Test: `TestRevokeBody`, with encode and raw-decode negative cases; the golden vector still passes. The rules for the key_id and key kinds are left to 03-03.
- **Skipped:** none.
- **Not run:** `-race` (no cgo on this host); e2e and golangci-lint (not available from this worktree, CI runs them).

## Pre-merge review fixes, round 2

PR #58, the findings left open after round 1. The owner decided all four on 2026-10-25. Each code fix has a test that failed with the check disabled and passes with it.

- **CLI exit 0 on a replayed KRL** (owner decision "IssuedAt now + 03-03"): 98538ed.
  - Fix: the CLI refuses a manifest whose issued_at is more than `wire.MaxRequestSkewSeconds` (300) before the request's CreatedAt. That constant is now the source of the signer's `maxClockSkew`.
  - Test: `TestRevokeSerialConfirm`. `replayed_earlier_krl` replays a genuine earlier v3 at entry 9 under the invented answer {3, 8, 9}; `replayed_just_outside_window` uses 301 s. Both fail with the check disabled. `issued_inside_window` (290 s) passes.
  - Remains: a genuine KRL that another revocation published within those 300 s still passes, and the output says so. 03-03-PLAN.md Task 2 and must_haves now own the next step: the CLI parses the confirmed KRL with `krl.Parse` and refuses unless every revoked target is listed.
- **No reconciliation at publish time** (owner decision "exact set in memory"): 2cb715d.
  - Fix: the signer keeps the multiset of logged revoked entries in memory. It is built with the log and gains a revoke leaf's entries only when that transaction commits; a failed commit reloads it from the log. `publishKRLLocked` compares it with the rows read in the same transaction after `krl.Encode` and before the ops key signs (so `krl_too_large` still comes first). On a mismatch it refuses `revocations_not_logged`, the transaction rolls back and the signer is marked broken.
  - Test: `TestRevocationsChangedWhileRunning` covers row_deleted, row_inserted and row_changed. In each case the row is changed through a separate handle while the signer stays open, revoke B is refused, no v2 is signed, the signer is broken and later issuance is refused. The three tampering cases fail with the check disabled. The `untouched` control fails when a commit does not update the set.
  - Test: `TestRevokeFailedTxDiscardsPendingEntries` fails when a failed transaction's entries are merged after the reload. A mutant that merges them before the reload is masked: `loadLog` replaces the set, so that mutant passes.
  - Runbook: `revocations_not_logged` is documented (4d86181 corrects what a stopped signer still does). The KRL in force stays served. Requests that write to the audit log are refused until restart, and only issuance is tested. Recovery is labelled UNVERIFIED.
- **Unauthenticated KRL route made one signer call per request** (owner decision "server-side cache now"): b018723.
  - Fix: keyroster-server caches the GetKRL answer for `krlTTL` (5 s), single-flighted like `currentStatus`. A failed read is not cached. The bytes are served unchanged. A revocation through this server drops the cache before it answers, both on success and when the outcome is unknown; it first waits for a refresh in flight, as `dropStatus` does.
  - Test: `TestKRLCache`. `burst_one_signer_call` sends 12 concurrent GETs and gets 1 call; it fails without the cache (12 calls). `revoke_drops_cache` serves v2 after the revoke; it fails without `dropKRL`. `stale_after_ttl` and `failure_not_cached` also pass.
  - e2e: 4d86181 makes `TestRevokeSerialEndToEnd` wait 6 s before its read after the signer restart, so the read reaches the signer and not the cache.
  - Remains: no signal for the KRL version. A change that does not go through a revocation on this server is served up to 5 s late.
- **Key ID and key entries not validated strictly** (Codex check): d3573ec.
  - Fix: each kind carries only its own fields, in Encode and in decode, and every error wraps ErrMalformedLeaf. A serial entry is CA key + serial. A key_id entry is CA key + key ID: OpenSSH scopes key IDs to a CA, and the 03-03 plan says "under the CA key(s) of the role". A key entry is the key alone, with valid_before 0, since it is never pruned.
  - Test: `TestRevokeBody` has 11 strict cases, each checked in Encode and in raw decode, plus round trips for a valid key_id entry and a valid key entry. All 18 new negative cases fail against the round-1 check. `leaf_revoke_v1.hex` still decodes unchanged.
- **Gates:**
  - `gofmt -l` is empty, and `go vet ./...` passes for windows, linux and darwin.
  - In WSL, `go test -race -count=1` passes for signer, signerdb, tlog, server, serverclient and cmd/keyroster.
  - golangci-lint v2.14.0 reports 0 issues.
- **Not run locally (UNVERIFIED here):** the e2e lanes. WSL does not resolve `keyroster.localhost`, so they rely on CI. No end-to-end run exists yet for the server cache with a real signer or for `revocations_not_logged`.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-24*
