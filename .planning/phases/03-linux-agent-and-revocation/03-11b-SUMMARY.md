---
phase: 03-linux-agent-and-revocation
plan: 11b
subsystem: machine identities (renew route, machine renew, revoke machine)
tags: [machine, renew, pop, budget, revoke, e2e]
status: in-progress
requirements-completed: []
---

# Phase 03 Plan 11b: Machine renew and revoke machine Summary (draft)

Draft kept current at each task boundary.

test-time base: server=185.572 serverclient=5.060 cmd=300.578 at=1794313017

## Reconcile (Task 1 Step 0)

- Preconditions: all seven hold at origin/main fdee078.
- no source file moved since fdee078 (`git diff --stat fdee078 origin/main` over the listed paths is empty; origin/main is fdee078).
- No caller of `acquire(` or `budgeted(` outside internal/server/signer.go and capacity_test.go.
- The allowlist of 16 details was confirmed against internal/signer/machineissue.go: every detail is emitted there as `CodeRefused` (the held and too-often details through `cert.MachineCertHeld` and `cert.MachineRenewTooOften`, internal/cert/machinerecent.go).
- The signer writes `req=` as `hex.EncodeToString(req.RequestID[:])`; the CLI compares that form.

collapsed details: empty_principals, bad_subject_key, bad_subject, bad_validity, extension_not_allowed (issuance tail, internal/signer/issue.go) and peer_not_allowed (the socket's peer check) answer machine_not_authenticated by design; a usability gap, never an oracle. A detail joins the allowlist only with the same reasoning as the 16.

## RED evidence

T1 RED: the Task 1 tests copied onto origin/main (fdee078) in a detached worktree fail to compile: `internal/server/capacity_test.go: sg.MachineIssue undefined (type signerAPI has no field or method MachineIssue)`, `internal/serverclient/machine_test.go: undefined: MachineRenewRequest`, `cmd/keyroster/dirpipe_test.go: undefined: serverclient.MachineRenewPath`.
T1 RED: `go vet -tags "e2e e2emachine" ./test/e2e/` on origin/main's harness: `test/e2e/machine_test.go: unknown field PoPMachines in struct literal of type serverOpts`.

## Tasks

- T1: in progress.

## Mutants

## Readings

## Deviations

- Task 1, e2e tracer: the role `deploy` is added at 12 h, the machine `ci` at 24 h, then the role is raised to 24 h with `role update`. A role that no user or group grants is checked against the user CA cap (12 h) until a machine carries it, so `role add deploy --max-ttl 24h` is refused before the machine exists. The certificate's lifetime is then 24 h, as the plan asks.
- Task 1, RED order: the tests and the production code of Task 1 were written in the same pass, not tests first. The RED evidence above is the new tests run against origin/main's unchanged code (a compile failure, which the plan counts); no test was seen failing against a partial implementation.
- Task 1, `TestMachineRenewNeverWritesKey`: the plan names "the base64 body lines of the key file" as needles. Go's pem writes 64-character lines (48 bytes each), and one of them holds only the public-key blob and the zero bytes after it; that line also appears, aligned, inside the request's base64, which carries the public key on purpose, so the literal rule fails on a correct implementation. The test keeps the raw 32-byte seed, the full 64-byte private key and every body line that carries a seed byte (found by decoding the body and locating the seed), all from the test's own source. Open item for Daniel.

## Threats

- T-03-73 (route half): mitigated. The route has its own per-client limiter (30 per minute, burst 10, global backstop 300 and 100), a 16 KiB body cap and strict JSON (`TestMachineRenewRoute/limiter_429_after_burst`, `oversize_413`, `unknown_field_400`, `malformed_body_400`).
- T-03-397 (server half): mitigated. Only the 16 allowlisted details pass through; every other refused detail answers `machine_not_authenticated`, every unlisted malformed detail `malformed_request`, and the log keeps the specific detail (`identity_details_collapsed/*`, `unlisted_detail_collapsed`, `unlisted_malformed_collapsed`).
- T-03-408: mitigated (Task 1 half). `machine renew` checks the answer against the root-verified bundle: an active or next machine CA key, a user certificate, principals present, signature and window by `CheckCert`, the request's key, kr3 with ca=machine, the name and this request's `req=` (`TestMachineRenewChecksAnswer/*`). Task 2 adds the lifetime, extension, critical-option and `--expect-principal` checks.
