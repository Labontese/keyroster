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

T1: fbec252

- T1 (tracer): the route, the budget share, the client, the first slice of `machine renew` and the e2e tracer, in fbec252. Verify gates 1 to 6 pass on it.

## Mutants

Each run alone on its named subtest (unmutated PASS first), killed by the named `--- FAIL:` line, restored with `git checkout --` and proven by `git diff --quiet HEAD --`.

mutant killed: M69 unknown_machine added to the pass-through (TestMachineRenewRoute/identity_details_collapsed/unknown_machine)
mutant killed: M70 the allowlist replaced by a denylist of the three identity details (TestMachineRenewRoute/unlisted_detail_collapsed)
mutant killed: M71 the pop.machines pre-check removed (TestMachineRenewRoute/pop_off_no_signer_call)
mutant killed: M72 MachineIssue takes no machine token, agent and total only (TestSignerBudget/machine_share_bounded)
mutant killed: M73 MachineIssue takes no agent token, machine and total only (TestSignerBudget/machine_and_agent_leave_interactive_floor)
mutant killed: M74 dropKRL called after a 5xx (TestMachineRenewRoute/no_dropKRL_on_5xx)
mutant killed: M75 the body cap removed (TestMachineRenewRoute/oversize_413)
mutant killed: M76 the route registered without its limiter (TestMachineRenewRoute/limiter_429_after_burst)
mutant killed: M77 unknown_message_type not mapped to signer_too_old (TestMachineRenewRoute/signer_too_old_403)
mutant killed: M78 lenient JSON, unknown fields accepted (TestMachineRenewRoute/unknown_field_400)
mutant killed: M79 CERTFILE written with the private key bytes (TestMachineRenewNeverWritesKey)
mutant killed: M80 CERTFILE written in place, no temp file and rename (TestMachineRenew/out_written_atomically)
mutant killed: M81 the --out and --key collision check removed, path and same file (TestMachineRenew/out_is_key_file_refused/same_path)
mutant killed: M85 the active-or-next machine CA key check removed (TestMachineRenewChecksAnswer/wrong_ca)
mutant killed: M86 the CA set is krl.RoleCAKeys, retired keys accepted (TestMachineRenewChecksAnswer/retired_ca_refused)
mutant killed: M87 the req= binding removed (TestMachineRenewChecksAnswer/replayed_older_cert_refused)
mutant killed: M88 key equality removed (TestMachineRenewChecksAnswer/wrong_key)
mutant killed: M90 the pop.machines early refusal removed (TestMachineRenew/pop_off_refused_before_send)
mutant killed: M101 the total token taken before the machine token (TestSignerBudget/queued_machine_calls_hold_no_total_token)
mutant killed: M102 the machine token not given back when the agent-token wait ends (TestSignerBudget/machine_token_released_when_agent_wait_ends)
mutant killed: M109 the machine and agent tokens not given back when the total-token wait ends (TestSignerBudget/machine_tokens_released_when_total_wait_ends)
mutant killed: M110 an unlisted CodeMalformed detail passed through with its own detail (TestMachineRenewRoute/unlisted_malformed_collapsed)
mutant killed: M103 the certificate type not checked, a host certificate accepted (TestMachineRenewChecksAnswer/host_cert_type_refused)
mutant killed: M104 the CertChecker.CheckCert call removed (TestMachineRenewChecksAnswer/bad_signature)
mutant killed: M105 the same-file check removed, path comparison only (TestMachineRenew/out_is_key_file_refused/hard_link)

## Readings

- T1 reading (`go test -race -count=1 -timeout 15m` of the three packages, on fbec252): server=155.905 serverclient=4.382 cmd=253.606 (deltas -29.7, -0.7, -47.0 s against the base; the base run was slower than this one, so the deltas are noise in the base, not a speed-up).
e2e GREEN run: 42821481669 (workflow_dispatch on fbec252): main lanes 788.457 s (9.5p1) and 789.537 s (10.5p1), neither ran `TestMachineIdentityEndToEnd`; probe lanes 286.118 s (9.5p1) and 292.194 s (10.5p1), each with `--- PASS: TestMachineIdentityEndToEnd` and its subtest `renew_and_login`.
- e2e run 42819221877 (the first dispatch, same commit): both probe lanes green (294.899 s and 287.177 s, the machine test passed) and main 9.5p1 green (790.192 s), but main 10.5p1 failed `TestAgentEnrollEndToEnd` at agent_enroll_test.go:369: sshd 10.5p1 logged `srclimit_penalise ... connections without attempting authentication` and closed the login before authentication, so the "revoked by file" line never came. That test and its files are untouched here; the rerun 42821481669 passed it on both lanes. Recorded as a flake of the main lane, not fixed (outside files_modified).
- Local e2e (10.5p1, namespace wrapper of 03-10b): `TestMachineIdentityEndToEnd/renew_and_login` passed (5.23 s) before the push.

## Deviations

- Task 1, e2e tracer: the role `deploy` is added at 12 h, the machine `ci` at 24 h, then the role is raised to 24 h with `role update`. A role that no user or group grants is checked against the user CA cap (12 h) until a machine carries it, so `role add deploy --max-ttl 24h` is refused before the machine exists. The certificate's lifetime is then 24 h, as the plan asks.
- Task 1, RED order: the tests and the production code of Task 1 were written in the same pass, not tests first. The RED evidence above is the new tests run against origin/main's unchanged code (a compile failure, which the plan counts); no test was seen failing against a partial implementation.
- Task 1, `TestMachineRenewNeverWritesKey`: the plan names "the base64 body lines of the key file" as needles. Go's pem writes 64-character lines (48 bytes each), and one of them holds only the public-key blob and the zero bytes after it; that line also appears, aligned, inside the request's base64, which carries the public key on purpose, so the literal rule fails on a correct implementation. The test keeps the raw 32-byte seed, the full 64-byte private key and every body line that carries a seed byte (found by decoding the body and locating the seed), all from the test's own source. Open item for Daniel.

## Threats

- T-03-73 (route half): mitigated. The route has its own per-client limiter (30 per minute, burst 10, global backstop 300 and 100), a 16 KiB body cap and strict JSON (`TestMachineRenewRoute/limiter_429_after_burst`, `oversize_413`, `unknown_field_400`, `malformed_body_400`).
- T-03-397 (server half): mitigated. Only the 16 allowlisted details pass through; every other refused detail answers `machine_not_authenticated`, every unlisted malformed detail `malformed_request`, and the log keeps the specific detail (`identity_details_collapsed/*`, `unlisted_detail_collapsed`, `unlisted_malformed_collapsed`).
- T-03-408: mitigated (Task 1 half). `machine renew` checks the answer against the root-verified bundle: an active or next machine CA key, a user certificate, principals present, signature and window by `CheckCert`, the request's key, kr3 with ca=machine, the name and this request's `req=` (`TestMachineRenewChecksAnswer/*`). Task 2 adds the lifetime, extension, critical-option and `--expect-principal` checks.

## x/crypto v0.58.0 (Task 2 Step 0, re-read in the module cache)

- An encrypted openssh-key-v1 file gives `*ssh.PassphraseMissingError` with `PublicKey` set from the clear header (`parseOpenSSHPrivateKey` fills it from `w.PubKey`); an encrypted legacy PEM block gives it with `PublicKey` nil.
- An unencrypted sk file gives the bare text `ssh: unhandled key type` (the default arm of the key-type switch).
- A wrong passphrase gives `x509.IncorrectPasswordError`.
