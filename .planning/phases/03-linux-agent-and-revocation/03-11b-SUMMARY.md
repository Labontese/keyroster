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

test-time base: server=115.228 serverclient=4.082 cmd=226.644 at=1794320369

The base was re-measured in place during Task 4 (detached worktree outside the repository at origin/main fdee078, nothing else running locally; the CI e2e run was remote). The first base (server=185.572 serverclient=5.060 cmd=300.578 at=1794313017) was slow: every later reading was below it. The T1 to T3 deltas below were taken against that first base.

## Reconcile (Task 1 Step 0)

- Preconditions: all seven hold at origin/main fdee078.
- no source file moved since fdee078 (`git diff --stat fdee078 origin/main` over the listed paths is empty; origin/main is fdee078).
- No caller of `acquire(` or `budgeted(` outside internal/server/signer.go and capacity_test.go.
- The allowlist of 16 details was confirmed against internal/signer/machineissue.go: every detail is emitted there as `CodeRefused` (the held and too-often details through `cert.MachineCertHeld` and `cert.MachineRenewTooOften`, internal/cert/machinerecent.go).
- The signer writes `req=` as `hex.EncodeToString(req.RequestID[:])`; the CLI compares that form.

collapsed details: empty_principals, bad_subject_key, bad_subject, bad_validity, extension_not_allowed (issuance tail, internal/signer/issue.go) and peer_not_allowed (the socket's peer check) answer machine_not_authenticated by design; a usability gap, never an oracle. A detail joins the allowlist only with the same reasoning as the 16.

## RED evidence

T1 RED: the Task 1 tests copied onto origin/main (fdee078) in a detached worktree fail to compile: `internal/server/capacity_test.go: sg.MachineIssue undefined (type signerAPI has no field or method MachineIssue)`, `internal/serverclient/machine_test.go: undefined: MachineRenewRequest`, `cmd/keyroster/dirpipe_test.go: undefined: serverclient.MachineRenewPath`.
T3 RED: the Task 3 tests run against Task 2's code (a359def plus the new tests): every TestRevokeMachine subtest fails (the dispatch had no `machine` case), as do TestMachineCommands/machine_remove_prints_revoke_hint, TestVerifyOutputMachineLine/line_after_host_before_probe and TestRevokeRefusalText/subject_kind_unsupported and subject_reserved; the two negatives (machine_remove_refused_edit_prints_no_hint, none_without_machine_entries) pass on the old code, as they should.
T2 RED: the Task 2 tests copied onto fbec252 (Task 1's code) in the detached worktree fail to compile: `cmd/keyroster/machinekey_test.go: undefined: machineKey`.
T1 RED: `go vet -tags "e2e e2emachine" ./test/e2e/` on origin/main's harness: `test/e2e/machine_test.go: unknown field PoPMachines in struct literal of type serverOpts`.

## Tasks

T1: fbec252
T2: a359def
T3: 84fd115
T4: b8d5c69

- T4: the rest of `TestMachineIdentityEndToEnd` (collapse_is_generic, if_due_sends_nothing, revoke_machine_refuses_login_and_renewal, keys_revokes_key_for_good, sk_through_agent, sk_key_file_named_error, audit_verify_counts_machine_certificates), in b8d5c69. The e2e test proves behaviour the unit tests of Tasks 1 to 3 prove, so there was no CI RED run; the evidence is the green run below. Verify 1 (the three vets, gofmt, the e2e lint on new lines: 0 issues) and verify 2 (no main lane ran the machine test) pass on b8d5c69. Task 1's variable `krl` (the KRL layout) is renamed `krlDir` so the package krl can be imported.
- T3: `revoke machine` through the kind-driven `runRevokeEntry`, the `machine remove` hint and the `machine certificates: N` line, in 84fd115. Verify gates 1 (94 PASS lines, every named one present, TestRevokeHost and TestRevokeUser whole) and 2 (revoke_test.go loses only the one `subject_kind_unsupported` row; the three packages under -race; frozen paths; capslock) pass on it. M108's killer `TestRevokeHost/proposal_exit_4_text_names_hold` exists on origin/main fdee078 under that name (revoke_test.go:1101) and asserts the host exit-4 text.
- T3, host byte identity: every string literal of origin/main's `runRevokeHost` is in the new revoke.go verbatim except eight, each an exact template of the old text: the five `run keyroster revoke host %s again` texts now read `keyroster %s %s again` with `revoke host`, `host key %s was not revoked` reads `%s %s` with the label `host key`, and the flag-set name is `"revoke " + kind`. The host's flag help, refusals, hold text, unknown-name line and success tail are whole literals of `hostRevokeKind`. TestRevokeHost (unchanged) passes whole.
- T2: key input, `--agent-key`, the full answer check, `--expect-principal`, `--if-due`, one text per refusal and the two fuzz targets, in a359def. Verify gates 1 to 4 passed on 976a1a4, whose code is the same except one fuzz seed, rewritten so that no private-key armor line sits in the source (the pre-push scan refused it); on a359def itself, verify 1 (85 PASS lines, no FAIL and no SKIP) and verify 2 (both fuzz targets at 20 s, no corpus file) were re-run and pass, as were vet and lint.
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
mutant killed: M82 a file of 64 KiB + 1 parsed (TestMachineKeyInput/over_max_refused_before_parse)
mutant killed: M83 a passphrase read from a non-terminal stdin (TestMachineKeyInput/encrypted_no_terminal_refused_immediately)
mutant killed: M84 sk detection removed, an encrypted sk file prompts (TestMachineKeyInput/sk_key_file_named_error/encrypted)
mutant killed: M89 --expect-principal ignored (TestMachineRenewChecksAnswer/missing_expected_principal)
mutant killed: M93 the buffers not cleared (TestMachineKeyInput/parse_clears_buffers)
mutant killed: M91 --if-due sends when not due (TestMachineRenewIfDue/not_due_sends_nothing)
mutant killed: M92 --if-due trusts a certificate for another key (TestMachineRenewIfDue/other_key_is_due)
mutant killed: M106 a lifetime above the machine cap accepted (TestMachineRenewChecksAnswer/lifetime_above_cap)
mutant killed: M107 the explicit critical-option check removed (TestMachineRenewChecksAnswer/critical_option_refused)
mutant killed: M94 revoke machine without the base floor (TestRevokeMachine/stale_base_refused_no_key_revoked)
mutant killed: M95 a --keys omission not reported, exit 0 (TestRevokeMachine/keys_at_cap_exit3)
mutant killed: M96 the exit-4 text without the name hold (TestRevokeMachine/pending_proposal_exit4_names_both_holds)
mutant killed: M97 the probe. pre-check removed (TestRevokeMachine/probe_name_refused_nothing_sent)
mutant killed: M98 the serials checked under the host CA (TestRevokeMachine/serials_checked_under_machine_ca)
mutant killed: M99 the machine remove hint removed (TestMachineCommands/machine_remove_prints_revoke_hint)
mutant killed: M100 recoveryKeptNotice dropped for machines (TestRevokeMachine/recovery_notice_every_run)
mutant killed: M108 the host path takes the machine exit-4 text (TestRevokeHost/proposal_exit_4_text_names_hold)

## Readings

- T1 reading (`go test -race -count=1 -timeout 15m` of the three packages, on fbec252): server=155.905 serverclient=4.382 cmd=253.606 (deltas -29.7, -0.7, -47.0 s against the base; the base run was slower than this one, so the deltas are noise in the base, not a speed-up).
e2e GREEN run: 42821481669 (workflow_dispatch on fbec252): main lanes 788.457 s (9.5p1) and 789.537 s (10.5p1), neither ran `TestMachineIdentityEndToEnd`; probe lanes 286.118 s (9.5p1) and 292.194 s (10.5p1), each with `--- PASS: TestMachineIdentityEndToEnd` and its subtest `renew_and_login`.
- e2e run 42819221877 (the first dispatch, same commit): both probe lanes green (294.899 s and 287.177 s, the machine test passed) and main 9.5p1 green (790.192 s), but main 10.5p1 failed `TestAgentEnrollEndToEnd` at agent_enroll_test.go:369: sshd 10.5p1 logged `srclimit_penalise ... connections without attempting authentication` and closed the login before authentication, so the "revoked by file" line never came. That test and its files are untouched here; the rerun 42821481669 passed it on both lanes. Recorded as a flake of the main lane, not fixed (outside files_modified).
- T2 reading (same command, on 976a1a4, the same code): server=128.722 serverclient=4.182 cmd=251.653 (deltas -56.9, -0.9, -48.9 s against the base; the cmd package stays below the base although it gained about 70 subtests, so the base run was slow).
- CI 42825986252 (on 4668ecc, Task 2's code): every job green, the fuzz job included (success in 33 m 36 s against 03-11's 32 m 21 s, with the two new targets).
- T3 reading (same command, gate 2 on 84fd115): server=125.493 serverclient=4.106 cmd=252.057 (deltas -60.1, -1.0, -48.5 s against the base of epoch 1794313017).
- Fuzz (20 s each on 976a1a4; FuzzMachineKeyFile again for 10 s on a359def): FuzzMachineKeyFile and FuzzMachineRenewAnswer found nothing; no corpus file was written.
e2e GREEN run: 42832901949 (workflow_dispatch on b8d5c69): every named PASS line on both probe lanes, both main lanes green with no machine and no probe test line.
e2e probe lane 9.5p1: 282.143 s
e2e probe lane 10.5p1: 277.041 s
e2e main lane 9.5p1: 760.192 s
e2e main lane 10.5p1: 799.599 s
- Lane times against 03-11 (PR #95): main 787.355 s (9.5p1) and 770.902 s (10.5p1), probe 292 s. The probe lanes stay under 420 s with the whole machine test; the main lanes do not compile it (tag `e2emachine`), so their change is runner noise.
- Local e2e of all of `TestMachineIdentityEndToEnd` (10.5p1, the namespace wrapper of 03-10b): every subtest passed before the push.
- Local e2e (10.5p1, namespace wrapper of 03-10b): `TestMachineIdentityEndToEnd/renew_and_login` passed (5.23 s) before the push.

## Deviations

- Task 1, e2e tracer: the role `deploy` is added at 12 h, the machine `ci` at 24 h, then the role is raised to 24 h with `role update`. A role that no user or group grants is checked against the user CA cap (12 h) until a machine carries it, so `role add deploy --max-ttl 24h` is refused before the machine exists. The certificate's lifetime is then 24 h, as the plan asks.
- Task 1, RED order: the tests and the production code of Task 1 were written in the same pass, not tests first. The RED evidence above is the new tests run against origin/main's unchanged code (a compile failure, which the plan counts); no test was seen failing against a partial implementation.
- Task 1, `TestMachineRenewNeverWritesKey`: the plan names "the base64 body lines of the key file" as needles. Go's pem writes 64-character lines (48 bytes each), and one of them holds only the public-key blob and the zero bytes after it; that line also appears, aligned, inside the request's base64, which carries the public key on purpose, so the literal rule fails on a correct implementation. The test keeps the raw 32-byte seed, the full 64-byte private key and every body line that carries a seed byte (found by decoding the body and locating the seed), all from the test's own source. Open item for Daniel.

## Threats

- T-03-73 (route half): mitigated. The route has its own per-client limiter (30 per minute, burst 10, global backstop 300 and 100), a 16 KiB body cap and strict JSON (`TestMachineRenewRoute/limiter_429_after_burst`, `oversize_413`, `unknown_field_400`, `malformed_body_400`).
- T-03-397 (server half): mitigated. Only the 16 allowlisted details pass through; every other refused detail answers `machine_not_authenticated`, every unlisted malformed detail `malformed_request`, and the log keeps the specific detail (`identity_details_collapsed/*`, `unlisted_detail_collapsed`, `unlisted_malformed_collapsed`).
- T-03-408: mitigated (Task 1 half). `machine renew` checks the answer against the root-verified bundle: an active or next machine CA key, a user certificate, principals present, signature and window by `CheckCert`, the request's key, kr3 with ca=machine, the name and this request's `req=` (`TestMachineRenewChecksAnswer/*`). Task 2 adds `pol=`, the issuance window, the lifetime of 60 s to the cap, no critical option, the machine profile's extensions and `--expect-principal` (`TestMachineRenewChecksAnswer/*`, `FuzzMachineRenewAnswer`). Residual: principals are not checked against the directory, which the CLI does not hold, except by `--expect-principal`; the summary line says so.
- T-03-74 and T-03-244: mitigated. The key file is bounded to 64 KiB before any parse, a passphrase is read only from `--passphrase-fd` or a terminal (never from a stdin that is not one), the file buffer, the passphrase and the Ed25519 key are cleared after signing, and no error carries key or passphrase bytes (`TestMachineKeyInput/*`, `FuzzMachineKeyFile`). ECDSA big integers cannot be cleared reliably in Go; the runbook says so in Task 5.
- T-03-72 (CLI half): mitigated. `revoke machine` sweeps every live certificate of the name, disables the entry and sweeps again, `--keys` blocks the entry's key, the exit-4 text names both holds, and every run that sent a request prints the former-name line (`default_no_keys_exit0`, `keys_revokes_entry_key`, `pending_proposal_exit4_names_both_holds`, `rename_line_every_run`, M94 to M98). Residual: certificates the same key obtained under a former name stay live until expiry, `revoke machine OLDNAME` or `--keys`; the CLI cannot see former names.
- T-03-409: mitigated. `checkHostTrustFloor` is the CheckBase of both kinds (M94); with no host trust state of this installation no floor is checked, and the output says so, as for hosts.
- T-03-411: accepted (OQ-4 of 03-11). `machine remove` revokes nothing; an installed or proposed removal ends with the hint that names `keyroster revoke machine` and `keyroster revoke key` (M99); a refused edit prints none.
- T-03-404: accepted. Every `revoke machine` run that sent a request ends with `recoveryKeptNotice` (M100).
- T-03-406: mitigated (CLI half). An sk key file is refused by its clear header before any prompt with the named error that points to `ssh-add` and `--agent-key` (`TestMachineKeyInput/sk_key_file_named_error/*`); a real security key stays UNVERIFIED (OQ-2).

## x/crypto v0.58.0 (Task 2 Step 0, re-read in the module cache)

- An encrypted openssh-key-v1 file gives `*ssh.PassphraseMissingError` with `PublicKey` set from the clear header (`parseOpenSSHPrivateKey` fills it from `w.PubKey`); an encrypted legacy PEM block gives it with `PublicKey` nil.
- An unencrypted sk file gives the bare text `ssh: unhandled key type` (the default arm of the key-type switch).
- A wrong passphrase gives `x509.IncorrectPasswordError`.
- Task 2, the refused-answer text: the plan's words, with the serial added inside the second sentence ("The signer logged the issuance (serial N) and it counts toward the 12 per hour for this key"), so an admin can find the issuance in the log.
- Task 2, sk detection: only by the clear header of an openssh-key-v1 file (PD6). The second check on `PassphraseMissingError.PublicKey` that the plan's Step 2 allows was left out: x/crypto sets that field only for openssh-key-v1 files, which the header check already covers, so it could never refuse anything the first did not.
- Task 2, test seams: `machineRenewTimeNow` (the clock of `--if-due` and CreatedAt) and `machineKeyParseHook` (counts parses for `over_max_refused_before_parse`), besides the plan's `machineKeyBufferHook`.
- Task 3, the probe. refusal: the text names the name and says nothing was revoked; it adds no advice on revoking a probe certificate by serial, which this plan does not test.
- Task 3, the hint's max TTL is printed as a Go duration (`2h0m0s`), the form `--max-ttl` accepts.
- Task 3, M94 as run: `CheckBase` is nil for the machine kind only (the host keeps the floor); M98 as run: the first sweep checks under the host CA role.
- Task 2, M83 as run: the mutant reads stdin (`ceremonyInput`) inside the non-terminal branch before refusing; the test's check that stdin was not read kills it.

## Handover (executor run 1 stopped after Task 2, half-context rule)

- Done: Task 1 (fbec252, SUMMARY 64167d7) and Task 2 (a359def); 34 mutants killed, none equivalent. The branch is pushed; no PR is open yet (Task 5 opens it). CI 42825986252 (workflow_dispatch on 4668ecc): build-test, cli-windows, cli-macos, lint, govulncheck, dependency-firewall and capslock green; the fuzz job was still running at the handover: check it first (a finding lands in Task 2's files). The CLI lanes do not check PASS lines, so whether `hard_link` ran or skipped there is not known.
- Next: Task 3 (`revoke machine`, the `machine remove` hint, the audit line; 8 mutants, cumulative floor 42), then Task 4 (the rest of the e2e test and its lane timing) and Task 5 (runbooks, tracking edits, gates, PR, final SUMMARY).
- The test-time base was measured at epoch 1794313017; Task 5's delta gate wants it under 24 h old, so a later continuation re-measures it in place (the detached base worktree outside the repository, kr-base-11b next to the repository, is still there; check it out at origin/main first).
- Local e2e works with the namespace wrapper of 03-10b (unshare with a bind-mounted /etc/hosts that maps keyroster.localhost to loopback) on the WSL OpenSSH 10.5p1 build.
- `TestAgentEnrollEndToEnd` flaked once on main 10.5p1 (sshd PerSourcePenalties closed the login before authentication); a rerun passed. If it recurs on the PR, it is outside files_modified.
