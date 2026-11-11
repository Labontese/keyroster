---
phase: 03-linux-agent-and-revocation
plan: 14c
status: in-progress
plan_head_before: 3da914f08220420b5b4604d6f867f594e476e0be
---

# Phase 3 Plan 14c: Installation binding for audit verify and the CLI (draft)

test-time base: cmd=236.661 audit=89.933 serverclient=4.220 at=1794379826

## Hand-over (session 1 stopped after Task 1)

- Session 1 did Task 1 (F05) only, as the Budget plans: one continuation after Task 1.
- That continuation (session 2) started at Task 2 and handed over again after it; see "Hand-over (session 2 stopped after Task 2)" below.
- The plan file is in the phase directory and **untracked**: it was copied byte for byte (`cmp` clean) and is committed only by Task 4's publish edit 1. Re-copy it with `cmp` if it is missing.
- Plan-head ledger: `.git/gsd-plan-head-before-03-14c` holds 3da914f08220420b5b4604d6f867f594e476e0be (origin/main at the start). The SUMMARY's `commits:` is `git rev-list --count 3da914f..HEAD`.
- Test-time base: the line above was measured in session 1, in the WSL boot that was up at the time. The continuation is another session, so Task 4's delta gate must re-measure the base first. Run it on origin/main in a detached worktree outside the repository, then replace the line in place (Q-09-3).
- Branch `p03/14c-installation-binding` is pushed. No PR is open yet; Task 4 opens it.

## Preconditions (Task 1, origin/main 3da914f)

- P1 stop guard holds: 03-14b's SUMMARY is on main, 03-12 sits at wave 30 with ["03-14b"], and 03-14b is the only plan at wave 29.
- P2 holds: 03-14b is on main, and this plan is not (no `"any-installation"`, no TrustUnpinned).
- P3 holds: every code anchor and the four trust_verify goldens exist.
- P4 holds: every pointer anchor occurs exactly once.
- P5 holds: T-03-350..356 are free as register rows, so no renumbering.
- P6: docs/format-registry.md is on origin/main (exit 0), so Task 4's registry step applies.
- P7 holds: cmd/keyroster/audit_test.go exists on main.
- P8: the test-time base above was measured on unchanged origin/main before any edit (WSL, go1.27.3, load average 0.00 at the start).
- P9 holds: the plan's open owner questions read "None open.".

## Task 1 (F05, Q-C7): done

- **R1** b21d7ca `test(audit): pin installation binding of audit verify (F05)`, signed.
- **T1** a419d6e `fix(audit): bind audit verify to one installation and print its ID (F05)`, signed.

**Declarations R1 added (behaviour unchanged):**
- `audit.Options.InstallationID` (documented, ignored by Verify);
- `--installation-id`, a string flag passed unvalidated into Options;
- `--any-installation`, a bool flag that is parsed and unused (`fs.BoolVar`).

**RED from a worktree of R1** (gate 2 exit 0, no `[build failed]` or `[setup failed]`):
- `--- FAIL:` TestVerifyInstallationBinding/{other_installation_refused, id_less_bundle_refused, malformed_expected_refused}. The first two verify with no error. The third gets the empty-log error, because R1 does not validate the expected ID.
- `--- FAIL:` all eight TestAuditVerifyInstallation cases. Each exits 0 with `OK:` and no installation line. unbound_refused, other_refused, both_flags_usage and malformed_flag_usage exit 0 where a refusal is wanted.
- Pass on R1, as planned:
  - own_export_ok, because nothing is refused yet;
  - unchecked_verifies_and_reports, because "" means not checked, and Report.Bundle already carries Y's ID;
  - id_added_after_anchor_ok, because nothing is refused yet. It pins the bundle-in-force rule against M1-2.

**Gates:** gate 1 exits 0, with all fourteen named PASS lines. The full packages under -race read audit 88.614 s and cmd 232.428 s. vet passes under no tag, `e2e`, `e2e_pkcs11` and `e2e_tpm`, and gofmt is clean. Gate 3 exits 0: T1 changes only verify.go and audit.go, and no test.

**Mutants.** Each compiles, `go vet` exits 0, and the file is restored and hash-checked against HEAD:
- M1-1, the comparison disabled: killed by TestVerifyInstallationBinding/other_installation_refused, /id_less_bundle_refused and TestAuditVerifyInstallation/other_refused.
- M1-2, the anchor's ID compared instead of the in-force bundle's: killed by TestVerifyInstallationBinding/id_added_after_anchor_ok.
- M1-3, runAuditVerify leaves Options.InstallationID empty: killed by TestAuditVerifyInstallation/other_refused.
- M1-4, no unbound refusal: killed by TestAuditVerifyInstallation/unbound_refused.
- M1-5, both flags accepted: killed by TestAuditVerifyInstallation/both_flags_usage.

**Moved callers.** Only arguments moved; every assertion is unchanged.
- test/e2e/audit_test.go: auditVerify now passes `--installation-id env.InstallationID`. auditVerifyPins passes `--any-installation` unless its extra arguments hold either flag. This covers every e2e caller of both helpers, including agent_enroll, approve, audit_login, ca_roles, hostcert, hosts, login, machine, recovery, restore, revoke, rotation and trust_flow.
- test/e2e/pkcs11_test.go pkcs11AuditVerify and test/e2e/tpm_test.go tpmAuditVerify now pass `--installation-id env.InstallationID`.
- New subtest TestAuditVerifiesIssuance/binds_installation, on that test's own signer and export. It runs in CI e2e and is not run locally.
- No cmd/keyroster test ran `audit verify` on an export before this plan. TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine stay green, unchanged.
- The `DisallowUnknownFields` / `not checked:` / `anchored:` grep finds only strings.Contains checks (test/e2e/audit_test.go:73, rotation_test.go:189 and 196), so no assertion moved.

**Note:** the CLI's unbound and mismatch refusals reach stderr through dispatch as `keyroster audit: audit verify: ...` or `keyroster audit: audit: ...`. The tests match the substrings the output contract names.

## Hand-over (session 2 stopped after Task 2)

- Session 2 did Task 2 (F06) only and handed over at the point the Budget allows, after Task 2's gates and mutants, with about half its context used.
- The next continuation starts at **Task 3**. It reads the plan's shared sections (frontmatter to `</context>`) and Tasks 3 to 5.
- The plan file is still untracked in the phase directory and `cmp`-identical to the plan; Task 4 commits it.
- The test-time base line above is still session 1's. Task 4's delta gate re-measures it first (another session), on origin/main in a detached worktree outside the repository, and replaces the line in place.
- Branch pushed at the Task 2 SUMMARY commit; no PR yet.

## Task 2 (F06, Q-C3 A): done

- **R2** 3797f4c `test(cli): pin the CLI's installation pin and trust verify's installation line (F06)`, signed.
- **T2** 7c50a92 `fix(cli): pin the installation ID at init and refuse another installation's bundle (F06)`, signed.

**Declarations R2 added (behaviour unchanged):**
- `Config.InstallationID` (`installation_id,omitempty`);
- Trust's `installationID` parameter, passed at all eleven call sites besides init's and at the test and e2e callers, and ignored;
- `TrustUnpinned`, called by init. In R2 both Trust and TrustUnpinned call the unexported `verifiedTrust`, which holds Trust's old body unchanged, so T2's client.go diff is only the pin check;
- `CheckInstallationPin` returning nil;
- `ErrInstallationMismatch`, and `ErrInstallationNotPinned` with a short placeholder text (no `--user`, no `--admin-key`).

**RED from a worktree of R2** (gate 2 exit 0, no `[build failed]` or `[setup failed]`): all twenty-three named cases end in `--- FAIL:`:
- TestClientTrust/{other_installation_refused, id_less_bundle_refused_when_pinned, unpinned_config_refused, malformed_pin_refused};
- TestRepinInstructionsKeepIdentity;
- TestInstallationPinned/{revoke_serial_refused_before_signing, join_token_refused, directory_command_refused, old_config_refused, rollback_to_id_less_refused, rebind_needs_reinit, admin_error_names_installation, known_hosts_sync_refused, machine_renew_refused};
- TestInit/{saves_installation, id_less_bundle_saves_none};
- TestRevokeRecover/{other_installation_refused, unpinned_config_refused, id_less_exports_with_pin_refused};
- TestCeremonyGolden/{successor_unchanged, successor_added_admin, successor_pop, genesis_pop}/trust_verify.

Pass on R2, as planned: TestClientTrust/{installation_pinned_ok, unpinned_id_less_ok, unpinned_variant_accepts_any}, TestInstallationPinned/own_installation_ok, TestRevokeRecover/{lost_still_first, no_installation_id_nothing_to_recover}, every root_sign leaf of TestCeremonyGolden, and every moved setup below.

**Gates:**
- Gate 1 exits 0, with every named PASS line and the TestHostForget `no_installation_id_refused_locally` line. Under -race: serverclient 4.146 s, cmd 251.278 s. `go vet ./...`, `go vet -tags e2e ./test/e2e/` and gofmt are clean.
- Gate 3 exits 0: the ID-less assertion strings keep their origin/main counts in host_test.go, dirpipe_test.go and machinerenew_test.go. Each trust_verify golden differs from origin/main by one added `installation id:` line. No root_sign golden or internal/rootceremony summary golden changed, and `-update-golden` from T2 is a no-op.
- Gate 4 exits 0: `TrustUnpinned(` occurs on exactly two non-comment lines (its definition and init.go), and T2 changes no test or golden.
- The goldens use the plan's values: `00112233445566778899aabbccddeeff` for the three successors and `<INSTALLATION_ID> (new in this version)` for genesis_pop.

**Mutants.** Each compiles, `go vet` exits 0, and the file is restored and hash-checked against HEAD:
- M2-1, an empty pin passes (TOFU): killed by TestClientTrust/unpinned_config_refused, TestInstallationPinned/old_config_refused and /rebind_needs_reinit, and TestRevokeRecover/unpinned_config_refused.
- M2-2, Trust skips the check: killed by TestClientTrust/other_installation_refused (and three more) and TestInstallationPinned/revoke_serial_refused_before_signing, /known_hosts_sync_refused and /machine_renew_refused (nine TestInstallationPinned cases in all).
- M2-3, an ID-less served bundle passes: killed by TestClientTrust/id_less_bundle_refused_when_pinned, TestInstallationPinned/rollback_to_id_less_refused and TestRevokeRecover/id_less_exports_with_pin_refused.
- M2-4, init does not save the ID: killed by TestInit/saves_installation and /pins_and_saves.
- M2-5, recover skips the pin check: killed by TestRevokeRecover/other_installation_refused, /unpinned_config_refused and /id_less_exports_with_pin_refused.
- M2-6, recover answers ErrInstallationNotPinned with the escalation: killed by TestRevokeRecover/unpinned_config_refused.
- M2-7, diagnose swallows the pin error: killed by TestInstallationPinned/admin_error_names_installation.
- M2-8, runTrustVerify omits the line: killed by TestCeremonyGolden/genesis_pop/trust_verify.

Unmutated, at T2, both mutant commands (vet, then `-timeout 5m -run`, no -race) pass: `ok github.com/Labontese/keyroster/internal/serverclient 0.069s` and `ok github.com/Labontese/keyroster/cmd/keyroster 2.182s`.

Cumulative: 13 of 13 mutants killed (Task 1: 5, Task 2: 8).

**Moved setups (assertions unchanged):**
- newDirEnvPolicy's config pins its bundle's ID. So do newDirEnv, roleEnv, popHostsEnv, hostEnv, newRenewEnv and newRecoverScenario, which build on it.
- `resignBundle` serves the re-signed bundle and re-saves the config with its ID. `serveResigned` serves it without re-pinning (F06's shape). Cases that keep their own downstream check this way:
  - TestDirectoryRebind/rebind_refused_without_bundle_id;
  - TestReadCommandsCheckInstallation/bundle_without_id;
  - TestHostForget/no_installation_id_refused_locally;
  - TestEditRevokesLossesBeforeInstall/no_installation_id_warns_and_installs;
  - TestMachineRenew/no_installation_id_refused.
  TestMachineRenewChecksAnswer/retired_ca_refused keeps its ID and so its pin.
- `noIDBundles` re-saves the config pinned to "". That keeps TestRevokeRecover/no_installation_id_nothing_to_recover; installation_id_lost_refused, krl_given_without_installation_id_refused and krl_malformed_refused refuse before the pin check. audit_test.go's caller reads no config.
- newLoginServer's config and newUserAddEnv's config pin their bundle's ID. TestUserAdd/policy_without_relying_party_refused swaps the trust document and re-pins the roots, so it also re-pins the swapped bundle's ID; the full-package run found this one.
- TestInit/pins_and_saves passes the saved ID to Trust. initServer gains `installation`, which peer_text_test.go's trustCommand and remote_text_test.go pass to Trust.
- test/e2e/revoke_test.go's revokeClient passes `env.Signer.InstallationID`.
- Reviewed, not moved: knownhosts_test.go's two htFix edits (about lines 130 and 665; they feed the host-trust writer directly and bypass Trust) and root_test.go's idlessGenesis (about line 1643; it feeds root sign only).

**Notes:**
- user.go:394 is runUserPending's diagnostic Trust, which the plan calls the approve path's. `keyroster user approve` reaches `adminSession.diagnose`. Both now return a pin error; M2-7 mutates diagnose, and user approve kills it.
- The counting keyring counts only directory and forget signatures. revoke_serial_refused_before_signing therefore puts a new `signCounter` (installpin_test.go) in front of it. The counter counts every sign request, an admin API request's included, and must read 0.
- printTrustSummary prints the WebAuthn RP line only when the policy names one. The init line then follows the log key line, and TestInit/saves_installation accepts either line before it.
- The cases assert Trust's own refusal text (`names installation <served>, but your config pins installation <pinned>`). An older check that names both IDs, such as the directory's installation check, cannot pass them on R2.

**UNVERIFIED:** test/e2e/revoke_test.go's revokeClient change was only compiled (vet `-tags e2e`). It first runs in CI e2e.

## Still to do (continuation)

- Task 3 (F10 and the export-line rules): R3, T3, twenty mutants, and the escape-byte readings (`od -c`, `grep -c '[\]u00'`).
- Task 4: the runbooks, registry, pointers, publish edits, gates, push and PR. Re-measure the base first.
- Task 5: a checkpoint, after Daniel merges.
