---
phase: 03-linux-agent-and-revocation
plan: 14c
status: in-progress
plan_head_before: 3da914f08220420b5b4604d6f867f594e476e0be
---

# Phase 3 Plan 14c: Installation binding for audit verify and the CLI (draft)

test-time base: cmd=259.024 audit=89.177 serverclient=3.989 at=1794409348

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

## Hand-over (session 3 stopped after Task 3)

- Session 3 did Task 3 only. It stopped after Task 3's gates and mutants under the half-context rule, at a task boundary.
- The next continuation starts at **Task 4**. It reads the plan's shared sections (frontmatter to `</context>`) and Tasks 4 and 5.
- The plan file is still untracked in the phase directory and `cmp`-identical to the plan. Task 4 commits it.
- The test-time base line above is still session 1's. No delta gate ran in session 3. Task 4's delta gate re-measures the base first (another session), on origin/main in a detached worktree outside the repository, and replaces the line in place.
- Branch pushed at the Task 3 SUMMARY commit. No PR yet.

## Task 3 (F10, Q-C4 B; PR #75 review follow-ups): done

- **R3** ce47d25 `test(audit): pin the verifier-clock bound and the export-line key rules (F10)`, signed.
- **T3** 1f8830e `fix(audit): refuse entries dated past the verifier's clock and export keys a reader would fold (F10)`, signed.

**Declarations R3 added (behaviour unchanged):**
- `audit.Options.Now` (documented, ignored by Verify);
- `var ErrEntryAhead`;
- `const maxLeafAheadMicros = krl.PruneMargin * 1_000_000`;
- `Report.LastTimeMicros` (never set);
- `var auditClock = time.Now` in cmd/keyroster (unused).

T3 adds two unexported helpers:
- `entryAheadError`, so the refusal carries the plan's text verbatim and still satisfies `errors.Is(err, ErrEntryAhead)`;
- `recoveryImportVersions`, which checkImportVersions now shares. Its messages are unchanged.

**RED from a worktree of R3** (gate 2 exits 0, with no `[build failed]` or `[setup failed]`). All twenty-three named cases end in `--- FAIL:`:
- TestVerifyLeafTimeBound/{forward_dated_republish_refused, past_allowance_refused, two_ahead_leaves_names_last}: Verify returns no error.
- TestVerifyLeafTimeBound/last_time_reported: LastTimeMicros reads 0.
- TestAuditVerifyClock/{prints_last_entry_time, clock_behind_refused}: the command exits 0 with `OK:` and no last entry time line.
- TestRevokeRecover/forward_dated_saved_export_refused: recover exits 0 and writes the request.
- The eleven TestVerifyBoundValues refusals and the five charset cases (upper_kind, title_kind, kelvin_kind, long_s_host_gone, nested_upper): the export verifies.

These pass on R3, as planned:
- `escaped_version_same_value_ok` and `policy_version_missing_ok`: nothing is bound yet.
- `zero_now_unbounded`: Now is 0.
- `within_allowance_cannot_drop_valid`: the KRL re-derivation refuses it (SHA-256 mismatch), not the bound. On T3 the test also checks that the error is not ErrEntryAhead.
- `allowance_is_prune_margin`: it checks a declaration.
- The ten `forget_only_<key>_refused` cases and `forget_only_keys_pinned`: forgetOnlyKeys already holds all ten keys. Their value is in M3-10..19.
- `go_reader_folds_case`: it reads Go's behaviour, which is the premise.
- TestExportKeysLowercase: the gate already passes at 3da914f.

**Fixture lines.** TestVerifyBoundValues uses TestVerifyGrepFields' fixture, which has no admin issue line:
- line 0 (bundle_install): every `*_on_bundle_install_refused` case;
- line 2 (directory_install v2): the version, replay, `bundle_version` and `policy_version` escaped, number-form and missing cases;
- line 4 (login_issue): `policy_version_edited_refused`.

The forget-only and charset cases inject onto line 0 (bundle_install) of the forget fixture.

**Kinds that render policy_version,** derived from `grep -n 'policy_version' internal/audit/*.go`. There are nine, as expected:
- issue and directory_install (decodeLeaf);
- revoke (decodeRevoke), revocation_recovery (decodeRecovery) and host_forget (decodeHostForget);
- login_issue (decodeLoginIssue), host_issue (decodeHostIssue), machine_issue (decodeMachineIssue) and probe_issue (decodeProbeIssue).

bundle_install, krl_publish, refusal, refusal_summary, clock_regression and ca_init render none, so a parsed policy_version is refused on them.

**Escape bytes:**
- `grep -c '[\]u00'` reads 7 in internal/audit/verify_test.go (0 before) and 18 in internal/audit/forget_test.go (8 before).
- `grep -c 'versio[\]u006e' internal/audit/verify_test.go` reads 4, and `grep -c '[\]u0068ost_gone' internal/audit/forget_test.go` reads 1. The raw `K` and `ſ` escapes are on two lines.
- `od -c` of `escaped_version_refused` shows `"   v   e   r   s   i   o   \   u   0   0   6   e   "`. Of `forget_only_host_gone_refused` it shows `"   \   u   0   0   6   8   o   s   t   _   g   o   n   e   "`.

**Kelvin reading.** go1.27.3 reads the Kelvin-sign line as kind `host_forget`, so Go folds the Kelvin sign; `go_reader_folds_case` logs this.

**Gates:**
- Gate 1 exits 0, with every named PASS line, ten `forget_only_*_refused` PASS lines, and no FAIL or DATA RACE. The full packages under -race read audit 87.429 s and cmd 232.060 s. go vet and gofmt are clean.
- Gate 2 exits 0.
- Gate 3 exits 0:
  - no case row of the origin/main tables moved;
  - the escapes are bytes;
  - `git diff --name-only $T2...$T3` stays within Task 3's ten files and .planning;
  - T3 changes no test.

**Mutants.** Each compiles, `go vet` exits 0, and the file is restored with `git checkout` and checked with `git diff --exit-code`. Unmutated at T3, all three mutant commands pass: audit 0.046 s, cmd 1.288 s, and the export gate 0.033 s.
- M3-1, the Now check dropped (`if false && ...`): killed by TestVerifyLeafTimeBound/forward_dated_republish_refused, /past_allowance_refused and /two_ahead_leaves_names_last.
- M3-2, the allowance set to 600 s: killed by /allowance_is_prune_margin (and forward_dated, past_allowance, two_ahead).
- M3-3, the comparison without the allowance: killed by /at_allowance_ok.
- M3-4, the CLI's Now multiplied by 0: killed by TestAuditVerifyClock/clock_behind_refused.
- M3-5, recover's Now multiplied by 0: killed by TestRevokeRecover/forward_dated_saved_export_refused.
- M3-6, both checkKeyCharset calls replaced by nil: killed by the five charset cases.
- M3-7, the directory_install version branch replaced by `error(nil)`: killed by TestVerifyBoundValues/escaped_version_refused and /spaced_version_refused.
- M3-8, the four other-kind `absent(...)` calls replaced by `error(nil)`: killed by the four `escaped_*_on_*_refused` cases.
- M3-9, the policy_version branch bypassed (`case !decodes || true`): killed by policy_version_edited, policy_version_escaped, policy_version_on_bundle_install and number_form.
- M3-10..19, one forgetOnlyKeys entry deleted at a time. Each is killed by its `forget_only_<key>_refused` case and by forget_only_keys_pinned. M3-10 is also killed by identity_on_bundle_install_refused and escaped_identity_on_directory_install_refused, and M3-19 by forget_key_only_refused.
- M3-20, decodeHostForget writing `k := "identity"; m[k] = ...`: killed by TestExportKeysLowercase.

**The same ten forget-key mutants on origin/main's TestVerifyForgetKeysOnOtherKinds,** in a detached worktree of 3da914f (unmutated ok, worktree removed afterwards):
- killed for identity (identity_on_bundle_install_refused, escaped_identity_on_directory_install_refused) and admin_fingerprints (forget_key_only_refused);
- surviving for the other eight (expected_name, enrolled_at_us, host_key_fingerprints, approved_once, host_gone, removal_version, confirmed_version, confirmed_sha256). That is the gap the per-key cases close.

Cumulative: 33 of 33 mutants killed (Task 1: 5, Task 2: 8, Task 3: 20).

**Notes and deviations:**
- The tool layer decoded the backslash-u escapes when the test text was first written, as the plan warned. They were rewritten as bytes with perl, and the readings above were taken from the committed files.
- checkBoundValues also requires a parsed `import_krl_versions` on a revocation_recovery line to equal the leaf's import versions. Truth 5 asks for it ("the leaf's own where the kind has them"); the action listed only the other-kind refusal. It shares recoveryImportVersions with checkImportVersions.
  - This branch, `bundle_version` on bundle_install and `sigs` on directory_install now each have a case and a killed mutant (Q2, session 4, below). After Q1 the nested carrier that session 3 named here is refused by the new check, so the cases use other carriers.
- **Residual: closed by owner decision Q1 (2026-11-11).** checkBoundKeysBelowTop refuses `version`, `directory`, `sigs`, `bundle_version`, `import_krl_versions` and `policy_version` anywhere on a leaf line except at the top level of decoded, after unescaping (session 4, below). A nested escaped key such as `"x":{"versio\u006e":1}` on a bundle_install line no longer verifies.
- The bound runs right after the scanner's error check, before revs.finish and the checkpoint checks.
- go1.27.3's gofmt split two one-line closures in the new tests. This was applied before R3, so no existing row moved.
- Checks for breakage outside files_modified:
  - test/e2e has no forward-shifted signer clock (no clock_regression, date or time-offset use).
  - `go vet` passes under the `e2e`, `e2e_pkcs11` and `e2e_tpm` tags.
  - The only other `audit.Verify(` caller is internal/signer/log_test.go, which leaves Now at 0. `go test -count=1 -timeout 15m ./internal/signer/` gives ok 59.284 s.
  - **UNVERIFIED:** the CLI and recover clock bound in the e2e lanes, and golangci-lint/gosec on the new code. Neither has run; CI runs them.
- recover.go's doc comment (step 2) names `recovery_clock_ahead`. The three recover refusals (`recovery_installation_not_pinned`, `recovery_installation_other`, `recovery_clock_ahead`) are CLI names and unregistered by design.

## Session 4 (continuation): owner decision Q1, the value branches (Q2), then Task 4

**Test-time base, re-measured.** Session 4 is a new session, so the base was measured again before any edit, on origin/main (3da914f) in a detached worktree outside the repository. go1.27.3; load average 0.02 at the start; no other job running. Readings: cmd 259.024 s, audit 89.177 s, serverclient 3.989 s. The `test-time base:` line above was replaced in place, so there is still one. The worktree was removed afterwards.

### Q1 (Daniel, 2026-11-11: "ja, alla nivåer"): bound keys at every depth

**Precondition: Export writes none of the six names below decoded's top level.** It holds, so there is no STOP.
- decodeLeaf's nested objects:
  - `counts` (refusal_summary) is keyed by `tlog.ReasonName`. That gives the fifteen names `peer_not_allowed` … `unauthorized` (`maxReason = ReasonUnauthorized`), or `unknown(N)` out of range. None of them is one of the six.
  - `keys` (ca_init) holds `role`, `alg`, `custody` and `fingerprint`.
  - decodeRevoke's `entries` hold `entry_kind`, `serial`, `ca_fingerprint`, `valid_before`, `key_id` and `key_fingerprint`.
- Every other decoder writes only scalars, or arrays of scalars, into decoded's top-level map. This covers decodeRecovery, decodeHostForget, decodeLoginIssue, decodeHostIssue, decodeMachineIssue and decodeProbeIssue, plus decodeLeaf's inline issue, refusal, clock_regression, bundle_install, directory_install and krl_publish cases.
- The line's other top-level values are `index` (a number), `leaf` (a base64 string) and `checkpoint` (a string).
- Mechanical check on export.go:
  - The only nested-map writes are `counts[tlog.ReasonName(...)]`, `e["fingerprint"]` and the `r[...]` lines listed above, plus the `role`/`alg`/`custody` literal.
  - `grep -cE '\b(r|e|counts)\["(version|directory|sigs|bundle_version|import_krl_versions|policy_version)"\]'` reads 0.
  - All 14 writes of the six names go to decodeLeaf's top-level `m`.

**Commits:**
- **R4** d18f25f `test(audit): pin the refusal of bound export keys below decoded's top level`, signed. It is test only and adds no declaration.
- **T4** e8f367a `fix(audit): refuse bound export keys anywhere but at decoded's top level`, signed.

**RED from a worktree of R4.** `go vet` exits 0, with no `[build failed]` or `[setup failed]`. All six cases end in `--- FAIL:`, and the export verifies with no error:
- TestVerifyBoundKeysBelowTop/version_on_directory_install
- /directory_on_directory_install
- /sigs_on_directory_install
- /bundle_version_on_bundle_install
- /import_krl_versions_on_revocation_recovery
- /policy_version_on_directory_install

Each case nests the escaped name in a new object `"x":{...}` of decoded, on a kind where that name is legal or bound at the top level. The recovery case uses its own revoke fixture.

**GREEN at T4.**
- The six cases pass, and so do TestVerifyBoundValues, TestVerifyForgetKeysOnOtherKinds, TestVerifyGrepFields, TestVerifyRecoveryImportVersions and TestExportKeysLowercase.
- Without -race: internal/audit 11.030 s, internal/signer 124.471 s and cmd/keyroster 90.406 s, all ok.
- go vet and gofmt are clean.

**The check.** checkBoundKeysBelowTop walks every value of the line other than decoded, and every value of decoded, collecting keys with walkKeys after unescaping. It then refuses the first of `boundKeys` it finds, in a fixed order. A walk error refuses the line.
- It runs after the forgetOnlyKeys loop and before checkBoundValues, so no existing refusal moves.
- It runs on leaf lines only, as the owner's rule says. A checkpoint line is checked as before.
- Deviation: its message is a new refusal text, `its key "<name>" is below the top level of decoded, where export never writes it (<kind>)`. The output contract does not list it. A text of its own lets the cases and the mutant tell this check from the value checks, whose wording the byte checks share.
- checkLineKeys' doc comment names it.

**Escape bytes.**
- The escapes were written as bytes with perl (`chr(92)`), because the tool layer decodes backslash-u sequences.
- `grep -c '[\]u00' internal/audit/verify_test.go` reads 13, up from 7 at T3: the six new cases.
- `od -c` of the version case reads `"   v   e   r   s   i   o   \   u   0   0   6   e   "   :   2`.

**Mutant M4-1:** the call replaced by `error(nil)`.
- `go vet` exits 0.
- Run with `-timeout 5m`, it is killed by all six TestVerifyBoundKeysBelowTop cases.
- The file was restored. Its sha256 prefix, c60ff47ba720ba54, reads the same before and after, and `git status` showed only the intended files.

### Q2: the three untested value branches in checkBoundValues

**Reachability after Q1.** The suggested carrier, the bytes `\"bundle_version\":3,` inside a JSON string value, does not work:
- Inside a JSON string every `"` is escaped, so the byte after `bundle_version` is a backslash, and the plain `"bundle_version":` never occurs inside a string.
- A `"` followed by `:` only occurs where a key ends.

Two of the keys are required on their kind: `bundle_version` on bundle_install (checkGrepFields) and `import_krl_versions` on revocation_recovery (checkImportVersions). For them the byte check needs exactly one plain occurrence with the leaf's own value. After Q1 that occurrence can sit only in one of three places:
- (a) As the plain top-level key. A second, hidden top-level key of the same name is then a duplicate after unescaping (walkKeys).
- (b) In a nested object. Q1 refuses it before checkBoundValues runs.
- (c) As the tail of another top-level key whose unescaped text holds a quote, such as `"x\"bundle_version":1`. This is the only carrier left. checkBoundValues refuses it first, and the charset check, which runs last, would refuse that key anyway.

`sigs` is not required on directory_install. checkReplayFields returns nil when neither plain key occurs, so spaced keys reach the branch with no other check involved.

**Cases** (commit **B** c2ffcfb, `test(audit): cover the sigs, bundle_version and import_krl_versions value checks`, signed; test only, no fix commit). Each passes on b2e8dee's code and at T4: they cover existing branches. The b2e8dee run used a throwaway worktree, which was removed.
- TestVerifyBoundValues/spaced_sigs_refused, on line 2 (directory_install v2). Both keys are spaced, the directory keeps the leaf's own value and sigs gets another.
- TestVerifyBoundValues/bundle_version_value_refused, on line 0 (bundle_install). It carries `"bundle_version" :2` and the top-level key `x\"bundle_version` with 1.
- TestVerifyRecoveryImportVersions/parsed_value_refused. It carries `"import_krl_versions" :[7,20]` and the top-level key `x\"import_krl_versions` with [7,19].
- `od -c` shows the escaped quote as bytes: `"   x   \   "   b   u   n   d   l   e   _   v   e   r   s   i   o   n   "   :   1   ,`.

**Mutants.** Each disables only its branch with `false && err != nil` or `ok && false`. Each compiles, `go vet` exits 0, and each runs with `-timeout 5m`. After each one, verify.go was restored with `git checkout` and `git diff --exit-code` was clean.
- M4-2, the sigs branch: killed by spaced_sigs_refused on the verdict. Verify returns no error.
- M4-3, the bundle_version branch: killed by bundle_version_value_refused, **on the message only**. Under the mutant the line is still refused, by the charset check: `its key "x\"bundle_version" is not lowercase ASCII letters, digits and underscores (bundle_install)`.
- M4-4, the import_krl_versions branch: killed by parsed_value_refused, **on the message only**. Under the mutant the charset check refuses the line (`... (revocation_recovery)`).

**Classification:**
- `sigs` on directory_install is reachable and does real work: only it refuses spaced_sigs.
- `bundle_version` on bundle_install and `import_krl_versions` on revocation_recovery refuse first, but after Q1 the charset check would refuse the same lines anyway. They are kept as defence in depth (Truth 5), and the orchestrator chooses the final label. Their kills show that the branch runs and refuses. They do not show that it is load-bearing.

The three UNVERIFIED lines about these branches are gone.

Cumulative: 37 of 37 mutants killed (Task 1: 5, Task 2: 8, Task 3: 20, session 4: 4). M4-3 and M4-4 are killed on the message only.

## Task 4 (session 4): runbooks, registry, pointers, publish edits, gates and PR

**Precondition.** After `git fetch origin`, origin/main is still 3da914f. Task 1's pointer anchor check exits 0, and the stop guard holds:
- 03-14b's SUMMARY is on main;
- 03-12 is at wave 30 with ["03-14b"];
- 03-14b is the only plan at wave 29.

**Commits:**
- b560970 `docs(runbooks): name and bind the installation in audit verify and the CLI's pin, and the clock bound (F05, F06, F10)`.
- 376718c `docs(03-14c): publish the plan, point 03-12, 03-13, 03-15 and 03-16 at it, correct the 03-08c SUMMARY, and shift the later waves`. This commit adds this plan, unchanged.
- 81a7966 `test(cli): state the re-pin paragraph rule without a negated conjunction`. The full gate's golangci-lint (staticcheck QF1001) flagged b560970's new condition in TestRepinInstructionsKeepIdentity. The fix rewrites the condition and leaves its meaning unchanged.

**Runbook texts.** Each new text names its CI tests and carries an UNVERIFIED label. The line numbers are at 81a7966.
- **Audit verify commands.** All ten audit verify command lines gain ` --installation-id <installation id>` after `--threshold 1`:
  - signer-install.md:791, 810, 844, 846, 1107, 1109, 1616 and 1618;
  - root-ceremony.md:464;
  - enroll-user.md:354.
  - test/e2e/restore_test.go's `restoreVerify` constant changes with them. `git grep 'keyroster audit verify --pin' -- test cmd ':!cmd/keyroster/audit.go'` finds no other constant.
- **signer-install.md.**
  - :306, a new paragraph after "The check that holds": `--installation-id`, `--any-installation`, the `installation id:` and `last entry time:` lines, and the ID-less form.
  - :323, a new paragraph on the 300 s clock bound, "until this machine's clock reaches the last entry's time minus 300 s".
  - :909, at the end of restore step 2, before 2b: what `<installation id>` is, the ID-less form, and the clock-ahead hold rule.
  - :1040, at the end of 2b part 3, the first `revoke recover`: `recovery_installation_other`, `recovery_installation_not_pinned` (with the full re-pin command) and `recovery_clock_ahead`.
  - :1157, after the recovered verifies' release-check paragraph: the clock-ahead hold rule.
- **root-ceremony.md.**
  - "Record the installation id line ..." at :206 (genesis step 4), :388 (rotation step 3) and :699 (policy change step 3).
  - "trust verify prints the same installation id line ..." at :238 (genesis step 5), :441 (rotation step 5) and :720 (policy change step 4).
  - :479 (rotation step 7): what `<installation id>` is, and the ID-less form.
  - Each is its own plain paragraph, never a sectionWindow marker line or a `- **` bullet. TestRootCeremonyPolicyChecks and TestSectionWindowRefusals pass.
- **ceremony-transcript-template.md:62.** The Installation ID line, after a blank line that follows the "Bundle SHA-256 prefix" line.
- **server-install.md:517.** In section 5, after "An existing config is replaced only with `--force`.": init saves and prints the ID, the refusals, and the literal re-pin command.
- **enroll-user.md.**
  - :67, in the invite section: the admin gives the ID with the invite, and the re-pin command.
  - :366, after the audit verify command: what `<installation id>` is, and the ID-less form.
- **host-setup.md.**
  - :680, appended to the join-token paragraph: the token's ID is the one the config pins.
  - :399, a change. Old: "bind the installed directory once:". New: "bind the installed directory once.", followed by a new paragraph at :401 ("Since 03-14c, before you run keyroster directory rebind, run `keyroster init --force ...` ... Then rebind:").
  - :2298, a change in the forget-check paragraph. Old: "`admin_fingerprints`); so the parser lists exactly the verified `host_forget` entries (PR #75 review, fix round 2)." New: "`admin_fingerprints`). It also refuses any key that is not lowercase ASCII letters, digits and underscores, binds the parsed `version`, `policy_version` and the other bound fields to the entry, and refuses those bound names below the top level of `decoded` (03-14c). So a JSON parser, also one that matches keys without regard to case, reads a `host_forget` only on a verified `host_forget` line (PR #75 review; 03-14c)."
  - :2315, the Run in CI line gains "(its charset cases included), `TestVerifyBoundValues` and `TestVerifyBoundKeysBelowTop`".
- **revoke.md:529-530.** Two refusal-table rows for the CLI's own refusals. The first quotes the mismatch text's tail, "it is another installation's bundle under your roots". The second is ErrInstallationNotPinned, with the full re-pin command.
- **machine-identities.md.**
  - :77, a new paragraph in `## Renew a machine certificate`, with the no-`--user` re-pin form.
  - Deviation: the init paragraph ended "... are needed. Then:". It now ends "... are needed.", and the command block is introduced by "Then renew:" at :89. This keeps the new paragraph right after the init paragraph without splitting "Then:" from its block. `## Renewal needs pop.machines` is untouched.
- **TestRepinInstructionsKeepIdentity** now checks signer-install.md, host-setup.md, revoke.md and enroll-user.md too, each with a per-file count of at least one, and the floor of two stays. A paragraph counts when it holds `--force` and either `keyroster init`, or `init` with `--root-pin` (the old rule). No existing paragraph tripped the rule. machine-identities.md stays off the list.

**Registry.** docs/format-registry.md is on origin/main. The 03-14c sentence is its own paragraph after the HostIssue/ProbeIssue/MachineIssue paragraph, and the numstat reads `2 0`. TestFormatRegistry passes. Recover's three refusal names are CLI names and unregistered by design.

**Pointers and publish edits** (Q-C6 A):
- The numstat reads 03-12 `4 4`, 03-13 `2 2`, 03-14 `1 1`, 03-15 `4 4`, 03-16 `2 2` and 03-08c SUMMARY `1 1`. Verify command 6 exits 0.
- 03-12 to 03-16 move to waves 31 to 35, and 03-12 depends on ["03-14c"], with the precondition clause.
- ROADMAP: `30/36 plans executed in 35 waves`, the Wave 30 block with the unchecked 03-14c row, the later blocks renumbered, and the Progress row `30/36`.
- STATE: `total_plans: 71`, `completed_plans: 65` and `Plan: 30 of 36`.
- **Deviation (pre-push hook):** the local pre-push scan refused the push. 03-15's line `2. After Claude reports the install ...`, which carries the third 03-15 anchor and so must change, names the owner's lab Windows host as written on main. In that line only, "in PowerShell on <host>" became "in PowerShell on the owner's Windows PC". The anchor and the numstat are unchanged. The two unpushed commits were remade (reset --soft, recommitted, signed) before the first push of them. The other occurrences of that host name in 03-15, which are on main and not touched here, stay.

**Local readings:**
- The runbook tests pass: TestRootCeremonyPolicyChecks, TestSectionWindowRefusals, TestRepinInstructionsKeepIdentity, TestHostTrustRunbooks, TestProbeAccountRunbook and TestCeremonyGolden, and TestProbeHoldReasonsDocumented in internal/agent/apply.
- TestRestoreRunbookChecks (`-tags e2e`, a document check) passes locally too.
- Verify commands 1, 4 (static part), 5 and 6, and the authorship and signature check, exit 0. The privacy, IP and title gate (command 9) exits 0 on the diff, the log and PR #99's title and body.

**Delta gate** (base above, at 81a7966's tree; load average 0.19 at the start): cmd/keyroster 244.954 s (base 259.024), internal/audit 93.261 s (base 89.177, +4.1) and internal/serverclient 4.185 s (base 3.989). It exits 0.

**Full gate:**
- The first run exits 1 on the two staticcheck QF1001 lines fixed in 81a7966. Every `go test` package was ok.
- The second run, at 81a7966, exits 0: `go test -race ./...` (36 ok; cmd/keyroster 274.543 s, internal/audit 114.879 s, internal/serverclient 6.252 s, internal/signer 491.720 s, internal/agent/apply 694.227 s), every vet tag (e2e_pkcs11 and e2e_tpm included), gofmt, golangci-lint (0 issues), capslock, dep-firewall, testonly-firewall and check-pinned-actions.
- capslock reports no new pair. keyroster-signer reads 91 against a baseline of 92 (`internal/signer CAPABILITY_RUNTIME` no longer reported). That stale pair predates this plan.

**PR #99**, https://github.com/Labontese/keyroster/pull/99, was opened by keyroster-bot with the plan's title and no auto-merge.

**Not done in this session:**
- The tracking update and the gates that run after it, the publish gate (command 7) and the ROADMAP gate (command 8). Before the update they fail by design: `completed_plans` reads 65 and the 03-14c row is unchecked.
- The final `docs(03-14c): complete installation-binding plan` commit and the pre-merge review (Task 4 step 5). Both are the orchestrator's.

