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
- The continuation starts at **Task 2**. It reads the plan's shared sections (from the frontmatter to `</context>`) and Tasks 2 to 5.
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

## Still to do (continuation)

- Task 2 (F06): R2, T2, eight mutants, the goldens and the TrustUnpinned grep.
- Task 3 (F10 and the export-line rules): R3, T3, twenty mutants, and the escape-byte readings (`od -c`, `grep -c '[\]u00'`).
- Task 4: the runbooks, registry, pointers, publish edits, gates, push and PR. Re-measure the base first.
- Task 5: a checkpoint, after Daniel merges.
