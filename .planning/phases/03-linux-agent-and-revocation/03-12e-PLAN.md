---
phase: 03-linux-agent-and-revocation
plan: 12e
type: execute
wave: 36
depends_on: ["03-12d"]
files_modified:
  - internal/trust/castate.go
  - internal/trust/rotation_test.go
  - internal/trust/fuzz_test.go
  - internal/krl/drain.go
  - internal/krl/drain_test.go
  - internal/signer/trust.go
  - internal/signer/logstate.go
  - internal/signer/signer.go
  - internal/signer/recovery.go
  - internal/signer/drain_test.go
  - internal/signer/trust_test.go
  - internal/signer/restore_test.go
  - internal/signer/recovery_test.go
  - internal/keystore/keystore.go
  - internal/keystore/software/software.go
  - internal/keystore/software/software_test.go
  - internal/keystore/agent/agent.go
  - internal/keystore/agent/agent_test.go
  - internal/doctor/doctor.go
  - internal/doctor/doctor_test.go
  - cmd/keyroster-signer/rotate.go
  - cmd/keyroster-signer/rotate_test.go
  - cmd/keyroster-signer/install.go
  - cmd/keyroster-signer/recover.go
  - cmd/keyroster-signer/doctor.go
  - cmd/keyroster-signer/doctor_test.go
  - internal/audit/verify.go
  - internal/audit/verify_test.go
  - internal/rootceremony/cachanges.go
  - internal/rootceremony/cachanges_test.go
  - cmd/keyroster/root.go
  - cmd/keyroster/root_test.go
  - cmd/keyroster/ceremony_golden_test.go
  - cmd/keyroster/runbook_test.go
  - cmd/keyroster/testdata/ceremony/
  - test/e2e/ca_rotation_test.go
  - .github/workflows/e2e.yml
  - docs/runbooks/ca-rotation.md
  - docs/runbooks/signer-install.md
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/ceremony-transcript-template.md
  - .planning/phases/03-linux-agent-and-revocation/03-12e-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [KEY-08]

estimate:
  tokens: 290000
  raw_tokens: 290000
  tasks: 4
  confidence: low

must_haves:
  truths:
    - "Early plan: scope, owner decisions and tests are fixed here; the tasks are planned out in full, and every path and line anchor reconciled against main, after 03-12d merges. Until then this file is a specification, not an executable plan"
    - "Ceremony 2 of D-14: `keyroster root sign --prev DIR --ca-switch ROLE [--drain-allowance 24h]` makes the `next` CA active and the old active CA `draining` with a `trusted_until`, in one successor. From its install, after the old key is removed and the signer restarted, the signer issues with the new generation; every agent keeps trusting the draining CA until trusted_until on its own clock and then drops it"
    - "The drain end is bound to the certificates the verified log records: no certificate of the newly draining key that the log records (issue, login_issue, host_issue, machine_issue and probe_issue leaves, and certificates carried by revocation_recovery leaves, kept or revoked) is still live by krl.EntryLive at trusted_until. The install computes this from the leaves, never from the issuance table; audit re-derives it; a refusal names the certificate that sets the largest ValidBefore and the earliest acceptable trusted_until"
    - "The old key is fenced: after a successful switch install, `ca-rotate retire-key` removes the draining generation from the backend (software) or prints the operator's command and re-checks (agent), and serve and doctor refuse `draining_key_still_usable` while it is held. A restore marker's recovery opens no CA private key, so a database restored from before the switch stays recoverable"
    - "The guarantee is scoped: it covers certificates the verified log records, checked by a running agent that applied the switch, and no certificate of the draining key leaves a conforming signer after the switch install and retire-key; the residuals (certificates signed outside the signer, certificates issued after the newest saved export, a later recovery that carries a long-lived certificate, consumers that do not re-evaluate, KRL entries without a known ValidBefore) are stated in ca-rotation.md and the register"
  artifacts:
    - path: "internal/krl/drain.go"
      provides: "the drain accumulator shared by the signer and audit"
    - path: "cmd/keyroster-signer/rotate.go"
      provides: "ca-rotate retire-key"
    - path: "test/e2e/ca_rotation_test.go"
      provides: "TestCARotationNoFailedLogin"
  key_links:
    - from: "internal/signer/trust.go"
      to: "internal/krl/drain.go"
      via: "InstallBundle reads the maximum ValidBefore per CA key from the verified log walk"
      pattern: "drain_window_too_short"
---

<objective>
Ceremony 2 of D-14 (KEY-08): the switch, with every fence it needs, proved by a login loop that never fails.

Purpose: 03-12 to 03-12d put generations, the chain rule for add-next and abort, and every reader in place. This plan turns on the one path they all handle: the successor that makes `next` active and the old key `draining`, an install that refuses a drain end that would cut off a certificate the log records, removal of the old key, a recovery that still works after that removal, and the end-to-end test.

Output: the switch transition and `--ca-switch`; the drain accumulator and the install binding, upper bound and `--previous`; `ca-rotate retire-key` and the serve refusal; recovery without CA keys; audit's re-derivation; doctor's pre-switch display; the rotation e2e and the host-CA test; the ca-rotation runbook's remaining sections.
</objective>

## Before execution (read this first)

This is an early plan, written with 03-12 and its siblings against kr-main at d15f044 and published in 03-12's PR. It is planned out in full by `/gsd-plan-phase`, and reconciled against main, after 03-12d merges: every path, line anchor, count, test name and threat ID is re-read there. The scope, owner decisions and the test and mutant lists below are fixed; the tasks, commands and RED routes are not. Do not execute this file as it stands.

At the reconcile, check in particular:
- the anchors of InstallBundle's leaf walk (internal/signer/trust.go, newLogWriter then rebuildLogFrom, which decodes the issue kinds), CheckTrust's own walk, audit's install and its active-CA map (internal/audit/verify.go), recovery.go's carried-certificate checks (:174-203 and :330-344) and the status of the KRL accumulator's package choice (internal/krl importing tlog has no cycle at d15f044; a new leaf package is the alternative, and the capslock pairs decide);
- that 03-12b's castate.go is where the switch rule is added (an earlier file list said verify.go);
- **the size, and the cut already applied.** At d15f044 this plan counted 51 files, and by the same bottom-up projection that sizes 03-12 (about 6k tokens per file, not the first count's 5.4k) that is about 306k, above the line of about 52 files or 280k. **The named fallback cut is therefore already applied: TestHostCARotation, its test file test/e2e/hostca_rotation_test.go and its enroll-user.md text are 03-12f's**, which lands after the switch anyway. The plan is now 49 files and about 290k, still at or above the line; nothing else may be cut on the planner's own authority, so the recount at the reconcile decides whether the owner is asked to split it further;
- the e2e lane's headroom for TestCARotationNoFailedLogin (about 9 to 11 minutes plus the export and removal steps, UNVERIFIED until run).

## Scope

**In.**
- **The switch transition** in the chain rule (castate.go): per role, the `next` entry becomes `active` and the previous `active` entry becomes `draining`, in one successor. Its trusted_until is at least `next.IssuedAt + max(MaxTTL of the role in the previous policy, in the next policy) + DrainMargin`, and at least next.IssuedAt. Earlier draining entries stay byte-identical, and there is no precondition on them (a role may have any number of draining entries). draining to retired and draining to active are refused, and a changed trusted_until is refused (immutable). Arithmetic is in integer seconds, parsed only here and in Validate, and every sum is checked against overflow and refused, never wrapped. DrainMargin is defined as krl.PruneMargin (300 s), and a test asserts it. checkBundleKeys now accepts any stored generation as the active entry (only the switch changes it) and leaves draining entries unconstrained by storage (a drained key may be removed or on lost hardware).
- **The ceremony tool:** `--ca-switch ROLE` and `--drain-allowance` (default 24 h, refused above `MaxDrainAllowance`, 7 days, a constant in internal/trust, because the signer never sees the ceremony's allowance); the CA-change line for a switch reads `CA <role> gen <N> <fingerprint>: <old state> -> <new state>, trusted until <t>; install by <t'> (advice)`; "install by" is advice and never a refusal; two switch goldens; an entry in successorSigningSections for the switch section.
- **The drain accumulator** (internal/krl/drain.go, or a leaf package both internal/signer and internal/audit import; neither imports the other): fed by InstallBundle's rebuildLogFrom pass, by CheckTrust (doctor) and by audit.Verify; its input is every certificate of the issue, login_issue, host_issue, machine_issue and probe_issue leaves (both probe polarities) and every certificate a revocation_recovery leaf carries, kept or revoked; it is keyed by the certificate's SignatureKey wire bytes and keeps, per key, the largest ValidBefore and the leaf index, serial and key ID that set it, in constant memory per CA key. It is never fed from the issuance table (a changed cert blob or ca_role in a row must not lower the maximum). A certificate that does not parse is a refusal, never skipped, and a cancelled scan never commits. Recovery's own issuance-only lookup stays a separate accumulator. BenchmarkInstallBundleDrainScan runs 1e5, 1e6 and 5e6 issue leaves with a host, probe and login mix, recording wall time and peak memory (memory must not grow with the leaf count beyond the existing hash list); the measured time goes in ca-rotation.md and is UNVERIFIED until run.
- **The install binding** `drain_window_too_short`: for each switched role the install refuses when `krl.EntryLive(maxVB, trusted_until)`, that is when trusted_until is below maxVB plus DrainMargin (equality is accepted, and saturation near 2^64 is a refusal). The refusal names the serial, key ID and ValidBefore of the certificate that sets maxVB and the earliest acceptable trusted_until. **The upper bound** `drain_window_too_long`: refuse trusted_until above `max(signer-now + max(MaxTTL_prev, MaxTTL_next), maxVB) + DrainMargin + MaxDrainAllowance + krl.PruneMargin`; the bound never falls below the binding or the floor (a table test, including a row with maxVB above signer-now plus the cap). A refused install writes nothing: no bundle row, no leaf, and Status still reports the old bundle. A refused switch bundle is burned material: it never leaves the signer host and is deleted before the ceremony is repeated, in a fresh output directory (root.go:720 re-signs a stored issued_at), because hosts accept any root-signed successor and refuse a re-made bundle of the same version until root clears it.
- **`--previous FILE`:** a switch install needs it; FILE is an off-box export or checkpoint and the log must extend it (a consistency check against the log key), otherwise `install_previous_not_extended`. After any restore and recovery the restored log is a fork of every export taken after the restore point, so the runbook requires a fresh export after the recovery and defines the newest export as the newest one the current log extends.
- **Key removal:** `keyroster-signer ca-rotate retire-key --state-dir D --role R` takes lockStateDir (so it is refused under the restore marker), then (1) opens the role's active generation and signs a test message, refusing `active_key_unusable` and removing nothing; (2) for each draining generation of the role the backend still holds: software deletes the generation's files and fsyncs the directory, agent and pkcs11 through the agent print the operator's command (`ssh-add -d` with the operator's public key file) and re-check; (3) exits 0 only when no draining generation is held. It writes no log leaf and refuses when the role has no draining entry. `keystore.Holds(role, generation, fingerprint, location)` (location is the generation row's, as in 03-12's KeyAt; software: lstat of the generation's file, any entry counts; agent: the agent lists the fingerprint) serves it, the start-up refusal and doctor. TPM and PIV removal are 03-12f's.
- **The start-up refusal** `draining_key_still_usable`: signer.New in its serving configuration refuses while the backend holds any draining key of the installed bundle, in any role; doctor reports the same check as failing; install-bundle and recover-revocations are not affected. "Held" is stricter than "usable": a damaged file still counts, which is fail-closed and avoids one scrypt run per drained generation at every start. Also, loadTrust opens `ActiveCA` by generation, so the signer issues with the bundle's active generation, not generation 1.
- **Recovery opens no CA private key:** signer.New gains a recovery configuration, used only by recover-revocations: it runs checkStoredTrust and the log checks, opens the log key and the ops key, checks CA entries by public key, and reaches no issuance path. The runbook path after a restore older than the last switch install: hold the units and write the marker; `keyroster revoke recover`; recover-revocations (clears the marker); a fresh export; `install-bundle --previous <that export>` for every bundle the restored database lacks, from the ceremony media; retire-key; serve. A lost switch bundle and a lost generation are 03-13's. A recovery that carries a certificate of a draining key with ValidBefore above trusted_until minus DrainMargin names it in its output (serial, key ID, kept or revoked) and never repairs it silently.
- **Audit:** the shared accumulator and the binding, the upper bound, and `issued_at <= install leaf time + PruneMargin` (the `install` function gains the leaf time); these checks are detective only, because leaf times are clamped forward. The issued_at check applies to every bundle_install whose bundle carries a CA entry that is not `active`; no log written before 03-12 holds such a bundle, so it is never retroactive. Certificates before and after a switch are checked against the CA active at their leaf (the active map stays). The switch transition lives only in the shared chain rule (castate.go, which VerifySuccessor runs) and never in a signer-only check: 03-12's audit rule (every `next` entry logged, and, once a ca_init precedes, every active CA entry logged) together with 03-12b's chain rule is what keeps a switch from activating a key that no leaf names, and `switch_activating_unlogged_key_refused` pins that the switch stays in the shared chain rule.
- **doctor:** per role, the certificate that sets maxVB for the active key (serial, key ID, ValidBefore) and the earliest trusted_until a switch could carry now (maxVB plus DrainMargin), so the owner sees a long admin host certificate before ceremony 2; and the draining-key-held fail. This needs internal/doctor/doctor.go and its tests, which an earlier file list omitted.
- **Tests that run end to end:** TestCARotationNoFailedLogin (user CA, agent backend, `LoginGraceTime 3`, the probe helper off, user TTL 60 s, `ca issue --installation-id`): a login runs every second through (1) prepare, ceremony 1, install; (2) convergence by the live count and a read of the agent's live file; (3) an export, the switch install with `--previous`, retire-key (`ssh-add -d` for the agent backend), the restart; (4) certificates now by the new key, a revoked old-key serial and a revoked new-key serial both refused, the KRL carrying the old key's section while it drains; (5) the drain, the timer-driven drop and the host-side proof (`keyroster-agent check`); (6) `audit verify --installation-id`. It ends with `login failures: 0`. The host-CA end-to-end test (TestHostCARotation) moved to 03-12f with the fallback cut; until it lands, ca-rotation.md labels the host-CA gate UNVERIFIED. The host drain itself is unit-tested only. The machine CA has unit and audit tests only; its e2e is UNVERIFIED and labelled.
- **The runbook:** ca-rotation.md gets the pre-switch check (doctor's display), ceremony 2, the install with `--previous`, retire-key, the restart, the drain, the host-side proof, the host-CA gate (ceremony 2 for the host role waits for clients to refresh), the burned-bundle rule, the upgrade gate and the guarantee with its residuals; signer-install.md the restore path and the backup-and-export rule; root-ceremony.md and the transcript template the switch confirmation. The enroll-user.md host-CA text is 03-12f's.
- **The host-side proof after trusted_until:** either `keyroster-agent check` on each host shows no `trust_expired`, no `bundle_behind` and a user_ca_keys without the old key, or each heartbeat's user_ca_keys hash equals the SHA-256 of `UserCAKeysFile(B, now)`, where B is the switch bundle as the verified audit export carries it, not the server's copy. This is detection, not enforcement.

**Out.** TPM and PIV generations and removal (03-12f), log and ops key rotation, the emergency move and the scoped exception for a lost bundle (03-13), a cap on admin host issuance, rollback-resistant activation, and moving a CA into another custody.

## Owner decisions that bind this plan (Daniel, 2026-11-13 and 2026-11-14)

- Binding on verified leaves, carried certificates included, stated as `!krl.EntryLive`, DrainMargin = krl.PruneMargin; the ceremony floor is a sanity bound, not the guarantee; the residuals above are confirmed.
- The draining key is removed right after a successful switch install; serve and doctor refuse while it is held. recover-revocations opens no CA private key.
- A switch install needs `--previous`; refused switch bundles are destroyed; the install refusal names the certificate and the earliest acceptable trusted_until; no export at the ceremony; admin host issuance stays uncapped and the certificate that sets maxVB is displayed before ceremony 2.
- The install refuses a trusted_until above an upper bound that never falls below the binding (MaxDrainAllowance 7 days); audit re-derives both checks.
- No routine retire (draining is terminal); entries are never removed.
- A runbook gate for host-CA rotation (in ca-rotation.md here); TestHostCARotation, which documents the failure of a client that never refreshed, and its enroll-user.md text are 03-12f's after the fallback cut.
- Hardware is optional; every test uses software keys or an in-process agent.

## Tests (fixed here)

- **trust:** TestCATransitions additions `switch_ok`, `switch_without_next_refused`, `switch_trusted_until_one_second_short_refused`, `switch_uses_larger_of_prev_and_next_ttl`, `switch_trusted_until_before_issued_at_refused`, `switch_sum_overflow_refused`, `second_switch_while_draining_ok`, `draining_trusted_until_immutable`, `draining_to_retired_refused`, `draining_to_active_refused`; TestDrainMarginIsPruneMargin; FuzzCATransitions extended to the switch.
- **signer:** TestCheckBundleKeysGenerations: `active_later_generation_ok` replaces 03-12's `active_not_generation_1_refused` (an active entry may now carry any stored generation, here the switch's) and `draining_unconstrained_by_storage` is new (a draining entry whose key the backend no longer holds installs), while `generation_field_mismatch_refused`, M111's one killer, stays; TestDrainBinding (`install_within_window_ok`, `no_certificates_ok`, `install_delayed_refused` with maxVB from a certificate issued after the ceremony's issued_at, `policy_lowered_ttl_refused`: a host cap of 30 d lowered to 1 d, the switch two bundles later at issued_at plus 1 d plus 300 s is refused and passes at the certificate's ValidBefore plus 300, the same for a probe certificate under a machine cap below and above 604800 s, `admin_host_cert_sets_maxvb`, `refusal_names_certificate`); TestDrainBindingCountsCarriedCertificates (one fixture, run against both the signer and audit.Verify: a revocation_recovery leaf carries a kept host certificate with ValidBefore V and no issue leaf, trusted_until = V + 299 is refused by both and V + 300 passes both, and the same with a revoked carried certificate); TestDrainBindingSignerAuditAgree (one generated corpus of all five issue kinds, both probe polarities, refusal and clock_regression leaves, a recovery that carries certificates and two rotations of one role, run against switch bundles around the boundary, with `row_tamper`: one issuance row's cert blob is replaced with a certificate of smaller ValidBefore and its ca_role changed, and InstallBundle still refuses); TestDrainBoundary (one table shared by the signer and audit: V + 299 refused, V + 300 accepted, `krl.EntryLive(V, trusted_until)` false exactly when the binding accepts, a certificate with ValidBefore V fails ssh.CertChecker at clock V and passes at V minus 1 so the sshd boundary is pinned, and a ValidBefore near 2^64 is refused, not wrapped); TestDrainBindingIsClockFree (issue under the old key with the signer clock +3 d and -3 d: at host-now = trusted_until no old-key certificate verifies and one second earlier the CA is still rendered); TestInstallUpperBound (`drain_window_too_long_refused`, `upper_bound_never_below_binding`, `upper_bound_at_limit_ok`); TestInstallPrevious (`switch_without_previous_refused`, `previous_not_extended_refused`, `previous_ok`); TestRefusedSwitchWritesNothing; TestRetireKey (`active_unusable_refused_nothing_removed`, `software_removes_draining_files_only`, `agent_prints_command_and_rechecks`, `no_draining_entry_refused`, `refused_under_restore_marker`); TestServeRefusesWhileBackendHoldsDrainingKey (software and agent); TestRestoredPreSwitchSignerCannotIssue (copy the database, install the switch, retire-key, restore the copy: start is refused; then under the marker recover-revocations without CA keys, a fresh export, install-bundle of the switch with `--previous`, and serve issues with the new key); TestRecoveryOpensNoCAKey; TestRecoveryNamesCertificateBeyondDrain; TestUnloggedSignatureNotCovered (a negative documentation test: a certificate signed directly through the agent with the old key and ValidBefore = trusted_until + 1 d is in no row and no leaf, and both InstallBundle and audit.Verify pass); TestRotationKRLKeepsLiveEntry; TestSignerRestartMixedBundle extended (new key active, old key draining, issue with the new key; a bundle whose active generation the backend does not hold refuses at start); BenchmarkInstallBundleDrainScan; FuzzDrainAccumulator (random issue-kind and recovery leaf sequences: the accumulator equals a naive maximum per SignatureKey and a malformed certificate is always a refusal).
- **audit:** `switch_activating_unlogged_key_refused` (a log with a ca_init and a bundle whose active entry is the current key, then a bundle whose active entry is a key that was never `next`, so the add-next step is skipped: refused, and the test asserts the ErrVersionChain text, so the refusal must come from the chain rule that VerifySuccessor runs and not from a signer-only check or from 03-12's `next` rule, which an earlier add-next would trip first; the control `switch_activating_logged_key_ok` is a legitimate add-next followed by the switch, which verifies), `drain_binding_violated_refused`, `carried_certificate_counts`, `upper_bound_violated_refused`, `issued_at_after_install_leaf_refused`, `issued_at_rule_not_retroactive` (an old log whose bundles hold only active entries and a fast ceremony clock still passes), `issue_after_switch_by_draining_refused`; FuzzVerifyExport seeded with a switch and a recovery that carries a certificate.
- **CLI:** the switch goldens; `drain_allowance_above_cap_refused`.
- **e2e:** TestCARotationNoFailedLogin in the `e2e-rotation` lane (the `-run` list in e2e.yml gains it); TestHostCARotation is 03-12f's.
- Record the signer package's quiet base (467 to 509 s at d15f044) for the delta gate; every e2e `ca issue` site, test/systemd/smoke.sh included, passes `--installation-id`.

## Mutants (M155 to M174)

- M155 the switch floor uses next's MaxTTL only (`switch_uses_larger_of_prev_and_next_ttl`); M156 DrainMargin is not krl.PruneMargin (TestDrainMarginIsPruneMargin, `switch_trusted_until_one_second_short_refused`); M157 a successor that changes a draining entry's trusted_until is accepted (`draining_trusted_until_immutable`); M158 "one draining per role" is kept (`second_switch_while_draining_ok`); M159 draining to retired is accepted (`draining_to_retired_refused`).
- M160 the drain binding is skipped (`install_delayed_refused`); M161 the binding is computed from issued_at instead of maxVB (`policy_lowered_ttl_refused`); M162 the binding reads issuance rows instead of leaves (TestDrainBindingSignerAuditAgree `row_tamper`); M163 carried certificates are skipped (TestDrainBindingCountsCarriedCertificates); M164 the binding refuses equality, `<=` instead of !EntryLive (TestDrainBoundary, V + 300 accepted); M165 audit's drain binding is skipped (`drain_binding_violated_refused`); M166 the upper bound is skipped (`drain_window_too_long_refused`); M167 the upper bound can fall below the binding (`upper_bound_never_below_binding`).
- M168 `--previous` is not checked (`previous_not_extended_refused`); M169 the draining-key presence check is skipped (TestServeRefusesWhileBackendHoldsDrainingKey); M170 retire-key removes before it proves the active key (`active_unusable_refused_nothing_removed`); M171 the recovery configuration opens CA private keys (TestRecoveryOpensNoCAKey); M172 loadTrust opens generation 1 instead of the active entry (TestSignerRestartMixedBundle issues with the new key); M173 audit's issued_at rule also applies to bundles with only active entries (`issued_at_rule_not_retroactive`); M174 audit ignores the install leaf time (`issued_at_after_install_leaf_refused`).
- List any equivalent mutant with its reason, as 03-10d did.

## Inherited duties (from 03-14b, 03-14c, 03-14d), which this plan carries

- Summary and the CA-change lines render the switch; each ca-rotation.md ceremony section gets the 03-14b checklist and an entry in successorSigningSections; goldens change by additions only; the ceremony tests' file lists widen.
- Every audit verify in the e2e and the runbook passes `--installation-id` or `--any-installation`; the five 03-14c audit tests stay green; any new audit.Options literal in cmd/ sets Now.
- The e2e goroutine's `ca issue` passes `--installation-id` set to the bundle's ID, and every `ca issue` site (smoke.sh included) is grepped and recorded.
- Shared helpers stay portable; a linux-only helper carries a build tag (Windows lint). Mutants continue from M155; threat IDs are the set's; the Q-09-3 test-time form; the private-term and label scan; the stop guard and ROADMAP gate. The 03-16 pointer (convergence, `--previous`, retire-key and the host-side proof) was made in 03-12's PR.

## Why it ships safely alone

It turns on a path every reader already handles, and it lands together with all of its fences: the binding (leaves, carried certificates), the upper bound, `--previous`, key removal with the serve refusal, and recovery without CA keys. The e2e proves zero failed logins for logged certificates.

## Size

49 files by the set's counting convention after the fallback cut: 36 code and test (the two internal/doctor files are the two that the first count of 49 omitted; the cut removed hostca_rotation_test.go), 2 goldens, 4 docs (the cut removed enroll-user.md), 7 planning (its own plan file, ROADMAP, STATE and 03-13 to 03-16; this plan expects to change 3 of them). About 290k estimated tokens raw (low confidence); the calibration has run 2x to 5x. See "Before execution" for the cut.

## Open owner questions

None open.

<tasks>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 1: Plan 03-12e out in full and reconcile it against main. Do not execute this file</name>
  <read_first>
    - The "Before execution" section above, and 03-12d-SUMMARY.md (the predecessor's SUMMARY, on main once it has merged)
  </read_first>
  <action>This is an early plan: a specification published in 03-12's PR so that the wave shift happens once. It carries no executable tasks. After 03-12d has merged, run the planner for it (`/gsd-plan-phase` on this plan's phase and number), which re-reads every path, line anchor, file count, test name and threat ID against main, writes the tasks with their verify commands and RED routes, and replaces this file. Do not run `/gsd-execute-phase` on this file as it stands.</action>
  <instructions>
    1. Confirm that 03-12d's SUMMARY is on origin/main.
    2. Plan this plan out in full, reconciled against main, and have it checked.
    3. Reply "planned" when the executable plan has replaced this file.
  </instructions>
  <verify>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-12d-SUMMARY.md</automated>
    <fails_when>non-zero exit: the predecessor has not merged, so this plan must not be planned out or executed yet</fails_when>
  </verify>
  <acceptance_criteria>
    - The executable plan has replaced this file, its tasks name every verify command, and its reconcile ledger records what differed from this specification at its base commit.
  </acceptance_criteria>
  <done>03-12e is planned out in full against main.</done>
  <resume-signal>Type "planned" after the executable plan has replaced this file</resume-signal>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| the old key → the signer's backend | after the switch install the old key must not remain usable |
| the audit log → the binding | the drain end is computed from leaves a verifier can re-derive |
| a restored database → the signer | recovery must work without the removed key |

## STRIDE Threat Register

Each ID below is defined only in this plan; the other IDs of the set are defined in the plan named in 03-12's register.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-77 | Denial of service | the old CA dropped while certificates it signed are still valid | high | mitigate | the binding over verified leaves, recovery-carried certificates included, stated as !EntryLive; DrainMargin = krl.PruneMargin; one TrustedAt rule; the signer and audit agree on one corpus; boundary tests. Residuals: certificates the log does not record, certificates issued after the newest saved export, a later recovery that carries a long-lived certificate |
| T-03-247 | Tampering | a rotation dropping a live revocation of an old-generation certificate | high | mitigate | the KRL is built from every row (nothing here filters by the bundle's CA set); TestRotationKRLKeepsLiveEntry; the e2e post-switch KRL |
| T-03-413 | Denial of service | a late install, a lowered TTL or a long admin host certificate cuts off valid old-key certificates | high | mitigate | the install binding is data-based and names the certificate that sets maxVB; doctor shows it before ceremony 2; "install by" is advice only; audit re-derives it |
| T-03-424 | Elevation of privilege | the old CA key is still usable after the switch: a restored pre-switch database, the agent socket, a hand copy | high | mitigate | `ca-rotate retire-key` after a successful install; serve and doctor refuse `draining_key_still_usable` (presence, fail-closed); retire-key first proves the active key. TPM and PIV removal in 03-12f. Residual: copies of the state directory and VM snapshots, clones elsewhere; rollback-resistant activation is later and optional hardware |
| T-03-427 | Elevation of privilege | a switch bundle the signer refused reaches hosts | medium | mitigate | refused bundles are burned and never leave the signer host; a repeat uses a fresh output directory; a refused install writes nothing. Residual: hosts accept any root-signed successor |
| T-03-428 | Elevation of privilege | certificates signed by the old key outside the signer (agent socket, stolen key) outlive trusted_until on hosts without the switch | high | accept (residual) | the guarantee is scoped to logged certificates; key removal shortens the window; stated in ca-rotation.md; audit cannot see them (TestUnloggedSignatureNotCovered documents it) |
| T-03-431 | Denial of service | a restore older than the last switch cannot be recovered once the old key is removed | medium | mitigate | recover-revocations opens no CA private key; the runbook path re-installs the switch from the ceremony media with `--previous` |
| T-03-432 | Tampering | a certificate of the draining key missing from the binding (a tampered issuance row, a recovery-carried certificate) | high | mitigate | the binding reads verified leaves, never rows; carried certificates count; the signer and audit agreement corpus with a row-tamper case |
| T-03-SC | Tampering | dependencies | low | mitigate | no module added; capslock is checked for the accumulator's package |

(T-03-426, defined in 03-12, has its upper-bound half here: `drain_window_too_long`, `upper_bound_never_below_binding` (TestInstallUpperBound), and the mutants M166 and M167.)
</threat_model>

<success_criteria>
- A switch installed within its window leaves every logged old-key certificate valid until it expires, and no login fails across prepare, ceremony 1, the switch and the drop.
- An install whose trusted_until would cut off a logged certificate is refused with the certificate named, and writes nothing.
- After retire-key the old key cannot sign on the signer host, serve refuses while it is held, and a restore older than the switch is recoverable.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-12e-SUMMARY.md` when the plan has been planned out and executed. Leave `requirements-completed` empty: KEY-08 completes in 03-13.
</output>
