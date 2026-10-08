# Deferred Items (phase 01)

Out-of-scope discoveries logged by plan executors. Each item names the plan that found it.

## Deferred Items

- **01-09: `TestSignerRefusals/created_301s_future` is timing-flaky under CPU load.** `internal/signer/signer_test.go` captures `now` once at the start of `TestSignerRefusals` and tests the ±300 s skew bound with `now ± 301`. When more than about one second passes before that subtest runs, `now + 301` falls inside the window and the request is accepted. It failed once in CI `build-test` on PR #9 (run 37307671187, first attempt) while the new scrypt-heavy root tests ran in parallel packages under `-race`, and passed on rerun. Fix: give the test signer a fixed clock (or compute `now` inside each edit function and use a wider margin). It was not fixed in 01-09 because `internal/signer/*` belongs to 01-07 (PR #8, open at the time).
  - **Resolved in quick task 261006-ixz (PR #16).**
    - **Corrected cause.** `CreatedAt` holds whole seconds and the signer clock does not. So `now + 301` is accepted as soon as the capture and the signer's read fall in different wall-clock seconds. A few milliseconds of delay across a second boundary is enough; it does not take about one second.
    - **CI failures.** It failed in run 37307671187 (PR #9) and run 37425878563 (PR #15).
    - **Fix.** `TestSignerRefusals` now runs on a stepping test clock (`fakeClock.Tick`: 1 µs per read from a whole-second base, with a self-check that the clock advanced less than 1 s).
    - **Same race in `TestEvidence/created_at_outside_skew_*`.** That sibling now runs on a `logEnv` signer pinned to a whole second.
    - **Production unchanged.** The 300 s window and its strict comparison stay as they were, and no non-test file changed.
- **01-08: `addLogKey` in `test/e2e/harness_test.go` is unused.** Its only caller was the `--log-key` case of `TestAuditVerifiesIssuance`, which now pins another root instead. 01-08 may not edit `harness_test.go` (01-07 owns it; 01-10 and 01-11 reuse it unchanged), and lint does not build the `e2e` tag, so nothing fails. Remove it in the next plan that is allowed to edit the harness. **Still open after 01-15:** 01-15 does not edit the harness.
- **01-08: `TestSignerRefusals/created_301s_future` is still not fixed.** 01-08 edited `internal/signer/log_test.go` only to migrate it to `audit.Options{Pins, Threshold}`; the plan does not list the signer test files, so the fixed-clock fix stays deferred. It did not fail on PR #10. Resolved in quick task 261006-ixz (PR #16); see the 01-09 entry.
- **01-13: capslock does not yet cover the PIV build (`-tags piv`).** The PIV backend (01-12, PR #14) was not on `main` when 01-13 ran, and capslock type-checks cgo packages, so a piv run needs `CGO_ENABLED=1`, the pcsclite headers (`libpcsclite-dev`) and its own baseline. `scripts/capslock-check.sh` is built for it (one more `check_target "keyroster-signer (piv)" piv 1 test/capslock/keyroster-signer-piv.json` call plus `--update` and the apt install in the `capslock` job), but that path was not added because it could not be exercised on the 01-13 branch. Add it in 01-15, once both PRs are on `main`.
  - **Still open; moved out of 01-15 to the next plan that edits CI (phase 2 or later).** 01-15 did not add the piv target, for two reasons:
    - Generating its baseline needs `libpcsclite-dev`. The workstation's WSL does not have it, and installing a package is not an executor auto-fix.
    - 01-15 makes `capslock` a required check. If its content changed in the same PR, the required version would not have run on `main` first (Pitfall 10).
  - **Owed.**
    - In `scripts/capslock-check.sh`, add one more `check_target "keyroster-signer (piv)" piv 1 test/capslock/keyroster-signer-piv.json` call (the script's header describes it).
    - Add the apt install of `libpcsclite-dev` to the `capslock` job.
    - Generate the baseline with `--update` on a host that has the headers, and review it.
    - Confirm in that PR that `capslock` stays green.
- **01-13: the dependency firewall's `-tags piv` pass is identical to the default pass until 01-12 lands.** `scripts/dep-firewall.sh` runs `go list -deps` with and without `-tags piv` (the plan's must-have). On the 01-13 branch no file carries the `piv` tag, so the piv pass lists the same packages plus `runtime/cgo`. It starts checking the PIV backend's dependencies as soon as 01-12 and 01-13 are both on one branch: whichever PR merges second is rebased by `scripts/merge-gate.sh` and runs `dependency-firewall` with the piv code. Confirm that run in 01-15.
  - **Confirmed and closed in 01-15.**
    - The piv pass checks the PIV backend: it downloads `github.com/go-piv/piv-go/v2 v2.6.0` and lists 228 packages, against 224 for the default pass.
    - Evidence: job 112204110888 (run 37443945057, PR #15 merge ref) and the `main` run at 92c6977 (job 112595286211). Both passed.
- **01-13: `TestSignerRefusals/created_301s_future` is still not fixed.** 01-13 touched `internal/signer/logstate.go` (to export the start-up log check for `doctor`) but no signer test file, so the fixed-clock fix stays deferred. Resolved in quick task 261006-ixz (PR #16); see the 01-09 entry.
- **01-14: the homelab trust root is a TEST root; a real offline ceremony and a successor rotation are owed (owner action).** The owner could not run the offline USB ceremony on 2026-10-06 and chose "Testceremoni nu, riktig sen". Claude therefore generated the two software roots (A `SHA256:rLH3utx6DsJeORfSrjkDK9bxFTHjebeJnVog0sX1WbA`, B `SHA256:aIDlGVSbtZuDo5wIm6yzA1XGtFk8hb4eFas6qnDjD8M`, threshold 1 of 2) on the owner's networked workstation in WSL. Each keyroster command ran in an unprivileged network namespace with only `lo`, but the host was online. The passphrases are files on the same disk as the keys. The homelab signer runs under bundle v1 (`2b63fb6d…b284a`) signed by these roots. It is dogfood only and must not be treated as a trusted CA. Owed:
  - **Real offline ceremony.** Run `docs/runbooks/root-ceremony.md` on a live USB with two new roots on separate sticks and paper fingerprints.
  - **Successor rotation.** Build bundle v2 that names the real roots, and have a test root sign it under the 01-06 successor rule (signed by a threshold of the current roots). Install it on the signer, and pin the real roots from then on.
    - **Gap found at the end of 01-14 (not exercised):** the signer side exists (`install-bundle` verifies a bundle against the installed one with `trust.VerifySuccessor`), but no `keyroster` command builds a successor yet: `root sign` only produces genesis bundles (version 1, all-zero `prev`). The rotation needs that command first.
    - **Alternative without it:** start the homelab signer over. Wipe its state, run `ca-init` again (new vTPM keys), and install a genesis bundle from the real ceremony. The test roots are not needed for that path.
  - **Keep the test roots until the rotation is done**, then destroy them. Deleting them from WSL is not secure erasure, so treat them as exposed either way.
  - **KEY-07 and must-have truth 2 of 01-14** (offline ceremony on USB media, checked against paper fingerprints) stay open until then.
  - **Still open after 01-15 (owner action, later phase).**
    - The 01-15 Windows check issued two more certificates from this dogfood signer (log leaves 2 and 3).
    - No successor-bundle builder exists yet. Until one does, the real ceremony means reinstalling the homelab signer: new state, `ca-init`, and a genesis bundle from the real roots.
    - KEY-07 stays open.
    - Real-hardware validation (YubiHSM 2, YubiKey PIV, a hardware root ceremony) is tracked in issue #13 (`needs-hardware`, open).
  - **Gap closure planned (2026-10-08, owner decision 1: rotate, do not rebuild).** This supersedes "No successor-bundle builder exists yet" above. The gap plans are:
    - **01-17 (merged, PR #22):** the successor builder, `keyroster root sign --prev`.
    - **01-18 (planned):** verification against the new roots, and the rotation runbook.
    - **01-20 (planned):** the owner's offline ceremony and the rotation of the homelab signer to the real roots.
    - **01-21 (planned):** destruction of the test roots and the closing of KEY-07.
    - The "Alternative without it" above (start the homelab signer over from a genesis bundle) is not taken.
    - KEY-07 stays open until 01-21.
    - The successor builder behind `root sign --prev` (`trust.BuildSuccessor`) accepts a chained v2 policy (`TestBuildSuccessor/round_trip_chained_policy`, 01-17). Authoring a new policy is Phase 4 work (quorum-signed policy changes), so the rotation carries the policy in force unchanged.
- **01-15: reconciliation of the items assigned to 01-15.**
  - **dependency-firewall piv pass:** confirmed and closed (see the 01-13 entry).
  - **capslock piv:** not done; moved to the next plan that edits CI (see the 01-13 entry).
  - **Scorecard publishes from `main` (01-03, REPO-03):** confirmed.
    - The workflow run on `main` at 92c6977 is run 37560131304 (push, success).
    - It produced code-scanning analyses 1905398269 (`supply-chain/online-scm`), 1905398223 (`supply-chain/local`) and 1905398177 (`supply-chain/branch-protection`), all on `refs/heads/main`.
    - The public API and the README badge report score 8 for commit 92c6977.
  - **Final required checks:** `.github/rulesets/main-integrity.json` lists all 17 phase checks (PR #18). Each check succeeded on `main` at 92c6977 before the change; `pr-title` runs on pull requests only.
    - **The live ruleset still requires the old seven.** Under the rollout rule in CONTRIBUTING.md, the owner applies the ruleset from the PR branch before approving.
    - Verify the live rules (01-15 Task 3 verify 1) at the merge gate. Mark REPO-01 complete only after that check passes.

## Design items deferred from the phase 1 code review (owner decision 2026-10-08)

The phase 1 code review left four findings whose remainder is design-level (`01-REVIEW-FIX.md`, "Verification gaps this closes"). Owner decision 4 defers them: they are recorded here with the decisions each one needs and a target, and they are not planned in phase 1. Each "Decisions needed" list is copied from the finding's section in `01-REVIEW-FIX.md`. No decision is taken here.

- **C-WR-06 part 2: `audit verify` cannot check issuance authorization offline (deferred, not planned).** An issue leaf records the evidence but only `RequestDigest = SHA-256(SigningBytes)`. The admin SSHSIG signatures, the admin quorum of the policy in force, and the match between the certificate and the approved request therefore cannot be verified offline. Part 1 (profile compliance) is fixed; `keyroster audit verify` states this limitation in its human output.
  - **Decisions needed:**
    - whether to log the full request signing bytes (bounded by `wire.MaxFrame`) or selected fields;
    - leaf-format versioning, and how logs written before the change are reported;
    - the offline SSHSIG check under the policy in force: namespace, sha512, distinct admins >= `AdminQuorum`, no root and no online key;
    - binding certificate fields to the request: subject key, principals, validity, extensions, CA role;
    - size and privacy of logging full requests.
  - **Target:** with the Phase 4 audit and visibility work (VIS-02 witnessed log, quorum-signed policy changes), because both change what the log carries.
- **C-WR-01 remainder: some log rollbacks are not detectable locally (deferred, not planned).** The local checks are fixed (`checkLogCovers` in serve and doctor). Still undetectable locally: the whole `signer.db` restored from an older copy (VM snapshot or backup); a cut that also rolls back the issuance rows and the high-water mark; a cut of trailing entries that issue nothing (refusal, refusal_summary, clock_regression). Detecting them needs external anchoring.
  - **Decisions needed:**
    - how host agents and the CLI witness checkpoints: keep the last checkpoint, require a consistency proof on every sync;
    - where operators keep checkpoints, and whether exports must be verified with `--previous`;
    - whether serve should refuse to start without a witnessed checkpoint at least as new as the local one;
    - whether to publish a tlog-tiles endpoint for C2SP witnesses.
  - **Target:** Phase 4 (VIS-02, success criterion 4: agents and the CLI verify signed checkpoints with consistency proofs), as the `deferred:` block of `01-VERIFICATION.md` already records.
- **D-WR-02: TPM custody is not authenticated through the endorsement-key certificate (deferred, not planned).** The manufacturer ID that decides `tpm` versus `vtpm` custody is self-reported. The bounded fix is committed: an allowlist of manufacturers, and `vtpm` for swtpm and any unknown ID. This hardens the `tpm` custody claim; it does not gate the software or `vtpm` levels, and hardware stays optional.
  - **Decisions needed:**
    - which vendor roots to embed;
    - how to handle fTPMs without an EK cert in NV;
    - whether a failed check refuses the TPM or only lowers custody to vtpm;
    - where the EK evidence is recorded (bundle or `ca_init` entry).
  - **Target:** with the real-hardware validation in issue #13 (`docs/security/needs-hardware.md` item 4, physical TPM), before the Phase 6 external security review.
- **D-WR-04: PIV custody and key origin are not attested (deferred, not planned).** Custody `piv` and the key origin are what the card reports. The bounded fix is documentation only: the docs say so, and the bundle signer is told to check the slot keys with `ykman piv keys info` and `ykman piv keys attest`. This hardens the `piv` custody claim; it does not gate the software levels, and hardware stays optional.
  - **Decisions needed:**
    - which Yubico roots and intermediates to trust (newer firmware uses another hierarchy);
    - whether Ed25519 slots on firmware 5.7 attest;
    - whether a failed attestation refuses the key or only lowers its custody;
    - how to test it without a card (fake roots through `Verifier.Roots`).
  - **Target:** with issue #13 (`docs/security/needs-hardware.md` item 2, YubiKey PIV, which collects the attestation evidence), before the Phase 6 external security review.
