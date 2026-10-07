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
