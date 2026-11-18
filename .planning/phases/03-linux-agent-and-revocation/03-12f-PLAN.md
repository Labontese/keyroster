---
phase: 03-linux-agent-and-revocation
plan: 12f
type: execute
wave: 38
depends_on: ["03-12e2"]
files_modified:
  - internal/keystore/tpm/tpm.go
  - internal/keystore/tpm/provision.go
  - internal/keystore/tpm/tpm_test.go
  - internal/keystore/piv/piv.go
  - internal/keystore/piv/piv_test.go
  - internal/keystore/piv/card.go
  - internal/signer/rotate.go
  - cmd/keyroster-signer/rotate.go
  - cmd/keyroster-signer/rotate_test.go
  - cmd/keyroster-signer/restart_test.go
  - test/e2e/tpm_test.go
  - test/e2e/hostca_rotation_test.go
  - .github/workflows/e2e-tpm.yml
  - .github/workflows/e2e.yml
  - docs/runbooks/ca-rotation.md
  - docs/runbooks/signer-install.md
  - docs/runbooks/enroll-user.md
  - .planning/phases/03-linux-agent-and-revocation/03-12f-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [KEY-08]

estimate:
  tokens: 125000
  raw_tokens: 125000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Early plan: scope, owner decisions and tests are fixed here; the tasks are planned out in full, and every path and line anchor reconciled against main, after 03-12e merges. Until then this file is a specification, not an executable plan"
    - "The homelab signer is a TPM signer (a Proxmox vTPM). This plan gives the TPM and PIV backends generations, key addressing by generation, presence checks and key removal, so `ca-rotate prepare`, the switch install, `ca-rotate retire-key` and the serve refusal of 03-12 and 03-12e work on every backend. Until it lands, prepare refuses tpm and piv by name"
    - "TPM: one P-256 key per generation, as `<role>-g<N>` key and auth files in the state directory, with noDA as at genesis; retire-key removes the draining generation's key and auth files. PIV: a generation takes the first slot in 0x87 to 0x95 that no generation row records; a slot emptied by retire-key stays recorded and is never reused"
    - "Real hardware is not exercised: the TPM path runs on swtpm in CI and the PIV path on the fake card in the piv-tagged build; both are UNVERIFIED on hardware"
  artifacts:
    - path: "internal/keystore/piv/piv.go"
      provides: "the slot allocator by generation rows, KeyAt, Holds and removal on PIV"
    - path: "internal/keystore/tpm/provision.go"
      provides: "ProvisionGeneration for the TPM backend"
  key_links:
    - from: "internal/keystore/piv/piv.go"
      to: "internal/signerdb/trust.go"
      via: "the allocator receives the slots that the generation rows record (the used argument of ProvisionGeneration) and returns the one it chose, which PrepareGeneration stores in the row's location column"
      pattern: "location"
---

<objective>
TPM and PIV generations (D-14, KEY-08): the two hardware-backed backends learn what the software and agent backends learned in 03-12 and 03-12e, so the homelab's TPM signer can rotate and the PIV backend holds its generations without ever reusing a slot.

Purpose: 03-13 uses this plan's PIV allocator and fake card for the ops and log keys, and 03-15 runs `ca-rotate prepare --role user` on the TPM homelab signer before the v4 ceremony. This plan therefore lands last before 03-13, so its removal tests run against the real switch path that 03-12e put on main.

Output: TPM generation provisioning, addressing and removal; PIV allocation by generation rows, addressing, presence and removal; the backend gate by name relaxed for tpm and piv; the restart and removal tests on swtpm and the fake card; the host-CA end-to-end test and its enroll-user text, moved here from 03-12e by its named fallback cut; the runbook text for both.
</objective>

## Before execution (read this first)

This is an early plan, written with 03-12 and its siblings against kr-main at d15f044 and published in 03-12's PR. It is planned out in full by `/gsd-plan-phase`, and reconciled against main, after 03-12e merges: every path, line anchor, count, test name and threat ID is re-read there. The scope, owner decisions and the test and mutant lists below are fixed; the tasks, commands and RED routes are not. Do not execute this file as it stands.

At the reconcile, check in particular: the TPM key files (`{role}.tpmkey` and `{role}.auth`, internal/keystore/tpm/tpm.go:119-127) and noDA handling; the PIV slots (0x82 to 0x86 in use, `slotFor` using RetiredKeyManagementSlot, internal/keystore/piv/piv.go:87-91 and :246-254, leaving 0x87 to 0x95: 15 slots) and its fake card (`card.go`, which of the three files holds it); that 03-12's `signer.CheckRotationBackend`, the `location` column and the `used` and `location` arguments of the keystore interfaces are as left; and that 03-12e's `keystore.Holds` and retire-key have the shape this plan extends.

## Scope

**In.**
- **TPM:** `ProvisionGeneration` creates one P-256 key per generation as `<role>-g<N>` key and auth files (generation 1 keeps `{role}.tpmkey` and `{role}.auth`), with noDA as at genesis; `KeyAt` opens exactly the generation's own key; `Holds` is "the generation's file exists" (lstat; any entry counts); retire-key deletes both files and fsyncs. The TPM backend implements `keystore.GenerationProvisioner` and `keystore.GenerationBackend`; the CA algorithm is ECDSA P-256 because TPMs practically never implement Ed25519.
- **PIV:** the slot of a generation is recorded in the generation row's `location` column. The allocator picks the first slot in 0x87 to 0x95 that **no generation row records** (CA generations, and 03-13's ops and log generations), never by slot occupancy; a slot deleted or overwritten by retire-key stays recorded, so it is never reused (the no-recycling rule holds by construction); `piv_no_free_slot` refuses before generating anything. The rule "never overwrite a slot" becomes "never overwrite a slot, except the draining generation's own slot in retire-key on firmware below 5.7". PIN once, touch never. Removal: firmware 5.7 and later can delete a slot's key (UNVERIFIED in this repository); older firmware overwrites the slot with a throwaway key; either needs the PIN or management key. `KeyAt` uses the recorded slot, which it receives as its `location` argument; `Holds` reads the recorded slot (reading it without the PIN is UNVERIFIED). 03-12 fixed the interfaces for this: ProvisionGeneration(role, generation, used) receives the locations that every stored row records, so the allocator sees which slots are taken, and returns (pub, location, err); PrepareGeneration stores the returned slot in the row; KeyAt and 03-12e's Holds receive the row's location. This plan therefore changes the TPM and PIV backends only, re-cuts no interface and edits neither keystore.go, internal/signerdb/trust.go nor internal/signer/trust.go. The CA algorithm may be Ed25519 on firmware 5.7 and later, otherwise P-256.
- **The backend gate:** `signer.CheckRotationBackend` (03-12) stops refusing tpm and piv: two map entries go, and `rotation_not_supported_on_backend` is then unreachable for the registered backends.
- **The host-CA end-to-end test, received from 03-12e by its named fallback cut:** TestHostCARotation (test/e2e/hostca_rotation_test.go, in the `e2e-rotation` lane; its `-run` list in e2e.yml gains it) and the enroll-user.md host-CA text. The e2e host profile cap is 90 s (test/e2e/hostcert_test.go:398); a client that synced after ceremony 1 connects to a host whose certificate is by the old key and, after renewal, by the new one; a client that did not sync fails against the renewed host, which documents the runbook gate of 03-12e's ca-rotation.md (UNVERIFIED there until this test runs); the host drain itself is unit-tested only. The enroll-user.md text says that a client that never refreshes cannot be rotated safely, and names the test.
- **Tests that run without hardware:** the TPM restart on swtpm in the existing e2e-tpm lane, and the PIV restart, allocation and removal on the fake card in the `piv`-tagged build (build-piv).
- **The runbook:** ca-rotation.md and signer-install.md say, per backend, what prepare creates, how the old key is removed (TPM: `retire-key` deletes the files; PIV: the firmware-dependent removal and the PIN), the 15-slot limit shared with the ops and log generations of 03-13, that a freed slot is never recycled, and what is UNVERIFIED (every real device).

**Out.** Rotation across custody or backend (a rotation never changes the backend or custody; moving a CA into stronger custody is a later plan), TPM endorsement-key and PIV attestation of a generation (later; UNVERIFIED), rollback-resistant activation by a TPM NV or PIV counter (later and optional, never the mechanism).

## Owner decisions that bind this plan (Daniel, 2026-11-13 and 2026-11-14)

- Hardware is optional and never required: software through HSM; every path here has a software or fake-card test.
- The draining key is removed from the backend right after the switch install (03-12e); this plan gives TPM and PIV their removal.
- This plan lands before 03-13 (which uses the PIV allocator) and before 03-15's prepare on the TPM homelab signer.
- Real PIV hardware stays UNVERIFIED, as in 01-12.

## Tests (fixed here)

- **TPM and PIV unit tests** (internal/keystore/tpm/tpm_test.go, piv_test.go): `tpm_retire_removes_both_files`, `piv_deleted_slot_not_reused`, `piv_no_free_slot_refused` (nothing generated), `never_overwrites` (a slot outside retire-key), `TestGenerationKeyAfterReopen` (the PIV backend reopens and finds a generation by its recorded slot), the TPM key and auth file naming.
- **cmd/keyroster-signer:** TestSignerRestartMixedBundle extended to TPM (through swtpm where available, otherwise the CI lane) and the PIV fake card: g1 active with g2 prepared, restart, issue with g1; after the switch, g2 active and g1 draining, issue with g2.
- **e2e-tpm (swtpm):** prepare the user CA, install `next`, switch, check that serve refuses before removal (`draining_key_still_usable`), `retire-key` removes the TPM key and auth files, then restart and issue with the new key.
- **e2e (host CA):** TestHostCARotation, as described in Scope.
- **Keep green:** the whole of 03-12 to 03-12e's rotation tests on the software and agent backends; build-piv; e2e-tpm.

## Mutants (M175 to M179)

- M175 the PIV allocator goes by slot occupancy, so a deleted slot is reused (`piv_deleted_slot_not_reused`).
- M176 PIV overwrites an occupied slot outside retire-key (`piv_no_free_slot_refused`, `never_overwrites`).
- M177 PIV Key ignores the recorded slot (TestGenerationKeyAfterReopen).
- M178 TPM Key opens the genesis key file for a generation's fingerprint (the TPM restart case).
- M179 TPM retire-key leaves the auth file (`tpm_retire_removes_both_files`).

## Inherited duties (from 03-14b, 03-14c, 03-14d), which this plan carries

- Mutants continue from M175; threat IDs are the set's; the Q-09-3 test-time form; the private-term and label scan; the stop guard and ROADMAP gate. The e2e-tpm workflow runs on pull_request; its run ID is recorded. Any `ca issue` site in the TPM test passes `--installation-id`.
- The tpm and piv code stay behind their existing build tags and do not change the default binary's capabilities (capslock).

## Why it ships safely alone

Until it lands, `ca-rotate prepare` refuses tpm and piv with a message that names this plan, so nothing can create a TPM or PIV generation the backends cannot open. It adds generations and key removal for TPM and PIV against the switch path that 03-12e already put on main.

## Size

24 files by the set's counting convention: 12 code and test (including internal/signer/rotate.go, which holds the backend gate and which an earlier count omitted, and the host-CA e2e test that 03-12e's fallback cut moved here), 3 docs (enroll-user.md came with the cut), 2 CI workflows (e2e-tpm.yml, and e2e.yml for the rotation lane's `-run` list, which an earlier count omitted) and 7 planning (its own plan file, ROADMAP, STATE and 03-13 to 03-16; this plan expects to change 3 of them). About 125k estimated tokens raw (low confidence); the calibration has run 2x to 5x.

## Open owner questions

None open.

<tasks>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 1: Plan 03-12f out in full and reconcile it against main. Do not execute this file</name>
  <read_first>
    - The "Before execution" section above, and 03-12e-SUMMARY.md (the predecessor's SUMMARY, on main once it has merged)
  </read_first>
  <action>This is an early plan: a specification published in 03-12's PR so that the wave shift happens once. It carries no executable tasks. After 03-12e has merged, run the planner for it (`/gsd-plan-phase` on this plan's phase and number), which re-reads every path, line anchor, file count, test name and threat ID against main, writes the tasks with their verify commands and RED routes, and replaces this file. Do not run `/gsd-execute-phase` on this file as it stands.</action>
  <instructions>
    1. Confirm that 03-12e's SUMMARY is on origin/main.
    2. Plan this plan out in full, reconciled against main, and have it checked.
    3. Reply "planned" when the executable plan has replaced this file.
  </instructions>
  <verify>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-12e-SUMMARY.md</automated>
    <fails_when>non-zero exit: the predecessor has not merged, so this plan must not be planned out or executed yet</fails_when>
  </verify>
  <acceptance_criteria>
    - The executable plan has replaced this file, its tasks name every verify command, and its reconcile ledger records what differed from this specification at its base commit.
  </acceptance_criteria>
  <done>03-12f is planned out in full against main.</done>
  <resume-signal>Type "planned" after the executable plan has replaced this file</resume-signal>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| the signer → the TPM or the card | generation keys live in the device or its files and must be addressed by generation |

## STRIDE Threat Register

Each ID below is defined only in this plan; the other IDs of the set are defined in the plan named in 03-12's register.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-246 | Denial of service | PIV slots used up | low | mitigate | `piv_no_free_slot` before generating; the allocator goes by generation rows, so each retired slot stays consumed: 15 slots shared with 03-13's ops and log generations, a limit stated in the runbook |
| T-03-SC | Tampering | dependencies | low | mitigate | no module added; the PIV build keeps its cgo build tag and stays out of the default binary |

(T-03-245, T-03-424 and the other rows of the set that touch these backends are defined in 03-12 and 03-12e and are not repeated here.)
</threat_model>

<success_criteria>
- A TPM signer and a PIV signer (fake card) prepare, switch, remove the old key and restart with the new generation, in CI.
- A PIV slot that retire-key emptied is never allocated again.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-12f-SUMMARY.md` when the plan has been planned out and executed. Leave `requirements-completed` empty: KEY-08 completes in 03-13.
</output>
