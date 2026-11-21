---
phase: quick-261121-aio
plan: 01
subsystem: signer
tags: [signer, doctor, keystore, ca-rotation, restore, runbooks]
status: complete
requires: []
provides: ["console texts that let an unrecorded later-generation key file go only once the restore section has run to its end, and keep it where that section stops on a lost generation"]
affects: [03-13]
key-files:
  created:
    - .planning/quick/261121-aio-console-says-when-an-unrecorded-key-file-may-be-destroyed/261121-aio-PLAN.md
    - .planning/quick/261121-aio-console-says-when-an-unrecorded-key-file-may-be-destroyed/261121-aio-SUMMARY.md
  modified:
    - internal/doctor/doctor.go
    - internal/doctor/doctor_test.go
    - internal/keystore/software/software.go
    - internal/keystore/software/software_test.go
    - internal/keystore/tpm/provision.go
    - internal/keystore/tpm/tpm.go
    - internal/keystore/tpm/tpm_test.go
    - cmd/keyroster-signer/doctor_test.go
    - cmd/keyroster/runbook_test.go
    - docs/runbooks/signer-install.md
decisions:
  - "The doctor warning and the software refusal take the condition in the words of the tpm refusal: once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it unless you placed it for a --key prepare."
  - "All three texts end with the same clause: where that section stops on a lost generation, keep it, because it may hold that generation's key. The software and the tpm hint differ only in the file names."
  - "\"never record it again with --key\" stays in the doctor warning, behind a semicolon, so that it does not read as waiting for the restore section; 03-13 decides whether it stays unconditional."
requirements: []
metrics:
  completed: 2026-11-21
actuals:
  tokens: 5500
  tasks: 3
  commits: 4
plan_head_before: 3d0d1b4
plan_head_after: 3f4f912
---

# Quick 261121-aio Plan 01: the console says when an unrecorded key file may be destroyed Summary

doctor's `unrecorded_generation_file` warning and the software backend's refusal over an existing `<role>-g<N>.age` file now say what the tpm refusal has said since 03-12f: destroy an unrecorded later-generation key file only once the restore section of signer-install.md has run to its end. All three texts also say to keep the file where that section stops on a lost generation, and the runbook sentence that describes them says the same. Only string literals and comments change in the Go code; no behaviour changes. The four commits of the work are 2c7fff7 (the plan), d7cb63f (the tests), 7a5a792 (the texts) and 3f4f912 (the runbook); the commit that records this SUMMARY follows them, so `commits: 4` counts the work before this record.

## Why

A `<role>-g<N>.age` file (software backend) or a `<role>-g<N>.tpmkey` / `.auth` pair (tpm backend) that no generation row names is normally the leftover of a prepare that a restore lost, and the operator destroys it. After a restore that lost a generation row, the same file can hold the key of a generation that is still in use. The runbook therefore lets such a file go only once the restore section has run to its end ("Prepare a CA key generation" and the restore section of docs/runbooks/signer-install.md; docs/security/custody.md). Of the three console texts that state this rule, only the tpm refusal carried that condition; 03-12f recorded the other two as a later item.

The texts were read against four states:

1. a prepare is running (the file is that prepare's, not a leftover);
2. the operator placed the file for a `--key` prepare;
3. a restore lost a prepare (the file is a leftover key and is destroyed);
4. a restore lost a generation whose key is still in use (the file may hold that key and must be kept).

The old doctor and software texts said to destroy the file in state 4. The new texts send the operator to the restore section first, which stops on a lost generation, and say to keep the file there.

## The texts

doctor's warning (internal/doctor/doctor.go), printed for software and tpm files alike:

- Before: `%s: no generation row names this file; if no prepare is running and a restore preceded it, it is a key from a lost prepare: destroy it unless you placed it for a --key prepare, and never record it again with --key`
- After: `%s: no generation row names this file; if no prepare is running and a restore preceded it, it is a key from a lost prepare: once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it unless you placed it for a --key prepare; where that section stops on a lost generation, keep it, because it may hold that generation's key; never record it again with --key`

The software backend's `ProvisionGeneration` refusal (internal/keystore/software/software.go):

- Before: `%w: %s (after a restore, a %s-g%d.age file that no generation row names is a key from a lost prepare: destroy it unless you placed it for a --key prepare)`
- After: `%w: %s (after a restore, a %s-g%d.age file that no generation row names is a key from a lost prepare: once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it unless you placed it for a --key prepare; where that section stops on a lost generation, keep it, because it may hold that generation's key)`

The tpm backend's `ProvisionGeneration` refusal (internal/keystore/tpm/provision.go) had the condition since 03-12f and gains the same last clause, so that the three texts say the same:

- Before: `%w: %s (after a restore, a %s-g%d.tpmkey or .auth file that no generation row names is a key from a lost prepare: once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it unless you placed it for a --key prepare)`
- After: `%w: %s (after a restore, a %s-g%d.tpmkey or .auth file that no generation row names is a key from a lost prepare: once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it unless you placed it for a --key prepare; where that section stops on a lost generation, keep it, because it may hold that generation's key)`

The sentence of docs/runbooks/signer-install.md, "Prepare a CA key generation", last sentence of the tpm paragraph (the paragraph rewrapped, nothing else in the file changed):

- Before: "doctor's `unrecorded_generation_file` warning and prepare's refusal over an existing file both say to destroy such a file after a restore: that holds only once the restore section has run to its end."
- After: "doctor's `unrecorded_generation_file` warning and prepare's refusal over an existing file, with the software and the tpm backend alike, say this in short: destroy such a file only once the restore section has run to its end, and keep it where that section stops on a lost generation."

Comments, checked against the code first: `Facts.UnrecordedGenerationFiles` and `generationResults` in doctor.go now name the tpm files too (cmd/keyroster-signer/doctor.go's `generationFiles` scans `{state-dir}/software` and `{state-dir}/tpm`), and `ErrKeyFilesExist` in both backends now names `ProvisionGeneration` too (both `Provision` and `ProvisionGeneration` return it over an existing file and write nothing over it).

## Tests

- `TestDoctorGenerationFiles/warn_text_states_the_conditions` (internal/doctor): the warning holds "no generation row names this file", "unless you placed it for a --key prepare", "once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it" (one string, so the condition stands directly before the verb), "where that section stops on a lost generation, keep it" and "never record it again with --key".
- `TestProvisionGeneration/refuses_existing_file` (internal/keystore/software): besides `ErrKeyFilesExist`, the path and the unchanged file, the error holds "is a key from a lost prepare", the condition and the keep clause.
- `TestTPMProvisionGenerationRefusals/existing_key_file_refused` and `/existing_auth_file_refused` (internal/keystore/tpm, against swtpm): the error also holds the keep clause.
- `TestDoctorUnrecordedGenerationFile/stray_file_warns` and `/tpm_stray_files_warn` (cmd/keyroster-signer): the printed doctor line holds the condition, for a software file and for a tpm pair.
- `TestCARotationBackendSteps/unrecorded_key_files_after_restore` (cmd/keyroster): in "Prepare a CA key generation", white space normalised, "but only after the restore section has run to its end" occurs exactly twice (the software and the tpm paragraph), the new sentence is there and the old phrase "both say to destroy such a file after a restore" is not; in "Snapshot restore: check the clock first", "but only once this restore has run to its end" and "The same holds for a `<role>-g<N>.tpmkey` and `.auth` pair" are there.

## RED

On the test commit d7cb63f, with code and document unchanged, the narrow runs (the tpm run with `KEYROSTER_TPM_REQUIRE=1`) failed exactly on these leaves and their parents, with no other failing test, no build or setup failure and no SKIP:

| Leaf | Assertion that failed |
|------|-----------------------|
| `TestDoctorGenerationFiles/warn_text_states_the_conditions` | doctor_test.go:530: the warning lacks "once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it" |
| `TestProvisionGeneration/refuses_existing_file` | software_test.go:648 (twice): want the lost-prepare hint with "once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it", and with "where that section stops on a lost generation, keep it" |
| `TestTPMProvisionGenerationRefusals/existing_key_file_refused` | tpm_test.go:803: ProvisionGeneration over user-g2.tpmkey: want ErrKeyFilesExist with the lost-prepare hint |
| `TestTPMProvisionGenerationRefusals/existing_auth_file_refused` | tpm_test.go:803: ProvisionGeneration over user-g2.auth: want ErrKeyFilesExist with the lost-prepare hint |
| `TestDoctorUnrecordedGenerationFile/stray_file_warns` | doctor_test.go:322: the warning lacks "once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it" |
| `TestDoctorUnrecordedGenerationFile/tpm_stray_files_warn` | doctor_test.go:374: the warning lacks the same |
| `TestCARotationBackendSteps/unrecorded_key_files_after_restore` | runbook_test.go:1689: lacks the new sentence; runbook_test.go:1693: still says "both say to destroy such a file after a restore" (not the count, not the restore section's phrases) |

After 7a5a792 every leaf passed except the runbook leaf; after 3f4f912 that one passed too.

## Mutants

Each was applied to the working tree after 3f4f912, alone. The unmutated run of the same command passed first; `go vet` of the mutated package (same environment) exited 0; no `[build failed]`, `[setup failed]` or `--- SKIP:` line; the file was restored from HEAD and its sha256 matched the one taken before; `git status --short -- cmd internal test docs .github` was empty afterwards. Every command carried `-count=1 -timeout 5m -v` and a `-run` naming the leaf.

| Mutant | Change | Result |
|--------|--------|--------|
| Q1 | doctor.go without "once the restore section of docs/runbooks/signer-install.md has run to its end, " | killed: `TestDoctorGenerationFiles/warn_text_states_the_conditions` (doctor_test.go:530) and both `TestDoctorUnrecordedGenerationFile` leaves (doctor_test.go:322, :374) |
| Q2 | doctor.go without "; where that section stops on a lost generation, keep it, because it may hold that generation's key" | killed: `warn_text_states_the_conditions` lacks "where that section stops on a lost generation, keep it" |
| Q3 | doctor.go without "; never record it again with --key" | killed: `warn_text_states_the_conditions` lacks "never record it again with --key" |
| Q4 | software.go without the condition | killed: `TestProvisionGeneration/refuses_existing_file` wants the condition |
| Q5 | software.go without the keep clause | killed: `refuses_existing_file` wants "where that section stops on a lost generation, keep it" |
| Q6 | tpm/provision.go without the keep clause | killed: both `TestTPMProvisionGenerationRefusals` existing-file leaves (`KEYROSTER_TPM_REQUIRE=1`) |
| D1 | signer-install.md: the new sentence replaced by the old one | killed: `unrecorded_key_files_after_restore` lacks the new sentence and still holds the old phrase |
| D2 | signer-install.md, software paragraph: ", but only after the restore section has run to its end" removed | killed: the phrase occurs 1 times, want 2 |
| D3 | signer-install.md, tpm paragraph: the same words removed | killed: the phrase occurs 1 times, want 2 |
| D4 | signer-install.md, restore section: "but only once this restore has run to its end" removed | killed: the restore section lacks the phrase |

## Gates

- The narrow runs of every changed test: green after 3f4f912. The runbook pattern `go test -count=1 -timeout 15m -v -run "Runbook|CARotation|SignerInstall|MoveAside|Restore" ./cmd/keyroster/`: 16 top-level tests pass, no SKIP.
- The full gate, 03-12f's Task 6 sixth verify command, taken unchanged from line 674 of 03-12f-PLAN.md on 3f4f912, with nothing else running in WSL. Run 1 exited 1 after 780 s: `internal/signer` `TestSignerRestore/restore_older_db` failed at signer_test.go:850 with `issue after restore: signer unavailable: clock_regression` (see Deviations); the command stops at its first `&&`, so nothing after the first `go test` ran. The unchanged re-run exited 0 after 1047 s: every package passed with `-race` (the tpm tests against swtpm with `KEYROSTER_TPM_REQUIRE=1`: internal/keystore/tpm 13.269 s; internal/signer 603.413 s; cmd/keyroster 390.083 s; cmd/keyroster-signer 67.846 s), the piv-tag run passed (internal/keystore/piv 1.424 s, cmd/keyroster-signer 54.424 s), every vet passed, gofmt listed nothing, the four golangci-lint passes reported 0 issues each, capslock matched its baselines (keyroster-signer 97 pairs, baseline 97; keyroster-agent 37, baseline 37; keyroster-agent-fetch 23, baseline 23; no new pair), the dependency firewall and the test-only firewall were clean, and all 55 `uses:` references were pinned to commit SHAs.
- The publish scan (the non-comment lines of the owner's two private pattern files, case-sensitive and case-insensitive, over the added lines of `git diff origin/main..HEAD` and over the commit messages), the scan for the repository's banned words and for dotted quads: no hit.
- Authorship: `git log origin/main..HEAD --format='%an <%ae> %cn'` shows only Daniel Gustafsson as author and keyroster-bot as committer; every commit is signed.

## Left unchanged on purpose

- internal/keystore/piv/piv.go, the `ErrSlotOccupied` text ("... every later PIV prepare stops here until the slot is emptied (docs/backends/piv.md)"): it tells the operator to destroy nothing, and the document it names carries the rule with its three conditions.
- The `ca-init` hints "remove %s only if no trust bundle uses these keys" (software.go and tpm/provision.go): they concern generation-1 files, carry their own condition, and `InitCA` refuses an initialised signer before they can print (internal/signer/trust.go, `ErrAlreadyInitialised`).
- `orphaned` in internal/signer/rotate.go ("... which no generation row records: remove it"): it names a key that the same run created.
- docs/security/needs-hardware.md's checklist line on a planted key in a generation slot.

## The sweep before the change

As the task's contract records it, the tree was swept for every text of this rule while the task was prepared: three search passes, each searching its own way (by word, along the code paths, through the documents and their pins), and one critic that re-read every text they listed and searched again on its own; 54 texts were listed, of which the nine that this task changes or pins belong to it. That sweep was part of the preparation, not of this session, and this session did not repeat or check it. This session did run its own search before the first edit, for the fragments that the new texts break ("lost prepare: destroy it", "--key prepare)", "--key prepare, and never", "and never record it again", "both say to destroy", "holds only once the restore section", "unless you placed it for a --key prepare", "no generation row names this file", "key from a lost prepare", "has run to its end"): the first eight over the whole tree outside .planning/phases, the last two over the tests, test/, scripts/ and .github/. The only hits were the three console texts, the runbook sentence, the pins in doctor_test.go and tpm_test.go that this task extends, custody.md's own pin in runbook_test.go (its words do not change), and a comment in cmd/keyroster-signer/rotate_test.go that does not quote the texts.

## Hand-over to 03-13

The runbook names 03-13 as the owner of the lost-generation case three times in signer-install.md: the sentence "The lost-bundle and lost-generation cases are 03-13's", the stop on an `install-bundle` refusal with `no stored generation` ("a lost generation, which is 03-13's case"), and the stop at the end of "Restore from before the last switch" ("those cases are 03-13's"). 03-13's plan (03-13-PLAN.md) does not yet speak of it. When 03-13 defines what happens where the restore section stops on a lost generation, it updates these three console texts, the sentence in signer-install.md and their pins, and decides whether "never record it again with --key" stays unconditional.

## UNVERIFIED

No restore of a real signer has exercised these texts. The rule itself is UNVERIFIED on the homelab signer, as custody.md says; CI runs the pins above.

## Deviations from Plan

1. **A gate re-run for a flake the task's flake list does not name.** The task allowed one unchanged re-run for a `clock_regression` failure of TestCheckLogAgainstLiveSigner or TestTrustChangedUnderLiveSigner and for `TestHostStatus/table`. Run 1 failed instead on `TestSignerRestore/restore_older_db` (`signer unavailable: clock_regression`, signer_test.go:850, after 780 s). That test and that symptom are recorded as an open, pre-existing flake in .planning/phases/03-linux-agent-and-revocation/deferred-items.md, of the same class as TestCheckLogAgainstLiveSigner's, and nothing under internal/signer changes here. The gate was re-run once, unchanged, and passed; every full-gate reading above except run 1's failure comes from the re-run.
2. **The sweep is reported as the contract records it.** "The sweep before the change" gives the preparation's three search passes, its critic and its 54 texts as the task's contract records them; this session did not see or check that work, and reports its own narrower search beside it.
3. **D3 was matched with a longer anchor.** The words that D3 removes (", but only after the restore section has run to its end") are the task's; because a white-space-tolerant match of those words alone also finds them in the software paragraph, the mutant matched them together with the tpm paragraph's following words ("because where that section stops on a lost generation the pair") so that it hit the tpm paragraph only. The mutation itself is unchanged.

## Known Stubs

None.
