---
phase: quick-261121-k7d
plan: 01
subsystem: docs
tags: [docs, security, piv, tpm, custody, needs-hardware]
status: complete
requires: []
provides: ["a hardware checklist that tracks every PIV limit piv.md says it tracks, a location limit stated as narrowly as the code has it, and custody.md's rule for an unrecorded tpm key pair"]
affects: [03-13]
key-files:
  created:
    - cmd/keyroster/securitydocs_test.go
    - .planning/quick/261121-k7d-track-the-piv-limits-and-state-the-tpm-key-pair-rule/261121-k7d-PLAN.md
    - .planning/quick/261121-k7d-track-the-piv-limits-and-state-the-tpm-key-pair-rule/261121-k7d-SUMMARY.md
  modified:
    - docs/security/needs-hardware.md
    - docs/security/custody.md
    - docs/backends/piv.md
decisions:
  - "The location limit is stated for generation 2 or later and another generation slot only, in piv.md's bullet and in the new checklist row alike, because generation 1 takes no location and Holds answers held, with the error, for a location that does not resolve."
  - "After an edited location the sentence says what the two card writes still do (fix round): retire-key overwrites a slot only when its key has the draining fingerprint, and prepare generates only into an empty slot, so no other key is written over. It no longer says that the edit \"is stopped by the fingerprint checks before any card write\", because ProvisionGeneration compares no fingerprint and prepare can generate into another free slot."
  - "Each pinned text is read in its own row, bullet or paragraph, and the checklist with its boxes unticked (fix round)."
  - "Both custody.md sentences on an unrecorded key file carry the guard \"when no prepare is running\", as doctor's warning and signer-install.md's software paragraph do."
  - "ca-rotation.md's bullet on the location column (both of its older wordings) and signer-install.md's tpm paragraph are left for a later change to those runbooks."
requirements: []
metrics:
  completed: 2026-11-21
actuals:
  tokens: 16900
  tasks: 2
  commits: 6
plan_head_before: 35d960b
plan_head_after: ff622ed
---

# Quick 261121-k7d Plan 01: the hardware checklist tracks the PIV limits, and custody.md states the tpm pair rule Summary

docs/security/needs-hardware.md now has a row for each limit that the needs-hardware list of docs/backends/piv.md says it tracks. The checklist row on emptying a generation slot now names the rule of piv.md "Generation slots". piv.md and the new row say what retire-key and prepare still do after an edited location, and state the location limit as narrowly as `Holds` has it. docs/security/custody.md now states the rule for an unrecorded tpm key pair, and both of its sentences on an unrecorded key file carry the guard "when no prepare is running". No product code changes.

The commits are c02e866 (the plan), 1413ab1 (the test, RED), 600facb (the three documents) and f61b9da (the first form of this SUMMARY), then, in the fix round after the pre-merge review, 5f46b8b (the location sentence) and ff622ed (the test's windows). The commit that adds the pre-merge review to this SUMMARY follows them. `commits: 6` is `git rev-list --count 35d960b..ff622ed`, measured before that last commit: every commit of the branch before it, the first form of this SUMMARY included; `plan_head_after` is ff622ed.

## Why

1. **piv.md's list had untracked limits.** docs/backends/piv.md, "What CI verifies, and what needs hardware", ends its needs-hardware list with "These are tracked in needs-hardware.md for the Phase 6 review (D-12)." The list's last bullet (the location column is not logged) had no row in the checklist. Two other bullets each had a row that left out one clause: "overwriting the slot by hand does not clear it", and that the management key file is "shredded, not proven erased".
2. **The row on emptying a slot left out the rule.** The checklist row on a key in a generation slot that no row records said the slot "is emptied with `ykman piv keys delete <slot>`". It did not say that this is allowed only by the rule of piv.md "Generation slots". signer-install.md says so: "only when the rule of piv.md "Generation slots" allows it".
3. **custody.md had no tpm pair rule.** It stated the rule for a software key file that no generation row names ("Software CA keys (KEY-06)"), but had no such rule for a tpm pair in "TPM and vTPM (KEY-04, D-07, D-08, D-09)". signer-install.md has the rule for both backends, and doctor and prepare print it for both.
4. **piv.md's location sentence was wider than the code.** It said "an edit that points at any slot that does not hold the draining key makes Holds answer "not held"". The code is narrower. Only a row of generation 2 or later that points at another generation slot, one that reads as empty or as another key, makes `Holds` answer "not held". The sentence's first half, "a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write", also said more than the code does (taken up in the fix round): `RemoveGeneration` overwrites a slot only when its key has the draining fingerprint, but `ProvisionGeneration` compares no fingerprint; it takes the first generation slot that no row's location names and generates only into a slot that reads as empty. After an edited location, prepare can therefore generate into another free slot, and neither command writes over any key but the draining one. The final sentence says that.
5. **custody.md's software sentence lacked the "no prepare is running" guard.** It said a file that no generation row names "is, unless you placed it for a `--key` prepare, a key from a lost prepare". While a prepare runs, its file exists before its row. doctor's warning and signer-install.md's software paragraph carry the guard "no prepare is running", and both custody.md sentences now carry it.

## The texts

**docs/security/needs-hardware.md, section "2. YubiKey 5 PIV (KEY-05)", block "CA key generations":**

- **The management key row.**
  - Before: "- [ ] The management key placed for the run by the block of piv.md step 5 and shredded on every exit status; retire-key without it refused naming `mgmt-key-file`; the card's answer to a wrong management key."
  - After: "- [ ] The management key placed for the run by the block of piv.md step 5 and shredded on every exit status (shredded, not proven erased: `shred` does not reliably erase a file on an SSD or a copy-on-write filesystem); retire-key without it refused naming `mgmt-key-file`; the card's answer to a wrong management key."
- **The row on a key that no row records.**
  - Before: "- [ ] A key in the next generation slot that no row records is refused `ErrSlotOccupied`, and is emptied with `ykman piv keys delete <slot>` on 5.7 and later, with the signer stopped and the management key given at `ykman`'s prompt (below 5.7 only `ykman piv reset`, which destroys every CA key)."
  - After: "- [ ] A key in the next generation slot that no row records is refused `ErrSlotOccupied`, and overwriting the slot by hand does not clear it. It is emptied with `ykman piv keys delete <slot>` on 5.7 and later, only when the rule of piv.md "Generation slots" allows it, with the signer stopped and the management key given at `ykman`'s prompt (below 5.7 only `ykman piv reset`, which destroys every CA key)."
- **New last row of the block.** It comes after "The 15-slot exhaustion" and before the blank line above "## 3. Hardware root ceremony (D-11)". In its final words (fix round, 5f46b8b): "- [ ] The location column is not logged (a later hardening item): after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used." Its first form (600facb) began "a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but for generation 2 or later ...".

**docs/backends/piv.md, the last bullet of the needs-hardware list:**

- Before: "- the location column is not logged: a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but an edit that points at any slot that does not hold the draining key makes Holds answer "not held", and audit cannot show which slot a generation used."
- After, in its final words (fix round, 5f46b8b): "- the location column is not logged: after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used."
- Its first form (600facb) kept the old first half, "a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but", and changed only the clause after it.

**docs/security/custody.md:**

- **"TPM and vTPM (KEY-04, D-07, D-08, D-09)", a new paragraph.** It comes after the paragraph on later-generation tpm files, which ends "until its owner hierarchy is cleared.", and before the paragraph on `noDA`: "A `{role}-g<N>.tpmkey` and `.auth` pair that no generation row names (doctor warns `unrecorded_generation_file`) is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare, to be destroyed and not recorded again, but after a restore only once the restore section of [signer-install.md](../runbooks/signer-install.md) has run to its end, because where that section stops on a lost generation the pair may hold that generation's key (what doctor and prepare print for such a pair is run in CI: TestDoctorUnrecordedGenerationFile, and on swtpm TestTPMProvisionGenerationRefusals; the rule itself is UNVERIFIED on a physical TPM and on the homelab vTPM signer)."
- **"Software CA keys (KEY-06)", one part of a sentence.**
  - Before: "one that no generation row names is, unless you placed it for a `--key` prepare, a key from a lost prepare,"
  - After: "one that no generation row names is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare,"
  - The rest of the sentence is unchanged. The two phrases that `TestCARotationBackendSteps/software_key_after_restore` pins stay.

**Wrapping.** Each text is wrapped to the lines around it: rows continue with six spaces, piv.md's bullet with two. `git diff --word-diff=plain` over the three documents shows only the words above as changed. The custody.md sentence part gains a line: its new fourth line ("only once the restore section of") is short, because the next line, the signer-install.md link, was already a line of its own and stays unchanged.

## The facts, as found before the first edit

Each was read at 35d960b before the first commit.

**internal/keystore/piv/piv.go:**

- **`generationSlot` (line 364).** Generation 0 is `ErrBadLocation`. Generation 1 is the role's own slot (`slotFor`) and refuses any location with `ErrBadLocation` ("generation 1 of role %s is in slot %s and takes no location"). Generation 2 or later goes to `parseLocation`.
- **`parseLocation` (line 346).** It accepts exactly one of the strings "87" to "95" (`firstGenerationSlot = 0x87`, `lastGenerationSlot = 0x95`, line 144). Every other string is `ErrBadLocation`.
- **`Holds` (line 637).** It returns `true` with the error when `generationSlot` fails or `slotKey` cannot read the slot. Otherwise it returns `pub != nil && fingerprint matches`: an empty slot (`slotKey` maps `ErrNotFound` to nil, line 403) or another key is not held.
- **`RemoveGeneration` (line 660).** It writes only after the slot's key has the draining fingerprint. An empty slot returns with no write, and another key is `ErrSlotHoldsAnotherKey`. The management key is read right before the write.

**internal/tlog/leaf.go:** `CAGenerationBody` (line 609) has the fields Role, Generation, PublicKey, Alg and Custody. It has no location field.

**`--key` and the tpm backend:**

- cmd/keyroster-signer/rotate.go line 145, the flag's help text: "agent; software and tpm: a key file you placed; piv refuses it".
- signer-install.md "Prepare a CA key generation": "tpm accepts it only for a key file you placed, which must carry noDA".

**cmd/keyroster-signer/doctor.go:**

- `generationFiles` (line 305) matches `^(user|host|machine|ops|log)-g([0-9]{1,10})\.(tpmkey|auth)$` in `{state-dir}/tpm`.
- `unrecordedGenerationFiles` (line 318) reports the names with N of at least 2 that no row names.
- doctor's warning (internal/doctor/doctor.go line 416) carries "if no prepare is running and a restore preceded it".

**The tests that the new paragraph names:**

- `TestDoctorUnrecordedGenerationFile` has the leaf `tpm_stray_files_warn`. It writes empty files into a bootstrapped state directory and needs no TPM.
- `TestTPMProvisionGenerationRefusals` (internal/keystore/tpm/tpm_test.go line 769) starts swtpm (`startSWTPM`). Its existing-file leaves check the refusal's lost-prepare hint.

**signer-install.md "Prepare a CA key generation":**

- The tpm paragraph says "because where that section stops on a lost generation the pair may hold that generation's key".
- The piv paragraph says "only when the rule of piv.md "Generation slots" allows it".
- The software paragraph says "when no prepare is running"; the tpm paragraph does not.

**docs/backends/piv.md:**

- "Generation slots" says "Overwriting the slot by hand does not clear it, because the slot stays occupied".
- Step 5 shreds the management key file on every exit status and says that `shred` does not reliably erase a file on an SSD or a copy-on-write filesystem.

**Nothing reads the changed lines.** `git grep -F` of the old and new clauses over `*.go`, `scripts/`, `.github/` and `test/` had one hit: a comment in cmd/keyroster-signer/doctor_test.go line 292 ("pair that no generation row names"), which describes that test and reads no document. The tests that read these documents read other parts of them:

- runbook_test.go reads piv.md step 5 and "Generation slots", and custody.md "Software CA keys (KEY-06)".
- internal/custodytext reads custody.md's banner, at line 198, away from the edits.

**The pinned phrases were absent.** Each leaf had at least one required phrase that was absent from its section before the edit, so the RED is real. "These are tracked in" was already in piv.md at 35d960b and is pinned so that the sentence stays; that leaf's RED came from the narrow clause and from the forbidden phrase. (Corrected after the pre-merge review: the first form of this SUMMARY said that every pinned phrase was absent.)

**Fix round, read at f61b9da before the first edit of the round:**

- `ProvisionGeneration` (internal/keystore/piv/piv.go line 492) compares no fingerprint. It refuses a malformed or repeated location of the rows ("the generation rows' location %q is refused (edited rows?)"), takes the first slot from 0x87 to 0x95 that no row's location names, refuses when that slot holds a key (`occupied`, `ErrSlotOccupied`) or cannot be read, and generates only then.
- prepare (internal/signer/rotate.go lines 152 to 167) passes every non-empty location of every row, of every role, as `used`.
- `RemoveGeneration` is as read before: it overwrites only after the slot's key has the draining fingerprint.

**The gate line.** Line 674 of .planning/phases/03-linux-agent-and-revocation/03-12f-PLAN.md is the full gate.

## piv.md's needs-hardware list against the checklist, bullet by bullet

1. **The card through `pcscd`, selection by serial, and the piv-go calls with the PIN retry counter read** (yubikey.go). Rows:
   - a user other than the signer user cannot use the card through `pcscd`;
   - two YubiKeys with and without `serial`;
   - the PIN retry guard row, which reads the counter with piv-go `Retries()`.

   The section's CI stand-in paragraph also names yubikey.go.
2. **piv-go's own code on a real card.** Rows:
   - GET METADATA on an empty slot: `ykman piv keys info 82` before `ca-init`, with `ErrNotFound`;
   - key generation: the `ca-init` row and the slot rows for 82 to 86;
   - Ed25519 and ECDSA signatures: the algorithm line per firmware, then issuing and logging in on a real sshd;
   - a session logged in once keeps signing PIN-once keys: the restart row and the day-long session row.
3. **Every `ykman`, `pcscd` and polkit step.** Rows:
   - "Follow docs/backends/piv.md steps 1-3 exactly";
   - the CI stand-in paragraph ("every `ykman`, `pcscd` and polkit step");
   - the `ykman` rows of the generation block.
4. **The generation slots.** The block "CA key generations":
   - generating into 0x87 to 0x95: the 0x87 prepare row and the 0x88 row;
   - signing after a reopen in a separate process: the restart row;
   - the algorithm per firmware: the prepare row;
   - the card's answer to a wrong management key: the management key row;
   - `ykman piv keys delete` and `ykman piv reset`: the unrecorded-key row;
   - the 15-slot exhaustion: its row;
   - deletion not implemented: its row.

   Some clauses of this bullet are covered only in part (the first form of this SUMMARY counted three; the review named more, and each was checked against the tree at f61b9da):
   - that an overwrite is atomic and destroys the old private key: only the row "retire-key overwrites the draining slot", and piv.md calls this Yubico's documented behaviour, not observed;
   - reading a slot's metadata when it is empty, overwritten or never used: the row "Holds reads the slot's metadata in the PIN-verified session", and the empty check of slot 82 before `ca-init`;
   - PIN once across processes: the restart row and the day-long session row;
   - generating into the slots beyond the two that have rows: only 0x87 (the prepare row) and 0x88 (the next-prepare row) have rows; 0x89 to 0x95 have none;
   - `ykman piv reset`: named only inside the parenthesis of the unrecorded-key row ("below 5.7 only `ykman piv reset`, which destroys every CA key"), with no step of its own;
   - the 15-slot exhaustion on a real card: its row says "checked on the fake card only" and asks for no run on a card.

   This task does not change these rows.
5. **A key in a generation slot that no row records.** The unrecorded-key row. It now also says that overwriting the slot by hand does not clear it. The bullet's "for every role" (the key stops PIV rotation for every role) has no row.
6. **The management key file is shredded, not proven erased.** The management key row. It now says so.
7. **The location column is not logged.** The new last row.

## Left unchanged on purpose

- **docs/runbooks/ca-rotation.md, "What this guarantees and what it does not", the bullet "The location column is not logged."** It keeps both older wordings: "is stopped by the fingerprint checks before any card write" and "an edit that points at any slot that does not hold the draining key makes the signer's check answer "not held"". Each says more than the code does, not less, and both are left for a later change to that runbook.
- **docs/runbooks/signer-install.md, "Prepare a CA key generation", the tpm paragraph.** It has no "no prepare is running" guard, while the software paragraph has one. It is left for a later change to that runbook.
- **needs-hardware.md's rows for the other bullets of piv.md's list.** Compared row by row above, each bullet has its rows. They are not changed, and the clauses covered only in part are named above.
- **The limit itself.** `Holds` and the log are as they were. The limit stays a later hardening item, as the 03-12f SUMMARY records.
- **The fixed files.** runbook_test.go, hosttrust_runbook_test.go, the four runbooks (ca-rotation, signer-install, enroll-user, machine-identities), CONTRIBUTING.md, the e2e workflow, ROADMAP.md and STATE.md do not change.

## The test

`TestSecurityDocs` (cmd/keyroster/securitydocs_test.go) is a new file in package main. It uses `sectionWindow`, `signingSection` and `normalizeSpace` of runbook_test.go and `readTestFile` of trust_test.go as they are. Its own `window` and `holds` closures have the form of those in `TestCARotationBackendSteps`. A third small closure, `doc`, reads a document under the repository root. Since the fix round (ff622ed) each text is read in its own row, bullet or paragraph, cut with `sectionWindow`'s `within`, `start` and `endNext` as `TestCARotationBackendSteps` uses them, white-space normalised; the software sentence is read in its section. The checklist is read with its boxes unticked: "- [x] " is replaced by "- [ ] " before any window is cut, so that a ticked box moves no window and breaks no start marker. The location sentence (from "after a database edit" to its end) is one constant, used by both piv leaves.

| Leaf | Window | Must hold |
|------|--------|-----------|
| `tpm_pair_after_restore` | custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)", the paragraph from the line beginning "A `{role}-g<N>.tpmkey` and `.auth` pair" to the next blank line | "A `{role}-g<N>.tpmkey` and `.auth` pair that no generation row names (doctor warns `unrecorded_generation_file`) is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare, to be destroyed and not recorded again, but after a restore only once the restore section of"; "has run to its end, because where that section stops on a lost generation the pair may hold that generation's key"; "the rule itself is UNVERIFIED on a physical TPM and on the homelab vTPM signer" |
| `software_file_while_no_prepare_runs` | custody.md "Software CA keys (KEY-06)" | "one that no generation row names is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare, to be destroyed and not recorded again, but after a restore only once the restore section of" |
| `piv_limits_tracked` | needs-hardware.md "2. YubiKey 5 PIV (KEY-05)", inside it the block from the line beginning "CA key generations (docs/backends/piv.md" to the section's end, inside it three rows, each from its start to the next line that begins "- [ ] " or is blank | the management key row: "shredded on every exit status (shredded, not proven erased: `shred` does not reliably erase a file on an SSD or a copy-on-write filesystem)"; the row starting "- [ ] A key in the next generation slot that no row records": "is refused `ErrSlotOccupied`, and overwriting the slot by hand does not clear it. It is emptied with `ykman piv keys delete <slot>` on 5.7 and later, only when the rule of piv.md "Generation slots" allows it, with the signer stopped"; the location row: "The location column is not logged (a later hardening item): " followed by the location sentence |
| `piv_location_limit` | piv.md "What CI verifies, and what needs hardware", and inside it the bullet from the line beginning "- the location column is not logged" to the next line that begins "- " or is blank | the bullet: "the location column is not logged: " followed by the location sentence; the section: "These are tracked in", and neither "points at any slot" nor "is stopped by the fingerprint checks before any card write" |

The location sentence is `after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used.` The test's name does not match the runbook pattern `Runbook|CARotation|SignerInstall|MoveAside|Restore`.

The first form of the test (1413ab1, until f61b9da) read each leaf's whole section and pinned shorter phrases: for the tpm paragraph "pair that no generation row names", "when no prepare is running and unless you placed it for a `--key` prepare", "to be destroyed and not recorded again, but after a restore only once the restore section of", "has run to its end, because where that section stops on a lost generation the pair may hold that generation's key" and "the rule itself is UNVERIFIED"; for the software sentence "when no prepare is running and unless you placed it for a `--key` prepare"; for the checklist "overwriting the slot by hand does not clear it", `only when the rule of piv.md "Generation slots" allows it`, "shredded, not proven erased", "The location column is not logged" and the narrow clause `for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held"`; for piv.md the narrow clause and "These are tracked in", and not "points at any slot". The RED and the mutants of the first round below ran on that form.

## RED

This section describes the first round; the fix round's RED is under "Pre-merge review", "The fix round".

On the test commit 1413ab1 (the test file as committed there, blob 5daf57a, run in the working tree before the commit), with the three documents unchanged, `go test -count=1 -timeout 5m -v -run "^TestSecurityDocs$" ./cmd/keyroster/` failed. The failing tests were exactly the four leaves and `TestSecurityDocs`, with no build or setup failure and no SKIP:

| Leaf | Assertions that failed |
|------|------------------------|
| `tpm_pair_after_restore` | securitydocs_test.go:45, five times: custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)" lacks each of its five phrases |
| `software_file_while_no_prepare_runs` | securitydocs_test.go:55: custody.md "Software CA keys (KEY-06)" lacks "when no prepare is running and unless you placed it for a `--key` prepare" |
| `piv_limits_tracked` | securitydocs_test.go:61, five times: needs-hardware.md "2. YubiKey 5 PIV (KEY-05)" lacks each of its five phrases |
| `piv_location_limit` | securitydocs_test.go:71: piv.md "What CI verifies, and what needs hardware" lacks the narrow clause; securitydocs_test.go:76: it still says an edit that "points at any slot" makes Holds answer "not held" |

After 600facb all four leaves pass.

## Mutants

This section describes the first round, on the first form of the test; the fix round's mutants, and K1 to K14 again on the test of ff622ed, are under "Pre-merge review", "The fix round".

The mutants were applied one at a time to the working tree after 600facb, each by the same rule:

- the unmutated run of the same command passed first;
- `go vet ./cmd/keyroster/` exited 0 on the mutated tree;
- no `[build failed]`, `[setup failed]` or `--- SKIP:` line appeared;
- the file was restored from HEAD, and its sha256 matched the one taken before;
- `git status --short -- cmd internal test docs .github` was empty afterwards.

Every command carried `-count=1 -timeout 5m -v` and `-run "^TestSecurityDocs$/^<leaf>$"`. Each match was white-space tolerant and had to occur exactly once before the file was written.

| Mutant | Change | Result |
|--------|--------|--------|
| K1 | custody.md: the new tpm paragraph removed | killed: `tpm_pair_after_restore` lacks all five phrases (:45) |
| K2 | custody.md: the new paragraph moved, unchanged, to the end of "Software CA keys (KEY-06)" | killed: `tpm_pair_after_restore` lacks all five phrases (:45) |
| K3 | custody.md, the new paragraph: "when no prepare is running and " removed | killed: lacks "when no prepare is running and unless you placed it for a `--key` prepare" (:45) |
| K4 | custody.md, the new paragraph: the restore clause from ", but after a restore" to "that generation's key" removed | killed: lacks the two restore phrases (:45) |
| K5 | custody.md, the new paragraph: "the rule itself is UNVERIFIED on a physical TPM and on the homelab vTPM signer" replaced by "run in CI" | killed: lacks "the rule itself is UNVERIFIED" (:45) |
| K6 | custody.md, the software sentence: "when no prepare is running and " removed | killed: `software_file_while_no_prepare_runs` lacks the guard (:55) |
| K7 | needs-hardware.md: the new last row removed | killed: `piv_limits_tracked` lacks "The location column is not logged" and the narrow clause (:61) |
| K8 | needs-hardware.md: the new last row moved, unchanged, to the end of "4. Physical TPM 2.0 (KEY-04)" | killed: the same two phrases (:61) |
| K9 | needs-hardware.md: ", only when the rule of piv.md "Generation slots" allows it" removed | killed: lacks that phrase (:61) |
| K10 | needs-hardware.md: ", and overwriting the slot by hand does not clear it" removed | killed: lacks "overwriting the slot by hand does not clear it" (:61) |
| K11 | needs-hardware.md: the parenthesis "(shredded, not proven erased: ... filesystem)" removed | killed: lacks "shredded, not proven erased" (:61) |
| K12 | needs-hardware.md, the new row: the clause from "for generation 2 or later" to "draining key," replaced by "an edit that points at any slot that does not hold the draining key" | killed: lacks the narrow clause (:61) |
| K13 | piv.md: the bullet's new clause replaced by the old one | killed: `piv_location_limit` lacks the narrow clause (:71) and holds "points at any slot" (:76) |
| K14 | piv.md: the sentence "These are tracked in [needs-hardware.md](../security/needs-hardware.md) for the Phase 6 review (D-12)." removed | killed: lacks "These are tracked in" (:71) |

## Gates

This section describes the first round; the fix round's checks are under "Pre-merge review", "The fix round".

All local gates ran on 600facb through `scripts/linux.sh`, one command at a time, with nothing else running in WSL.

- **The narrow run.** `go test -count=1 -timeout 5m -v -run "^TestSecurityDocs$" ./cmd/keyroster/`: the four leaves pass.
- **The runbook pattern.** `go test -count=1 -timeout 15m -v -run "Runbook|CARotation|SignerInstall|MoveAside|Restore" ./cmd/keyroster/`: exit 0 (4.839 s). It ran 16 top-level tests, all passing, with no SKIP and no FAIL; `TestCARotationBackendSteps/software_key_after_restore` passes. `TestSecurityDocs` is not among them.
- **The race run.** `go test -race -count=1 ./cmd/keyroster/ ./internal/custodytext/`: ok (cmd/keyroster 299.594 s, internal/custodytext 1.058 s).
- **The vet, gofmt and lint legs of the full gate.** They were taken unchanged from line 674 of 03-12f-PLAN.md and chained with `&&`, exit 0 in 156 s:
  - every `go vet` form (`./...`; `-tags piv` and `-tags piv,pivfake` over internal/keystore/piv and cmd/keyroster-signer; `-tags e2e`, `"e2e e2erotation"`, `"e2e e2eprobe e2emachine"`, `"e2e systemdsmoke"`, `e2e_pkcs11` and `e2e_tpm` over test/e2e);
  - `bash -n test/systemd/smoke.sh`;
  - `test -z "$(gofmt -l .)"`;
  - the four golangci-lint passes (default, `GOOS=windows`, `GOOS=darwin`, and `--build-tags piv,pivfake`), each with 0 issues.
- **Left to CI.** These legs of line 674 were not run locally, because no non-test code changes and CI runs every package:
  - the `go test -race ./...` leg and the piv-tag `go test -race` leg;
  - `scripts/capslock-check.sh`, `scripts/dep-firewall.sh`, `scripts/testonly-firewall.sh` and `scripts/check-pinned-actions.sh`.
- **The publish scan.** It used the non-comment lines of the owner's two private pattern files, case-sensitive and case-insensitive, over the added lines of `git diff origin/main..HEAD` and over the commit messages. It found nothing. The scan for the repository's refused words, for dotted quads and for paths under a user directory also found nothing.
- **Authorship.** `git log origin/main..HEAD --format='%an <%ae> %cn'` shows only Daniel Gustafsson as author and keyroster-bot as committer, and every commit carries an SSH signature.
- **No flake re-runs were needed.**

## Commits

- c02e866 `docs(quick-261121-k7d): plan the hardware checklist rows and the tpm pair rule`
- 1413ab1 `test(docs): pin the tpm pair rule and the tracked piv limits`
- 600facb `docs(security): track the piv limits and state the tpm key pair rule`
- f61b9da `docs(quick-261121-k7d): record the documentation change` (the first form of this SUMMARY)
- 5f46b8b `docs(security): say what the card writes still do after an edited piv location` (fix round)
- ff622ed `test(docs): read each row, bullet and paragraph as a window of its own` (fix round)
- the commit that adds the pre-merge review to this SUMMARY: `docs(quick-261121-k7d): record the pre-merge review`

## UNVERIFIED

- **The checklist.** Every row of the hardware checklist is still to be run on hardware, the three new and changed rows included. This task changes what the checklist tracks, not what has been run.
- **The tpm pair rule.** It has not been exercised by a restore of a real signer. It is UNVERIFIED on a physical TPM and on the homelab vTPM signer, as the new paragraph says. CI runs what doctor and prepare print for such a pair.

## Pre-merge review

The orchestrator ran the review on the open PR at head f61b9da (2026-11-21), in a read-only detached worktree of that head, while the PR's first CI round was running. This section is written from the run's record, not from a description of what the review was meant to do.

### Who reviewed what

Eight agents in one run, and Codex:

- One lens on Opus at high effort, "texts-pins-and-record". It read in full the diff, this task's PLAN, this SUMMARY, the PR text and the new test file; it read the code and the document sections around the changed texts in part and lists the ranges. On a private copy of the tree it ran the new test, the runbook pattern (16 top-level tests, no SKIP, `TestSecurityDocs` not among them), `go vet ./cmd/keyroster/`, and eight mutants of its own. It reported eight items.
- One Codex lens at high effort (264 s, 104,979 tokens), started through a thin runner on Sonnet at low effort whose only task was to start Codex and hand back its result. It read the checkout statically and reported three items.
- Six skeptics on Sonnet at high effort: two judged the one item that the lens had rated high, one judged each of the three Codex items, and one batch skeptic judged the lens's other seven items.

The eight agents used about 798,000 tokens; Codex's own tokens come on top. The orchestrator had read the whole diff of the documents and the test, the PLAN, this SUMMARY and the PR text before the review. After it, the orchestrator read every item and every skeptic's reason, read `ProvisionGeneration`, `RemoveGeneration` and prepare's collection of the rows' locations for the one point on which two skeptics disagreed, and made the rulings below.

### Result

Eleven items. The skeptics upheld four, all at low severity, and refuted seven. No item shows a changed text that leads an operator to destroy, use or trust a key against the rules.

Of the lens's eight mutants, four were killed (the checklist row with "generation 1 or later"; the tpm guard turned into "while a prepare is running"; the tpm paragraph moved to the section on the TPM test setup; "to be destroyed" turned into "to be kept") and four survived, each named below.

What the lens verified to hold, by its own statements: the narrow location clause is exact for every edit of a generation row that the signer still loads, and no edit other than the location makes a draining key that is still on the card read as not held; `RemoveGeneration` writes only after the fingerprint matches; the tpm backend takes `--key` for a pair the operator placed; the two custody.md sentences, followed to the letter in five states (a prepare is running; a file placed for a `--key` prepare; a prepare that stopped with no restore; a restore that lost a prepare; a restore that lost a generation in use), destroy no key that a bundle names; the new texts agree with signer-install.md, doctor's warning, the prepare refusals and piv.md, apart from the two differences this task leaves for later; the two tests the new paragraph names show what it says, the first without a TPM and the second on swtpm; `CAGenerationBody` has no location field; the line numbers and facts of this SUMMARY match the tree; the commits, their subjects and their authorship match the git log; a reading of the added lines for private addresses, user paths and host names found none.

### The four upheld items

1. **The checklist leaf read the whole section, not the row** (the lens rated it high; both skeptics judged it low). With the rule pointer moved from the row on emptying a slot to the row on the management key, `piv_limits_tracked` still passed (the lens's first surviving mutant). Ruling: taken up. Each of the three rows is now read as a window of its own inside the block "CA key generations", and the new paragraph and the bullet likewise.
2. **"is stopped by the fingerprint checks before any card write" said more than the code does** (Codex rated it medium; its skeptic judged it low). The lens raised the same point at low and the batch skeptic refuted it there, so the orchestrator read the code: `RemoveGeneration` overwrites a slot only when its key has the draining fingerprint, and `ProvisionGeneration` compares no fingerprint: it skips the slots the rows record and generates only into a slot that reads as empty. An edited location can therefore make prepare use another free slot, and no key is written over. Ruling: upheld. The new row and piv.md's bullet now say what the two commands do; ca-rotation.md's bullet keeps the older words and is named under "Left unchanged on purpose".
3. **This SUMMARY said that every pinned phrase was absent before the edit** (Codex, low). "These are tracked in" was already in piv.md; that leaf's RED came from the narrow clause and from the forbidden phrase. Corrected under "The facts".
4. **Two more statements of the record** (the lens, low; the batch skeptic upheld two of its three parts). The PR text said every mutant removed, moved or widened a new text, and K14 removes a sentence that was there before. The comparison of piv.md's list with the checklist counted three clauses as covered only in part; the lens named more (the skeptic called that a matter of reading). Ruling: both corrected; the comparison no longer gives a count and names the further clauses.

### The seven refuted items, and the orchestrator's rulings

- **The software leaf did not pin "one that no generation row names"** (Codex, medium): with "one that a generation row names" both leaves that read that sentence passed. Refuted as a gap in older text that this task did not change. Ruling: taken up; the leaf now holds the sentence from that condition to the restore condition as one phrase.
- **The software leaf's phrase was not tied to the `.age` sentence** (the lens, low). Refuted. Ruling: closed by the same change.
- **The location row could move out of the block "CA key generations"** (the lens, low; its second surviving mutant). Refuted. Ruling: taken up with item 1: the rows are read inside the block.
- **A negated bullet passed** (the lens, medium; its third surviving mutant, the clause prefixed with "it is no longer the case that"). Refuted as a property of every phrase pin. Ruling: taken up for the location sentence, which is now pinned as one phrase from its first word in both documents.
- **A contradicting sentence added beside the tpm rule passed** (the lens, low; its fourth surviving mutant). Refuted for the same reason. Ruling: not closed; a pin cannot see a sentence added beside the one it holds.
- **The clause "overwriting the slot by hand does not clear it" stands in a row a tester ticks, without the rule** (the lens, medium). Refuted: section 2 of the checklist is run on two cards that the tester initialises with `ca-init` for it, and `ca-init` refuses a card that already holds a key in a role slot, so the key in the generation slot is one the tester put there. Ruling: no change.
- **The fingerprint wording** (the lens, low): the same point as upheld item 2, refuted by the batch skeptic; see there.

### Recorded, not changed

- The lens did not check: the race runs and the lint passes (taken from this SUMMARY), the validity of the commit signatures (it saw that each commit carries one), the executor's fourteen mutants (it ran its own), and the publish scan with the owner's private pattern files. It read the Go files and the longer documents in part.
- Codex ran no test: its sandbox is read-only.

### The fix round

Two commits. No product code changes, and custody.md does not change in this round.

- **5f46b8b `docs(security): say what the card writes still do after an edited piv location`.** It changes docs/backends/piv.md's last bullet of the needs-hardware list and the last row of needs-hardware.md's block "CA key generations".
  - The sentence no longer says that an edited location "is stopped by the fingerprint checks before any card write".
  - From "after a database edit" to its end, it is now the same in both documents: "after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used."
  - Each document is wrapped as the lines around it, and no other line changes.
  - After this commit the test of f61b9da still passed (its phrases stay).
- **ff622ed `test(docs): read each row, bullet and paragraph as a window of its own`.** It changes cmd/keyroster/securitydocs_test.go only.
  - The windows and phrases are those of "The test" above.
  - The location sentence is one constant.
  - The checklist is read with its boxes unticked.
  - The software leaf holds the sentence from "one that no generation row names" to the restore condition as one phrase.
  - The doc comment says that each text is read in its own row, bullet or paragraph.
  - gofmt lists nothing, and `go vet ./cmd/keyroster/` exits 0.

**The RED of the new test.** It ran on f61b9da's documents, before ff622ed was committed: the two documents of 5f46b8b were restored from f61b9da in the working tree only, and the new test was run.

- `piv_limits_tracked` failed at securitydocs_test.go:83: the location row lacks "The location column is not logged (a later hardening item): " followed by the location sentence.
- `piv_location_limit` failed twice:
  - securitydocs_test.go:92: the bullet lacks "the location column is not logged: " followed by the location sentence;
  - securitydocs_test.go:99: the section still says "is stopped by the fingerprint checks before any card write".
- `tpm_pair_after_restore` and `software_file_while_no_prepare_runs` passed.
- There was no build or setup failure and no SKIP.

The two documents were then restored from HEAD, and `git status --short -- docs` was empty. On HEAD all four leaves pass.

**The mutants.** They ran after ff622ed, one at a time, by the rule of the first round:

- the unmutated run of the same command passed first;
- `go vet ./cmd/keyroster/` exited 0 on the mutated tree;
- no `[build failed]`, `[setup failed]` or `--- SKIP:` line appeared;
- each file was restored from HEAD, and its sha256 matched the one taken before (the test file's as well);
- `git status --short -- cmd internal test docs .github` was empty afterwards;
- `-count=1 -timeout 5m -v` and `-run "^TestSecurityDocs$/^<leaf>$"`;
- each match white-space tolerant and found exactly once before the file was written.

**F1 to F4 on the test's earlier form.** They are the review's mutants. Each was first run on the test file of f61b9da, restored in the working tree only, with the documents of HEAD; F3 there ran with the bullet of HEAD. On that form each one passed its leaf.

| Mutant | Change | On f61b9da's test | On ff622ed's test |
|--------|--------|-------------------|-------------------|
| F1 | needs-hardware.md: ", only when the rule of piv.md "Generation slots" allows it" moved from the row on a key that no row records to the end of the management key row | passed the leaf | killed: the row on a key that no row records lacks its phrase (:80) |
| F2 | needs-hardware.md: the location row moved, unchanged, out of the block into the per-card list, after the row on attestation evidence | passed the leaf | killed: the start marker "- [ ] The location column is not logged" occurs 0 times in the block (:74) |
| F3 | piv.md: the bullet's clause prefixed: "but it is no longer the case that for generation 2 or later ..." | passed the leaf | killed: the bullet lacks the location sentence (:92) |
| F4 | custody.md, the software sentence: "one that no generation row names" replaced by "one that a generation row names" | passed the leaf | killed: the section lacks the sentence's phrase (:60) |
| F5 | needs-hardware.md: the parenthesis "(shredded, not proven erased: ... filesystem)" moved from the management key row to the end of the row "serve, `install-bundle` and doctor with the management-key file absent." | | killed: the management key row lacks its phrase (:77) |
| F6 | piv.md, the bullet: the words from "after a database edit" to "so no other key is written over," replaced by "a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write," | | killed: the bullet lacks the location sentence (:92), and the section holds "is stopped by the fingerprint checks before any card write" (:99) |
| F7 | needs-hardware.md, the location row: the same replacement | | killed: the location row lacks its phrase (:83) |
| K1 | custody.md: the new tpm paragraph removed | | killed: the paragraph's start marker occurs 0 times (:50) |
| K2 | custody.md: the new paragraph moved, unchanged, to the end of "Software CA keys (KEY-06)" | | killed: the start marker occurs 0 times in the TPM section (:50) |
| K3 | custody.md, the new paragraph: "when no prepare is running and " removed (anchored as in the first round) | | killed: the paragraph lacks its first phrase (:52) |
| K4 | custody.md, the new paragraph: the restore clause removed | | killed: the paragraph lacks its first and second phrases (:52) |
| K5 | custody.md, the new paragraph: "the rule itself is UNVERIFIED on a physical TPM and on the homelab vTPM signer" replaced by "run in CI" | | killed: the paragraph lacks its third phrase (:52) |
| K6 | custody.md, the software sentence: "when no prepare is running and " removed (anchored as in the first round) | | killed: the section lacks the sentence's phrase (:60) |
| K7 | needs-hardware.md: the location row removed | | killed: its start marker occurs 0 times in the block (:74) |
| K8 | needs-hardware.md: the location row moved, unchanged, to the end of "4. Physical TPM 2.0 (KEY-04)" | | killed: its start marker occurs 0 times in the block (:74) |
| K9 | needs-hardware.md: ", only when the rule of piv.md "Generation slots" allows it" removed | | killed: the row on a key that no row records lacks its phrase (:80) |
| K10 | needs-hardware.md: ", and overwriting the slot by hand does not clear it" removed | | killed: the same row lacks its phrase (:80) |
| K11 | needs-hardware.md: the parenthesis "(shredded, not proven erased: ... filesystem)" removed | | killed: the management key row lacks its phrase (:77) |
| K12 | needs-hardware.md, the location row: inside the location sentence, the clause from "for generation 2 or later" to "draining key," replaced by "an edit that points at any slot that does not hold the draining key" | | killed: the location row lacks its phrase (:83) |
| K13 | piv.md, the bullet: inside the location sentence, the same clause and "makes" replaced by the old clause | | killed: the bullet lacks the location sentence (:92), and the section holds "points at any slot" (:99) |
| K14 | piv.md: the sentence "These are tracked in [needs-hardware.md](../security/needs-hardware.md) for the Phase 6 review (D-12)." removed (it was there before this task) | | killed: the section lacks "These are tracked in" (:96) |

**The control and the survivor.**

- **The control C1 must pass.** It ticks the boxes of the three rows in needs-hardware.md ("- [x] "). `piv_limits_tracked` passes.
- **One mutant survives, and is recorded, not closed.** This is the lens's fourth mutant. It adds a contradicting sentence inside the new tpm paragraph, after "homelab vTPM signer).": "Such a pair may always be destroyed at once, even after a restore." `tpm_pair_after_restore` passes, as the review's ruling expects: a pin cannot see a sentence added beside the one it holds.

**The checks of the fix round.** They ran on ff622ed through `scripts/linux.sh`, one Go command at a time:

- **The narrow run** of `TestSecurityDocs`: the four leaves pass.
- **The runbook pattern** `go test -count=1 -timeout 15m -v -run "Runbook|CARotation|SignerInstall|MoveAside|Restore" ./cmd/keyroster/`: exit 0 (2.888 s). 16 top-level tests pass, with no SKIP and no FAIL; `TestCARotationBackendSteps/software_key_after_restore` passes, and `TestSecurityDocs` is not among them.
- **The race run** `go test -race -count=1 ./cmd/keyroster/ ./internal/custodytext/`: ok (cmd/keyroster 280.620 s, internal/custodytext 1.034 s).
- **The gofmt, vet and golangci-lint legs** of line 674 of 03-12f-PLAN.md, in the form of the first round: every `go vet` form, `bash -n test/systemd/smoke.sh`, `test -z "$(gofmt -l .)"` and the four golangci-lint passes, chained with `&&`: exit 0 in 120 s, 0 issues in each lint pass. The long `go test -race ./...` leg, the piv-tag `go test -race` leg, capslock and the firewalls were left to CI, as in the first round.
- **The publish scan** used the owner's two private pattern files, over the added lines of `git diff origin/main..HEAD` and the commit messages. It found nothing, and neither did the word, dotted-quad and user-path scan.
- **Authorship.** Daniel Gustafsson is the only author and keyroster-bot the only committer. `git diff --stat origin/main..HEAD` lists exactly the six files of the first round.

**The first round's CI.** It ran on f61b9da with all 30 required checks green and no rerun. The runs were 44897343583, 44897343587, 44897343617, 44897343635, 44897343638, 44897343652, 44897343666, 44897343687, 44897343688 and 44897343798. The `go test` times of the lanes were:

| Lane | Time |
|------|------|
| e2e (10.5p1) | 803.372 s |
| e2e (9.5p1) | 765.288 s |
| e2e-rotation (10.5p1) | 533.104 s |
| e2e-rotation (9.5p1) | 541.466 s |

The orchestrator's rulings on this session's two deviations (the longer anchors for K3 and K6; the third closure of the test) are that both are accepted as recorded.

## Deviations from Plan

1. **K3 and K6 were matched with longer anchors.** After 600facb, the words that both mutants remove ("when no prepare is running and ") occur twice in custody.md: once in the tpm paragraph and once in the software sentence. Each mutant therefore matched them together with words that occur once:
   - K3: "(doctor warns `unrecorded_generation_file`) is, when no prepare is running and unless";
   - K6: "row names is, when no prepare is running and unless".

   The mutation itself is unchanged. The other mutants match their own words, each exactly once.
2. **The test has a third small closure.** Besides `window` and `holds`, in the form of `TestCARotationBackendSteps`, the test has `doc`, which reads a document under the repository root through `readTestFile`. It only shortens the four reads.

## Known Stubs

None.
