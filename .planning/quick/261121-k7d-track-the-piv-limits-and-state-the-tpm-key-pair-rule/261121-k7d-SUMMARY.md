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
  - "Both custody.md sentences on an unrecorded key file carry the guard \"when no prepare is running\", as doctor's warning and signer-install.md's software paragraph do."
  - "ca-rotation.md's bullet on the location column and signer-install.md's tpm paragraph are left for a later change to those runbooks."
requirements: []
metrics:
  completed: 2026-11-21
actuals:
  tokens: 9600
  tasks: 2
  commits: 3
plan_head_before: 35d960b
plan_head_after: 600facb
---

# Quick 261121-k7d Plan 01: the hardware checklist tracks the PIV limits, and custody.md states the tpm pair rule Summary

docs/security/needs-hardware.md now has a row for each limit that the needs-hardware list of docs/backends/piv.md says it tracks. The checklist row on emptying a generation slot now names the rule of piv.md "Generation slots". piv.md and the new row state the location limit as narrowly as `Holds` has it. docs/security/custody.md now states the rule for an unrecorded tpm key pair, and both of its sentences on an unrecorded key file carry the guard "when no prepare is running". No product code changes.

The commits are c02e866 (the plan), 1413ab1 (the test, RED) and 600facb (the three documents). The commit that adds this SUMMARY follows them. `commits: 3` is `git rev-list --count 35d960b..600facb`, measured before this SUMMARY was committed; `plan_head_after` is 600facb.

## Why

1. **piv.md's list had untracked limits.** docs/backends/piv.md, "What CI verifies, and what needs hardware", ends its needs-hardware list with "These are tracked in needs-hardware.md for the Phase 6 review (D-12)." The list's last bullet (the location column is not logged) had no row in the checklist. Two other bullets each had a row that left out one clause: "overwriting the slot by hand does not clear it", and that the management key file is "shredded, not proven erased".
2. **The row on emptying a slot left out the rule.** The checklist row on a key in a generation slot that no row records said the slot "is emptied with `ykman piv keys delete <slot>`". It did not say that this is allowed only by the rule of piv.md "Generation slots". signer-install.md says so: "only when the rule of piv.md "Generation slots" allows it".
3. **custody.md had no tpm pair rule.** It stated the rule for a software key file that no generation row names ("Software CA keys (KEY-06)"), but had no such rule for a tpm pair in "TPM and vTPM (KEY-04, D-07, D-08, D-09)". signer-install.md has the rule for both backends, and doctor and prepare print it for both.
4. **piv.md's location sentence was wider than the code.** It said "an edit that points at any slot that does not hold the draining key makes Holds answer "not held"". The code is narrower. Only a row of generation 2 or later that points at another generation slot, one that reads as empty or as another key, makes `Holds` answer "not held".
5. **custody.md's software sentence lacked the "no prepare is running" guard.** It said a file that no generation row names "is, unless you placed it for a `--key` prepare, a key from a lost prepare". While a prepare runs, its file exists before its row. doctor's warning and signer-install.md's software paragraph carry the guard "no prepare is running", and both custody.md sentences now carry it.

## The texts

**docs/security/needs-hardware.md, section "2. YubiKey 5 PIV (KEY-05)", block "CA key generations":**

- **The management key row.**
  - Before: "- [ ] The management key placed for the run by the block of piv.md step 5 and shredded on every exit status; retire-key without it refused naming `mgmt-key-file`; the card's answer to a wrong management key."
  - After: "- [ ] The management key placed for the run by the block of piv.md step 5 and shredded on every exit status (shredded, not proven erased: `shred` does not reliably erase a file on an SSD or a copy-on-write filesystem); retire-key without it refused naming `mgmt-key-file`; the card's answer to a wrong management key."
- **The row on a key that no row records.**
  - Before: "- [ ] A key in the next generation slot that no row records is refused `ErrSlotOccupied`, and is emptied with `ykman piv keys delete <slot>` on 5.7 and later, with the signer stopped and the management key given at `ykman`'s prompt (below 5.7 only `ykman piv reset`, which destroys every CA key)."
  - After: "- [ ] A key in the next generation slot that no row records is refused `ErrSlotOccupied`, and overwriting the slot by hand does not clear it. It is emptied with `ykman piv keys delete <slot>` on 5.7 and later, only when the rule of piv.md "Generation slots" allows it, with the signer stopped and the management key given at `ykman`'s prompt (below 5.7 only `ykman piv reset`, which destroys every CA key)."
- **New last row of the block.** It comes after "The 15-slot exhaustion" and before the blank line above "## 3. Hardware root ceremony (D-11)": "- [ ] The location column is not logged (a later hardening item): a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used."

**docs/backends/piv.md, the last bullet of the needs-hardware list:**

- Before: "- the location column is not logged: a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but an edit that points at any slot that does not hold the draining key makes Holds answer "not held", and audit cannot show which slot a generation used."
- After: "- the location column is not logged: a database edit of a PIV generation's location is stopped by the fingerprint checks before any card write, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used."

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

**The pinned phrases were absent.** Each phrase that the new test requires was absent from its section before the edit, so the RED is real.

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

   Three clauses of this bullet are covered only in part:
   - that an overwrite is atomic and destroys the old private key: only the row "retire-key overwrites the draining slot", and piv.md calls this Yubico's documented behaviour, not observed;
   - reading a slot's metadata when it is empty, overwritten or never used: the row "Holds reads the slot's metadata in the PIN-verified session", and the empty check of slot 82 before `ca-init`;
   - PIN once across processes: the restart row and the day-long session row.

   This task does not change these rows.
5. **A key in a generation slot that no row records.** The unrecorded-key row. It now also says that overwriting the slot by hand does not clear it.
6. **The management key file is shredded, not proven erased.** The management key row. It now says so.
7. **The location column is not logged.** The new last row.

## Left unchanged on purpose

- **docs/runbooks/ca-rotation.md, "What this guarantees and what it does not", the bullet "The location column is not logged."** It keeps the wider words "an edit that points at any slot that does not hold the draining key makes the signer's check answer "not held"". It says more than the code does, not less, and is left for a later change to that runbook.
- **docs/runbooks/signer-install.md, "Prepare a CA key generation", the tpm paragraph.** It has no "no prepare is running" guard, while the software paragraph has one. It is left for a later change to that runbook.
- **needs-hardware.md's rows for the other bullets of piv.md's list.** Compared row by row above, each bullet has its rows. They are not changed, and the clauses covered only in part are named above.
- **The limit itself.** `Holds` and the log are as they were. The limit stays a later hardening item, as the 03-12f SUMMARY records.
- **The fixed files.** runbook_test.go, hosttrust_runbook_test.go, the four runbooks (ca-rotation, signer-install, enroll-user, machine-identities), CONTRIBUTING.md, the e2e workflow, ROADMAP.md and STATE.md do not change.

## The test

`TestSecurityDocs` (cmd/keyroster/securitydocs_test.go) is a new file in package main. It uses `sectionWindow`, `signingSection` and `normalizeSpace` of runbook_test.go and `readTestFile` of trust_test.go as they are. Its own `window` and `holds` closures have the form of those in `TestCARotationBackendSteps`. A third small closure, `doc`, reads a document under the repository root. Each leaf reads one section, white-space normalised:

| Leaf | Document and section | Must hold |
|------|----------------------|-----------|
| `tpm_pair_after_restore` | custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)" | "pair that no generation row names"; "when no prepare is running and unless you placed it for a `--key` prepare"; "to be destroyed and not recorded again, but after a restore only once the restore section of"; "has run to its end, because where that section stops on a lost generation the pair may hold that generation's key"; "the rule itself is UNVERIFIED" |
| `software_file_while_no_prepare_runs` | custody.md "Software CA keys (KEY-06)" | "when no prepare is running and unless you placed it for a `--key` prepare" |
| `piv_limits_tracked` | needs-hardware.md "2. YubiKey 5 PIV (KEY-05)" | "overwriting the slot by hand does not clear it"; `only when the rule of piv.md "Generation slots" allows it`; "shredded, not proven erased"; "The location column is not logged"; the narrow clause |
| `piv_location_limit` | piv.md "What CI verifies, and what needs hardware" | the narrow clause and "These are tracked in"; and not "points at any slot" |

The narrow clause is `for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held"`. The test's name does not match the runbook pattern `Runbook|CARotation|SignerInstall|MoveAside|Restore`.

## RED

On the test commit 1413ab1, with the three documents unchanged, `go test -count=1 -timeout 5m -v -run "^TestSecurityDocs$" ./cmd/keyroster/` failed. The failing tests were exactly the four leaves and `TestSecurityDocs`, with no build or setup failure and no SKIP:

| Leaf | Assertions that failed |
|------|------------------------|
| `tpm_pair_after_restore` | securitydocs_test.go:45, five times: custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)" lacks each of its five phrases |
| `software_file_while_no_prepare_runs` | securitydocs_test.go:55: custody.md "Software CA keys (KEY-06)" lacks "when no prepare is running and unless you placed it for a `--key` prepare" |
| `piv_limits_tracked` | securitydocs_test.go:61, five times: needs-hardware.md "2. YubiKey 5 PIV (KEY-05)" lacks each of its five phrases |
| `piv_location_limit` | securitydocs_test.go:71: piv.md "What CI verifies, and what needs hardware" lacks the narrow clause; securitydocs_test.go:76: it still says an edit that "points at any slot" makes Holds answer "not held" |

After 600facb all four leaves pass.

## Mutants

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
- the commit that adds this SUMMARY: `docs(quick-261121-k7d): record the documentation change`

## UNVERIFIED

- **The checklist.** Every row of the hardware checklist is still to be run on hardware, the three new and changed rows included. This task changes what the checklist tracks, not what has been run.
- **The tpm pair rule.** It has not been exercised by a restore of a real signer. It is UNVERIFIED on a physical TPM and on the homelab vTPM signer, as the new paragraph says. CI runs what doctor and prepare print for such a pair.

## Deviations from Plan

1. **K3 and K6 were matched with longer anchors.** After 600facb, the words that both mutants remove ("when no prepare is running and ") occur twice in custody.md: once in the tpm paragraph and once in the software sentence. Each mutant therefore matched them together with words that occur once:
   - K3: "(doctor warns `unrecorded_generation_file`) is, when no prepare is running and unless";
   - K6: "row names is, when no prepare is running and unless".

   The mutation itself is unchanged. The other mutants match their own words, each exactly once.
2. **The test has a third small closure.** Besides `window` and `holds`, in the form of `TestCARotationBackendSteps`, the test has `doc`, which reads a document under the repository root through `readTestFile`. It only shortens the four reads.

## Known Stubs

None.
