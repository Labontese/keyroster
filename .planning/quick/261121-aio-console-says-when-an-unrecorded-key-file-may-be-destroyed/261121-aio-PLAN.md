---
phase: quick-261121-aio
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
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
autonomous: true
requirements: []
must_haves:
  truths:
    - "doctor's unrecorded_generation_file warning, printed for software and tpm files alike, says to destroy an unrecorded later-generation key file only once the restore section of docs/runbooks/signer-install.md has run to its end, and to keep it where that section stops on a lost generation, because it may hold that generation's key. \"never record it again with --key\" stays, behind a semicolon, so that it does not read as waiting for the restore section."
    - "The software backend's ProvisionGeneration refusal over an existing <role>-g<N>.age file carries the same condition and the same last clause; the tpm backend's refusal over an existing .tpmkey or .auth file, which had the condition since 03-12f, gains the same last clause. The software and the tpm hint differ only in the file names."
    - "The last sentence of the tpm paragraph of signer-install.md \"Prepare a CA key generation\" says what these console texts say, for both backends: destroy such a file only once the restore section has run to its end, and keep it where that section stops on a lost generation."
    - "Every edit in a non-test Go file is inside a string literal or a comment: no behaviour changes. The comments of Facts.UnrecordedGenerationFiles and generationResults name the tpm files too, and the comments of both backends' ErrKeyFilesExist name ProvisionGeneration too."
    - "Tests pin each text: the doctor warning (internal/doctor and the printed line of cmd/keyroster-signer doctor, for a software file and a tpm pair), both ProvisionGeneration refusals, and the runbook sentence with the phrases around it. The test commit fails exactly on these leaves before the code and the document change."
    - "Left unchanged on purpose: piv.go's ErrSlotOccupied text, the ca-init hints \"remove %s only if no trust bundle uses these keys\", rotate.go's orphaned text, and needs-hardware.md's checklist line on a planted key in a generation slot. No ROADMAP.md or STATE.md change."
---

<objective>
A later-generation key file that no generation row names is normally the leftover of a prepare that a restore lost, and the operator destroys it. After a restore that lost a generation row, the same file can hold the key of a generation that is still in use, so the runbook lets it go only once the restore section has run to its end. Of the three console texts that state this rule, only the tpm refusal carried that condition (03-12f). Give the doctor warning and the software refusal the same condition, give all three the clause that says to keep the file where the restore section stops on a lost generation, and make the runbook sentence that describes them say the same.
</objective>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: pin the texts (RED)</name>
  <files>internal/doctor/doctor_test.go, internal/keystore/software/software_test.go, internal/keystore/tpm/tpm_test.go, cmd/keyroster-signer/doctor_test.go, cmd/keyroster/runbook_test.go</files>
  <action>TestDoctorGenerationFiles/warn_text_states_the_conditions requires the condition directly before "destroy it", the keep clause and "never record it again with --key". TestProvisionGeneration/refuses_existing_file requires the lost-prepare hint, the condition and the keep clause. Both TestTPMProvisionGenerationRefusals existing-file leaves require the keep clause. Both TestDoctorUnrecordedGenerationFile stray-file leaves require the condition in doctor's printed line. A new leaf TestCARotationBackendSteps/unrecorded_key_files_after_restore pins the new runbook sentence, the absence of the old one, the two "but only after the restore section has run to its end" of the software and tpm paragraphs, and the two phrases of the restore section. Run each package's leaves and record every FAIL.</action>
  <verify><automated>bash scripts/linux.sh 'go test -count=1 -v -run "TestDoctorGenerationFiles" ./internal/doctor/ ; go test -count=1 -v -run "TestProvisionGeneration" ./internal/keystore/software/ ; KEYROSTER_TPM_REQUIRE=1 go test -count=1 -v -run "TestTPMProvisionGenerationRefusals" ./internal/keystore/tpm/ ; go test -count=1 -v -run "TestDoctorUnrecordedGenerationFile" ./cmd/keyroster-signer/ ; go test -count=1 -v -run "TestCARotationBackendSteps" ./cmd/keyroster/'</automated></verify>
  <done>The FAIL lines are exactly the seven leaves above and their parents; no build failure, no SKIP.</done>
</task>

<task type="auto">
  <name>Task 2: the console texts and their comments</name>
  <files>internal/doctor/doctor.go, internal/keystore/software/software.go, internal/keystore/tpm/provision.go, internal/keystore/tpm/tpm.go</files>
  <action>Replace the three format strings and the four comments. Change nothing outside string literals and comments.</action>
  <verify><automated>the Task 1 command: every leaf passes except the runbook leaf</automated></verify>
</task>

<task type="auto">
  <name>Task 3: the runbook sentence</name>
  <files>docs/runbooks/signer-install.md</files>
  <action>Replace the last sentence of the tpm paragraph of "Prepare a CA key generation" and rewrap that paragraph; change nothing else in the file.</action>
  <verify><automated>bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "Runbook|CARotation|SignerInstall|MoveAside|Restore" ./cmd/keyroster/'</automated></verify>
  <done>Every top-level test passes with no SKIP. Then the mutants: each removes one clause of a text or one pinned phrase of the runbook and must fail its leaf. Then the full gate of 03-12f's Task 6 (03-12f-PLAN.md line 674), the publish scan with the owner's private pattern files, and the authorship check.</done>
</task>

</tasks>
