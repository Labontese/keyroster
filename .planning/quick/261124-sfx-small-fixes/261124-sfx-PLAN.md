---
phase: quick-261124-sfx
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - scripts/merge-gate.sh
  - CONTRIBUTING.md
  - .planning/phases/01-trust-core/01-SKELETON.md
  - test/distro/run-in.sh
  - internal/server/session_test.go
  - internal/serverclient/client_test.go
  - cmd/keyroster/knownhosts_test.go
  - internal/agent/fetch/fetch_test.go
  - internal/signer/log_test.go
  - test/e2e/hosttrust_test.go
  - test/e2e/hostcert_test.go
  - test/e2e/agent_enroll_test.go
  - test/e2e/agent_status_test.go
  - test/e2e/login_test.go
  - test/e2e/revoke_test.go
  - test/e2e/roles_test.go
  - test/e2e/ca_rotation_test.go
  - test/e2e/stall_test.go
  - docs/runbooks/ca-rotation.md
  - docs/runbooks/signer-install.md
  - cmd/keyroster/securitydocs_test.go
  - cmd/keyroster/runbook_test.go
autonomous: true
requirements: []
must_haves:
  truths:
    - "The merge gate's header, its message after a green rebase, CONTRIBUTING.md and 01-SKELETON.md no longer say that GitHub always dismisses the approval after a rebase: they say to run the gate again, which exits 2 when the owner must approve the new head. The script's control flow does not change."
    - "The Arch lane of test/distro/run-in.sh tries its one pacman sync at most three times, 30 s apart, over the same snapshot mirror and package, with pacman.conf untouched."
    - "Four unit tests no longer depend on random text or on load: the absence check of bob's name on alice's account page, the decode-message form of json_errors_in_own_words, the CA lines' names of names_are_principals_not_entry_names, the bound of more_repolls_immediately and the clock of TestCheckLogAgainstLiveSigner. Each changed assertion still fails its mutant."
    - "Nine end-to-end retry helpers whose callers run a command of three admin requests wait 3 s before a retry, not 2 s. No bound, deadline or anchor of a timed test changes."
    - "ca-rotation.md's bullet on the location column says what the PIV backend does, signer-install.md's tpm paragraph carries the software paragraph's guard, and both are pinned. CONTRIBUTING.md's e2e-rotation row names the third client."
    - "No product code changes. No ROADMAP or STATE change."
---

<objective>
Ten small fixes collected over the last weeks, each read at 2d61b55 before it is changed: the merge gate's texts on an approval after a rebase (item 1), a bounded retry of the Arch lane's package sync (item 2), four unit tests whose checks depend on random text or on load (items 3 to 6), the end-to-end helpers' wait before a rate-limited command is retried (item 7), and three documentation passages (items 8, 9 and 13). Tests, documents, comments, one message of scripts/merge-gate.sh and one CI helper script change; no product code.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: the unit tests (items 3 to 6)</name>
  <files>internal/server/session_test.go, internal/serverclient/client_test.go, cmd/keyroster/knownhosts_test.go, internal/agent/fetch/fetch_test.go, internal/signer/log_test.go</files>
  <action>Item 3: look for "bob" on alice's account page with her two fingerprints removed. Item 4: require the whole decode message, the test's own URL, `/healthz: `, the CLI's words, the offset and `)`, with one regular expression. Item 5: read the CA lines' names with htCALines and require the principal only. Item 6: the re-poll leaf's fetcher polls every hour and the bound is a minute; the live-signer log test's clock advances only by the monotonic reading. Each change has its mutant (Q3, Q4a to Q4c, Q5, Q6a): the unmutated narrow run passes, one exact replacement, `go vet` exits 0, the narrow run fails with the leaf's `--- FAIL:` line, the file is restored and its sha256 matches. The two item 6 leaves run 20 times under the race detector.</action>
  <verify><automated>go test -race -count=1 ./internal/server/ ./internal/serverclient/ ./cmd/keyroster/ ./internal/agent/fetch/ ./internal/signer/ && go vet ./... && test -z "$(gofmt -l .)"</automated></verify>
</task>

<task type="auto">
  <name>Task 2: the end-to-end retry helpers (item 7)</name>
  <files>test/e2e/hosttrust_test.go, test/e2e/hostcert_test.go, test/e2e/agent_enroll_test.go, test/e2e/agent_status_test.go, test/e2e/login_test.go, test/e2e/revoke_test.go, test/e2e/roles_test.go, test/e2e/ca_rotation_test.go, test/e2e/stall_test.go</files>
  <action>Read the admin limiter and the commands each helper's callers run, directly and through joinApproved, enrollApproved, joinHostCert and joinProbeHost. Where a command of three admin requests (host approve, user approve) is among them, the wait becomes 3 s with a comment that gives the arithmetic, and a log line that names the wait changes with it. The helpers of hosts_test.go, machine_test.go and probe_certs_test.go stay. Nothing under test/e2e runs locally; `go vet` runs under every e2e tag set.</action>
  <verify><automated>go vet -tags e2e ./test/e2e/ && go vet -tags 'e2e e2erotation' ./test/e2e/</automated></verify>
</task>

<task type="auto">
  <name>Task 3: the Arch lane's retry (item 2)</name>
  <files>test/distro/run-in.sh</files>
  <action>Replace the one pacman line with a POSIX sh loop of at most three tries, 30 s apart, two messages on stderr and `exit 1` after the third failure; one sentence in the comment says why. A copy of the loop with pacman replaced by a function that fails N times runs under dash for N = 0, 2 and 3.</action>
  <verify><automated>sh -n test/distro/run-in.sh</automated></verify>
</task>

<task type="auto">
  <name>Task 4: the pins, then the documents (items 1, 8, 9, 13)</name>
  <files>cmd/keyroster/securitydocs_test.go, cmd/keyroster/runbook_test.go, docs/runbooks/ca-rotation.md, docs/runbooks/signer-install.md, CONTRIBUTING.md, .planning/phases/01-trust-core/01-SKELETON.md, scripts/merge-gate.sh</files>
  <action>Commit the pins of items 8 and 9 first and show them failing on the old texts; then correct the location bullet, the tpm paragraph, the e2e-rotation row, the merge gate's header and message, CONTRIBUTING.md's two sentences on an approval after a push or a rebase and 01-SKELETON.md's line on exit 3. Two document mutants per pinned passage (Q8a, Q8b, Q9a, Q9b). `bash -n` and shellcheck of the script.</action>
  <verify><automated>go test -count=1 -run 'TestSecurityDocs|TestCARotationBackendSteps' ./cmd/keyroster/ && bash -n scripts/merge-gate.sh</automated></verify>
</task>

<task type="auto">
  <name>Task 5: the full gate</name>
  <files>none</files>
  <action>Run the full local gate once on the tree of the documents' commit: the race run of every package, the linters for linux, windows and darwin and with the piv tags, capslock, the firewalls and the pinned-actions check.</action>
  <verify><automated>the full gate of 03-12g's Task 5</automated></verify>
</task>

</tasks>
