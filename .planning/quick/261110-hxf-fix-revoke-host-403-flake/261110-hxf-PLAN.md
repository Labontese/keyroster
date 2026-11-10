---
phase: quick-261110-hxf
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - cmd/keyroster/revoke_test.go
autonomous: true
requirements: []
must_haves:
  truths:
    - "TestRevokeHost/success_line_says_agent_keeps_state no longer fails when random hex in the output contains 403. It checks for the text a 403 really prints, HTTP 403 from serverclient, and for not_approved."
    - "A mutant that makes the success path print HTTP 403 still fails the subtest."
    - "No production code changes. No ROADMAP or STATE change."
---

<objective>
The success-line subtest searched stdout and stderr for the bare substring 403, which a fingerprint can contain (it failed once on CI's cli-windows lane). Match the real 403 text instead, without weakening the test.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: match the real 403 text</name>
  <files>cmd/keyroster/revoke_test.go</files>
  <action>Read how revoke prints a 403 (cmd/keyroster/revoke.go, internal/serverclient/client.go: "HTTP %d"). Change the bare 403 to HTTP 403. Grep cmd/keyroster tests for the same bare pattern. Prove with a mutant that the subtest still fails, then restore.</action>
  <verify><automated>go test ./cmd/keyroster/ -run TestRevokeHost -count=50 && go vet ./cmd/keyroster/ && gofmt -l cmd/keyroster</automated></verify>
</task>

</tasks>
