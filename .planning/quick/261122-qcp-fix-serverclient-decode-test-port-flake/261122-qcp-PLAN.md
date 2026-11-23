---
phase: quick-261122-qcp
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - internal/serverclient/client_test.go
autonomous: true
requirements: []
must_haves:
  truths:
    - "TestConnectErrorTransport/json_errors_in_own_words no longer fails when one of its test listeners gets a port that holds 000 (40005, 51000). It looks for the peer's zeros in the message with the request's URL taken out."
    - "Three zeros anywhere outside the URL still fail the subtest: a mutant that makes decodeError print the peer's value fails it on the number-literal body."
    - "No production code changes. No ROADMAP or STATE change."
---

<objective>
The subtest serves two bodies whose bad part is long (4000 zeros of a number literal, 4000 spaces) and requires that the client's decode error holds the CLI's own sentence, no "peer text" label, and not the peer's zeros, which it looks for as `strings.Contains(msg, "000")`. The message begins with the request's URL (client.go: `fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))`), and `startTLS` listens on a port the kernel picks. On a CI run the port was 40005, which holds "000" itself, and the subtest failed. Look for the zeros in the message with the URL removed, so the only text taken out is text whose place the test itself chose.
</objective>

<tasks>

<task type="auto">
  <name>Task 1: look for the peer's zeros outside the request URL</name>
  <files>internal/serverclient/client_test.go</files>
  <action>Replace the assertion of json_errors_in_own_words with `msg := err.Error()` and a check of `strings.ReplaceAll(msg, url, "")` for "000", where `url` is the loop's own `startTLS` result. Add a comment saying why. The two other conditions and the t.Errorf line stay as they are. Prove it before and after the change: R1 pins the two test listeners to 40005 and 40006 with a temporary edit of startTLS (fails before, passes after); R2 runs the subtest 2000 times on ports the kernel picks (failures before, each on a port that holds 000; none after); Q1 is a mutant of decodeError that prints the peer's value, which must still fail the subtest. None of the temporary edits is committed; each file is restored from HEAD and its sha256 compared.</action>
  <verify><automated>go test -count=1 -timeout 5m -v -run '^TestConnectErrorTransport$/^json_errors_in_own_words$' ./internal/serverclient/ && go test -race -count=1 ./internal/serverclient/ && go vet ./internal/serverclient/ && test -z "$(gofmt -l internal/serverclient)"</automated></verify>
</task>

</tasks>
