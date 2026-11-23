---
phase: quick-261122-qcp
plan: 01
subsystem: serverclient-tests
tags: [flaky-test, serverclient, tests]
status: complete
requires: []
provides: ["a json_errors_in_own_words assertion and a malformed_date_no_hint assertion that the test listener's port cannot trip"]
affects: []
key-files:
  modified: [internal/serverclient/client_test.go, internal/serverclient/admin_test.go]
decisions:
  - "The check for the peer's zeros runs on the message with the request's URL removed (strings.ReplaceAll(msg, url, \"\")), not on a longer run of zeros or a pattern for the whole message: three zeros anywhere outside the URL still fail it, and the only text taken out is text whose place the test chose."
  - "The second test's check for the peer's nines is made the same way, on the message with the client's server URL removed (strings.ReplaceAll(err.Error(), c.Server(), \"\")), in one expression in the old order, so a nil error still ends at the first clause."
requirements: []
metrics:
  completed: 2026-11-22
actuals:
  tasks: 1
  commits: 6
plan_head_before: e8e8fe5
---

# Quick 261122-qcp Plan 01: the decode-error test of the server client no longer depends on its listener's port Summary

TestConnectErrorTransport/json_errors_in_own_words required that the client's decode error does not hold "000", the peer's zeros. The message begins with the request's URL, and the URL holds the port of a test listener the kernel picks. When that port holds "000" itself (40005 on CI), the subtest failed. The zeros are now looked for in the message with the URL taken out. A second test of the package, TestAdminJSONClockSkewHint/malformed_date_no_hint, made the same kind of check for "999" and is changed the same way. Test-only; no behaviour change.

## What failed and why

- CI: the `build-test` job of a pull request (run 44970457523, job 137048878046, attempt 1), step "Test (race detector)", on a change that touched no Go code outside one new test file of cmd/keyroster:

  ```
  client_test.go:1177: body "{\"a\":               "...: err = "https://localhost:40005/healthz: decode: the response is not valid JSON (at byte 4006)", want "decode: the response is not valid JSON (at byte " in the CLI's own words
  ```

- The sentence is the right one. The subtest (internal/serverclient/client_test.go, lines 1162-1180 at the base) serves two bodies whose bad part is long (`{"a":1` + 4000 zeros + `e999}`, and `{"a":` + 4000 spaces + `x}`) and requires the CLI's own sentence, no "peer text" label, and no "000" in the message.
- internal/serverclient/client.go:445 words the error as `fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))`, so the message begins with `https://localhost:PORT/healthz`. `startTLS` (client_test.go:136-147) returns `"https://localhost:" + port` of an `httptest` listener on a port the kernel picks, and `get` asks for `/healthz`. `decodeError` (client.go:454-475) words a syntax error and a type error with "(at byte %d)" and nothing of the peer's text.
- Ports that hold "000" in Linux's default range, 32768 to 60999 (28,232 ports; the range in the WSL used for the runs below is the same, read from /proc/sys/net/ipv4/ip_local_port_range): 55. Counted by listing every port in the range whose decimal form contains "000": 40000-40009, 50000-50009 and 60000-60009 (30), and the 25 other ports that end in 000, 33000 to 59000 without 40000 and 50000. The kernel did not pick evenly: measured, 10,000 of 10,000 binds of 127.0.0.1:0 on the kernel used for the runs below (6.6.87.2-microsoft-standard-WSL2) gave odd ports. Counted, 15 of the 55 are odd, of 14,116 odd ports in the range. If the pick among odd ports is even, that is about 15 in 14,116 per listener (0.11 %), and about 0.2 % for a run of the subtest with its two listeners; this rate is computed, not measured. R2 below met 2 failures in 2000 runs.

## The assertion

Before:

```go
if msg := err.Error(); !strings.Contains(msg, want) || strings.Contains(msg, "peer text") || strings.Contains(msg, "000") {
```

After:

```go
// The message begins with the request's URL, whose port is
// the test listener's and can hold "000" itself (40005,
// 51000): the peer's zeros are looked for in the rest.
msg := err.Error()
if !strings.Contains(msg, want) || strings.Contains(msg, "peer text") || strings.Contains(strings.ReplaceAll(msg, url, ""), "000") {
```

`url` is the loop's own `startTLS` result. The two other conditions and the `t.Errorf` line are unchanged. The byte offset the CLI prints stays inside the checked text; for these two bodies it is fixed and holds no "000".

## The two messages of a passing run

Read with a temporary `t.Logf` of the message (removed again; the file's sha256 matched HEAD afterwards):

- `https://localhost:36565/healthz: decode: the response has a JSON value of the wrong type (at byte 4010)` (the number-literal body)
- `https://localhost:46253/healthz: decode: the response is not valid JSON (at byte 4006)` (the spaces body)

Each is the URL, `/healthz: `, the `want` text, a number and `)`, and nothing else.

## Sweep for the same defect

The first pattern, `git grep -n -E 'Contains\([^)]*"[0-9a-f]{2,6}"\)' -- '*_test.go'`, gives seven lines at the base. It stops at the first `)`, so it cannot see a call in the first argument (`strings.Contains(err.Error(), "999")`), and it missed internal/serverclient/admin_test.go:112. Its absence checks were cmd/keyroster/host_test.go:1122 and client_test.go:1176; the others are presence checks: internal/doctor/doctor_test.go:206 (`"90"`) and the four `identityOf` lines of cmd/keyroster/host_test.go (763, 779, 831, 874).

The wider pattern, `git grep -n -E '(^|[^!])(strings|bytes)\.Contains\(.*, *"[0-9a-f]{2,6}"\)' -- '*_test.go'`, gives three lines at the base:

- cmd/keyroster/host_test.go:1122, `strings.Contains(p, "0600")`: `p` is `joinFileProtection("windows")`, a fixed sentence in cmd/keyroster/host.go. No port, fingerprint, serial or time in it.
- internal/serverclient/admin_test.go:112: the second test, changed here.
- internal/serverclient/client_test.go:1176: the first test, changed here.

After the two changes it gives the same three lines (host_test.go:1122, admin_test.go:115, client_test.go:1180): the changed lines still hold a `strings.Contains(..., "999")` and a `strings.Contains(..., "000")`, now made on the text without the URL.

This pattern does not see either: a condition spread over several lines, a check inside a helper function, a regular expression, or a literal that is not two to six hex digits. The sweep shows these three lines; it is not a proof that no other test has the defect.

## Proof

None of the temporary edits below was committed. After each, the file was restored from HEAD, its sha256 matched the one taken before the edit, and `git status --short -- cmd internal test docs .github` was empty. The narrow command is `go test -count=1 -timeout 5m -v -run '^TestConnectErrorTransport$/^json_errors_in_own_words$' ./internal/serverclient/`.

- **R1, fixed ports that hold "000".** A temporary edit of `startTLS` closed the listener `httptest.NewUnstartedServer` made and listened on 127.0.0.1:40005 for the first call and 127.0.0.1:40006 for the second (both free), before `StartTLS`.
  - R1-before, base assertion: FAIL, both bodies:
    - `client_test.go:1186: body "{\"a\":100000000000000"...: err = "https://localhost:40005/healthz: decode: the response has a JSON value of the wrong type (at byte 4010)", ...`
    - `client_test.go:1186: body "{\"a\":               "...: err = "https://localhost:40006/healthz: decode: the response is not valid JSON (at byte 4006)", ...`
  - R1-after, the same edit applied to the fixed test: PASS.
- **R2, 2000 runs on ports the kernel picks** (the narrow command with `-count=2000 -timeout 30m`, output kept outside the repository and counted from it).
  - R2-before, base: 2 of 2000 runs failed, both on the number-literal body, on ports 40007 and 40005. Both hold "000".
  - R2-after, fixed test: 0 of 2000 failed.
- **Q1, the assertion still sees the peer's zeros.** The unmutated narrow run passed first. Mutant in `decodeError`: the type-error case also prints the value, `fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d): %s", typeErr.Offset, typeErr.Value)`. `go vet ./internal/serverclient/` exited 0, and the output held no `[build failed]`, `[setup failed]` or `--- SKIP:` line. The narrow run failed on the number-literal body, with the zeros after the URL: `err = "https://localhost:46869/healthz: decode: the response has a JSON value of the wrong type (at byte 4010): number 1000000000...`. client.go was restored, and its sha256 matched HEAD.

## The second test: TestAdminJSONClockSkewHint/malformed_date_no_hint

This subtest had not failed in CI; the wider pattern of the sweep above showed it. The server answers 401 with the header `Date: not a date ` and 60 nines; the client must give no clock hint and must not repeat the nines. internal/serverclient/admin.go:383 words the error as `fmt.Errorf("%s%s: %w", c.base, path, ErrAdminAuth)`, and `adminServer` (admin_test.go:20-24) uses `startTLS`, so the message begins with the URL of the test's own listener. `c.Server()` (client.go:333) returns `c.base.String()`, the same text.

Ports that hold "999" in 32768 to 60999, counted the same way: 56, of which 41 are odd. If the pick among odd ports is even, that is about 41 in 14,116 per run (0.29 %, computed, not measured); the subtest has one listener.

Before (admin_test.go:112):

```go
if !errors.Is(err, ErrAdminAuth) || strings.Contains(err.Error(), "clock") || strings.Contains(err.Error(), "999") {
```

After:

```go
// The message begins with the client's server URL, whose port is
// the test listener's and can hold "999" itself (39991, 45999):
// the peer's nines are looked for in the rest.
if !errors.Is(err, ErrAdminAuth) || strings.Contains(err.Error(), "clock") || strings.Contains(strings.ReplaceAll(err.Error(), c.Server(), ""), "999") {
```

The condition stays one expression in the same order, so `err.Error()` is not called when `err` is nil.

The message of a passing run, read with a temporary `t.Logf` (removed again; the file's sha256 matched HEAD afterwards): `https://localhost:35481/api/v1/admin/users: admin authentication failed`, with `c.Server()` = `https://localhost:35481`.

Narrow command: `go test -count=1 -timeout 5m -v -run '^TestAdminJSONClockSkewHint$/^malformed_date_no_hint$' ./internal/serverclient/`. Restores and sha256 checks as above.

- **R3, a fixed port that holds "999".** The same temporary edit of `startTLS` as R1, with 127.0.0.1:32999 (free).
  - R3-before, base assertion: FAIL, `admin_test.go:113: error https://localhost:32999/api/v1/admin/users: admin authentication failed`.
  - R3-after, the same edit applied to the fixed test: PASS.
- **R4, 2000 runs on ports the kernel picks** (`-count=2000 -timeout 30m`).
  - R4-before, base: 4 of 2000 runs failed, on ports 39993, 38999, 34999 and 41999. Each holds "999".
  - R4-after, fixed test: 0 of 2000 failed.
- **Q2, the check still sees the peer's nines.** The unmutated narrow run passed first. Mutant in admin.go, the 401 case's plain return: `return fmt.Errorf("%s%s: %w (date %s)", c.base, path, ErrAdminAuth, he.date)`. `go vet ./internal/serverclient/` exited 0, and the output held no `[build failed]`, `[setup failed]` or `--- SKIP:` line. The narrow run failed, with the nines after the URL: `admin_test.go:116: error https://localhost:36279/api/v1/admin/users: admin authentication failed (date not a date 999999999...`. admin.go was restored, and its sha256 matched HEAD.

## Gates

- `go test -race -count=1 ./internal/serverclient/`: ok (4.1 s).
- Both narrow runs: PASS.
- `gofmt -l internal/serverclient`: no output. `go vet ./internal/serverclient/`: exit 0.
- `golangci-lint run ./...`, the same with `GOOS=windows` and with `GOOS=darwin`, and `CGO_ENABLED=1 golangci-lint run --build-tags piv,pivfake ./internal/keystore/piv/... ./cmd/keyroster-signer/...`: 0 issues each.
- The publish scan over the staged added lines: exit 0 before each commit.
- The full `go test -race ./...`, capslock and the firewalls were not run locally. Two test files change, and CI runs every package.

## Commits

- `docs(quick-261122-qcp): plan the fix of the port-dependent decode-error test` (the PLAN)
- `test(serverclient): look for the peer's zeros outside the request URL` (client_test.go)
- `docs(quick-261122-qcp): record the test fix` (this SUMMARY)
- `test(serverclient): look for the peer's nines outside the request URL` (admin_test.go)
- `docs(quick-261122-qcp): record the second test and correct the port figures` (this SUMMARY)
- `docs(quick-261122-qcp): record the pre-merge review` (this SUMMARY)

## Not changed here

- No product code. ROADMAP.md and STATE.md are not edited.
- The one line of the wider pattern that this task does not change, cmd/keyroster/host_test.go:1122, is an absence check made on a fixed sentence, with no digits a test did not choose, and is not changed.

## Deviations from Plan

- The PLAN names one test. A second test of the package, TestAdminJSONClockSkewHint/malformed_date_no_hint in internal/serverclient/admin_test.go, had the same defect and is changed here.

## Pre-merge review

The orchestrator ran the review on the open pull request at head 6c23b4b (2026-11-22), in a read-only detached worktree of that head, and a check of the fix round at head 9bba25d. This section is written from the two runs' records, not from a description of what they were meant to do.

### Who reviewed what

Two agents in the first run, and no Codex lens (the change was one condition in a test file):

- One lens on Opus at high effort. It read the diff, the test function and its helpers, the code that words the error, this task's PLAN, this SUMMARY as it then was and the pull request's text, and it read the failing line in the CI job's log. On a private copy of the tree it ran the narrow run, the package with the race detector, `go vet`, `gofmt` and golangci-lint for linux, windows and darwin; repeated R1 on 40005 and 40006 and ran it again on 51000 and 60000, each with the old and the new assertion; repeated Q1; ran six mutants of the client of its own; ran the subtest 2000 times with the new assertion and 2000 times with the old one; recomputed the port counts; measured the parity of the ports the kernel gives a listener; and searched the test files with a wider pattern, pinning the listener of the test it met to port 32999. It reported seven items.
- One skeptic on Sonnet at high effort judged all seven, with runs of its own for five of them.

The two agents used about 236,000 tokens. The orchestrator had read the whole diff, the PLAN, the SUMMARY and the pull request's text before the review, and read every item and the skeptic's reasons after it.

### Result

Seven items. The skeptic upheld all seven: two at low weight and five as notes. None is a defect of the changed assertion. The lens's statement, which its mutants bear out, is that the new check is the old check minus text inside the URL, so it is as strong as before for the peer's text: a mutant that prints a second copy of the URL directly followed by the peer's zeros is still caught.

Its runs on the first test: with the listeners pinned to 40005 and 40006, and to 51000 and 60000, the old assertion fails for both bodies and the new one passes; 2000 runs with the new assertion, none failed; 2000 runs with the old one, one failed, on port 40009; Q1 failed on the number-literal body; all six of its own mutants of the client failed the subtest.

### The items and the rulings

1. **The first sweep pattern cannot see a call in the first argument** (low weight), so it had missed the same defect in internal/serverclient/admin_test.go:112, which the lens showed by pinning that test's listener to port 32999. Ruling: taken up. The second test is changed in this task, and "Sweep for the same defect" now gives the wider pattern, its lines and what it does not see.
2. **"About 0.4 %" assumed an even pick over all ports** (low weight). Ruling: taken up. The figures are now marked as measured, counted or computed.
3. **The sentence on odd ports** (a note; the executor had reported the sentence itself before the review). The first round's SUMMARY said that every port seen in the runs was odd, although R1 pins the even port 40006 by hand. Ruling: replaced by the executor's own measurement of 10,000 binds.
4. **The second test has the same defect** (a note, the same place as item 1). Ruling: as item 1.
5. **The count's wording** (a note): "without 40000, 50000 and 60000", where 60000 is outside the range named. Ruling: corrected.
6. Two notes are about tests as they were before this change, in places that this change does not alter. They are kept for a later task and are not described here.

### The fix round and its check

The fix round is the two commits after 6c23b4b: the second test's assertion, and this SUMMARY's corrected figures, its sweep section and the section on the second test.

One verifier on Sonnet at high effort (about 110,000 tokens) checked it at head 9bba25d on a private copy: the narrow run of the second test and the package with the race detector; R3 itself (port 32999: the old assertion fails, the new one passes); Q2 itself (fails, with the nines after the URL); five mutants of its own, of which the four that print the peer's Date, add nines or print a clock hint failed the subtest, and the one that repeats the client's own URL passed, as it should, because that is not the peer's text; 2000 runs with the new assertion, none failed; the counts by a script of its own (55 and 15, 56 and 41, 14,116); the parity (10,000 of 10,000 binds gave odd ports); both patterns at the base and at the head; the line references. It confirmed that the new condition keeps its order, so a nil error ends at the first clause, and that `c.Server()` is the text the message begins with.

It reported two notes. The front matter's `decisions` entry named only the first test: taken up in the commit that adds this section. A client that printed its own URL a second time would pass: that is the boundary the check is meant to have, and nothing changes for it.

### Recorded, not changed

- The lens did not check: the validity of the commit signatures (it saw that each commit carries one), the lint pass with the piv tags, the race run over all packages, capslock and the firewalls. It could not confirm from the job's log alone what change the failing CI run was on.
- The verifier did not repeat R4's 2000 runs on the base, the lint passes, `gofmt` or `go vet` on the head, and could not check the executor's sha256 statements or the message it read on port 35481.
- The commit that adds this section and widens the `decisions` entry was read by the orchestrator and not reviewed by an agent.
