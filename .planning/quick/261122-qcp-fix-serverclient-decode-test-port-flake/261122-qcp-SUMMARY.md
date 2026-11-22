---
phase: quick-261122-qcp
plan: 01
subsystem: serverclient-tests
tags: [flaky-test, serverclient, tests]
status: complete
requires: []
provides: ["a json_errors_in_own_words assertion that the test listener's port cannot trip"]
affects: []
key-files:
  modified: [internal/serverclient/client_test.go]
decisions:
  - "The check for the peer's zeros runs on the message with the request's URL removed (strings.ReplaceAll(msg, url, \"\")), not on a longer run of zeros or a pattern for the whole message: three zeros anywhere outside the URL still fail it, and the only text taken out is text whose place the test chose."
requirements: []
metrics:
  completed: 2026-11-22
actuals:
  tasks: 1
  commits: 3
plan_head_before: e8e8fe5
---

# Quick 261122-qcp Plan 01: the decode-error test of the server client no longer depends on its listener's port Summary

TestConnectErrorTransport/json_errors_in_own_words required that the client's decode error does not hold "000", the peer's zeros. The message begins with the request's URL, and the URL holds the port of a test listener the kernel picks. When that port holds "000" itself (40005 on CI), the subtest failed. The zeros are now looked for in the message with the URL taken out. Test-only; no behaviour change.

## What failed and why

- CI: the `build-test` job of a pull request (run 44970457523, job 137048878046, attempt 1), step "Test (race detector)", on a change that touched no Go code outside one new test file of cmd/keyroster:

  ```
  client_test.go:1177: body "{\"a\":               "...: err = "https://localhost:40005/healthz: decode: the response is not valid JSON (at byte 4006)", want "decode: the response is not valid JSON (at byte " in the CLI's own words
  ```

- The sentence is the right one. The subtest (internal/serverclient/client_test.go, lines 1162-1180 at the base) serves two bodies whose bad part is long (`{"a":1` + 4000 zeros + `e999}`, and `{"a":` + 4000 spaces + `x}`) and requires the CLI's own sentence, no "peer text" label, and no "000" in the message.
- internal/serverclient/client.go:445 words the error as `fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))`, so the message begins with `https://localhost:PORT/healthz`. `startTLS` (client_test.go:136-147) returns `"https://localhost:" + port` of an `httptest` listener on a port the kernel picks, and `get` asks for `/healthz`. `decodeError` (client.go:454-475) words a syntax error and a type error with "(at byte %d)" and nothing of the peer's text.
- Ports that hold "000" in Linux's default range, 32768 to 60999 (28,232 ports; the range in the WSL used for the runs below is the same, read from /proc/sys/net/ipv4/ip_local_port_range): 55. Counted by listing every port in the range whose decimal form contains "000": 40000-40009, 50000-50009 and 60000-60009 (30), and the 25 other ports that end in 000, 33000 to 59000 without 40000, 50000 and 60000. The subtest has two listeners, so each run had about 2 x 55 / 28,232 (0.4 %) chance to fail. Every port seen in the runs below was odd; with only odd ports in play, 15 of the 55 can be met.

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

`git grep -n -E 'Contains\([^)]*"[0-9a-f]{2,6}"\)' -- '*_test.go'` gives seven lines. Absence checks among them:

- cmd/keyroster/host_test.go:1122, `strings.Contains(p, "0600")`: `p` is `joinFileProtection("windows")`, a fixed sentence in cmd/keyroster/host.go. No port, fingerprint, serial or time in it.
- internal/serverclient/client_test.go:1176: the one fixed here.

The others are presence checks: internal/doctor/doctor_test.go:206 (`"90"`) and the four `identityOf` lines of cmd/keyroster/host_test.go (763, 779, 831, 874).

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

## Gates

- `go test -race -count=1 ./internal/serverclient/`: ok (4.1 s).
- The narrow run: PASS.
- `gofmt -l internal/serverclient`: no output. `go vet ./internal/serverclient/`: exit 0.
- `golangci-lint run ./...`, the same with `GOOS=windows` and with `GOOS=darwin`, and `CGO_ENABLED=1 golangci-lint run --build-tags piv,pivfake ./internal/keystore/piv/... ./cmd/keyroster-signer/...`: 0 issues each.
- The publish scan over the staged added lines: exit 0 before each commit.
- The full `go test -race ./...`, capslock and the firewalls were not run locally. One test file changes, and CI runs every package.

## Commits

- `docs(quick-261122-qcp): plan the fix of the port-dependent decode-error test` (the PLAN)
- `test(serverclient): look for the peer's zeros outside the request URL` (client_test.go)
- `docs(quick-261122-qcp): record the test fix` (this SUMMARY)

## Not changed here

- No product code. ROADMAP.md and STATE.md are not edited.
- No other absence check on text with digits or hex that a test did not choose was met by the sweep above.

## Deviations from Plan

None.
