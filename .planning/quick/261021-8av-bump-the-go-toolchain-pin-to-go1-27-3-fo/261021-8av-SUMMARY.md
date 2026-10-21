---
phase: quick-261021-8av
plan: 01
subsystem: build
tags: [go, toolchain, govulncheck, supply-chain, ci]
status: complete
requires: []
provides: ["go.mod toolchain pin go1.27.3"]
affects: [".github/workflows/ci.yml (govulncheck and every setup-go job)", ".github/workflows/piv.yml (build-piv)"]
tech-stack:
  added: []
  patterns: []
key-files:
  created: []
  modified: [go.mod]
decisions:
  - "Bump only go.mod's toolchain line (go1.27.2 -> go1.27.3); the go 1.26.0 directive, go.sum and tools/ stay unchanged"
requirements: [REPO-02]
metrics:
  completed: 2026-10-21
  duration: "about 20 min"
actuals:
  tokens: 1     # chars/4 over the realized diff: one changed line in go.mod
  tasks: 2
  commits: 1
plan_head_before: 52b99c46254a3fd687016fca44fd8f6aa9c1dc7e
plan_head_after: 2fd917ff6f94f141ec35a0b8ed71eee6602a6272
---

# Quick 261021-8av Plan 01: Go toolchain go1.27.3 for GO-2026-6809 Summary

go.mod now pins `toolchain go1.27.3` instead of go1.27.2. On the 2026-10-21 vulnerability DB, CI's govulncheck invocation exits 0 again: before the change it exited 3 on GO-2026-6809 (crypto/x509), and afterwards it exits 0 on the go1.27.3 stdlib. This is one signed commit, `2fd917f`, and it changes only go.mod. Nothing was pushed and no PR was opened.

## Commit

- `2fd917f` build(go): pin toolchain go1.27.3 for GO-2026-6809 (crypto/x509)
  - The commit changes only go.mod (`git show --name-only --format= HEAD` = `go.mod`). Outside .planning, `git diff --name-only 52b99c4 HEAD` = `go.mod`.
  - It is SSH-signed (`gpgsig` header present once in `git cat-file commit HEAD`). It has no deletions.
  - `git rev-list --count 52b99c4..HEAD` = 1.

## Task 1: RED, pin, GREEN (tracer)

### Step 0: download integrity (T-8av-01)

Both checks ran before anything fetched go1.27.3, and both gave the same result.

`export PATH="$HOME/sdk/go1.27.1/bin:$PATH" && GOTOOLCHAIN=local go env GOSUMDB GONOSUMDB GOPRIVATE GOINSECURE GOFLAGS GOPROXY` (Windows), and `bash scripts/linux.sh 'GOTOOLCHAIN=local go env GOSUMDB GONOSUMDB GOPRIVATE GOINSECURE GOFLAGS GOPROXY'` (WSL):

```
sum.golang.org
(empty)
(empty)
(empty)
(empty)
https://proxy.golang.org,direct
```

### RED (unmodified tree, go1.27.2)

`bash scripts/linux.sh 'go tool -modfile=tools/go.mod govulncheck ./...'` exited **3**:

```
=== Symbol Results ===

Vulnerability #1: GO-2026-6809
    Distrust compromised intermediate certificates in crypto/x509
  More info: https://pkg.go.dev/vuln/GO-2026-6809
  Standard library
    Found in: crypto/x509@go1.27.2
    Fixed in: crypto/x509@go1.27.3
    Example traces found:
      #1: internal/wire/frame.go:132:26: wire.ReadMessage calls io.ReadFull, which eventually calls x509.Certificate.Verify

Your code is affected by 1 vulnerability from the Go standard library.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
Use '-show verbose' for more details.
```

`-show verbose` does not print the Go version or the DB date; `-show version` does. `bash scripts/linux.sh 'go tool -modfile=tools/go.mod govulncheck -show version ./...'` exited **3**:

```
Go: go1.27.2
Scanner: govulncheck@v1.8.0
DB: https://vuln.go.dev
DB updated: 2026-10-21 00:27:29 +0000 UTC
(followed by the same GO-2026-6809 symbol result)
```

### Pin

go.mod line 5 changed from `toolchain go1.27.2` to `toolchain go1.27.3`. Line 3 is still `go 1.26.0`. tools/go.mod and go.sum were not edited, and `go get` was not run.

- Windows: `export PATH="$HOME/sdk/go1.27.1/bin:$PATH" && go version` printed `go: downloading go1.27.3 (windows/amd64)`, then `go version go1.27.3 windows/amd64`.
- WSL: `bash scripts/linux.sh 'go version'` printed `go version go1.27.3 linux/amd64`.

### GREEN (go1.27.3)

`bash scripts/linux.sh 'go tool -modfile=tools/go.mod govulncheck ./...'` exited **0**:

```
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
Use '-show verbose' for more details.
```

`bash scripts/linux.sh 'go tool -modfile=tools/go.mod govulncheck -show version,verbose ./...'` exited **0**:

```
Go: go1.27.3
Scanner: govulncheck@v1.8.0
DB: https://vuln.go.dev
DB updated: 2026-10-21 00:27:29 +0000 UTC
...
Govulncheck scanned the following 18 modules and the go1.27.3 standard library:
...
=== Module Results ===
Vulnerability #1: GO-2026-5932  (golang.org/x/crypto/openpgp, unmaintained; Found in v0.57.0, Fixed in: N/A)
```

RED and GREEN used the same instrument and the same DB timestamp (2026-10-21 00:27:29 UTC). The only thing that moved is the stdlib, from go1.27.2 to go1.27.3.

**GO-2026-5932** (x/crypto/openpgp) is a module-level result. It appears in both RED and GREEN, no code path reaches it, it has no fix, and it does not affect the exit code. This change has nothing to do with it and does not touch it.

### No module drift

- `bash scripts/linux.sh 'go mod tidy -diff'` exited 0 and printed no diff. stderr had only `go: downloading ...` lines while the go1.27.3 module cache warmed.
- `git status --porcelain -- go.sum tools` printed nothing, and `git diff --quiet 52b99c4 -- go.sum tools` exited 0.

### Tracer gate

Task 1's `<verify>` string, run verbatim before the commit, exited 0.

## Task 2: local CI parity under go1.27.3

Every command below ran under go1.27.3. All WSL commands went through `bash scripts/linux.sh '<cmd>'`.

| Check | Command | Result |
|---|---|---|
| Windows scan (CI-style) | `go build -modfile=tools/go.mod -o bin/kr-govulncheck golang.org/x/vuln/cmd/govulncheck && GOOS=windows bin/kr-govulncheck ./...` | exit 0, "No vulnerabilities found." |
| macOS scan (CI-style) | `GOOS=darwin bin/kr-govulncheck ./...` (same chain) | exit 0, "No vulnerabilities found." |
| Module integrity | `go mod verify && cd tools && go mod verify` | "all modules verified" twice, exit 0 |
| Static build | `CGO_ENABLED=0 go build ./...` | exit 0 |
| Cross-compile windows | `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/keyroster` | exit 0 |
| Cross-compile darwin | `CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o /dev/null ./cmd/keyroster` | exit 0 |
| Cross-compile freebsd | `CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o /dev/null ./cmd/keyroster` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| gofmt | `gofmt -l .` | no output, exit 0 (see the caveat below) |
| Race suite | `KEYROSTER_REQUIRE_ORACLE=1 KEYROSTER_REQUIRE_SSH_AGENT=1 CGO_ENABLED=1 go test -race -count=1 ./...` | exit 0, 24 `ok` packages, no FAIL/SKIP/panic lines, no reruns needed |
| Native Windows build | `export PATH="$HOME/sdk/go1.27.1/bin:$PATH" && go build ./...` (switches to go1.27.3) | exit 0 |
| dep-firewall | `bash scripts/dep-firewall.sh` | exit 0. Only the documented `os/exec <- modernc.org/libc` exception, for default and piv |
| testonly-firewall | `bash scripts/testonly-firewall.sh` | exit 0, "clean (6 GOOS/tag combinations)" |
| capslock | `bash scripts/capslock-check.sh` | exit 0, capslock v0.3.3, "91 (package, capability) pairs; baseline has 91". Baseline unchanged |

The ignore rule `/bin/` (.gitignore:2) covered `bin/kr-govulncheck`. It was deleted after the final verify.

**gofmt caveat:** WSL's PATH gofmt is `/home/daniel/sdk/go1.27.1/bin/gofmt`, not go1.27.3's. The commit changes no .go file. CI's gofmt under go1.27.3 stays authoritative.

Task 2's `<verify>` string ran verbatim after the commit and exited 0. It checks:
- a single-file commit;
- the `gpgsig` header;
- the Conventional Commits subject;
- the toolchain line.

It also re-ran:
- the windows/darwin scans;
- capslock-check;
- dep-firewall;
- go mod verify.

## UNVERIFIED (CI only)

These checks were not run locally and are not claimed as passed. They run on the PR.

- build-piv's `CGO_ENABLED=1 go tool -modfile=tools/go.mod govulncheck -tags piv ./...`. It needs the pcsc-lite headers (`/usr/include/PCSC`), which WSL lacks. The piv build uses the same stdlib, so GO-2026-6809 should be gone there too, but that scan was not run.
- golangci-lint on linux, windows and darwin.
- fuzz.
- e2e, e2e-pkcs11 and e2e-tpm.
- cli-windows on windows-2025.
- systemd.
- codeql.
- scorecard.
- That CI's `actions/setup-go` with `go-version-file: go.mod` actually installs go1.27.3.

## Deviations from Plan

None in code or scope: go.mod's toolchain line is the only change.

The plan's step 2 said "verbose" might print the Go version. It does not; `-show version` does. The GREEN run used `-show version,verbose` to capture both.

Several executor-boilerplate steps were deliberately not used:
- The worktree branch allow-list (`agent-*`): the orchestrator named this branch.
- The cwd sentinel and the commit ledger under `git rev-parse --git-dir`: that path resolves into the main checkout's `.git`, where the plan forbids helper files. The root-pin guard replaced them, and the base 52b99c4 was used directly.
- The STATE/ROADMAP state verbs: the orchestrator owns docs.

## Notes

- The CLAUDE.md stack table still names Go toolchain 1.27.1 (`Go toolchain | **1.27.1** (go directive 1.26)`). That is out of scope here and was left unchanged.

## Self-Check: PASSED

- go.mod contains `toolchain go1.27.3` and `go 1.26.0`: FOUND
- Commit 2fd917f is an ancestor of HEAD (HEAD itself), signed, and go.mod-only: FOUND
- No .planning file committed and nothing pushed: confirmed (`git status --short` shows only this quick directory untracked)
