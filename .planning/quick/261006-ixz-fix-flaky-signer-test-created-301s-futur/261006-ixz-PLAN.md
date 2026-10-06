---
phase: quick-261006-ixz
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - internal/signer/refusal_test.go
  - internal/signer/signer_test.go
  - internal/signer/log_test.go
  - internal/signer/evidence_test.go
  - .planning/phases/01-trust-core/deferred-items.md
  - .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-PLAN.md
  - .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-SUMMARY.md
autonomous: true
# Quick task: no REQUIREMENTS.md ID. It guards the D-14 stale_request refusal path
# (request freshness, internal/signer/issue.go maxClockSkew) against a flaky test.
requirements: [D-14]

estimate:
  tokens: 70000
  raw_tokens: 70000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "TestSignerRefusals/created_301s_future and created_301s_past give the same result no matter how much wall-clock time passes. With a 1.1 s pause injected into the subtest loop they still pass, and they pass 200 of 200 runs under -race."
    - "TestEvidence/created_at_outside_skew_future and _past give the same result no matter how much wall-clock time passes. With a 1.1 s pause injected before the refusal they still pass, and they pass 200 of 200 runs under -race."
    - "The production freshness check is exactly as strict as before. No non-test file under internal/signer changes: maxClockSkew stays 300 s, and issue.go keeps the strict > / < comparison."
    - "The whole ./internal/signer suite passes under -race on Linux (WSL), and go vet and gofmt are clean."
    - "All three deferred-items.md entries about this test are marked resolved, and the 01-09 entry states the corrected root cause (crossing a second boundary, not about one second of delay)."
    - "A keyroster-bot PR with a Conventional Commits title is open, has auto-merge (squash) enabled, and has every required check green. scripts/merge-gate.sh exits 2 (owner approval pending)."
  artifacts:
    - path: internal/signer/refusal_test.go
      provides: "fakeClock.Tick: a signer clock that advances 1 µs on each read and never reads the wall clock"
    - path: internal/signer/signer_test.go
      provides: "TestSignerRefusals: the signer runs on a stepping clock that starts on a whole second. Every request takes CreatedAt from that clock, and the test fails if the clock advances 1 s or more."
    - path: internal/signer/log_test.go
      provides: "logEnv.clock plus newLogEnvClock(t, fx, clock). It is passed to fx.Bootstrap and to Config.Clock. nil keeps time.Now."
    - path: internal/signer/evidence_test.go
      provides: "created_at_outside_skew_* subtests run on a signer pinned to a whole second, with CreatedAt = pinned ± 301"
    - path: .planning/phases/01-trust-core/deferred-items.md
      provides: "Flaky-test entries marked resolved, with the corrected root cause and the PR number"
  key_links:
    - from: "TestSignerRefusals (signerOpts.clock = clk.Tick)"
      to: "internal/signer/issue.go:55 s.clock() freshness check"
      via: "newTestSigner start() passes signer.Config.Clock; bootstrap() passes the same clock to fx.Bootstrap"
      pattern: "signerOpts\\{clock: clk\\.Tick\\}"
    - from: "TestEvidence created_at_outside_skew_*"
      to: "internal/signer/issue.go:55 s.clock() freshness check"
      via: "newLogEnvClock passes the pinned clock to Config.Clock in logEnv.open()"
      pattern: "newLogEnvClock\\("
---

<objective>
Make the request-freshness boundary tests in `internal/signer` deterministic without touching the production check.

**Root cause (corrected).** `IssueRequest.CreatedAt` holds whole seconds, but the signer clock has sub-seconds (`internal/signer/issue.go:55-57`). The future case works like this:
- `TestSignerRefusals` captures `now` from the wall clock once, then the signer reads the wall clock `T1` at the check.
- For `now + 301`, the skew is `d = T1 - floor(T0) - 301 s`. That is below -300 s only while `T1 < floor(T0) + 1 s`.
- So `created_301s_future` fails whenever the capture and the signer's read fall in **different wall-clock seconds**. That can take a few milliseconds of delay, not "about one second". Its failure rate grows with CPU load (CI `build-test` on PR #9 run 37307671187; PR #15 run 37425878563).

`TestEvidence/created_at_outside_skew_future` (`internal/signer/evidence_test.go:164-171`) has the same race. It reads the wall clock in `logEnv.request()`, and the `logEnv` signer reads it again. The `_past` variants cannot fail, because elapsed time only pushes them further out, but they share the computation and are fixed the same way.

**Seam (existing).** The production side needs nothing new:
- `signer.Config.Clock` is a `serial.Clock` that defaults to `time.Now` (`internal/signer/signer.go:46,121`).
- The socket tests reach it through `signerOpts.clock` in `newTestSigner`, which also feeds `fx.Bootstrap`. `TestRefusalClockRegressionEpisodes` already uses that path with `fakeClock`.
- The in-package `logEnv` (`internal/signer/log_test.go`) builds `Config` without a clock today. This plan adds an optional clock to it.

The production code (`internal/signer/issue.go`, `maxClockSkew = 300 * time.Second`) stays byte-identical.

Purpose: CI stops failing at random on PRs, and the ±300 s refusal stays proven at ±301 s.
Output: two test commits, a docs commit (this plan, its SUMMARY, the deferred-items update), and an open keyroster-bot PR waiting on the owner.
</objective>

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@CONTRIBUTING.md
@.planning/phases/01-trust-core/deferred-items.md
@internal/signer/issue.go
@internal/signer/signer_test.go
@internal/signer/refusal_test.go
@internal/signer/log_test.go
@internal/signer/evidence_test.go
@internal/serial/serial.go

<interfaces>
Read and grep facts the executor relies on (do not re-derive them):
- `internal/signer/issue.go:55-58` reads `now := s.clock()`, then `created := time.Unix(CreatedAt, 0)` (whole seconds). It refuses with `request_time_skew` when `now.Sub(created) > maxClockSkew || < -maxClockSkew`.
- `internal/signer/issue.go:85` calls `serial.Next(last, s.clock, time.Sleep)`, which reads the clock at least twice and needs `cur >= max(last+1, n)`. It runs before `cert.Build` (`:102`), and **every** refusal mapped by `buildRefusal` (bad_subject_key for a certificate subject or the CA key, bad_subject, bad_validity, extension_not_allowed, bad_principal, empty_principals) passes through it. With a **frozen** clock, once the seed issuance has stored LastSerial == the frozen microsecond, every later subtest that reaches `cert.Build` stalls for `maxWaits` and returns `serial_unavailable`. That covers `certificate_subject`, `bad_key_id_subject` and `empty_key_id_subject`. So `TestSignerRefusals` must use a clock that advances on each read, not the frozen `fakeClock.Now`.
- `internal/signer/refusal_test.go` (`//go:build linux`, package `signer_test`):
  - `fakeClock{mu sync.Mutex; t time.Time}` has the methods `Now`, `Set` and `Add`.
  - `newFakeClock()` returns `&fakeClock{t: time.Now()}`.
  - `requestAt(t, clk)` returns `newRequest(t, "alice")` with `CreatedAt = clk.Now().Unix()`.
  - `TestRefusalClockRegressionEpisodes` asserts `NowMicros == start.UnixMicro()` exactly. Do not change `Now`, `Set`, `Add` or `newFakeClock`.
- `internal/signer/signer_test.go` (`//go:build linux`, package `signer_test`):
  - `signerOpts.clock func() time.Time` is used by both `bootstrap()` (`fx.Bootstrap(..., ts.opts.clock)`) and `start()` (`Config.Clock`).
  - `TestSignerRefusals` is at about line 478. `now` is captured at line 480. The seed is issued in `certSubject` with `newRequest(t, "seed")`. The loop builds `newRequest(t, "alice")` at line 519.
- `internal/signer/log_test.go` (package `signer`, no build tag; it imports `time` and does not import `internal/serial`):
  - `newLogEnv(t)` returns `newLogEnvFx(t, NewFixture(t, 1, 1))`.
  - `newLogEnvFx` calls `fx.Bootstrap(t, db, e.backend, nil)` and then `e.open()`.
  - `open()` calls `New(Config{Backend, DB, AllowUIDs: {1000}, Logger})` with no Clock.
  - `request()` sets `CreatedAt = time.Now().Unix()` and signs the evidence.
- `serial.Clock` is `func() time.Time`, so a `func() time.Time` value is assignable to `Config.Clock` and to the `fx.Bootstrap` clock parameter without importing `serial`.
- Refusal rate limiter: `refuse()` always writes the slog record that `TestSignerRefusals` counts, before the limiter decides whether the record also becomes a log leaf. A clock that never refills the bucket therefore does not change those assertions. `refuseThroughSigner` runs on a fresh `logEnv` (full bucket), so its single expected leaf is still appended.
- Linux-only tests (Unix sockets, `-race` needs cgo) run in WSL through `bash scripts/linux.sh '<command>'`. The command string must contain no `$VAR` and no inner quotes. Every command below is written that way. Anything that needs either goes into a script file outside the repo.
</interfaces>
</context>

<tasks>

<task type="tracer">
  <name>Task 1: TestSignerRefusals on a stepping test clock (red first, then deterministic)</name>
  <files>internal/signer/refusal_test.go, internal/signer/signer_test.go</files>
  <read_first>internal/signer/signer_test.go (lines 93-264 and 478-533), internal/signer/refusal_test.go (lines 1-45 and 237-302), internal/signer/issue.go (lines 48-114), internal/serial/serial.go (Next)</read_first>
  <precondition>The current branch is quick/261006-ixz-flaky-clock and is based on origin/main f69d050. git status shows changes only in .planning/config.json, .planning/milestone.lock and .planning/state.json (all orchestrator-owned, never committed) and possibly .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/ holding this plan. That directory may be untracked, in which case Task 3 commits it, or already committed by the orchestrator; either is fine.</precondition>
  <action>
<!-- planner-discipline-allow: time.Sleep -->
RED (reproduce before fixing, on the unmodified tree):
(a) Time one iteration: `bash scripts/linux.sh 'go test -race -count=1 -v -run TestSignerRefusals/created_301s ./internal/signer/'`. Use the result to choose foreground or `run_in_background` for the 200-run commands below; the Bash foreground limit is 10 min.
(b) Informational baseline: `bash scripts/linux.sh 'go test -race -count=200 -timeout 60m -run TestSignerRefusals/created_301s_future ./internal/signer/'`. Record how many runs failed. Zero is possible, because the race needs a second boundary to fall between capture and check, so this is not the gate.
(c) Deterministic RED:
- In `TestSignerRefusals`'s subtest closure, insert `time.Sleep(1100 * time.Millisecond)` temporarily, directly after `tc.edit(t, req)`.
- Run `bash scripts/linux.sh 'go test -count=1 -run TestSignerRefusals/created_301s ./internal/signer/'`.
- It MUST exit non-zero with `created_301s_future` failing in `wantErrorResponse`, and `created_301s_past` passing. Record the failure line for the SUMMARY.
- Then revert with `git checkout -- internal/signer/signer_test.go` and confirm that `git status --porcelain -- internal/signer` prints nothing.

GREEN (the seam is the existing `signerOpts.clock` → `signer.Config.Clock` plus `fx.Bootstrap`):
1. In `internal/signer/refusal_test.go`, add the method `func (c *fakeClock) Tick() time.Time`. Under `c.mu` it advances `c.t` by `time.Microsecond` and returns the new time.
   - Doc comment: as a signer clock, Tick moves only when read and never reads the wall clock. It is strictly increasing, so `serial.Next` always progresses, and a test's time checks no longer depend on how long the test takes.
   - Leave `newFakeClock`, `Now`, `Set` and `Add` unchanged, because `TestRefusalClockRegressionEpisodes` asserts the frozen `Now` value exactly.
2. In `TestSignerRefusals` (`internal/signer/signer_test.go`):
   - (a) Replace the wall-clock capture with `base := time.Now().Truncate(time.Second)`, `clk := &fakeClock{t: base}`, `ts := newTestSigner(t, signerOpts{clock: clk.Tick})` and `now := uint64(base.Unix())`. Keep the existing `//nolint:gosec // G115` comment style on that conversion.
   - (b) In `certSubject`, keep `newRequest(t, "seed")` but set its `CreatedAt = now` before `ts.issue`.
   - (c) In the loop, build the request with `requestAt(t, clk)` instead of `newRequest(t, "alice")`. That helper is the same "alice" request with `CreatedAt` taken from the clock, which is `base`'s second.
   - (d) Leave the table edits exactly as they are (`now - 301`, `now + 301`, `0`, `1<<64 - 1`), and the expected codes and reasons.
   - (e) After the loop, add a self-check: if `clk.Now().Sub(base) >= time.Second`, call `t.Fatalf`. The message says the stepping clock used a full second of reads, so the ±301 s cases no longer test the boundary they claim. A future clock reader that spins then fails loudly instead of reintroducing a flake.
   - (f) Above the clock setup, write a short comment saying why:
     - `CreatedAt` is whole seconds and the signer clock is not.
     - With a whole-second base and 1 µs per read, `now + 301` is exactly 301 s ahead of the signer minus the reads, so the outcome no longer depends on CPU load.
     - A frozen clock would not work, because the seed issuance would make later `serial.Next` calls stall.
   - Do not truncate or change anything in non-test code.
3. Run the GREEN commands from `<verify>`, then commit only the two files: `git add internal/signer/refusal_test.go internal/signer/signer_test.go`, then `git commit -m "test(signer): drive TestSignerRefusals from a stepping test clock"`. The commit is signed by repo config.
4. Determinism proof on the committed fix:
   - Insert the same 1100 ms pause after `tc.edit(t, req)` again.
   - Run `bash scripts/linux.sh 'go test -count=1 -run TestSignerRefusals/created_301s ./internal/signer/'`. It MUST pass.
   - Revert with `git checkout -- internal/signer/signer_test.go` and confirm that `git status --porcelain -- internal/signer` prints nothing.
   - Record both runs (RED fail, GREEN pass) for the SUMMARY.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=200 -timeout 60m -run TestSignerRefusals/created_301s ./internal/signer/' && bash scripts/linux.sh 'go test -race -count=3 -run TestSignerRefusals ./internal/signer/' && bash scripts/linux.sh 'go test -race -count=3 -run TestRefusalClockRegressionEpisodes ./internal/signer/' && S=$(git status --porcelain -- internal/signer) && test -z "$S"</automated>
  </verify>
  <done>
- With the injected 1.1 s pause, the unmodified test fails on `created_301s_future`, and the fixed test passes.
- `TestSignerRefusals/created_301s` passes 200/200 under -race.
- The full `TestSignerRefusals` table and `TestRefusalClockRegressionEpisodes` pass.
- The fix is committed (signed, author keyroster-bot), and no injected pause remains in the tree.
  </done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Pin the signer clock in TestEvidence's created_at_outside_skew subtests</name>
  <files>internal/signer/log_test.go, internal/signer/evidence_test.go</files>
  <read_first>internal/signer/log_test.go (lines 55-160), internal/signer/evidence_test.go (lines 30-80 and 160-173)</read_first>
  <behavior>
    - created_at_outside_skew_future: the signer clock is pinned to a whole second `at`, and CreatedAt is `at + 301`. The request is refused with request_time_skew (class stale_request), with one new refusal leaf and nothing issued, no matter how much wall-clock time passes before Issue.
    - created_at_outside_skew_past: the same, with CreatedAt `at - 301`.
    - Every other logEnv user (newLogEnv, newLogEnvFx, restart via close/open) keeps time.Now exactly as today.
  </behavior>
  <action>
<!-- planner-discipline-allow: time.Sleep -->
RED (reproduce):
- On the tree with Task 1 committed, insert `time.Sleep(1100 * time.Millisecond)` temporarily, between `req.Evidence = SignRequest(t, req, e.fx.Admins...)` and `e.refuseThroughSigner(...)` in the `created_at_outside_skew_*` subtest of `TestEvidence` (`internal/signer/evidence_test.go`).
- Run `bash scripts/linux.sh 'go test -count=1 -run TestEvidence/created_at_outside_skew ./internal/signer/'`. It MUST exit non-zero, with `created_at_outside_skew_future` failing ("request issued" or a refusal other than request_time_skew). Record it.
- Revert with `git checkout -- internal/signer/evidence_test.go`, and confirm that `git status --porcelain -- internal/signer` prints nothing.

GREEN (use the same `Config.Clock` seam, now reachable from the in-package env):
1. `internal/signer/log_test.go`:
   - Add a field `clock func() time.Time` to `logEnv`, with the comment "signer and bootstrap clock; nil means time.Now". Use `func() time.Time` rather than `serial.Clock`, so the file needs no new import; it is assignable to both.
   - Move the body of `newLogEnvFx` into a new `newLogEnvClock(t *testing.T, fx *Fixture, clock func() time.Time) *logEnv`. It stores `clock` in `e.clock` and passes `e.clock` to `fx.Bootstrap(t, db, e.backend, e.clock)` in place of the literal `nil`.
   - `newLogEnvFx(t, fx)` becomes `return newLogEnvClock(t, fx, nil)`, keeping its `t.Helper()`.
   - In `open()`, add `Clock: e.clock` to the `Config` literal.
   - A nil clock gives exactly today's behaviour everywhere else.
2. `internal/signer/evidence_test.go`, in the `for _, skew := range []int64{-301, 301}` subtest:
   - Compute `at := time.Now().Truncate(time.Second)`.
   - Build the env with `newLogEnvClock(t, NewFixture(t, 1, 1), func() time.Time { return at })` instead of `newLogEnv(t)`.
   - Then `req := e.request()`, then set `req.CreatedAt = uint64(at.Unix() + skew)` with `//nolint:gosec // G115: a current timestamp`. This replaces the old relative adjustment of the wall-clock value.
   - Re-sign the evidence as today, then call `e.refuseThroughSigner(t, req, tlog.ReasonStaleRequest, "request_time_skew")` unchanged.
   - Add a one-line comment: the signer is pinned to `at`, so the skew is exactly ±301 s regardless of elapsed wall time.
   - A frozen clock is correct here, and stepping is not needed: the request is refused at the freshness check before `serial.Next`, and nothing is issued. `fakeClock` is not visible in this package anyway, because it is in a linux-tagged `signer_test` file.
3. Run the `<verify>` commands, then commit only the two files: `git add internal/signer/log_test.go internal/signer/evidence_test.go`, then `git commit -m "test(signer): pin the signer clock in the evidence freshness subtests"`.
4. Determinism proof on the committed fix:
   - Re-insert the 1100 ms pause at the same spot.
   - `bash scripts/linux.sh 'go test -count=1 -run TestEvidence/created_at_outside_skew ./internal/signer/'` MUST pass.
   - Revert with `git checkout -- internal/signer/evidence_test.go`, and confirm a clean `internal/signer`.
   - Record both runs.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=200 -timeout 60m -run TestEvidence/created_at_outside_skew ./internal/signer/' && bash scripts/linux.sh 'go test -race -count=1 ./internal/signer/' && bash scripts/linux.sh 'go vet ./internal/signer/' && F=$(bash scripts/linux.sh 'gofmt -l internal/signer') && test -z "$F" && D=$(git diff --name-only origin/main -- internal/signer) && test -z "$(printf '%s\n' "$D" | grep -v -e '_test\.go$' -e '^$')" && git diff --quiet origin/main -- go.mod go.sum && S=$(git status --porcelain -- internal/signer) && test -z "$S"</automated>
  </verify>
  <done>
- With the injected pause, the unmodified subtest fails on `_future`, and the fixed one passes.
- `TestEvidence/created_at_outside_skew` passes 200/200 under -race.
- The whole `./internal/signer` suite passes under -race in WSL, and vet and gofmt are clean.
- No non-test file under `internal/signer` differs from origin/main, and `go.mod`/`go.sum` are unchanged.
- The change is committed signed.
  </done>
</task>

<task type="auto">
  <name>Task 3: Deliver via the Delivery Protocol (PR as keyroster-bot, auto-merge, green checks, merge gate exit 2)</name>
  <files>.planning/phases/01-trust-core/deferred-items.md, .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-PLAN.md, .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-SUMMARY.md</files>
  <read_first>CONTRIBUTING.md ("Pull request flow" and "Claude's pull requests (keyroster-bot)"), scripts/merge-gate.sh (header exit codes), .planning/phases/01-trust-core/deferred-items.md</read_first>
  <action>
Do not set MSYS_NO_PATHCONV for any `scripts/gh-as-bot.sh` or `scripts/merge-gate.sh` call. Never approve or merge, and never use the owner's gh token (only `scripts/gh-as-bot.sh` talks to GitHub). Never stage `.planning/config.json`, `.planning/milestone.lock` or `.planning/state.json`, and never `git add -A` or `git add .`. Stage explicit paths only.

1. Pre-flight:
   - Run `git fetch origin`. If `git merge-base --is-ancestor origin/main HEAD` fails, `main` has moved:
     - Run `git rebase --autostash origin/main`. Repo config re-signs the commits. `--autostash` is needed because the tracked `.planning/config.json` has unstaged changes, and a plain rebase refuses to start.
     - Afterwards, confirm that `git stash list` has no autostash entry left and that `git status --porcelain` still shows the orchestrator-owned files unchanged.
     - If the autostash pop conflicts, STOP and report. Do not resolve it by committing or discarding those files.
     - Then re-run the Task 2 `<verify>` command.
   - Confirm that `git log --format=%an origin/main..HEAD | sort -u` prints only `keyroster-bot`.
   - Confirm that every commit in `git rev-list origin/main..HEAD` has a `gpgsig` header (`git cat-file commit <sha>`).
2. Push the code: `git push -u origin quick/261006-ixz-flaky-clock`. The credential helper in repo config authenticates as the bot.
3. Open the PR as the bot: `bash scripts/gh-as-bot.sh pr create --base main --head quick/261006-ixz-flaky-clock --title "test(signer): make the request-freshness boundary tests deterministic" --body-file <file>`. Write the body file in the session scratch directory, not in the repo. The body:
   - gives the corrected root cause (crossing a second boundary between the whole-second `CreatedAt` and the sub-second signer clock; failing runs 37307671187 on PR #9 and 37425878563 on PR #15);
   - names the seam: the existing `signerOpts.clock` → `Config.Clock`, `fakeClock.Tick` (1 µs per read from a whole-second base, with a self-check), and the new optional `logEnv` clock;
   - states that production is unchanged (`internal/signer/issue.go`, `maxClockSkew` = 300 s; no non-test file touched);
   - gives the evidence: the informational baseline count, RED with the injected 1.1 s pause, GREEN 200/200 under -race for both, the full suite under -race, vet and gofmt.
   - It must NOT carry the owner-bypass line.

   Record the PR number N.
4. Enable auto-merge: `bash scripts/gh-as-bot.sh pr merge quick/261006-ixz-flaky-clock --auto --squash`.
5. Planning documents, which travel with the code per CONTRIBUTING:
   - (a) In `.planning/phases/01-trust-core/deferred-items.md`, append a **Resolved in quick task 261006-ixz (PR #N)** note to the 01-09 entry. It corrects the cause: the failure needs only the capture and the signer's read to fall in different wall-clock seconds (a few ms can do it), not about one second. It names both failing CI runs and describes the fix in one or two sentences: the stepping fake clock in `TestSignerRefusals`, and the pinned `logEnv` clock for the `TestEvidence` sibling, which had the same race. It states that the production 300 s window is unchanged.
   - Append "Resolved in quick task 261006-ixz (PR #N); see the 01-09 entry." to the two "still not fixed" entries (01-08 and 01-13). Leave every other entry untouched.
   - (b) Write `.planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-SUMMARY.md` per the summary template. Include the commits, the chosen seam and why a frozen clock was rejected, the RED/GREEN evidence with commands and counts, timings, PR #N, and the remaining owner step.
   - (c) Stage with `git add .planning/phases/01-trust-core/deferred-items.md .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-PLAN.md .planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-SUMMARY.md`. Confirm that `git diff --cached --name-only` lists a subset of those three paths. It must include `deferred-items.md` and the SUMMARY. PLAN.md is absent when the orchestrator already committed it. The list must never include `.planning/config.json`, `.planning/milestone.lock` or `.planning/state.json`.
   - (d) Commit with `git commit -m "docs(quick-261006-ixz): record the deterministic freshness tests"`, then `git push`.
6. Wait for the required checks on the final head (`build-test`, `lint`, `govulncheck`, `pr-title`, `e2e (9.5p1)`, `e2e (10.5p1)`, `fuzz`). Run `bash scripts/gh-as-bot.sh pr checks quick/261006-ixz-flaky-clock --required --watch --interval 30` with `run_in_background`, because the e2e and fuzz checks are slow, and wait for it to exit.
   - If a check fails, read its log (`bash scripts/gh-as-bot.sh run view <run-id> --log-failed`).
   - If this change caused it (for example `lint` on a `//nolint` or gosec G115), fix it in a new signed commit, push, and watch again.
   - If it is an unrelated, demonstrably flaky job, rerun it with `bash scripts/gh-as-bot.sh run rerun <run-id> --failed` and say so in the return.
7. Run the merge gate: `bash scripts/merge-gate.sh quick/261006-ixz-flaky-clock`. Expected exit 2, which prints the PR URL and "awaiting owner approval".
   - Exit 3 means `main` moved: the gate rebased, re-signed, force-pushed and waited for green. Run the gate again until it returns 2.
   - Exit 1 or 4 (including a rebase refused because `.planning/config.json` is modified): STOP and report. Do not stash, commit or discard the three orchestrator-owned files to get past it.
   - The owner's approval and the merge are human steps, outside this plan.
8. Finally, confirm that `git status --porcelain` lists only `.planning/config.json`, `.planning/milestone.lock` and `.planning/state.json`.
  </action>
  <verify>
    <automated>bash scripts/gh-as-bot.sh pr checks quick/261006-ixz-flaky-clock --required && M=$(bash scripts/gh-as-bot.sh pr view quick/261006-ixz-flaky-clock --json autoMergeRequest --jq '.autoMergeRequest.mergeMethod') && test "$M" = SQUASH && D=$(git diff --name-only origin/main...HEAD) && test -z "$(printf '%s\n' "$D" | grep -v -e '^internal/signer/[a-z_]*_test\.go$' -e '^\.planning/phases/01-trust-core/deferred-items\.md$' -e '^\.planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/' -e '^$')" && C=$(grep -c '261006-ixz' .planning/phases/01-trust-core/deferred-items.md) && test "$C" -ge 3 && { bash scripts/merge-gate.sh quick/261006-ixz-flaky-clock; test $? -eq 2; }</automated>
  </verify>
  <done>
- PR #N is open from `quick/261006-ixz-flaky-clock` with the title `test(signer): make the request-freshness boundary tests deterministic`, as keyroster-bot, with auto-merge (squash) enabled.
- Every required check is green on the final head.
- The PR diff touches only the four signer test files, `deferred-items.md` and this quick directory.
- `deferred-items.md` marks all three entries resolved, citing PR #N.
- `scripts/merge-gate.sh` exits 2.
- The three orchestrator-owned `.planning` files are still uncommitted.
  </done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| test code → production signer | A test-only fix must not weaken the signer's request-freshness refusal (the ±300 s window, part of the D-13/D-14 issuance gate) |
| bot → GitHub | Claude acts on GitHub only as keyroster-bot. The owner's approval is the human gate. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-ixz-01 | Elevation of Privilege | internal/signer/issue.go freshness check | high | mitigate | No non-test file under internal/signer may differ from origin/main (`git diff --name-only origin/main -- internal/signer` filtered to non-`_test.go` must be empty, Task 2 verify). maxClockSkew stays 300 s with strict `>`/`<`. The ±301 s cases are kept exactly, not widened. |
| T-ixz-02 | Tampering | test determinism claim | medium | mitigate | `fakeClock.Tick` base truncated to a whole second plus a self-check that fails if the clock advanced 1 s or more. The RED/GREEN runs with an injected 1.1 s pause prove the result is independent of wall time. A clean-tree gate (`git status --porcelain -- internal/signer` empty) proves no injected pause was left behind or committed. |
| T-ixz-03 | Spoofing | PR, approval and merge | high | mitigate | Every GitHub call goes through scripts/gh-as-bot.sh (GH_TOKEN/GITHUB_TOKEN unset). No approve or merge commands. The plan stops at merge-gate exit 2 for the owner. |
| T-ixz-04 | Information Disclosure | local GSD state files | low | mitigate | Explicit-path `git add` only. Staged and PR-diff file lists are gated, so .planning/config.json, milestone.lock and state.json are never committed. |
| T-ixz-SC | Tampering | npm/pip/cargo/go module installs | high | mitigate | No dependency is added or installed. `git diff --quiet origin/main -- go.mod go.sum` is gated in Task 2, so the package-legitimacy gate has nothing to admit. |
</threat_model>

<verification>
- RED evidence: with an injected 1.1 s wall-clock pause, the unmodified `TestSignerRefusals/created_301s_future` and `TestEvidence/created_at_outside_skew_future` fail. The fixed versions pass with the same pause.
- `go test -race -count=200` passes for both boundary subtests, and `go test -race ./internal/signer/` passes (all in WSL via scripts/linux.sh).
- `go vet ./internal/signer/` (Linux, so the linux-tagged files are vetted) and `gofmt -l internal/signer` are clean.
- The production file gate and the go.mod/go.sum gate pass.
- PR checks are green, auto-merge is squash, and merge-gate exit is 2.
</verification>

<success_criteria>
- The flaky `created_301s_future` failure mode is gone. Its outcome depends only on the injected test clock, which is proven by the 1.1 s pause test and 200/200 runs under -race. The same holds for the TestEvidence sibling.
- The production freshness window is byte-identical (no non-test file in internal/signer changed).
- deferred-items.md: all three entries are resolved, and the root cause is corrected.
- A bot PR is open with auto-merge squash and all required checks green, and the merge gate returns 2 (waiting for the owner).
</success_criteria>

<output>
Create `.planning/quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/261006-ixz-SUMMARY.md` in Task 3 step 5, before the docs commit.
</output>
