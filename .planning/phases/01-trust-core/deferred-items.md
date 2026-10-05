# Deferred Items (phase 01)

Out-of-scope discoveries logged by plan executors. Each item names the plan that found it.

## Deferred Items

- **01-09: `TestSignerRefusals/created_301s_future` is timing-flaky under CPU load.** `internal/signer/signer_test.go` captures `now` once at the start of `TestSignerRefusals` and tests the ±300 s skew bound with `now ± 301`. When more than about one second passes before that subtest runs, `now + 301` falls inside the window and the request is accepted. It failed once in CI `build-test` on PR #9 (run 37307671187, first attempt) while the new scrypt-heavy root tests ran in parallel packages under `-race`, and passed on rerun. Fix: give the test signer a fixed clock (or compute `now` inside each edit function and use a wider margin). It was not fixed in 01-09 because `internal/signer/*` belongs to 01-07 (PR #8, open at the time).
