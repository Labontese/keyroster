---
phase: quick-261124-sfx
plan: 01
subsystem: tests-and-docs
tags: [flaky-test, e2e, ci, docs, merge-gate]
status: complete
requires: []
provides:
  - "merge gate texts that say to run the gate again after a green rebase instead of claiming a dismissed approval"
  - "a bounded retry of the Arch lane's package sync"
  - "five unit tests that random text, load or the wall clock no longer trip, or that now see a leak they could not see; each changed assertion fails its mutant"
  - "end-to-end retries that wait as many seconds as the largest command each helper runs sends admin requests"
  - "a correct and pinned location bullet in ca-rotation.md and a guarded, pinned tpm paragraph in signer-install.md"
affects: []
key-files:
  modified:
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
    - test/e2e/agent_forget_test.go
    - test/e2e/hosts_test.go
    - test/e2e/machine_test.go
    - test/e2e/probe_certs_test.go
    - docs/runbooks/ca-rotation.md
    - docs/runbooks/signer-install.md
    - cmd/keyroster/securitydocs_test.go
    - cmd/keyroster/runbook_test.go
decisions:
  - "The decode-message test compares the whole message: the test's own URL, /healthz: , the CLI's words, the offset (4010 or 4006) and ')'. No peer text can stand anywhere in it, digits after the offset included."
  - "Every end-to-end retry waits as many seconds as the largest command its helper runs sends admin requests, because a refused request spends no token and the bucket refills one a second. That is 5 s for machine_test.go; 4 s for the two helpers that run host remove; 3 s for those whose largest command is host approve, user approve, host forget or revoke user of a user in no directory; and 2 s for those that run only directory changes. No bound, deadline or anchor of a timed test changes."
  - "The re-poll test bounds the gap between its two requests' arrivals at 900 ms and the whole Once at a minute, with an hour's poll interval. The live-signer log test's clock advances only by the monotonic reading, and its requests are stamped with that clock."
requirements: []
metrics:
  completed: 2026-11-24
actuals:
  tasks: 5
  commits: "18 (17 measured with git rev-list before the commit that lists the re-poll leaf's gap bound under load as unverified, plus that commit)"
plan_head_before: 2d61b55d6e7317d4658a96447f5e759a730131ba
plan_head_after: 0fdb8fc58bb69daee4fa9097023fa3be0e5eb230
---

# Quick 261124-sfx Plan 01: ten small fixes to tests, three documents, the merge gate's texts and the Arch lane Summary

Ten small fixes, each read at 2d61b55 before it was changed. The merge gate's texts no longer claim that GitHub always dismisses the approval after a rebase. The Arch lane retries its package sync. Five unit tests change. Two absence checks no longer run on random text (items 3 and 5). One assertion now sees a leak it could not see (item 4). Two tests no longer depend on load or on the wall clock (item 6). Every changed assertion fails its mutant; TestCheckLogAgainstLiveSigner, which has no mutant, passes 20 race runs. Every end-to-end retry waits as many seconds as the largest command its helper runs sends admin requests. The pull request's pre-merge review raised five points, and the fix round closed all of them ("Pre-merge review"). Two runbook passages say what the code does and are pinned, and one CONTRIBUTING.md row names the test's third client. No product code changes.

## The mutant rule

Every Q below followed one rule. The unmutated narrow run passed first. One exact replacement, whose old string occurs once in its file. `go vet` of the package exited 0. The narrow run failed with the named leaf's `--- FAIL:` line and with no `[build failed]`, `[setup failed]`, `--- SKIP` or test-timeout line. Then `git checkout --` of the file, sha256 before and after equal, and `git status --short -- cmd internal test docs scripts .github` empty. Each mutant ran on the committed test, so the status was empty after every restore. The labels run Q3 to Q9b; none was committed.

## Item 1: the merge gate's texts

- **Wrong (read at 2d61b55).** scripts/merge-gate.sh:13-15 says that after exit 3 "GitHub dismissed the approval, so the owner must approve the new head", and :250 prints `rebased onto main: owner re-approval needed`. CONTRIBUTING.md:118 says "A new push dismisses an earlier approval", :169 says "the owner then approves the new head", and 01-SKELETON.md:55 says "GitHub dismissed the approval ... so present the checkpoint again for re-approval of the new head". The script exits 3 after every green rebase without reading the review state. On 2026-11-22 GitHub kept three approvals across rebases that left the diff unchanged.
- **Change.** The header's exit-3 entry is now four lines: run the script again; it exits 2 when the owner must approve the new head, and GitHub has kept an approval when a rebase left the diff unchanged. The message is now `rebased onto main and green: run the gate again (it exits 2 if the owner must approve the new head)`. CONTRIBUTING.md now says "A new push can dismiss an earlier approval", and that the gate's next run tells whether the owner must approve the new head. 01-SKELETON.md's line on exit 3 says to run the gate again: exit 2 means the owner must approve the new head; otherwise the gate goes on to wait for the merge.
- **Proof.** `bash -n scripts/merge-gate.sh` passes. shellcheck is not installed in the WSL used here, and no workflow runs it, so it did not run. The script's diff holds only comment lines and the one `echo`. A run after exit 3 reads the review decision on every run, before any branch:

  ```bash
  view=$(bot_gh pr view "$branch" --json number,state,reviewDecision,mergeStateStatus,url \
  	--jq '[(.number | tostring), .state, (.reviewDecision // ""), (.mergeStateStatus // ""), .url] | join("|")')
  IFS='|' read -r number state decision merge_state url <<<"$view"
  ```

  Once the branch contains origin/main, the run reaches:

  ```bash
  if [ "$decision" != APPROVED ]; then
  	echo "$url"
  	echo "awaiting owner approval (review: ${decision:-none}, merge state: $merge_state)"
  	return 2
  fi
  ```

  and otherwise `echo "approved; waiting for the owner to squash-merge #$number"` and the wait loop. What GitHub does with an approval on a rebase cannot be shown locally: the observation of 2026-11-22 is the evidence.

## Item 2: the Arch lane's package sync

- **Wrong (read at 2d61b55).** test/distro/run-in.sh:37 runs `pacman -Syyu --noconfirm --needed openssh` once, under `set -eu` (:5), against the one Server line the script writes (:35). One stalled fetch fails the lane. On 2026-11-22 the archive was down for hours, and when it answered again one stalled fetch failed the first re-run.
- **Change.** The line becomes a POSIX sh loop: at most three tries, 30 s apart, over the same command, the same snapshot mirror and the same package, with pacman.conf untouched, so the signature checks stay. Each failed try but the last prints `run-in.sh: pacman failed (try N of 3); trying again in 30 s` on stderr. After the third it prints `run-in.sh: pacman failed 3 times against the Arch Linux Archive snapshot <snapshot>` and exits 1. One sentence in the comment above says why: on 2026-11-22 the archive was down for hours, and when it answered again one stalled fetch failed the first re-run; a retry rides out a stall, not an outage. (The first round's sentence said that one stalled fetch failed the lane for hours; the fix round corrected it.)
- **Proof.** `sh -n test/distro/run-in.sh` (Git Bash) and `dash -n test/distro/run-in.sh` (WSL) pass. A copy of the loop, taken from the file's bytes, ran outside the repository with `pacman` replaced by a shell function that fails N times and then succeeds. It ran as `dash -eu` in WSL, where /bin/sh is /usr/bin/dash:
  - N=0: one call, exit 0, no message.
  - N=2: three calls, the messages for tries 1 and 2, exit 0, 60 s.
  - N=3: three calls, the messages for tries 1 and 2, then `run-in.sh: pacman failed 3 times against the Arch Linux Archive snapshot 2026/11/20`, exit 1, 60 s.

  The green path on real Arch is the CI lane `e2e-distro (archlinux)`.

## Item 3: another user's name on the account page

- **Wrong (read at 2d61b55).** internal/server/session_test.go:82, in TestSession/account_shows_own_data_only, looks for "bob" in the whole of alice's account page. The page holds alice's two passkey fingerprints, which are random base64 (43 characters each). Either of them can hold "bob", at roughly 1 in 3,000 runs (computed, not measured).
- **Change.** The name is looked for in the page with alice's two fingerprints removed (`strings.NewReplacer(fingerprint(e.alice), "", fingerprint(e.alice2), "")`). The check of bob's fingerprint stays on the whole page. A comment says why.
- **Proof, Q3.** Narrow command: `go test -count=1 -timeout 5m -v -run '^TestSession$/^account_shows_own_data_only$' ./internal/server/`.
  - Replacement in internal/server/account.go: `page := &accountPage{Name: u.Name, Status: u.Status, DirectoryVersion: view.version}` becomes `page := &accountPage{Name: u.Name, Status: u.Status + " " + view.dir.Users[len(view.dir.Users)-1].Name, DirectoryVersion: view.version}`. The test's directory holds alice and bob, sorted, so alice's Status cell reads `active bob`, and "active", which the leaf requires, is still on the page.
  - Failing line: `session_test.go:85: alice's account page shows bob's data:`.
  - sha256 before and after: `a274851f09c1faf726c167cfe3b297e985af30fb9eb45ba0842b9bc0c51fe995`.

## Item 4: the decode message's form

- **Wrong (read at 2d61b55).** internal/serverclient/client_test.go:1180, in TestConnectErrorTransport/json_errors_in_own_words, checks the message for three things: the CLI's words, no "peer text", and no "000" outside the URL. For the body of 4,000 spaces, the "000" check sees nothing. If the client appended encoding/json's own text for that body ("invalid character 'x' looking for beginning of value"), the check would still pass.
- **Change.** The message is compared whole, and that one comparison replaces the three checks. Each body carries its full expected tail in the table, ending with its offset and `)`. The comparison is `msg != url+"/healthz: "+want`: the test's own URL, `/healthz: `, the CLI's words, the offset and `)`.
  - The offsets are 4010 for the body of zeros (6 bytes of `{"a":1`, 4000 zeros and the 4 of `e999`) and 4006 for the body of spaces (5 bytes of `{"a":`, 4000 spaces and the `x`). The comment above the table gives this arithmetic.
  - The comment above the comparison says what it refuses.
  - No `regexp` import is needed.
  - The first round compared against a regular expression instead ("Pre-merge review").
  - A temporary `t.Logf` (removed again; the file's sha256 matched the edited file afterwards) showed both messages beginning with the URL exactly:
    - `https://localhost:35463/healthz: decode: the response has a JSON value of the wrong type (at byte 4010)`, with url `https://localhost:35463`
    - `https://localhost:45447/healthz: decode: the response is not valid JSON (at byte 4006)`, with url `https://localhost:45447`

    The exact comparison passes on this toolchain, so both offsets are confirmed.
- **Proof, Q4a to Q4d.** Each mutant ran on the assertion at 2d61b55 (the "old" one) or on the first round's regular expression, and then on the exact comparison.
  - Narrow command: `go test -count=1 -timeout 5m -v -run '^TestConnectErrorTransport$/^json_errors_in_own_words$' ./internal/serverclient/`.
  - All four are in internal/serverclient/client.go, whose sha256 before and after every run is `3ce7ec7af6f8e9917c80683b3cb469327ae14f2f08c80447a01e034d34e75238`.
  - **Q4a.** `msg = fmt.Sprintf("the response is not valid JSON (at byte %d)", syntaxErr.Offset)` becomes `msg = fmt.Sprintf("the response is not valid JSON (at byte %d): %v", syntaxErr.Offset, syntaxErr)`.
    - Old assertion: PASS (the mutant survives).
    - Exact comparison: FAIL, `client_test.go:1187: body "{\"a\":               "...: err = "https://localhost:42491/healthz: decode: the response is not valid JSON (at byte 4006): invalid character 'x' looking for beginning of value", ...`.
  - **Q4b.** `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d)", typeErr.Offset)` becomes `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d): %s", typeErr.Offset, typeErr.Value)`.
    - Old assertion: FAIL.
    - Exact comparison: FAIL, `client_test.go:1187: body "{\"a\":100000000000000"...: err = "https://localhost:38695/healthz: decode: the response has a JSON value of the wrong type (at byte 4010): number 1000000000...`.
  - **Q4c, the peer's text before `: decode:`.** `return fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))` becomes `return fmt.Errorf("%s%s%.6s: decode: %w", c.base, path, data, decodeError(err))`.
    - Old assertion: PASS (the mutant survives: neither six-byte excerpt holds "000").
    - Exact comparison: FAIL for both bodies, `err = "https://localhost:34457/healthz{\"a\":1: decode: ...` and `err = "https://localhost:42359/healthz{\"a\": : decode: ...`.
  - **Q4d, digits after the offset.** `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d)", typeErr.Offset)` becomes `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d000)", typeErr.Offset)`.
    - The first round's regular expression: PASS (the mutant survives). That run used the test file of a9a4d51 in the worktree; both files were restored afterwards, and their sha256 values matched (client_test.go `8b7bc349400937daf293366657abc1293561cd522a7b423a16d1e44d91a2c0f4`, client.go as above).
    - Exact comparison: FAIL, `err = "https://localhost:39629/healthz: decode: the response has a JSON value of the wrong type (at byte 4010000)", ...`.
  - `go test -race -count=1 ./internal/serverclient/`: ok (4.0 s).

## Item 5: the sweep, and the entry name in known_hosts

- **Wrong (read at 2d61b55).** cmd/keyroster/knownhosts_test.go:593, in TestKnownHosts/names_are_principals_not_entry_names, looks for "srv1" in the whole managed known_hosts. That file holds an @cert-authority line with a random ed25519 host CA key in base64. The key can hold "srv1", at about 1 in 400,000 runs (computed, not measured).
- **Change.**
  - The leaf now collects the file's lines that are neither empty nor comments. It requires them to be exactly one line: `hostCALine("web1", f.bundle.CAs[1])` without its newline. `f.bundle.CAs[1]` is the fixture's only host CA (knownhosts_test.go:106-107), and the writer receives it unchanged through `hostTrustCAs` and `trust.TrustedCAs`. No short string is looked for inside the key, and a second line, or a line of another kind, fails too.
  - `htCALines` now fails the test when a second `@cert-authority` line carries a key it has already seen, because the map would otherwise hide the first line. The whole cmd/keyroster package passes with that check, so no leaf has two lines of one key.
  - The first round compared only the CA lines' names, read through `htCALines` ("Pre-merge review").
- **Proof.**
  - Narrow command: `go test -count=1 -timeout 5m -v -run '^TestKnownHosts$/^names_are_principals_not_entry_names$' ./cmd/keyroster/`.
  - The sha256 of cmd/keyroster/knownhosts.go before and after each mutant is `ee3aff0433bf1704818ff9f604f6ca3b0d7bd5fe93975b33059b59f18ae86d67`.
  - **Q5.** In cmd/keyroster/knownhosts.go (hostTrustNames), `active = append(active, p)` becomes `active = append(active, p, h.Name)`. Fails, `knownhosts_test.go:610: known_hosts lines ["@cert-authority srv1,web1 ssh-ed25519 AAAA... keyroster host CA generation 1"], want only "@cert-authority web1 ssh-ed25519 AAAA... keyroster host CA generation 1"`. The first round's check failed this mutant too (`knownhosts_test.go:598: CA line names ["srv1" "web1"], want the principal web1 only`).
  - **Q5b, one more CA line of the same key before the real one.** In knownHostsFile, `b.WriteString(hostCALine(names, ca))` becomes `b.WriteString(hostCALine("srv1", ca) + hostCALine(names, ca))`. The writer does not see entry names there, so the mutant writes the entry name "srv1" as a literal. Fails, `knownhosts_test.go:610: known_hosts lines ["@cert-authority srv1 ssh-ed25519 AAAA... keyroster host CA generation 1" "@cert-authority web1 ssh-ed25519 AAAA... keyroster host CA generation 1"], want only ...`.
  - `go test -count=1 -timeout 15m -run '^(TestKnownHosts|TestMachineHostTrust)$' ./cmd/keyroster/`: ok (7.9 s).
  - `go test -count=1 -timeout 20m ./cmd/keyroster/`: ok (140.6 s).
- **The sweep.** The pattern `(?:^|[^!\w])(?:strings|bytes)\.Contains\(.*,\s*(\[\]byte\()?"[A-Za-z0-9+/=_.:-]{2,8}"|NotContains\(.*"[A-Za-z0-9+/=_.:-]{2,8}"` runs over every `*_test.go`.
  - Read at 2d61b55, it gives 74 lines in 37 files. It was re-run here with `git grep -n -P` at 2d61b55 and gave the same 74 lines in 37 files.
  - The two real cases among them are session_test.go:82 (item 3) and knownhosts_test.go:593 (this item).
  - Four more are absence checks of five letters or more, on text that holds a fingerprint, a port or a log. Their odds are negligible and they are not changed: test/e2e/websignin_test.go:266, enroll_test.go:150, probe_certs_test.go:673 and probe_selftest_test.go:853.
  - At the head of the first round, the pattern gave 72 lines. knownhosts_test.go:593 and client_test.go:1180 were gone, and session_test.go:84 still matched, now made on the page without the fingerprints.
  - The pattern does not see an absence check whose string is a variable, a regular-expression check, or a string longer than eight characters.

## Item 6: two tests that failed once under load

- **Wrong (read at 2d61b55).**
  - internal/agent/fetch/fetch_test.go:277, in TestFetch/more_repolls_immediately, bounds one `Once` at 900 ms, under -race and with a fetcher that polls every second (:142). A second of load fails it.
  - internal/signer/log_test.go:432, in TestCheckLogAgainstLiveSigner, uses the wall clock (`newLogEnv`, clock nil). If the wall clock steps back between two of its 60 issues, an issue fails with `clock_regression` (internal/serial/serial.go).
- **Change.**
  - **The re-poll leaf** sets `ts.f.cfg.Poll = time.Hour`. The fetcher reads `cfg.Poll` only in New (fetch.go:177-181) and Run (:249). The leaf now has two bounds:
    - Its own handler records the time each of the two requests arrives. The gap between the first and the second arrival must be below 900 ms, and the message says that a re-poll after `more: true` must be immediate. The gap holds only the spooling of the first answer and the second request, so it catches a wait of about a second or more between the rounds.
    - The bound on the whole `Once` is a minute, the limit for the call.
    - A `t.Logf` prints the gap. The gap is checked before the request list and the minute bound.
  - **The log test** builds its environment with `newLogEnvClock(t, NewFixture(t, 1, 1), clock)`, where `clock` is `func() time.Time { return base.Add(time.Since(base)) }`. The signer's clock therefore advances only by the monotonic reading. The constructor exists at log_test.go:99 and passes the clock to Bootstrap and to `Config.Clock`.
    - Each request the test issues also takes `CreatedAt` from that clock and is signed again (`SignRequest`), as internal/signer/drain_test.go:468-470 does. So a step of the wall clock cannot fail an issue with `request_time_skew` either.
    - The shared `request` helper is unchanged.
- **Proof, Q6a and Q6c.**
  - Narrow command: `go test -count=1 -timeout 3m -v -run 'TestFetch/more_repolls_immediately' ./internal/agent/fetch/`.
  - Both mutants are insertions in `Once`'s round loop (fetch.go:463-531), after line 530 (the `}` that closes `if !resp.More {`), as the last statement of the loop's body. The replacement's old string, `\t\t\treturn true, err\n\t\t}\n\t}\n\treturn true, nil\n}`, occurs once.
  - sha256 of fetch.go before and after both: `47304efcfbcb54233584eaa3b3ba6c29cba708aab7ffe6169b96c76a447135ca`.
  - **Q6a** inserts `time.Sleep(min(NextPoll(f.cfg.Poll), 61*time.Second))`. It now fails by the gap bound: `fetch_test.go:299: the second request arrived 1m1.04234382s after the first, want below 900 ms: a re-poll after more: true must be immediate` (`--- FAIL: TestFetch/more_repolls_immediately (61.07s)`). In the first round it failed by the minute bound, `fetch_test.go:283: requests [...] in 1m1.058271796s`.
  - **Q6c** inserts `time.Sleep(time.Second)`. Fails by the gap bound, `fetch_test.go:299: the second request arrived 1.016664298s after the first, want below 900 ms: ...` (`--- FAIL: TestFetch/more_repolls_immediately (1.05s)`).
  - Not run: the uncapped sleep of one poll interval (at least 50 minutes with an hour's poll). It would end the run by the test timeout.
- **Repeated runs.**
  - `go test -race -count=50 -v -run 'TestFetch/more_repolls_immediately' ./internal/agent/fetch/`: ok (3.7 s), 50 PASS lines, no FAIL. The gaps the leaf logged ranged from 16.6 ms to 21.5 ms, with a median of 17.9 ms.
  - The first round's `-race -count=20` run of the leaf with only the minute bound was ok (2.1 s).
  - `go test -race -count=20 -v -run '^TestCheckLogAgainstLiveSigner$' ./internal/signer/` with the requests stamped by the test's clock: ok (16.1 s), 20 PASS lines, no FAIL. The first round's run with only the signer's clock was ok (14.7 s).

## Item 7: the end-to-end helpers' retry

- **The rule (internal/server/ratelimit.go).**
  - The admin routes share one bucket per client address: `adminLimit: newLimiter(lim.AdminPerMinute, lim.AdminBurst, 0, 0)` (internal/server/server.go:189).
  - The defaults are 60 a minute and a burst of 20 (ratelimit.go:60-61), so the bucket refills one request a second. The bucket is keyed by the client address only (`clientKey`, :209-223).
  - A refused request spends no token (`AllowN`, :180), and Retry-After is always 1 s (:201).
  - So a wait of N seconds lets a command of N admin requests through at its first retry. Every retry site under test/e2e now waits as many seconds as the largest command its helper runs sends admin requests, and its comment names that command and its count.
- **The requests of each command** (cmd/keyroster at the head of this task; no product file changes):
  - GET directory: `fetchVerifiedDirectory`, dirpipe.go:137.
  - POST directory: `installVersion`, dirpipe.go:384.
  - A directory change (role add, update, grant or revoke; group add; host-group add, map or unmap; machine add; host add): GET and POST directory, two.
  - host join-token: host.go:506, one.
  - host pending: host.go:577, one.
  - host status: hoststatus.go:154, one.
  - host principals: GET directory through host.go:284, one.
  - known-hosts sync: knownhosts.go:1083, one.
  - host ca-key: none (host.go:329 reads only the trust path, which is outside the admin bucket).
  - revoke serial, key or key-id: one POST each (`send`, revoke.go:164).
  - host approve: GET pending hosts (host.go:823, which calls :577), then GET and POST directory (host.go:865), three.
  - user approve: GET pending credentials (user.go:588), then GET and POST directory (user.go:631 or :704), three.
  - host forget: GET pending hosts (host.go:1036, which calls :577), GET hosts status (host.go:1041, which calls hoststatus.go:154), POST forget (host.go:1135), three.
  - host remove: four. GET directory, a sweep of the host's certificates before the install (dirpipe.go:302, then :605, then revoke.go:164), POST directory (dirpipe.go:305), and a second sweep after it (dirpipe.go:308). The second sweep only warns when it fails. Both sweeps run only when the bundle has an installation ID, which the end-to-end bundles have.
  - revoke user: a sweep (revoke.go:491), GET directory, POST directory only when the user is in the directory, a second sweep (revoke.go:558). That is three for a user in no directory and four for a user in one.
  - revoke machine NAME: a sweep (revoke.go:794), GET and POST directory (revoke.go:810), one revocation per key with `--keys` (revoke.go:862, through `revokeHostKey`, revoke.go:963-973), a second sweep (revoke.go:884). That is four, or five with `--keys` and one key.
- **The sites, as verified.** The callers were followed through joinApproved, enrollApproved, joinApprovedHeld, joinHostCert and joinProbeHost. Line numbers are at the head of this task.

| Retry site | Commands its callers run through it (admin requests each) | Largest | Wait |
|---|---|---|---|
| `kr` of TestAgentEnrollEndToEnd (agent_enroll_test.go) | directory changes (2), host join-token (1), host pending (1), host approve (:324, 3), revoke serial (1), host remove (:417, 4) | host remove, 4 | 3 s to 4 s |
| the inline loop around host forget (agent_enroll_test.go:442) | host forget (3) | host forget, 3 | 2 s to 3 s |
| `run` and `kr` of TestAgentReenrollEndToEnd (agent_forget_test.go) | through enrollApproved and joinApprovedHeld: directory changes (2), host join-token (1), host pending (1), host approve (3); host remove (:71, 4), host forget (:122, :161, :171, 3), host status (1), revoke serial (1) | host remove, 4 | 3 s to 4 s |
| `kr` of TestAgentStatusEndToEnd (agent_status_test.go) | through enrollApproved: directory changes, host join-token, host pending, host approve (3); host status (1), revoke serial (1) | host approve, 3 | 3 s |
| `kr` of TestCARotationNoFailedLogin (ca_rotation_test.go) | directory changes (2); through joinApproved: host join-token, host pending, host approve (3); host status (1), revoke serial (1) | host approve, 3 | 3 s |
| `kr` of TestDeliveryDuringHeldSignature (stall_test.go) | through enrollApproved only: directory changes, host join-token, host pending, host approve (3) | host approve, 3 | 3 s |
| `hostCertKR` (hostcert_test.go) | through joinHostCert and joinProbeHost: directory changes, host join-token, host pending, host approve (3); host status (1); directory changes (2) | host approve, 3 | 3 s |
| `hostTrustKR` (hosttrust_test.go) | through joinHostCert: host approve (3); user approve (:364, 3); directory changes (2); known-hosts sync (1); host status (1) | host approve and user approve, 3 | 3 s |
| `loginFixture.kr` (login_test.go) | user approve (:343, 3); directory changes (2); host principals (1); host ca-key (0) | user approve, 3 | 3 s |
| `kr` of TestRolesHostPrincipalsEndToEnd (roles_test.go) | user approve (:93, :95, 3); directory changes (2); host principals (1); host ca-key (0) | user approve, 3 | 3 s |
| `revokeCLIRetry` (revoke_test.go), used by TestRevokeUserEndToEnd and the two recovery drills | user approve (revoke_test.go:258, :260, 3); directory changes (2); revoke key-id, serial, key (1); revoke user carol (recovery_test.go:442: carol is in no directory, the drill installs none, so 3); revoke recover (0) | user approve and revoke user, 3 | 3 s |
| `kr` of TestMachineIdentityEndToEnd (machine_test.go) | directory changes (2); revoke machine ci (:179, 4); revoke machine ci2 --keys, one key (:197, 5) | revoke machine --keys, 5 | 2 s to 5 s |
| `kr` of TestDirectoryHostsEndToEnd (hosts_test.go) | directory changes (2); host principals (1) | a directory change, 2 | 2 s |
| `kr` of TestProbeCertsAgainstSSHD (probe_certs_test.go) | directory changes (2) | a directory change, 2 | 2 s |

The table the fix round started from ("Pre-merge review") put `revokeCLIRetry` at 4 s, for a revoke user of a user in a directory. Every revoke user run through it is of carol, who is in no directory, and the one revoke user of a user in a directory (revoke_test.go:304) runs through `env.keyroster` without a retry. So the count is 3 and the wait stays 3 s. agent_systemd_test.go's `kr` has no retry.

- **Changed sites whose retry lies inside a timed window.** The longer wait acts only after a refusal. These are the places where a refused call's retry now takes 1 s or more of a window. No bound, deadline or anchor changed.
  - **TestAgentEnrollEndToEnd** (4 s):
    - `host approve` (:324) is inside the 10 s window, which runs from `before` (:312) to the first apply (:335). A refused approval's retry spends 4 s of it.
    - The poll of `host pending` (:288-292, 30 s) also lies inside a window.
    - `revoke serial` (:362) is at the start of `took`, which is logged, not bounded.
    - `host remove` (:417) and `revoke serial` (:426) sit inside no bound.
  - **The inline loop around host forget** (3 s) polls within its unchanged 32 s deadline (:442) for `host_removal_not_applied` and `host_swap_pending` as well as for the limiter. So it now makes about 10 attempts instead of 16.
  - **TestAgentReenrollEndToEnd** (4 s), within `forgetWait`, 32 s:
    - `host pending` (:74, in the loop at :73);
    - `host status` (:94, in the loop at :92; :135, in the loop at :134);
    - joinApprovedHeld's 30 s poll of `host pending` (agent_status_test.go:62).
  - **TestMachineIdentityEndToEnd** (5 s) has no deadline around any call of its helper. Its whole test sends 19 admin requests against a fresh bucket of 20, so its retry does not fire today.
  - **The sites at 3 s**, unchanged since the first round:
    - joinApprovedHeld's, joinHostCert's (hostcert_test.go:71) and joinProbeHost's (probe_selftest_test.go:134) 30 s polls of `host pending`;
    - waitStatus's 30 s poll (agent_status_test.go:107-108);
    - the 240 s poll for a silent agent (agent_status_test.go:302-303);
    - TestCARotationNoFailedLogin's 150 s poll of `host status` (ca_rotation_test.go:728-729), and its revocations and waitStatus at :747 and :835-837, the latter between the switch and the drain, whose bound is trusted_until + 120 s (:856);
    - TestHostCARotation's hcrSync (hostca_rotation_test.go:527, :630, :761) and hcrCommitted (:570, :731);
    - hosttrust_test.go's 60 s heartbeat poll (:416) and hostcert_test.go's 60 s polls (:285-297, :370-380).
- **Proof.** None locally: the refusal needs the bucket's level that only a CI lane reaches, and nothing under test/e2e runs locally. `go vet` passed under each tag set: `e2e`, `e2e e2emachine`, `e2e e2eprobe`, `e2e e2erotation`, `e2e systemdsmoke`, `e2e_pkcs11` and `e2e_tpm`. The full gate's vet lines and the CI lanes run them again.
  - In the CI runs of the first round's head, both main e2e lanes logged `roles_test.go:187: keyroster host-group unmap web runner --yes was rate-limited; running it again in 3 s`, and the tests passed. That is a refused command of two requests recovering at its first retry, not a command of three or more.

## Item 8: the location bullet of ca-rotation.md

- **Wrong (read at 2d61b55).** docs/runbooks/ca-rotation.md:935-939 says that a database edit of a PIV generation's location "is stopped by the fingerprint checks before any card write" and that an edit "that points at any slot" that does not hold the draining key makes the signer's check answer "not held". The code bears out less:
  - internal/keystore/piv/piv.go `generationSlot` (:364-383): generation 1 takes no location, and generation 2 or later resolves only "87" to "95" (`parseLocation`, :346-358).
  - `Holds` (:637-649) answers held, with the error, for a location that does not resolve.
  - `RemoveGeneration` (:661-677) overwrites only a slot whose key has the draining fingerprint, and `ProvisionGeneration` (:531-538) generates only into an empty slot.
  - The signer's check reaches `Holds` through `keystore.Holds` (internal/keystore/keystore.go:171), from internal/signer/rotate.go:547 and :557, internal/signer/trust.go:618 and cmd/keyroster-signer/doctor.go:254.
  - docs/backends/piv.md's pinned sentence (`locationLimit`, cmd/keyroster/securitydocs_test.go:47) says the same as the new bullet, with "Holds" where the bullet says "the signer's check".
- **Change.** The bullet now reads: after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes the signer's check answer "not held", and audit cannot show which slot a generation used. A new leaf, TestSecurityDocs/ca_rotation_location_bullet, reads the bullet's own window ("Run in CI", from `- **The location column is not logged.**` to the next bullet or blank line). It holds `retire-key still overwrites a slot only when its key has the draining fingerprint` and `for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key`, and refuses `points at any slot` and `is stopped by the fingerprint checks before any card write`.
- **Proof.** Items 8 and 9 share the RED and its command, so their RED is recorded under item 9.
  - **Q8a.** `generation's location, retire-key still overwrites a slot only when its` becomes `generation's location, retire-key overwrites a slot only when its`. Fails: `securitydocs_test.go:111: ca-rotation.md "Run in CI", the bullet on the location column lacks "retire-key still overwrites a slot only when its key has the draining fingerprint"`.
  - **Q8b.** `later an edit that points at another generation slot, one that does not` becomes `later an edit that points at a generation slot, one that does not`. Fails: `securitydocs_test.go:111: ... lacks "for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key"`.
  - Narrow command: `go test -count=1 -timeout 5m -v -run '^TestSecurityDocs$/^ca_rotation_location_bullet$' ./cmd/keyroster/`. sha256 of ca-rotation.md before and after both: `c29362e017f0a7692db8ab60a8310770ecedf15f67e543434548cdd4fee1db7b`.

## Item 9: the tpm paragraph of signer-install.md

- **Wrong (read at 2d61b55).** docs/runbooks/signer-install.md:476-488, the tpm paragraph on a key pair that no generation row names, lacks two things that the software paragraph beside it (:466-474) has: the guard "when no prepare is running and no `--key` prepare of yours is waiting for it", and the closing "never record a lost key with `--key`". The restore section's own sentence (:1122-1131) carries both for the software file and the tpm pair alike, and so does doctor's warning text (internal/doctor/doctor.go:416).
- **Change.** The tpm paragraph's sentence is the software paragraph's, clause by clause, with "pair" for "file": a pair of that name that no generation row names (doctor warns `unrecorded_generation_file`) is, when no prepare is running and no `--key` prepare of yours is waiting for it, a key from a prepare that the restore lost; destroy it unless you placed it for a `--key` prepare, but only after the restore section has run to its end, because where that section stops on a lost generation the pair may hold that generation's key, and never record a lost key with `--key`. The paragraph's last sentence is rewrapped, not reworded. `when no prepare is running` and ``never record a lost key with `--key` `` join the tpm list of TestCARotationBackendSteps/unrecorded_key_files_after_restore. The software paragraph already held each phrase once (counted on the whitespace-normalised window), so they join its list too.
- **Proof, the RED.** The pins' commit (0d03d7f) was checked out in a detached worktree outside the repository and run there with `go vet ./cmd/keyroster/ && go test -count=1 -timeout 15m -v -run "^(TestSecurityDocs|TestCARotationBackendSteps)$" ./cmd/keyroster/`. It exited 1 with exactly these lines and no others:
  - `runbook_test.go:1904: the tpm paragraph of signer-install.md "Prepare a CA key generation" lacks "when no prepare is running"`
  - ``runbook_test.go:1904: the tpm paragraph of signer-install.md "Prepare a CA key generation" lacks "never record a lost key with `--key`"``
  - `--- FAIL: TestCARotationBackendSteps/unrecorded_key_files_after_restore`
  - `securitydocs_test.go:111: ca-rotation.md "Run in CI", the bullet on the location column lacks "retire-key still overwrites a slot only when its key has the draining fingerprint"`
  - `securitydocs_test.go:111: ... lacks "for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key"`
  - `securitydocs_test.go:117: ... still says "points at any slot"`
  - `securitydocs_test.go:117: ... still says "is stopped by the fingerprint checks before any card write"`
  - `--- FAIL: TestSecurityDocs/ca_rotation_location_bullet`

  The same command passes on the documents' commit.
- **Q9a.** ``no prepare is running and no `--key` prepare of yours is waiting for it, a`` becomes ``no prepare runs and no `--key` prepare of yours is waiting for it, a``. Fails: `runbook_test.go:1904: the tpm paragraph ... lacks "when no prepare is running"`.
- **Q9b.** ``hold that generation's key, and never record a lost key with `--key`.`` becomes ``hold that generation's key, and do not record a lost key with `--key`.``. Fails: ``runbook_test.go:1904: the tpm paragraph ... lacks "never record a lost key with `--key`"``.
- Narrow command for both: `go test -count=1 -timeout 5m -v -run '^TestCARotationBackendSteps$/^unrecorded_key_files_after_restore$' ./cmd/keyroster/`. sha256 of signer-install.md before and after both: `ce9598239310656f9db9867d968c5547a1256ca8041500a61475c8f963a7d8bd`.

## Item 13: the e2e-rotation row of CONTRIBUTING.md

- **Wrong (read at 2d61b55).** CONTRIBUTING.md:82 describes TestHostCARotation's two clients and not its third. test/e2e/hostca_rotation_test.go:448-459 says that a third client's file gains generation 2's line from a not-due `keyroster machine renew` and reaches the host before and after the renewal.
- **Change.** The row now adds: "and that a client whose file `keyroster machine renew` refreshed keeps reaching it too".
- **Proof.** Text only and unpinned; compared with the test's own comment.

## UNVERIFIED

- Item 1: what GitHub does with an approval when a rebase changes the diff, or leaves it unchanged. The observation of 2026-11-22 is the only evidence.
- Item 2: a real stall of the archive. Only the scratch copy of the loop ran; the green path is the CI lane.
- Item 6: a wall clock that steps back. It cannot be produced on demand; the clock is monotonic by construction.
- Item 6: that the re-poll leaf's gap bound holds under the load that failed the old bound. The gap was 16.6 ms to 21.5 ms in 50 unloaded runs; a stall of 900 ms or more that lands between the two arrivals would still fail the leaf.
- Item 7: that a refused command of N admin requests now recovers at its first retry after N seconds. No test empties the bucket; CI showed only a refused command of two requests recovering after 3 s.

## Gates

- **The full gate, once, on the tree of the documents' commit (8e0ef45, tree 66e0792dcfa597228552fb5ead044e1981b807d6).** The command is the sixth `<automated>` line of Task 5 in .planning/phases/03-linux-agent-and-revocation/03-12g-PLAN.md on main, taken from the file's bytes by script. Nothing else ran in WSL meanwhile. Its reading comes in two parts:
  - In this task's worktree it exited 1 after 881 s, at its fourth lint (`golangci-lint run --build-tags "e2e,e2erotation" --new-from-rev=origin/main ./test/e2e/`). Everything before that passed: `go test -race -count=1 -timeout 15m ./...` with 36 `ok` lines and no FAIL; `go vet ./...`; `go vet` of test/e2e under each of the six tag sets; `bash -n test/systemd/smoke.sh`; gofmt; and `0 issues.` from the lints for linux, windows and darwin. The fourth lint warned `can't prepare diff by revgrep: no version control repository found` and, without its diff filter, listed 17 issues of the whole of test/e2e. None of them lies on a line this task adds: the only changed hunk in those files is agent_enroll_test.go:240-245, and the listed lines there are :84, :118 and :353. The cause is the checkout. The worktree's `.git` file names a Windows path (`gitdir: C:/...`), which git inside WSL cannot open (`git rev-parse HEAD` in WSL: `fatal: not a git repository`), so the `--new-from-rev` lint cannot pass in a linked worktree on this host.
  - The rest of the same line, from the fourth lint to its end, also taken from the plan's bytes by script, then ran in a full clone of the same commit outside the repository. Its HEAD was 8e0ef45, its tree 66e0792..., the same as the worktree's, and `origin/main` was set to 2d61b55. It exited 0 after 141 s. The fourth lint gave `0 issues.`. capslock gave 97, 37 and 23 (package, capability) pairs, each equal to its baseline, so no new pair. The dependency firewall and the test-only firewall (6 GOOS/tag combinations) were clean, and all 55 `uses:` references in .github/workflows are pinned to commit SHAs.
  - So lint gave `0 issues.` four times in all, three in the worktree and one in the clone.
- **The full gate of the fix round, once, on the tree of 0fdb8fc (tree a404a77201ec67cd903fcccf49265141845d7880)**, in the same two parts. Before it started, `pgrep -fa "go test|golangci-lint"` in WSL showed only its own shell.
  - **In the worktree:** exit 1 after 851 s, at the fourth lint. Everything before it passed: 36 `ok` lines and no FAIL, every vet, `bash -n test/systemd/smoke.sh`, gofmt, and `0 issues.` three times. The fourth lint gave the same warning and listed the same 17 issues. None of them lies on a changed line: the listed lines in agent_enroll_test.go are :84, :118 and :355, and that file's changed hunks are :240-247 and :436-442.
  - **In the full clone** (HEAD 0fdb8fc, the same tree, `origin/main` at 2d61b55), the rest of the line exited 0 after 128 s:
    - `0 issues.`;
    - capslock 97, 37 and 23 pairs, each equal to its baseline;
    - both firewalls clean;
    - 55 pinned `uses:` references.
- `git diff --name-only origin/main...HEAD` lists only the files of the task's scope: the first round's 22 files, the four e2e files the fix round adds (agent_forget_test.go, hosts_test.go, machine_test.go and probe_certs_test.go), this task's PLAN and this SUMMARY.
- **Authorship and signatures.** Over `git log origin/main..HEAD`, every commit is authored by the owner's noreply address `121555671+Labontese@users.noreply.github.com` and committed by `keyroster-bot <337682656+keyroster-bot@users.noreply.github.com>`. Each carries an SSH signature, and `%G?` is `G`, signer keyroster-bot, for each, checked against an allowed-signers file outside the repository that holds the committer's configured signing key.
- `scripts/check-pr-title.sh` with the pull request's title in `PR_TITLE`: `PR title OK`.
- shellcheck is not installed in the WSL used here and did not run.
- The staged-lines scan exited 0 before each commit.

## Commits

All eighteen are signed by keyroster-bot as committer and authored as the owner. Before each, `git diff --cached` of every staged file was read whole and the staged-lines scan exited 0.

- `docs(quick-261124-sfx): plan ten small fixes` (the PLAN)
- `test(server): look for another user's name outside the page's fingerprints`
- `test(serverclient): require the whole decode message`
- `test(cli): read the CA lines' names for an entry name`
- `test: steady the immediate re-poll test and the live-signer log test`
- `test(e2e): wait three seconds before a rate-limited command is retried`
- `ci(distro): retry the Arch lane's package sync`
- `test(cli): pin the location bullet and the tpm paragraph's guard` (the pins; RED)
- `docs: correct the location bullet, the tpm paragraph, the rotation row and the merge gate's texts`
- `docs(quick-261124-sfx): record the small fixes` (this SUMMARY)
- `test(cli): compare the managed file's lines exactly and refuse a second line of one CA key` (ba98027)
- `test(serverclient): compare the whole decode message with its offset` (d0b556b)
- `test(e2e): size each retry's wait to the largest command its helper runs` (fdd34ba)
- `test(fetch): bound the gap between the two requests of an immediate re-poll` (1f3b232)
- `test(signer): stamp the live-signer test's requests with its own clock` (5cde560)
- `ci(distro): correct the comment on the Arch lane's retry` (0fdb8fc)
- `docs(quick-261124-sfx): record the review's fix round` (this SUMMARY)
- `docs(quick-261124-sfx): list the re-poll leaf's gap bound under load as unverified` (this SUMMARY)

## Deviations from Plan

- **Item 7 covers nine helpers, not seven.** The helpers of ca_rotation_test.go (TestCARotationNoFailedLogin) and stall_test.go (TestDeliveryDuringHeldSignature) also run a command of three admin requests: they pass their `kr` to joinApproved and enrollApproved, which run `host approve` through it. Reading the callers' indirect calls showed this; a search for "approve" alone does not show it. Both now wait 3 s like the others.
- **Item 4's expression.** The form first proposed, `^[^ ]*: decode: ` followed by the quoted `want`, would require `decode: ` twice, because `want` already begins with it. The expression used is anchored on the test's own URL and path instead: `^` + the quoted `url+"/healthz: "+want` + `[0-9]+\)$`. That also refuses peer text without spaces placed before `: decode:` (Q4c).
- **The full gate ran in two parts** ("Gates"): in the worktree up to its fourth lint, which cannot read git in a linked worktree on this host, and from that lint to its end in a full clone of the same commit.
- **The fix round's count for `revokeCLIRetry` differs from the table the round started from.** That table gave 4 s, for a revoke user of a user in a directory. The only revoke user run through the helper is of carol, who is in no directory (recovery_test.go:442; the drill installs none), so the count is three and the wait stays 3 s (item 7).
- **Q5b names the entry as a literal.** knownHostsFile does not see entry names, so the mutant writes `"srv1"`, the leaf's entry name, into the extra line.
- **The pins' commit was amended before its RED run**, to rewrap one comment line of TestSecurityDocs. Nothing else of it changed, and the RED ran on the amended commit.

## Not changed here

- No product code.
- ROADMAP.md and STATE.md are not edited.
- `hcrSetupPayback` in test/e2e/hostca_rotation_test.go stays as it is.
- Not in this task:
  - docs/backends/piv.md, step 3: a task of its own;
  - a quoted text that is not in the tree: nothing to fix;
  - `keyroster machine renew` without `$HOME` and the sentence on `--no-known-hosts`: a task of their own;
  - the checkpoint lines of the future plans 03-13 to 03-16: a task of their own.
- The sweep's four other absence checks at negligible odds (test/e2e/websignin_test.go:266, enroll_test.go:150, probe_certs_test.go:673, probe_selftest_test.go:853) stay as they are.

## Self-Check: PASSED

The PLAN and this SUMMARY exist; the sixteen commits before the fix round's record are ancestors of HEAD; no row of either file begins with a label form that other plans read.

## Pre-merge review

The review ran on head a9a4d51 while that head's checks were running. This section is written from the review's run record.

### Who read what, and who judged

- **The reader** was Codex (gpt-6-astra, high effort, read-only, static). It read the diff outside the quick task's folder and the pull request's text. It raised five points: two it rated critical, two high and one medium.
- **The judge** was one skeptic, Claude Sonnet at high effort. It worked statically and ran nothing, because another task was running timed tests on the machine. It judged all five points and refuted none. It rated two of them medium and three low. It also followed every retry helper's callers and built the table of requests the fix round started from.
- **The orchestrator** read the code behind each point and ruled that all five be fixed.

### The five points and what closed each

1. **knownhosts_test.go, names_are_principals_not_entry_names** (medium). The loop over `htCALines` reads a map keyed by the CA key, so a second `@cert-authority` line of the same key hides the first. A writer that wrote `srv1` on one line and `web1` on the next would pass it; the old check for "srv1" failed on that. Closed by ba98027 (item 5): the managed file's lines are compared exactly, and `htCALines` refuses a second line of one key.
2. **client_test.go, json_errors_in_own_words** (low). The expression ended in `[0-9]+\)$`, so the peer's digits right after the offset passed (`(at byte 4010000)`); the old check for "000" failed on them. Closed by d0b556b (item 4): the whole message is compared, with its offsets 4010 and 4006.
3. **The retry helpers** (low). `revoke machine` sends four admin requests, or five with `--keys` and one key, and `host remove` sends four. The helper of machine_test.go still waited 2 s, and the comment of the nine changed helpers named three requests as the largest command. The skeptic noted that the helper of machine_test.go cannot fire today, since its test sends 19 admin requests against a bucket of 20. Closed by fdd34ba (item 7): every retry waits as many seconds as the largest command its helper runs sends admin requests.
4. **fetch_test.go, more_repolls_immediately** (medium). With the bound at a minute, a fixed wait of one second between the two requests passed; the old bound of 900 ms failed on it. Closed by 1f3b232 (item 6): the gap between the two requests' arrivals is bounded at 900 ms.
5. **log_test.go, TestCheckLogAgainstLiveSigner** (low). The signer's clock was the monotonic one, while the requests' `CreatedAt` was the wall clock, so a wall step of more than 300 s during the test would fail it with request_time_skew. Closed by 5cde560 (item 6): the requests are stamped with the test's clock and signed again.

The orchestrator made one correction of its own. The comment this task added to test/distro/run-in.sh said that on 2026-11-22 one stalled fetch failed the lane for hours. In fact the archive was down for hours, and when it answered again one stalled fetch failed the first re-run. The first round's sentence came from the task's own brief. Closed by 0fdb8fc.

### The fix round's record

- **Commits and checks.**
  - Commits: ba98027, d0b556b, fdd34ba, 1f3b232, 5cde560 and 0fdb8fc, then this section's commit.
  - Each is signed and authored as the others. Before each, the whole staged diff was read and the staged-lines scan exited 0.
  - Before each repeated run and before the full gate, `pgrep -fa "go test|golangci-lint"` in WSL showed only its own shell.
- **New mutants** (the mutant rule above):
  - **Q5b** in cmd/keyroster/knownhosts.go. `b.WriteString(hostCALine(names, ca))` becomes `b.WriteString(hostCALine("srv1", ca) + hostCALine(names, ca))`. Fails, `knownhosts_test.go:610: known_hosts lines ["@cert-authority srv1 ssh-ed25519 ..." "@cert-authority web1 ssh-ed25519 ..."], want only ...`. sha256 before and after: `ee3aff0433bf1704818ff9f604f6ca3b0d7bd5fe93975b33059b59f18ae86d67`.
  - **Q4d** in internal/serverclient/client.go. `(at byte %d)", typeErr.Offset)` becomes `(at byte %d000)", typeErr.Offset)` in the type-error case. It passed the first round's expression and fails the exact comparison, `err = "https://localhost:39629/healthz: decode: the response has a JSON value of the wrong type (at byte 4010000)"`. sha256 before and after: `3ce7ec7af6f8e9917c80683b3cb469327ae14f2f08c80447a01e034d34e75238`.
  - **Q6c** in internal/agent/fetch/fetch.go. `time.Sleep(time.Second)` is inserted after line 530. Fails by the gap bound, `fetch_test.go:299: the second request arrived 1.016664298s after the first, want below 900 ms: a re-poll after more: true must be immediate`. sha256 before and after: `47304efcfbcb54233584eaa3b3ba6c29cba708aab7ffe6169b96c76a447135ca`.
  - Q5, Q4a to Q4c and Q6a were run again on the new assertions and fail them (items 4 to 6).
- **Repeated runs.**
  - The re-poll leaf: `-race -count=50`, ok, gaps 16.6 ms to 21.5 ms.
  - The live-signer test: `-race -count=20`, ok (16.1 s).
  - cmd/keyroster as a whole: ok (140.6 s).
- **Full gate.** In the worktree up to its fourth lint, then the rest in a full clone of 0fdb8fc ("Gates").
