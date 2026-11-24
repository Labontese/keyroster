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
  - "a 3 s retry wait in the nine end-to-end helpers that run a command of three admin requests"
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
    - docs/runbooks/ca-rotation.md
    - docs/runbooks/signer-install.md
    - cmd/keyroster/securitydocs_test.go
    - cmd/keyroster/runbook_test.go
decisions:
  - "The decode-message test requires the whole message, anchored on the test's own URL: ^ + QuoteMeta(url + \"/healthz: \" + want) + [0-9]+\\)$. It refuses the peer's text before ': decode:' as well as after the offset."
  - "The end-to-end retry wait is 3 s wherever a helper's callers run host approve or user approve, directly or through joinApproved, enrollApproved, joinHostCert or joinProbeHost: nine helpers. No bound, deadline or anchor of a timed test changes."
  - "The re-poll test's fetcher polls every hour with a bound of a minute; the live-signer log test's clock advances only by the monotonic reading."
requirements: []
metrics:
  completed: 2026-11-24
actuals:
  tasks: 5
  commits: "10 (9 measured with git rev-list before this SUMMARY's own commit, plus that commit)"
plan_head_before: 2d61b55d6e7317d4658a96447f5e759a730131ba
plan_head_after: 8e0ef458e3d5a33467f46f2708bcb30cace1d682
---

# Quick 261124-sfx Plan 01: ten small fixes to tests, three documents, the merge gate's texts and the Arch lane Summary

Ten small fixes, each read at 2d61b55 before it was changed. The merge gate's texts no longer claim that GitHub always dismisses the approval after a rebase. The Arch lane retries its package sync. Five unit tests change. Two absence checks no longer run on random text (items 3 and 5). One assertion now sees a leak it could not see (item 4). Two tests no longer depend on load or on the wall clock (item 6). Every changed assertion fails its mutant; TestCheckLogAgainstLiveSigner, which has no mutant, passes 20 race runs. Nine end-to-end retry helpers wait 3 s, long enough for a command of three admin requests. Two runbook passages say what the code does and are pinned, and one CONTRIBUTING.md row names the test's third client. No product code changes.

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

- **Wrong (read at 2d61b55).** test/distro/run-in.sh:37 runs `pacman -Syyu --noconfirm --needed openssh` once, under `set -eu` (:5), against the one Server line the script writes (:35). One stalled fetch fails the lane.
- **Change.** The line becomes a POSIX sh loop: at most three tries, 30 s apart, over the same command, the same snapshot mirror and the same package, with pacman.conf untouched, so the signature checks stay. Each failed try but the last prints `run-in.sh: pacman failed (try N of 3); trying again in 30 s` on stderr. After the third it prints `run-in.sh: pacman failed 3 times against the Arch Linux Archive snapshot <snapshot>` and exits 1. One sentence in the comment above says why.
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

- **Wrong (read at 2d61b55).** internal/serverclient/client_test.go:1180, in TestConnectErrorTransport/json_errors_in_own_words, checks the message for the CLI's words, no "peer text" and no "000" outside the URL. For the body of 4,000 spaces, the "000" check sees nothing. encoding/json's own text for that body ("invalid character 'x' looking for beginning of value") would pass if the client appended it.
- **Change.** One regular expression for the whole message replaces the three checks: `` ^ + regexp.QuoteMeta(url+"/healthz: "+want) + `[0-9]+\)$` ``. That is the test's own URL, `/healthz: `, the CLI's words (which begin with `decode: `), the byte offset, `)` and the end. The `regexp` import is added, and the comment above says what the expression refuses. A temporary `t.Logf` (removed again; the file's sha256 matched the edited file afterwards) showed both messages beginning with the URL exactly:
  - `https://localhost:35463/healthz: decode: the response has a JSON value of the wrong type (at byte 4010)`, with url `https://localhost:35463`
  - `https://localhost:45447/healthz: decode: the response is not valid JSON (at byte 4006)`, with url `https://localhost:45447`
- **Proof, Q4a to Q4c, each first on the old assertion (the committed state at 2d61b55) and then on the new one.** Narrow command: `go test -count=1 -timeout 5m -v -run '^TestConnectErrorTransport$/^json_errors_in_own_words$' ./internal/serverclient/`. All are in internal/serverclient/client.go, whose sha256 before and after every run is `3ce7ec7af6f8e9917c80683b3cb469327ae14f2f08c80447a01e034d34e75238`.
  - **Q4a.** `msg = fmt.Sprintf("the response is not valid JSON (at byte %d)", syntaxErr.Offset)` becomes `msg = fmt.Sprintf("the response is not valid JSON (at byte %d): %v", syntaxErr.Offset, syntaxErr)`.
    - Old assertion: PASS (the mutant survives).
    - New assertion: FAIL, `client_test.go:1186: body "{\"a\":               "...: err = "https://localhost:42645/healthz: decode: the response is not valid JSON (at byte 4006): invalid character 'x' looking for beginning of value", ...`.
  - **Q4b.** `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d)", typeErr.Offset)` becomes `msg = fmt.Sprintf("the response has a JSON value of the wrong type (at byte %d): %s", typeErr.Offset, typeErr.Value)`.
    - Old assertion: FAIL.
    - New assertion: FAIL, `client_test.go:1186: body "{\"a\":100000000000000"...: err = "https://localhost:35923/healthz: decode: the response has a JSON value of the wrong type (at byte 4010): number 1000000000...`.
  - **Q4c, the peer's text before `: decode:`.** `return fmt.Errorf("%s%s: decode: %w", c.base, path, decodeError(err))` becomes `return fmt.Errorf("%s%s%.6s: decode: %w", c.base, path, data, decodeError(err))`.
    - Old assertion: PASS (the mutant survives: neither six-byte excerpt holds "000").
    - New assertion: FAIL for both bodies, `err = "https://localhost:43185/healthz{\"a\":1: decode: ...` and `err = "https://localhost:36967/healthz{\"a\": : decode: ...`.
  - `go test -race -count=1 ./internal/serverclient/`: ok (4.0 s).

## Item 5: the sweep, and the entry name in known_hosts

- **Wrong (read at 2d61b55).** cmd/keyroster/knownhosts_test.go:593, in TestKnownHosts/names_are_principals_not_entry_names, looks for "srv1" in the whole managed known_hosts. That file holds an @cert-authority line with a random ed25519 host CA key in base64, which can hold "srv1", at about 1 in 400,000 runs (computed, not measured).
- **Change.** The leaf reads the CA lines' names with htCALines, the helper its neighbours use, and requires each to be `[web1]`, the principal only.
- **Proof, Q5.** Narrow command: `go test -count=1 -timeout 5m -v -run '^TestKnownHosts$/^names_are_principals_not_entry_names$' ./cmd/keyroster/`.
  - Replacement in cmd/keyroster/knownhosts.go (hostTrustNames): `active = append(active, p)` becomes `active = append(active, p, h.Name)`. The Host line comes from all names and stays `[web1]`; the CA line's names become `[srv1 web1]`.
  - Failing line: `knownhosts_test.go:598: CA line names ["srv1" "web1"], want the principal web1 only`.
  - sha256 before and after: `ee3aff0433bf1704818ff9f604f6ca3b0d7bd5fe93975b33059b59f18ae86d67`.
- **The sweep.** The pattern `(?:^|[^!\w])(?:strings|bytes)\.Contains\(.*,\s*(\[\]byte\()?"[A-Za-z0-9+/=_.:-]{2,8}"|NotContains\(.*"[A-Za-z0-9+/=_.:-]{2,8}"` over every `*_test.go`, read at 2d61b55, gives 74 lines in 37 files. It was re-run here with `git grep -n -P` at 2d61b55 and gives the same 74 lines in 37 files. The two real cases among them are session_test.go:82 (item 3) and knownhosts_test.go:593 (this item). Four more are absence checks of five letters or more on text that holds a fingerprint, a port or a log, at negligible odds, and are not changed: test/e2e/websignin_test.go:266, enroll_test.go:150, probe_certs_test.go:673 and probe_selftest_test.go:853. At the head of this task the pattern gives 72 lines: knownhosts_test.go:593 and client_test.go:1180 are gone, and session_test.go:84 still matches, now made on the page without the fingerprints. The pattern does not see an absence check whose string is a variable, a regular-expression check, or a string longer than eight characters.

## Item 6: two tests that failed once under load

- **Wrong (read at 2d61b55).**
  - internal/agent/fetch/fetch_test.go:277, in TestFetch/more_repolls_immediately, bounds one `Once` at 900 ms, under -race and with a fetcher that polls every second (:142). Load of a second fails it.
  - internal/signer/log_test.go:432, in TestCheckLogAgainstLiveSigner, uses the wall clock (`newLogEnv`, clock nil). A step back of the wall clock between two of its 60 issues fails an issue with `clock_regression` (internal/serial/serial.go).
- **Change.**
  - The re-poll leaf sets `ts.f.cfg.Poll = time.Hour` and bounds `Once` at a minute, with a comment. The fetcher reads `cfg.Poll` only in New (fetch.go:177-181) and Run (:249).
  - The log test builds its environment with `newLogEnvClock(t, NewFixture(t, 1, 1), func() time.Time { return base.Add(time.Since(base)) })`, so the signer's clock advances only by the monotonic reading. The constructor exists at log_test.go:99 and passes the clock to Bootstrap and to `Config.Clock`.
- **Proof, Q6a.** Narrow command: `go test -count=1 -timeout 3m -v -run 'TestFetch/more_repolls_immediately' ./internal/agent/fetch/`.
  - The mutant is an insertion in `Once`'s round loop (fetch.go:463-531) of `time.Sleep(min(NextPoll(f.cfg.Poll), 61*time.Second))`, after line 530 (the `}` that closes `if !resp.More {`), as the last statement of the loop's body. The replacement's old string, `\t\t\treturn true, err\n\t\t}\n\t}\n\treturn true, nil\n}`, occurs once.
  - Failing line: `fetch_test.go:283: requests ["GET /api/v1/agent/state" "GET /api/v1/agent/state?bundle=1"] in 1m1.058271796s, want two at once, the second with the new bundle version`, with `--- FAIL: TestFetch/more_repolls_immediately (61.08s)`. The leaf's own minute bound caught it.
  - sha256 before and after: `47304efcfbcb54233584eaa3b3ba6c29cba708aab7ffe6169b96c76a447135ca`.
  - Not run: the uncapped sleep of one poll interval (at least 50 minutes with an hour's poll) would end the run by the test timeout instead of the leaf's bound.
- **Repeated runs.**
  - `go test -race -count=20 -run 'TestFetch/more_repolls_immediately' ./internal/agent/fetch/`: ok (2.1 s). Again with `-v`: 20 PASS lines of the leaf, no FAIL.
  - `go test -race -count=20 -v -run '^TestCheckLogAgainstLiveSigner$' ./internal/signer/`: ok (14.7 s), 20 PASS lines, no FAIL.

## Item 7: the end-to-end helpers' retry

- **Read at 2d61b55.** The admin routes share one bucket per client address: `adminLimit: newLimiter(lim.AdminPerMinute, lim.AdminBurst, 0, 0)` (internal/server/server.go:189), with defaults of 60 a minute and a burst of 20 (internal/server/ratelimit.go:60-61), keyed by the client address only (`clientKey`, :209-223). A refused request takes no token (`AllowN`, :180), and Retry-After is always 1 s (:201).
  - `keyroster host approve` sends three admin requests: GET pending hosts (cmd/keyroster/host.go:577), GET directory (cmd/keyroster/dirpipe.go:137) and POST directory (dirpipe.go:384). `verifiedTrust`'s GET of the trust path (server.go:230) is outside the admin bucket.
  - `keyroster user approve` sends three: GET pending credentials (cmd/keyroster/user.go:588), then editDirectory's GET and POST.
  - A retry after 2 s finds about two refilled requests, the two reads spend them, and the POST is refused again.
- **Change.** Line numbers from here to the end of this item are at the head of this task. In the nine helpers below, the retry's `time.Sleep(2 * time.Second)` becomes `time.Sleep(3 * time.Second)`, with a comment that gives the arithmetic. The two log lines that name the wait (revoke_test.go, roles_test.go) now say 3 s. No other line of test/e2e changes; no bound, deadline or anchor changes.

| Helper | What its callers run through it | Wait |
|--------|----------------------------------|------|
| `hostTrustKR` (hosttrust_test.go) | host approve through joinHostCert (hosttrust_test.go:297; hostca_rotation_test.go:508); user approve (hosttrust_test.go:364); known-hosts sync, host status | 3 s |
| `hostCertKR` (hostcert_test.go) | host approve through joinHostCert (hostcert_test.go:269, :406) and joinProbeHost (probe_selftest_test.go:419); host status | 3 s |
| `kr` of TestAgentEnrollEndToEnd (agent_enroll_test.go) | host approve (:322); host pending, revoke serial | 3 s |
| `kr` of TestAgentStatusEndToEnd (agent_status_test.go) | host approve through enrollApproved (:225); host status, revoke serial | 3 s |
| `loginFixture.kr` (login_test.go) | user approve (:343) | 3 s |
| `revokeCLIRetry` (revoke_test.go) | user approve through its caller's kr (:258, :260); role add and grant, revoke | 3 s |
| `kr` of TestRolesHostPrincipalsEndToEnd (roles_test.go) | user approve (:93, :95) | 3 s |
| `kr` of TestCARotationNoFailedLogin (ca_rotation_test.go) | host approve through joinApproved (:674); host status, revoke serial | 3 s |
| `kr` of TestDeliveryDuringHeldSignature (stall_test.go) | host approve through enrollApproved (:168) | 3 s |
| `kr` of hosts_test.go | no host approve or user approve, directly or through a helper | 2 s, unchanged |
| `kr` of machine_test.go | no host approve or user approve, directly or through a helper | 2 s, unchanged |
| `kr` of TestProbeCertsAgainstSSHD (probe_certs_test.go) | no host approve or user approve, directly or through a helper | 2 s, unchanged |

agent_forget_test.go already waits 3 s, and agent_systemd_test.go's `kr` has no retry; neither changes.

- **Calls of a changed helper inside a timed window.** The longer wait acts only after a refusal; these are the places where a refused call's retry now takes 1 s more of a window:
  - joinApprovedHeld's poll of `host pending` within 30 s (agent_status_test.go:62), reached from agent_status_test.go, stall_test.go and ca_rotation_test.go; the same 30 s poll in joinHostCert (hostcert_test.go:71), in joinProbeHost (probe_selftest_test.go:134) and in TestAgentEnrollEndToEnd (agent_enroll_test.go:286-290).
  - waitStatus's 30 s poll of `host status --json` (agent_status_test.go:107-108), from TestAgentStatusEndToEnd (:229, :246, :289) and from TestCARotationNoFailedLogin (caRotRevoke at :747 and :835, and :837); and the 240 s poll for a silent agent (agent_status_test.go:302-303).
  - TestCARotationNoFailedLogin's 150 s poll of `host status` (ca_rotation_test.go:728-729). The revocation and the waitStatus at :835-837 lie between the switch and the drain, whose bound is trusted_until + 120 s (:856).
  - TestAgentEnrollEndToEnd: `host approve` (:322) inside the 10 s window from `before` (:310) to the first apply (:333-335); `revoke serial` at the start of `took` (:359-372), which is logged, not bounded (the 20 s deadline starts after the call returns).
  - TestHostCARotation: hcrSync's `known-hosts sync` (hostca_rotation_test.go:527, :630, :761), and hcrCommitted's poll of `host status` up to installed + 45 s (:570) and up to r1 + 44 s (:731).
  - hosttrust_test.go's 60 s poll of the heartbeat's directory version (:416), and hostcert_test.go's 60 s polls of host status (:285-297, :370-380).
- **Proof.** None locally: the refusal needs the bucket's level that only a CI lane reaches, and nothing under test/e2e runs locally. `go vet` passed under each tag set: `e2e`, `e2e e2emachine`, `e2e e2eprobe`, `e2e e2erotation`, `e2e systemdsmoke`, `e2e_pkcs11` and `e2e_tpm`. The full gate's vet lines and the CI lanes run them again.

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
- Item 7: that a refused approval now recovers at its first retry. No test empties the bucket.

## Gates

- **The full gate, once, on the tree of the documents' commit (8e0ef45, tree 66e0792dcfa597228552fb5ead044e1981b807d6).** The command is the sixth `<automated>` line of Task 5 in .planning/phases/03-linux-agent-and-revocation/03-12g-PLAN.md on main, taken from the file's bytes by script. Nothing else ran in WSL meanwhile. Its reading comes in two parts:
  - In this task's worktree it exited 1 after 881 s, at its fourth lint (`golangci-lint run --build-tags "e2e,e2erotation" --new-from-rev=origin/main ./test/e2e/`). Everything before that passed: `go test -race -count=1 -timeout 15m ./...` with 36 `ok` lines and no FAIL; `go vet ./...`; `go vet` of test/e2e under each of the six tag sets; `bash -n test/systemd/smoke.sh`; gofmt; and `0 issues.` from the lints for linux, windows and darwin. The fourth lint warned `can't prepare diff by revgrep: no version control repository found` and, without its diff filter, listed 17 issues of the whole of test/e2e. None of them lies on a line this task adds: the only changed hunk in those files is agent_enroll_test.go:240-245, and the listed lines there are :84, :118 and :353. The cause is the checkout. The worktree's `.git` file names a Windows path (`gitdir: C:/...`), which git inside WSL cannot open (`git rev-parse HEAD` in WSL: `fatal: not a git repository`), so the `--new-from-rev` lint cannot pass in a linked worktree on this host.
  - The rest of the same line, from the fourth lint to its end, also taken from the plan's bytes by script, then ran in a full clone of the same commit outside the repository. Its HEAD was 8e0ef45, its tree 66e0792..., the same as the worktree's, and `origin/main` was set to 2d61b55. It exited 0 after 141 s. The fourth lint gave `0 issues.`. capslock gave 97, 37 and 23 (package, capability) pairs, each equal to its baseline, so no new pair. The dependency firewall and the test-only firewall (6 GOOS/tag combinations) were clean, and all 55 `uses:` references in .github/workflows are pinned to commit SHAs.
  - So lint gave `0 issues.` four times in all, three in the worktree and one in the clone.
- `git diff --name-only origin/main...HEAD` lists only the files of the task's scope: the 22 files above and this task's PLAN, plus this SUMMARY once it is committed.
- **Authorship and signatures.** Over `git log origin/main..HEAD`, every commit is authored by the owner's noreply address `121555671+Labontese@users.noreply.github.com` and committed by `keyroster-bot <337682656+keyroster-bot@users.noreply.github.com>`. Each carries an SSH signature, and `%G?` is `G`, signer keyroster-bot, for each, checked against an allowed-signers file outside the repository that holds the committer's configured signing key.
- `scripts/check-pr-title.sh` with the pull request's title in `PR_TITLE`: `PR title OK`.
- shellcheck is not installed in the WSL used here and did not run.
- The staged-lines scan exited 0 before each commit.

## Commits

All ten are signed by keyroster-bot as committer and authored as the owner. Before each, `git diff --cached` of every staged file was read whole and the staged-lines scan exited 0.

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

## Deviations from Plan

- **Item 7 covers nine helpers, not seven.** The helpers of ca_rotation_test.go (TestCARotationNoFailedLogin) and stall_test.go (TestDeliveryDuringHeldSignature) also run a command of three admin requests: they pass their `kr` to joinApproved and enrollApproved, which run `host approve` through it. Reading the callers' indirect calls showed this; a search for "approve" alone does not show it. Both now wait 3 s like the others.
- **Item 4's expression.** The form first proposed, `^[^ ]*: decode: ` followed by the quoted `want`, would require `decode: ` twice, because `want` already begins with it. The expression used is anchored on the test's own URL and path instead: `^` + the quoted `url+"/healthz: "+want` + `[0-9]+\)$`. That also refuses peer text without spaces placed before `: decode:` (Q4c).
- **The full gate ran in two parts** ("Gates"): in the worktree up to its fourth lint, which cannot read git in a linked worktree on this host, and from that lint to its end in a full clone of the same commit.
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

The PLAN and this SUMMARY exist; the nine commits before this one are ancestors of HEAD; no row of either file begins with a label form that other plans read.
