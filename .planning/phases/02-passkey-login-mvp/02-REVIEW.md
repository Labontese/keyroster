---
phase: 02-passkey-login-mvp
reviewed: 2026-10-23
depth: standard (six parallel area reviews; cross-file tracing in area F)
method: six parallel area reviews A-F over e42f370..391a49f, merged by the orchestrator; two independent skeptics per critical/high/medium finding; low findings were not adversarially verified; a separate threat-model audit traced every T-02-* row
diff_base: e42f370
files_reviewed: 140
findings:
  critical: 0
  warning: 0
  info: 8
  total: 8
status: issues_found
---

# Phase 2 code review (passkey login MVP, `e42f370..391a49f`)

No Critical or Warning finding survived verification. Three findings were raised at medium or high:
- Both skeptics refuted two of them as documented design or an already recorded residual.
- Both skeptics upheld the third (E) but rated it low.

Two further findings were reported twice. They are merged below, so the 11 raw low/medium reports become 8 Info findings, plus 2 refuted.

`files_reviewed` (140) is the sum over the areas. Areas overlap, so the count of distinct files is lower.

## Severity mapping

| Review result | Recorded as |
|---|---|
| Critical, upheld by both skeptics | Critical (lower of the two upheld severities) |
| High, upheld by both | Warning-high (lower of the two upheld severities) |
| Medium, upheld by both | Warning, or Info when both skeptics rated it low |
| Low (not adversarially verified) | Info |
| Upheld by one skeptic only | Disputed (none this phase) |
| Refuted by both | Listed under Refuted |

## Summary by area

| Area | Scope | Files | Critical | Warning | Info | Refuted |
|------|-------|-------|----------|---------|------|---------|
| A | Signer: login issuance, directory install, restore runbook | 24 | 0 | 0 | 1 | 0 (the freshness report duplicates F, refuted) |
| B | Server auth: directory install, sessions, banner | 22 | 0 | 0 | 2 | 0 |
| C | Server login: begin, approve, redeem | 16 | 0 | 0 | 1 | 0 |
| D | Directory: roles, groups, host groups, renderer | 22 | 0 | 0 | 0 (the revocation report is merged into F-IN-01) | 1 |
| E | CLI login: loopback, cert check, agent | 22 | 0 | 0 | 2 | 0 |
| F | Cross-cutting: signer/audit/CLI/runbooks | 34 | 0 | 0 | 2 | 1 |
| **Total** | | 140 | **0** | **0** | **8** | **2** |

## Critical

None.

## Warnings

None.

## Info

### Area A: signer

| ID | File:line | Finding | Verified |
|----|-----------|---------|----------|
| A-IN-01 | `docs/runbooks/signer-install.md:424` | The restore runbook is stale since 02-09 shipped `keyroster directory install` (merged with the same report from F) | no (low) |

**A-IN-01: the signer restore runbook says lost directory versions cannot be replayed until 02-09.**
- **Scenario:**
  - After a restore that lost `directory_install` entries, step 3 (L424-438) still says no command can replay them "until plan 02-09 adds `keyroster directory install`". It tells the operator to keep the signer stopped until then.
  - That command exists now (`cmd/keyroster/directory.go:324`, proposal files from `dirpipe.go:34-37`). The runbook gives no procedure, so the operator either keeps the CA down or starts it with no guidance.
  - While it runs it serves the older directory, so a user disabled in a lost version can log in again.
  - A replayed version that newly binds a passkey would also be refused with 409 `credential_not_pending` (`internal/server/directory.go:296-304`), because the pending row was deleted at the original install.
  - These code paths are UNVERIFIED: read from the code, not run.
- **Fix:**
  - Rewrite step 3: write each lost leaf's `directory.json` and `directory.json.sigs` from the saved export into a proposal directory, then replay them in log order with `keyroster directory install`.
  - State the exposure window, and keep the server unreachable to users until the replay is done.
  - Document the 409 limit for versions that bind a passkey, or add an operator path that skips the pending check for a byte-identical replay of a logged version.

### Area B: server auth

| ID | File:line | Finding | Verified |
|----|-----------|---------|----------|
| B-IN-01 | `internal/server/directory.go:389` | The pending check skips credential IDs already in the base, so a re-keyed or moved credential is never checked | no (low) |
| B-IN-02 | `internal/server/login.go:429` | The KEY-06 custody banner is missing from error pages rendered while the signer status is known | no (low) |

**B-IN-01: the pending check skips re-keyed or moved credentials.**
- **Scenario:**
  - `directoryBindings` treats a binding as new only when its ID is missing from `base.credIDs`.
  - An admin-signed successor that keeps credential ID X but changes its SPKI or alg, or moves X to another user, therefore installs without a `credential_not_pending` check. The handler's doc promises that check "with the same algorithm and key".
  - `withSession` and `boundCredential` match on user and ID only, so a web session opened with the old key survives up to 12 h after a re-key.
  - The admin signature remains the authority. This is a gap in a server safeguard, not an escalation.
- **Fix:**
  - Keep each base credential's (user, alg, SPKI) in `directoryView`, and count a changed binding as newly bound. Alternatively, refuse such transitions outright, in the server or as a successor rule in the signer.
  - Store the SPKI hash in the sessions row and compare it in `withSession`.

**B-IN-02: the banner is missing on error pages.**
- **Scenario:**
  - The signer reports software custody.
  - `GET /login/<id>` for an expired or used approval calls `loginGone`, which renders a 404 with `pageData` that bypasses `statusPage`. The page therefore has no evaluation-only banner, although the status was fetched at L450.
  - The HTML 429 pages (`ratelimit.go:239`, `login.go:178`) and `internalErrorPage` (`render.go:117`) have the same gap.
- **Fix:** pass the held `statusView` into `loginGone`. Build the 429 and 500 pages through `statusPage` from a fresh cached status. Only `signerUnavailable` stays without a banner.

### Area C: server login

| ID | File:line | Finding | Verified |
|----|-----------|---------|----------|
| C-IN-01 | `internal/server/login.go:732` | Redeem uses one clock reading taken before the status refresh, so the 290 s code cap does not guarantee the signer's 300 s window (T-02-107) | no (low) |

**C-IN-01: the code cap does not guarantee the signer's window.**
- **Scenario:**
  - `now` is read once at L732. It is used for the expiry check (L741) and for `RedeemLogin` (L755), with `currentStatus` (up to 3 s) in between.
  - The signer call then has up to 10 s. A code capped at CreatedAt+290 and redeemed at T+289.9 can reach the signer after T+300. The code is burnt, and the signer refuses `request_time_skew`.
  - The impact is UX only: nothing is minted wrongly.
  - The comment at L63-66 and T-02-107 claim it "always" fits.
  - The timing was not reproduced by execution (UNVERIFIED).
- **Fix:** re-read the clock after `currentStatus`, or check the status before the expiry check. Bound the signer context deadline at CreatedAt+300 s minus a margin, or lower `loginCodeCap`. Otherwise, correct the comment and T-02-107.

### Area E: CLI login

| ID | File:line | Finding | Verified |
|----|-----------|---------|----------|
| E-IN-01 | `cmd/keyroster/login.go:320` | The CLI checks that an agent is usable only after the signer has issued and logged the certificate | yes: both skeptics upheld it, at low (raised as medium) |
| E-IN-02 | `cmd/keyroster/login.go:315` | The agent lifetime is computed before the Windows agent is started, so on a cold start the key outlives its certificate | no (low) |

**E-IN-01: the agent is checked after issuance, so each failed attempt leaves a dead logged certificate.**
- **Scenario:**
  - On Unix with `SSH_AUTH_SOCK` unset, or on Windows when `winagent.Ensure` returns `ErrOwnerUnverifiable`, the user still approves with the passkey.
  - The signer issues the certificate and commits a `login_issue` leaf. Only then does `connectLoginAgent`, called only from `addLoginToAgent` (L574), fail.
  - Every retry adds another logged grant that nobody holds. The ephemeral key is zeroed at exit, but in the log these grants look exactly like real ones, which works against "full visibility".
  - `login_unix_test.go:76-88` locks in the after-issuance order. No plan records this order as accepted.
- **Fix:** call `connectLoginAgent` right after `plan()` and before begin, including Ensure's owner check and List on Windows. Hold the connection until the Add and the listing check, and pass it to `addLoginToAgent`.

**E-IN-02: the key can outlive its certificate after a Windows cold start.**
- **Scenario:**
  - `checkLoginCert` turns the remaining validity into `LifetimeSecs` at L315, with a 1 s margin.
  - `winagent.Ensure` then may start the agent, poll for up to 5 s, verify the owner and retry once.
  - The keyring counts the lifetime from its own Add, so the key-plus-certificate stays in the agent past ValidBefore by the start delay. That breaks the promise in enroll-user.md:283-286. sshd already refuses the expired certificate, so access is not affected.
- **Fix:** connect first, as in E-IN-01. Then recompute the lifetime from a fresh `loginNow()` immediately before `ag.Add`, and refuse below `minLoginRemaining`.

### Area F: cross-cutting

| ID | File:line | Finding | Verified |
|----|-----------|---------|----------|
| F-IN-01 | `docs/runbooks/enroll-user.md:223` | The runbooks call `user disable`, role revoke and group member removal a "revocation" but never say that issued certificates stay valid until they expire (merged with the same report from D) | yes: both skeptics upheld it, at low (raised as medium) |
| F-IN-02 | `internal/serverclient/client.go:735` | The CLI takes its software-custody banner only from the server's unauthenticated header | no (low) |

**F-IN-01: "revocation" does not end access that was already issued.**
- **Scenario:**
  - A laptop is stolen with a fresh certificate (up to the 12 h user CA cap). The admin runs `keyroster user disable alice`, as the runbook calls it a revocation (enroll-user.md:192, 212-226; host-setup.md about L236).
  - Phase 2 has no KRL or `RevokedKeys`, and disable only blocks new issuance. `AccountPrincipals` never reads the disabled status. So the certificate keeps logging in to every host that lists its principal, until ValidBefore.
  - No runbook says so or gives an immediate cut-off.
- **Fix:**
  - In "Disabling a user" and in host-setup.md, state that these actions only stop new certificates, and that issued ones stay valid until ValidBefore.
  - Give the immediate cut-off: revoke the role or unmap the account, then re-render and install the principals files on every host.
  - Point to the Phase 3 KRL work.

**F-IN-02: a compromised server can hide the custody banner.**
- **Scenario:**
  - The signer runs the software keystore, and the root-signed bundle records `custody=software`.
  - A compromised server sends `Keyroster-Custody: user=tpm,...`. `checkCustody` reads only the header, so no banner is printed.
  - That contradicts docs/security/custody.md ("no ... configuration of the CLI or the server can hide or soften the warning") and server-install.md:364-365.
- **Fix:** also derive the software roles from the root-verified bundle the CLI already fetches, and print the banner if either source says software. Alternatively, refuse when the header contradicts the bundle. Otherwise, correct the docs.

## Disputed

None. No finding was upheld by exactly one skeptic.

## Refuted

- **D (raised as high): host-group role mapping does not control who reaches an account**, at `internal/directory/directory.go:292`.
  - **Claim:** any role may grant another role's principal (`role:<other>`, `u:<user>`), so the signed directory and sshd disagree.
  - **Why both skeptics refuted it:** the mechanics are accurate, but this is documented design. 02-11-PLAN D-06 says the signer validates principal syntax only and does not enforce a convention, and 02-11-SUMMARY:99 says D-06 sets only the CLI default and a documented convention.
  - **Note:** the suggested hardening could still be filed as a todo: refuse a principal granted by more than one role, and refuse `role:<X>` on a role not named X.
- **F (raised as medium, also reported by A as low): the signer can issue a login certificate that `audit verify` then rejects**, at `internal/signer/login.go:48`.
  - **The mechanism is real:** freshness is checked once at L48, while the serial (L104) and issuedAt (L112) come from later clock reads. A scratch test reproduced it with an injected clock.
  - **Why both skeptics refuted it:** it is already recorded as an accepted residual in 02-04-SUMMARY:288 ("Freshness residual").
  - **Note:** the fix stays cheap. Re-check freshness against the serial and issuedAt in whole seconds after `serial.Next`, and add a stalled-clock regression test.

## Threat-model audit

The audit ran on a read-only worktree at 391a49f, with ASVS level 1 and `block_on: high`. High and critical rows were traced end to end.

| Status | Count |
|---|---|
| SECURED (`mitigate`, verified in code or process) | 110, including 13 process-only rows from 02-13/02-14 |
| ACCEPTED (`accept`, residual recorded) | 21 |
| OPEN | 0 |
| **Total closed** | **131 / 131** |

**OPEN threats:** none.

**Qualified rows:**
- **T-02-14** (high): mitigated only in part. The C-WR-01 residual belongs to Phase 4, as recorded.
- **T-02-72**: not exercised. No laptop credential was bound, because the same synced passkey was used (deferred-items.md:24).
- **T-02-115**: the default refusal branch is unreachable and labelled UNVERIFIED in the code.

**Test runs in the audit:**
- Windows `go test ./...`: green, 21 packages.
- WSL `go test -race ./...`: green, 24 packages.
- `scripts/testonly-firewall.sh`: clean for all 6 GOOS/tag combinations.
- The signer dependency graph has none of the server-only modules.
- e2e with OpenSSH 10.5p1: every Phase 2 test passed in a private mount namespace. The only failure was the Phase 1 test `TestSSHDRejects/pty_allowed`, because the namespace has no pty; it passed in the first run.

**Findings outside the gate (they do not block):**
1. **T-02-57 documentation does not match the code.**
   - 02-12-PLAN.md:225 and :509 say the loopback state is never persisted.
   - The code stores it in plaintext: `0004_login.sql:18`, and `internal/server/login.go:387` and `:649`.
   - The server must know the state to build the redirect, and PKCE plus the hashed code still protect the flow. Fix the wording only.
2. **Process gap:** 02-14-SUMMARY.md lacks a `## Threat Flags` section.

**Unregistered flags:** none. R-02-09-2 is accepted in 02-09-SUMMARY:454 and tracked in a pending todo.
