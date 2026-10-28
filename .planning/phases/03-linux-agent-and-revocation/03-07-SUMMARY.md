---
phase: 03-linux-agent-and-revocation
plan: 07
subsystem: agent
tags: [agent, enrollment, join-token, mtls, fetcher, spool, outbox, pop, chain, krl, restore, capslock, dep-firewall]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-05: spool (OpenDir, ReadFileAt, WriteFileAt, Write), state (Pins, WritePins, Verify), Apply; 03-06: preflight with host_pop_not_enabled, the Include graph, drop-in repair, Phase 2 takeover; 03-06b/03-06c: krl-served.json, the restore runbook's capture block and step 2b"
provides:
  - "keyroster host join-token|pending|approve; serverclient agent paths and types (MaxAgentStateResponse 8 MiB, the state answer's more field)"
  - "keyroster-server --agent-listen: AgentTLSConfig (RequireAnyClientCert, one self-signed Ed25519 certificate, VerifyConnection), AgentHandler with POST /api/v1/agent/enroll and GET /api/v1/agent/state only; BrowserTLSConfig unchanged; admin routes POST /api/v1/admin/join-tokens and GET /api/v1/admin/hosts/pending; serverdb 0005_agents.sql"
  - "keyroster-agent-fetch (linux): the unprivileged fetcher; internal/agent/fetch"
  - "keyroster-agent install, run, identity, krl-version; internal/agent/join (kr-join-v1:), internal/agent/enroll (keyroster/agent-enroll/v1 PoP, the spool/outbox hand-over files)"
  - "wire GetBundle 0x08/0x88 and GetDirectoryVersion 0x09/0x89; signer chain reads; signerclient GetBundle, GetDirectoryVersion"
  - "internal/tlspin: the server URL and TLS pin rules without net/http"
  - "dep-firewall and capslock targets for keyroster-agent-fetch"
  - "signer-install.md's restore cross-check of the kept server KRL copy against the hosts (T-03-277 mitigated)"
affects: [03-08, 03-09, 03-10, 03-12, 03-13, 03-14, 03-16]

actuals:
  tokens: 82683
  tasks: 3
  commits: 12
plan_head_before: ef382931e0b84354e963ac66c333b639e78b3252
plan_head_after: 36c9044

tech-stack:
  added: []
  patterns:
    - "Every fetcher-written file the root applier reads goes through spool.ReadFileAt; every applier answer to the fetcher goes into the root-owned outbox through spool.WriteFileAt"
    - "Spool file names come only from an item's kind and its uint64 version"
    - "The state answer is assembled from separately encoded items, so the byte budget counts exactly what is sent"
    - "Install checks every path before it writes any, and sets owners and modes on descriptors, never by name"

key-files:
  created:
    - internal/tlspin/tlspin.go
    - internal/agent/join/join.go
    - internal/agent/join/join_test.go
    - internal/agent/join/fuzz_test.go
    - internal/agent/enroll/pop.go
    - internal/agent/enroll/pop_test.go
    - internal/agent/fetch/fetch.go
    - internal/agent/fetch/fetch_test.go
    - internal/agent/apply/enroll.go
    - internal/agent/apply/enroll_test.go
    - internal/agent/apply/run.go
    - internal/agent/apply/installed.go
    - internal/agent/apply/installed_test.go
    - cmd/keyroster-agent/install.go
    - cmd/keyroster-agent/install_test.go
    - cmd/keyroster-agent/run.go
    - cmd/keyroster-agent/identity.go
    - cmd/keyroster-agent/krlversion.go
    - cmd/keyroster-agent-fetch/main.go
    - cmd/keyroster-agent-fetch/main_other.go
    - internal/wire/chain.go
    - internal/signer/chain.go
    - internal/signer/chain_test.go
    - internal/serverdb/migrations/0005_agents.sql
    - internal/serverdb/agents.go
    - internal/server/agent.go
    - internal/server/agent_test.go
    - internal/server/agenttls.go
    - internal/server/hosts.go
    - internal/serverclient/agent.go
    - test/e2e/agent_enroll_test.go
    - test/capslock/keyroster-agent-fetch.json
  modified:
    - internal/serverclient/client.go
    - internal/server/server.go
    - internal/server/signer.go
    - internal/server/server_test.go
    - internal/server/routes_test.go
    - internal/serverdb/db_test.go
    - internal/signer/server.go
    - internal/signerclient/client.go
    - internal/signerdb/trust.go
    - internal/signerdb/directory.go
    - internal/wire/frame.go
    - internal/directory/hosts.go
    - internal/agent/paths/paths.go
    - internal/agent/paths/paths_test.go
    - internal/agent/apply/apply.go
    - internal/agent/apply/configgraph.go
    - internal/agent/apply/configgraph_test.go
    - internal/agent/apply/adopt_test.go
    - internal/agent/apply/dropin_test.go
    - internal/agent/apply/harness_test.go
    - cmd/keyroster/host.go
    - cmd/keyroster/host_test.go
    - cmd/keyroster-server/serve.go
    - cmd/keyroster-server/main.go
    - test/e2e/server_test.go
    - test/e2e/restore_test.go
    - test/capslock/keyroster-agent.json
    - scripts/dep-firewall.sh
    - scripts/capslock-check.sh
    - .golangci.yml
    - docs/runbooks/host-setup.md
    - docs/runbooks/server-install.md
    - docs/runbooks/signer-install.md
    - docs/runbooks/revoke.md
    - .planning/phases/03-linux-agent-and-revocation/03-06c-PLAN.md

key-decisions:
  - "03-07: agents are served on a separate listener (--agent-listen) whose TLS config requires exactly one self-signed Ed25519 client certificate; the browser listener keeps NoClientCert and registers no agent route, so browsers never see a certificate prompt; the cost is one more port and a firewall rule"
  - "03-07: the join string names the agent listener's port, which the server's mint answer reports, on the host name of the admin's keyroster init config (the plan did not say where the port comes from; open question for the owner)"
  - "03-07: approval is the installed admin-signed directory holding an active host entry whose keys equal the agent's enrolled host keys; the server records nothing else"
  - "03-07: the PoP is signed with the Ed25519 and ECDSA host keys only (a directory host entry can name no other type), with the installation ID of pins.json"
  - "03-07: the state answer is filled bundles, directories, KRL within MaxAgentStateResponse (8 MiB); the first item always goes; more: true when anything was left out (budget or the 16-per-kind cap)"
  - "03-07: a refused KRL (currentKRL error) makes the whole state answer 503, so no host gets state while the server refuses its KRL"
  - "03-07 carry-over B (D-R2): T-03-277 mitigated by the restore cross-check against the hosts' installed KRL (keyroster-agent krl-version)"

patterns-established:
  - "An agent-side package that the root applier imports (join, enroll, tlspin) imports no net/http or crypto/tls; TestPaths and dep-firewall check the applier's graph"
  - "The fetcher logs a line only when it differs from the previous one, so a host waiting for approval logs it once"

requirements-completed: [AGENT-01, AGENT-02, AGENT-03, AUTHZ-02, REVOKE-02, REVOKE-03]

duration: 110min
completed: 2026-10-28
status: complete
---

# Phase 3 Plan 07: Agent Transport Summary

**A host now enrolls with a one-time join token and every host key's SSHSIG proof of possession, an admin approves it by signing the host entry they type into the directory, and from then on the unprivileged `keyroster-agent-fetch` pulls signed state over pinned mTLS on a separate agent listener while the root `keyroster-agent run` verifies and applies it. In CI a revocation made with `keyroster revoke serial` reaches the enrolled host's real sshd in under a second, with the same sshd PID.**

PR: **#71** (`p03/07-agent-transport`), opened without auto-merge. Requirements AGENT-01, AGENT-02, AGENT-03, AUTHZ-02, REVOKE-02 and REVOKE-03 are complete as CI-verified; real hosts re-check them in 03-16.

## Owner attention first

1. **Where the join string's port comes from (a gap in the plan, decided here, for you to confirm).** With two listeners, the CLI's saved server URL is the browser listener, where agent routes are 404. The mint answer (`POST /api/v1/admin/join-tokens`) now reports the agent listener's port (`agent_port`, from `--agent-listen`). The CLI builds the join string's server URL from the host name of its own `keyroster init` config and that port. A server lying about the port changes only which port the fetcher dials; the TLS root pins and the host name still bind it. The alternative is a `--agent-port` flag on `host join-token`.
2. **The listener decision (plan must_have):** a separate `--agent-listen` listener whose TLS config requires exactly one self-signed Ed25519 client certificate, and whose mux registers only the two agent routes. The browser listener keeps `NoClientCert` (now named `server.BrowserTLSConfig`, the same config as before) and registers no agent route. The rationale: browsers that see client certificates in the OS store never get a picker, and the two route sets are disjoint. The cost is one more port and a firewall rule (server-install.md).
3. **capslock: keyroster-agent 23 -> 36 pairs, and a new fetcher baseline of 21 pairs with no EXEC.** Listed below with the example paths capslock gave.
4. **A refused KRL stops the whole state answer.** When the server's `currentKRL` refuses (for example a signer restored without the recovery, which 03-06b detects), the state route answers 503, so hosts get no bundle or directory either until the KRL is resolved. The other choice, serving bundles and directories without the KRL, would let principal additions through while revocations stall.

## Accomplishments

- **Join token (`internal/agent/join`).** `kr-join-v1:` + unpadded base64url of canonical JSON; `Parse` refuses every edge of the plan (empty server, no TLS or trust pins, threshold 0 or above the pins, an installation ID that is not 32 lowercase hex digits, a token that is not 32 bytes, unsorted or duplicate pins, a URL not in normal form, a root without a pin or a pin without a root, expires_at not RFC 3339 UTC whole seconds). `String` and `GoString` redact the token. `FetchConfig` (fetch.json) and `FetcherToken` (join-token) are the fetcher's parts: it never sees the trust pins.
- **`internal/tlspin` (Rule 3).** The server URL and pin rules moved out of serverclient so the root applier (no net/http, no crypto/tls) parses join strings with exactly the CLI's rules; serverclient re-exports them.
- **Enrollment PoP (`internal/agent/enroll`).** `PoP{domain, installation_id, token_sha256, identity_spki_sha256, host_keys, facts_sha256}` canonical JSON, signed by each host key under `keyroster/agent-enroll/v1`; `Verify` requires one signature by exactly each key, in order. `token_sha256` is the SHA-256 of the 32 raw bytes, the same value the server stores. The spool/outbox hand-over files (`enroll-request.json`, `enroll-pop.json`, `identity.pub`) and their types live here, so the fetcher never imports the applier.
- **Install (`keyroster-agent install`).** Every path of the F2 truth with its owner and mode, created relative to its parent opened with O_NOFOLLOW; directories chowned and chmodded through a no-follow descriptor, files written to an O_EXCL temporary file whose owner and mode are set on the descriptor before the rename (never chowned by name, so a link in the fetcher's own directory cannot redirect it). Every path is checked before any is written. `paths.Allowed` gains exactly the four paths outside the state directory.
- **Applier loop (`keyroster-agent run`).** Every `--interval` (5 s, at least 1 s): `CheckStateDirs` (state, accepted/ and now the outbox; `state_dir_unsafe`, also at every `apply --once` start), the enrollment answer (`apply.Enroll`), and Apply when the spool's document names changed, on the first round, and again 60 s after a failed apply. Before approval the spool holds no document, so a round writes and logs nothing. `AllowAdoption` stays false.
- **Fetcher (`keyroster-agent-fetch`, `internal/agent/fetch`).** Ed25519 identity (PKCS #8, 0600) and a self-signed certificate (CN keyroster-agent, random serial, now-1 h to +100 y); `identity.pub` into the spool; the enrollment step; then state polls with the newest spooled versions, `more` followed at once up to 64 times, every item written one at a time in answer order through `spool.Write`. The poll is 60 s with a uniform crypto/rand jitter of a sixth either way. Its graph has no os/exec (dep-firewall) and no EXEC capability (capslock).
- **Server.** `0005_agents.sql` (`join_tokens`, `agents`); `serverdb.EnrollAgent` uses the token with the plan's conditional UPDATE and records the agent in one transaction, so every refusal leaves the token unused. `AgentTLSConfig`, `AgentHandler` (built with `newRouteMux`, its own recorded pattern list), `requireAgent` (approval by `HostForKey` and equal key sets; `last_seen_us` updated), the per-identity limiter (30/min, burst 10, global backstop 100 times that), `handleAgentEnroll` (16 KiB body cap), `handleAgentState` (strict version query, byte-budgeted fill), `handleMintJoinToken` and `handlePendingHosts`. `--agent-listen` in serve.go: a second `http.Server` with the same certificate holder, timeouts and shutdown. `grep -c ClientAuth cmd/keyroster-server/serve.go` is 0, and server.go names no `/api/v1/agent/` route.
- **Chain catch-up (Task 2).** `TypeGetBundle` 0x08 / `0x88` (capped like a Status) and `TypeGetDirectoryVersion` 0x09 / `0x89` (capped like a directory); the signer reads the stored row or refuses `not_found`; `signerclient.GetBundle`, `GetDirectoryVersion`; the server's `signerAPI` and `fakeSigner` gain both. The state answer carries every version above the agent's, ascending, at most 16 of each.
- **CLI.** `keyroster host join-token|pending|approve`, each refusing `host_pop_not_enabled` locally on the policy it verified before any admin request; `approve` re-derives every fingerprint from the server's answer and refuses an answer that does not check out, or two pending agents under one name.
- **`keyroster-agent identity`** prints `agent identity: SHA256:...` and `host key: SHA256:... ssh-ed25519`, exactly the lines `host pending` and `host approve` print; the e2e compares them.

## The state budget (F12)

- `MaxAgentStateResponse` is 8 388 608 bytes. The three largest items, each at its cap, encode to 7 455 045 bytes together: KRL 5 619 784 (below its share `krl.MaxKRLResponse` = 5 620 744), directory 1 485 545, bundle and policy 349 664 (`TestAgentState/largest_items_fit_budget`).
- `fillAgentState` assembles the answer from separately encoded items, so the size it budgets is exactly the size it sends; `budget_exact_fits` and `budget_one_byte_short_defers_last` pin max and max+1, and the first item always goes.

## Task Commits

1. **Task 1 (tracer):** `cef59c0` feat(agent): enroll hosts with a one-time join token and pull signed state over pinned mTLS
2. **Carry-over A1:** `2c474d3` test(agent): require the adoption resume to repair the drop-in before any Phase 2 removal
3. **Carry-overs A2, A5:** `80ac377` fix(agent): refuse a NUL byte and a .. Include component as sshd_config_unsafe
4. **Carry-overs A3, A4:** `6557d7d` fix(agent): roll an installed host back to the agent's own drop-in and repair it before the first sshd -T
5. **Task 2:** `03cb4d7` feat(agent): catch agents up through the signer's chain and pin every enrollment and transport edge
6. **Carry-over B:** `f4fb528` feat(restore): cross-check the kept server KRL copy against the hosts' installed KRL
7. **Task 3 gates:** `3c3f332` chore(agent): gate the fetcher's dependency graph and capabilities per binary
8. **Task 3 docs:** `7a9efb0` docs(agent): document host enrollment, the agent listener and how fast changes arrive
9. **Task 2 follow-up:** `622f894` test(agent): log the accepted certificate login in TestAgentEnrollEndToEnd
10. **Plan metadata:** `405475c` docs(03-07): complete agent-transport plan (this file, STATE.md, ROADMAP.md, REQUIREMENTS.md)
11. **Pre-handback review, test:** `04c2078` test(server): pin re-enrollment after a host entry's removal and its limit
12. **Pre-handback review, docs:** `36c9044` docs(agent): state the re-enrollment limit and that enrolled hosts receive every KRL

Every commit is SSH-signed by keyroster-bot (`%G?` = G against the configured signing key). `git rev-list --count ef38293..36c9044` is 12; it counts the plan metadata commit, which landed before the review fixes. A last `docs(03-07)` commit updates this file.

## Carry-overs and how each was closed

**A. PR #68 (agent apply code from 03-06)**

| Item | Commit | How it was closed | Proof |
|---|---|---|---|
| A1: the adoption-resume repair runs before any Phase 2 removal (mutant M8 survived) | `2c474d3` | The resume tests now check, at every `phase2-remove` fault point, that the drop-in on disk is already `DropIn` | M8 (the repair moved after the removal loop) now fails `TestAdopt/resume_repairs_edited_dropin` at all four removals |
| A2: a NUL byte in any file the walk reads is `sshd_config_unsafe` | `80ac377` | `configGraph.visit` refuses a NUL, naming its line. Probed with real sshd 9.5p1 and 10.5p1 in WSL: sshd keeps a line only up to its first NUL and joins the next line to it (`Banner /etc/x<NUL>junk` then `MaxStartups 3` fails as "Banner extra arguments"; `AuthorizedPrincipalsComma<NUL>` then `nd /x` would be one line to sshd) | `TestIncludeGraph/nul_byte_in_included_file_unsafe`, `nul_byte_in_sshd_config_unsafe`; the check off fails both |
| A3: on an installed host, roll back to `DropIn`, not to an unvetted `dropin.prev` | `6557d7d` | `restoreDropIn` writes `DropIn` when last-good is the agent's and a previous file existed; a drop-in that was missing is removed again, as 03-05's `sshd_t_failure_rolls_back_dropin` requires (deviation 13) | `TestDropInRepair/rollback_restores_agents_dropin_not_the_edit`; the condition off fails it |
| A4: repair the agent's own drop-in before the first `sshd -T` when last-good is ours | `6557d7d` | When the start-of-run `sshd -T` fails on an installed host whose drop-in is not `DropIn`, the apply takes the lock (only on this path), writes `DropIn`, reads `sshd -T` again, then reloads and self-tests (`activatePreRepair`); `e.locked`, which gates status.json, is unchanged. The harness's `sshd -t`/`-T` can now refuse a drop-in (`rejectDropIn`) | `TestDropInRepair/dropin_sshd_refuses_repaired_before_dump` and `..._by_noop_run`, `sshd_dump_failure_with_own_dropin_not_repaired`; the pre-repair off fails both |
| A5: refuse `..` in Include paths | `80ac377` | `includePattern` refuses any `..` component | `TestIncludeGraph/dot_dot_include_unsafe`; the refusal off makes it a foreign-setting finding instead, and the test fails |

**B. PR #70: T-03-277 (owner decision D-R2), now mitigate**

- `keyroster-agent krl-version` prints the pinned line `installed KRL version: N`: the larger of accepted/'s version and the KRL in current's generation (`apply.InstalledKRLVersion`; it reads through no-follow descriptors, takes no lock and refuses an unsafe state directory). `TestInstalledKRLVersion` covers none, after an install, and after a rollback that kept a newer KRL in current; ignoring current fails it.
- signer-install.md, after the capture block: root runs it on at least one enrolled host, preferably every reachable one, and runs a block with the numbers as arguments. The block stops when any host enforces a newer KRL than the kept copy (a rolled-back copy), counts a missing copy as version 0 (a removed copy, or a lost server state directory), refuses no argument and anything that is not a version, and compares with `[ "$h" -le "$v" ] || stop`, so a test error fails closed. Step 2b runs only after its `cross-check passed:` line. The residual (no enrolled host, or every reachable host under the same control as the server account) is stated, with escalation.
- Pinned in `TestRestoreRunbookChecks` (the block whole, the pointer, the head, the command, its pinned line, the rule, the missing-copy rule, the residual, step 2b's gate, and their order between the capture line, the file restore and the admin's `keyroster revoke recover`). `TestRestoreCrossCheck` runs the block on fixture copies (above, equal, below, no copy, bad arguments, a two-line copy). `TestAgentEnrollEndToEnd` runs `krl-version` on the enrolled host against the server's own `krl-served.json` (passes) and against the older genuine copy it served before the revocation (stops: `a host enforces KRL v1793196839, above v1793196835 of the kept server copy`).
- T-03-277 in 03-06c-PLAN.md is now `mitigate` with that residual. revoke.md's sentence follows.

## Tracer gate (Task 1)

The tracer's e2e cannot run in WSL (keyroster.localhost does not resolve there), so it ran in CI before Task 2 started: **E2E run 40695885890** on `cef59c0`, both lanes green, each with `--- PASS: TestAgentEnrollEndToEnd`. First apply 0.7 s and 1.2 s after the approval; the revocation's KRL applied 0.8 s and 0.9 s after `keyroster revoke serial`; the sshd PID unchanged. Then **E2E run 40703522592** on `f4fb528` (Tasks 1 and 2 and both carry-overs): both lanes green, with `TestAgentEnrollEndToEnd`, `TestRestoreCrossCheck` and `TestRestoreRunbookChecks`.

## What ran and what did not

**Ran (2026-10-28):**

- **WSL (Ubuntu, Go 1.27.3), on a copy of the tree built from `git ls-files -co --exclude-standard`, removed afterwards:**
  - the full gate on `7a9efb0`'s code: `CGO_ENABLED=1 go test -race -count=1 ./...` passed in every package; `go vet` for linux, windows and darwin, with `-tags e2e` and `-tags e2edistro`; gofmt clean; golangci-lint 0 issues for linux, windows, darwin and `--build-tags e2edistro`; capslock-check (signer 92/92, agent 36/36, fetcher 21/21, EXEC only through execsite); dep-firewall (four targets clean); testonly-firewall; check-pinned-actions;
  - Task 2's verify: the named cases of join, enroll, fetch, apply and cmd/keyroster-agent with `-v`; `-race` on `TestChain`, `TestIdentityCommand`, `TestAgentState`; `FuzzParseJoin` for 20 s;
  - `TestRestoreRunbookChecks`, `TestRestoreCrossCheck` and `TestRestoreCopyCaps` (e2e tag, no network needed);
  - real sshd 9.5p1 and 10.5p1 `sshd -T` probes of NUL handling.
- **Windows:** `go test -count=1 ./...` passes except the known `internal/agent/paths` `TestAllowed` (POSIX paths; not in the Windows CI lane).
- **CI:** E2E runs 40695885890 and 40703522592 (above). The PR's required checks are in the handback.

**Mutants (each applied in the WSL copy, run, and restored byte for byte):**

- Carry-over A: M8, the NUL check off, the `..` refusal off, the rollback condition off, the pre-repair off: all killed.
- Task 2 (18): approval by the first key only; approval ignoring a disabled host; the budget ignored; the first item dropped over budget; no 16 cap; the version grammar not checked; a token accepted at expires_at; minting without the pop.hosts check; a CA-signed client certificate accepted; the state answer not checked; a PoP of another identity posted; `more` not followed; the state body read under 4 MiB; a request of another installation signed; an RSA host key kept; unsorted pins accepted; the CLI's local pop.hosts check off; install's mode check off: all killed. (A first "empty version accepted" mutant survived because `strconv.ParseUint("")` refuses it anyway: an equivalent mutant, replaced by the grammar-off one. Two first approval mutants did not compile and were rewritten.)
- Carry-over B: current's KRL ignored in `InstalledKRLVersion`: killed.

**UNVERIFIED (not run here):**

- **Every homelab step,** until 03-16: the system user commands (`useradd`, Alpine's `addgroup`/`adduser`), install as root with a real `keyroster-agent` user (owners other than the test's uid are 03-08's `agent-smoke.sh`), running the fetcher and the applier by hand, the agent listener drop-in and firewall rule, and `keyroster-agent krl-version` with the cross-check on a real host.
- **Root-owned layout.** Every install and enrollment test ran as one non-root user, so `keyroster-agent:root` and `root:keyroster-agent` were the same uid and gid; cross-user writes and reads are 03-08's.
- **An agent behind the server by more than one bundle in e2e.** The chain catch-up is unit-tested (`TestAgentState/catch_up_ascending`, `more_than_16_continues`); no e2e installs a successor bundle.
- **Session resumption with a changed client certificate.** `VerifyConnection` runs on resumed handshakes by crypto/tls's contract; no test resumes a session.
- **Facts.** `sshd_version` is not collected (deviation 4); `os-release` parsing ran only on missing files in tests.

## Capslock pairs

`test/capslock/keyroster-agent-fetch.json` (new, 21 pairs, **no EXEC**):

| Package | Capabilities |
|---|---|
| `cmd/keyroster-agent-fetch` | ARBITRARY_EXECUTION, FILES, MODIFY_SYSTEM_STATE, NETWORK, REFLECT, SYSTEM_CALLS, UNANALYZED, UNSAFE_POINTER |
| `internal/agent/fetch` | ARBITRARY_EXECUTION, FILES, NETWORK, REFLECT, SYSTEM_CALLS |
| `internal/agent/enroll` | NETWORK, REFLECT |
| `internal/agent/spool` | FILES |
| `internal/serverclient` | NETWORK |
| `internal/trust` | REFLECT |
| `golang.org/x/crypto/ssh` | NETWORK, REFLECT |
| `golang.org/x/sys/unix` | SYSTEM_CALLS (spool's descriptor-relative writes, `unix.Close`, `Fstat`, `Renameat`) |

capslock's example paths: NETWORK through `serverclient.(*Client).send` (`http.NewRequestWithContext`); MODIFY_SYSTEM_STATE through `os/signal.NotifyContext`; ARBITRARY_EXECUTION through `ed25519.GenerateKey` -> `crypto/fips140.isBypassed` (the over-approximation the Phase 2 baselines record); `enroll`'s NETWORK is reached through its x/crypto/ssh import, not a call it makes.

`test/capslock/keyroster-agent.json` 23 -> 36 pairs (13 new): `cmd/keyroster-agent` MODIFY_SYSTEM_STATE (`signal.NotifyContext` in `run`); `internal/agent/apply` FILES (enrollment's key and os-release reads); `internal/agent/enroll` ARBITRARY_EXECUTION; `internal/agent/join` REFLECT, UNSAFE_POINTER (JSON decoding); `internal/agent/spool` FILES, UNANALYZED; `internal/agent/state` FILES, REFLECT; `internal/directory` ARBITRARY_EXECUTION and `internal/webauthn` ARBITRARY_EXECUTION (`krl-version` -> `state.LoadStored` -> `directory.Parse` -> `webauthn.ParsePublicKey` -> `x509.ParsePKIXPublicKey` -> `fips140.isBypassed`); `internal/trust` REFLECT, UNSAFE_POINTER. No new EXEC pair; EXEC still leaves the module only through execsite (2 edges). The signer's baseline is unchanged (92).

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `internal/tlspin`**
- **Issue:** `join.Parse` needs `ParseServerURL`, `ParseRoots`, `PinOf` and `CheckPin`, but serverclient imports net/http, which the applier's graph bans (D-05).
- **Fix:** the four functions moved into `internal/tlspin`; serverclient re-exports them unchanged.
- **Commit:** `cef59c0`

**2. [Plan gap] The join string's agent port**
- See "Owner attention first", item 1. The mint answer reports `agent_port`; `no_agent_listener` (409) when the server runs none.
- **Commit:** `cef59c0`

**3. [Rule 2 - Missing critical] `install_pins_differ`**
- **Issue:** install would have silently replaced a `pins.json` that pins another root set or installation.
- **Fix:** install refuses unless the existing `pins.json` is byte-equal (a re-run with the same join string is a no-op).
- **Commit:** `cef59c0`; `TestInstallLayout/pins_differ_refused` in `03cb4d7`.

**4. [Plan detail] `Facts.SSHDVersion` is empty**
- Reading it needs `sshd -V`, an exec site the plan does not list. `host pending` shows it as `unknown`.

**5. [Plan detail] Where the join edge tests live**
- `TestParse/expiry_boundary` checks the whole-second rule of `expires_at`; the clock boundary (refused at expires_at, accepted a second earlier, on the server's injected clock) is `TestAgentEnroll/expiry_boundary` in internal/server, as are `second_use_refused` and `ttl_above_hour_refused`. The CLI also refuses `--ttl` above 1 h before any call.

**6. [Plan detail] `identity` registers itself**
- `cmd/keyroster-agent/identity.go` registers from its own `init`, the package's pattern; commands.go is unchanged.

**7. [Plan detail] e2e mechanics**
- `serverOpts` gains `PoPHosts` and `AgentListen` (test/e2e/server_test.go, not in the plan's list); `keyroster-agent run --interval` (at least 1 s) and the fetcher's `--poll 1s`.
- The plan's "within 3 polls" is a measured bound: the test waits up to 20 s for the applier's status to name the new KRL and logs the time (0.8 s and 0.9 s in CI), then checks the refusal.
- The test user stands in for keyroster-agent through `--fetch-user`.

**8. [Plan detail] `chain_out_of_order` is the fetcher's refusal**
- The spool is keyed by version, so the applier never sees an answer's order; the fetcher refuses a non-ascending answer (`serverclient.AgentStateResponse.Check`) and writes nothing. The applier's refusal of a gapped chain is 03-05's `bundle_chain_gap` / `directory_chain_gap` (TestApply), unchanged.

**9. [Rule 2] `VerifyConnection`, not `VerifyPeerCertificate`**
- gosec G123: `VerifyPeerCertificate` is not called on a resumed TLS session. The agent certificate check runs in `VerifyConnection`, which is.

**10. [Plan detail] Files beyond the plan's list**
- internal/tlspin; internal/directory/hosts.go (`IsHostKeyType`); internal/signerdb trust.go and directory.go (`BundleByVersion`, `DirectoryByVersion`, which signer/chain.go reads); internal/agent/apply/harness_test.go (the fake sshd's real private key, `rejectDropIn`); routes_test.go (two admin routes listed); serverdb db_test.go (schema version 5); internal/agent/paths; .golangci.yml (`agent-apply-no-http` excludes internal/agent/fetch, the network half); cmd/keyroster-server/main.go (usage); test/e2e/server_test.go.

**11. [Plan detail] The system user commands**
- `useradd` gains `--user-group`, and Alpine's line creates a group first (`addgroup -S keyroster-agent && adduser -S -D -H -G keyroster-agent ...`): the outbox's group must be keyroster-agent's own, and busybox `adduser -S` otherwise uses `nogroup`.

**12. [Plan detail] The agent limiter's global backstop**
- 100 times the per-identity rate (3 000 requests a minute), not the 10 times of the other route classes, so a fleet of about 3 000 hosts polling every 60 s fits.

**13. [Rule 1 - Bug] A3's first version broke 03-05's `sshd_t_failure_rolls_back_dropin`**
- **Found during:** Task 2's full apply run.
- **Issue:** restoring `DropIn` also where the drop-in had been missing left a drop-in `sshd -t` refuses.
- **Fix:** only a previous file is replaced by `DropIn`; a missing one is removed again. Amended into `6557d7d` before it was pushed.

**14. [Plan detail] `pop_uses_pinned_installation`**
- A request naming another installation is refused before signing (`enroll_request_other_installation_refused`), so this case can only show that the PoP carries pins.json's ID; a mutant reading the request's ID instead is equivalent on every accepted request.

**15. [Plan detail] `run` retries**
- A failed apply runs again 60 s later on an unchanged spool, so a transient failure (sshd stopped) does not wait for the next new version.

**16. [Rule 1 - Bug, found in review] A false remedy for `host_keys_in_use`**
- **Issue:** the first host-setup.md table said `keyroster host remove <old name>` fixes `host_keys_in_use`. It does only for a key on a directory entry: the server never deletes an `agents` row, so a host whose agent state was reinstalled with the same host keys can never enroll again in this version, and after `host remove` the old agent shows up in `host pending` again (a later `host approve <name>` would approve that old identity).
- **Fix:** the table states the one remedy that works and the limit; `TestAgentEnroll/host_keys_in_use` now also enrolls the keys of a removed directory entry, and `removed_host_agent_keeps_its_keys` pins the limit. Deregistration is an open question for the owner. The same review found revoke.md, enroll-user.md and host-setup.md still saying that no host receives a KRL automatically; they now say an enrolled host does.
- **Commits:** `04c2078`, `36c9044`

---

**Total deviations:** 16: 1 Rule 3, 3 Rule 2, 2 Rule 1, 1 plan gap, 9 plan details.
**Impact on plan:** No new Go module. No production exec site was added; the fetcher has none in its graph.

## TDD Gate Compliance

- Task 2 is `tdd="true"`, but Task 1, the tracer, had built the code first, as in 03-05 and 03-06. Most Task 2 tests passed on their first run; there is no separate RED commit, and RED was not faked.
- **Evidence instead:** the 24 mutants above, each killed by the test that names the rule.
- **Real RED:** the full apply run found deviation 13; `TestInstalledKRLVersion` first failed on the test's own fixture (no KRL before the first install).

## Issues Encountered

- **Heredoc backslashes.** Two Python edits run through a Bash heredoc turned `\n` inside Go strings into newlines; the build caught both, and the edits were redone with the Edit tool. Nothing broken was committed.
- **`keyroster.localhost` in WSL.** The e2e suite ran only in CI, as planned.
- **Stray binaries.** An early `GOOS=linux go build ./cmd/...` left `keyroster-agent` and `keyroster-server` in the repository root; they were deleted before the first commit and never staged.

## Known Stubs

None. `sshd_version` is reported empty on purpose (deviation 4).

## Threat Flags

| Flag | File | Description |
|---|---|---|
| threat_flag: new listener | cmd/keyroster-server/serve.go | `--agent-listen` opens a second TCP port that any client can reach for a TLS handshake; the handshake requires a self-signed Ed25519 client certificate, and enrollment needs a minted token (T-03-46). The runbook's firewall rule is UNVERIFIED |
| threat_flag: unauthenticated enrollment cost | internal/server/agent.go | `POST /api/v1/agent/enroll` verifies up to eight SSHSIG signatures per request before the token is checked; the per-identity limiter is per self-generated identity, so the global backstop (3 000 a minute) bounds it |
| threat_flag: spool growth | internal/agent/fetch/fetch.go | The fetcher never removes old spool files, so every bundle, directory and KRL version stays in the spool; the applier reads at most 64 per kind. Pruning is a follow-up (03-08?) |
| threat_flag: install as root | cmd/keyroster-agent/install.go | A root command that chowns paths to the fetcher's user; every path is checked first and owners are set on descriptors |
| threat_flag: no deregistration | internal/serverdb/agents.go | An `agents` row is never deleted. After its host entry is removed, the old agent is pending again, and an admin who approves that name re-approves the old identity, whose key may belong to a decommissioned host; it would then read the signed directory (D-03's exposure, read-only). A reinstalled host with the same host keys cannot enroll again |

## Open questions for the owner

1. The agent port (Owner attention 1): keep the server-reported port, or add `--agent-port` to `host join-token`?
2. A refused KRL makes the whole state answer 503 (Owner attention 4): keep, or serve bundles and directories without the KRL?
3. Spool pruning: who removes old versions, the fetcher (it knows nothing of what the applier accepted) or the applier through the outbox (03-08's status)?
4. `install_pins_differ` makes moving a host to another deployment a manual removal of `/var/lib/keyroster-agent`: acceptable, or should install offer a `--replace`?
5. The agent limiter (30/min, burst 10, backstop 3 000/min): right for your fleet?
6. **Deregistration and re-enrollment.** An enrolled agent can never be removed and its host keys never enroll again (deviation 16, threat flag "no deregistration"). Options: an admin-signed `keyroster host forget <name>` that deletes the agent row, letting `host remove` also drop the row whose keys it removes, or leaving it to 03-08's identity rotation. Until then a reinstalled host needs the server's database edited by hand, which no runbook describes.

## User Setup Required

None in this plan. On the homelab (03-16), the owner mints join tokens and approves hosts; the server needs `--agent-listen` and a firewall rule.

## Next Phase Readiness

- **03-08:** units for `keyroster-agent-fetch` (user keyroster-agent) and `keyroster-agent run` (root), the outbox's `status.json`, heartbeats, `agent-smoke.sh` for the root-owned layout and cross-user writes, identity rotation, and spool pruning.
- **03-09:** host certificates can bind to the enrolled host keys the directory entry names.
- **03-16:** every homelab step above, including the restore cross-check on a real host.

## Self-Check: PASSED

- **Files.** Every created key file exists, `test/capslock/keyroster-agent-fetch.json` is tracked and holds no EXEC pair.
- **Commits.** `cef59c0`, `2c474d3`, `80ac377`, `6557d7d`, `03cb4d7`, `f4fb528`, `3c3f332`, `7a9efb0`, `622f894`, `405475c`, `04c2078` and `36c9044` are ancestors of HEAD; `git rev-list --count ef38293..36c9044` is 12.
- **Task 1 acceptance.** `grep -n RequireAnyClientCert internal/server/agenttls.go` prints the config line; `grep -c ClientAuth cmd/keyroster-server/serve.go` prints 0; `grep -rn /api/v1/agent/ internal/server/server.go` prints nothing; TestAgentEnrollEndToEnd's CI log shows the pending host, the approval, the first apply, the accepted login and the refusal.
- **Task 2 acceptance.** Every named case of the behaviour list exists and passes (`go test -v` output), including TestParse/expiry_boundary, TestFetch/response_max_plus_one_refused and enroll_pop_mismatch_not_posted, TestEnroll/enroll_request_fifo_refused and state_dir_unsafe_refused, TestInstallLayout, TestHostPoPRequired/join_token_refused and enroll_refused, TestAgentListenerRequiresClientCert, TestBrowserListenerUnchanged, TestAgentState/budget_exact_fits, budget_one_byte_short_defers_last, more_than_16_continues, largest_items_fit_budget and catch_up_ascending, TestChain/absent_version_not_found, TestIdentityCommand and TestHostApprovePoPRequired/approve_refused_locally and join_token_refused_locally.
- **Task 3 acceptance.** `bash scripts/dep-firewall.sh` prints the `== keyroster-agent-fetch,`, `== keyroster-agent,` and `== keyroster-signer,` headers and passes; host-setup.md has "How fast changes arrive" and LoginGraceTime; every new runbook step carries a CI or UNVERIFIED label.
