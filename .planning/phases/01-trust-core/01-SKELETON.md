# Walking Skeleton — keyroster

**Phase:** 1 (Trust Core)
**Generated:** 2026-10-04
**Delivered by:** plans 01-01 (repository + CI), 01-02 (issuance through the signer, accepted by real sshd 10.5p1), 01-04 (the same path proven in CI on sshd 9.5p1 and 10.5p1, required on `main`) and 01-05 (Merkle audit log + `keyroster audit verify`). The skeleton is complete when the 01-05 PR is merged to `main`.

## Capability Proven End-to-End

An admin on the signer host runs `keyroster ca issue` against a running `keyroster-signer` (Unix socket, CA key held in an ssh-agent and selected by pinned fingerprint), gets a user certificate that real `sshd` (portable OpenSSH 9.5p1 and 10.5p1, built in CI from SHA-256-pinned tarballs) accepts, the issuance is a leaf of the signer's SQLite Merkle log with a signed checkpoint before the certificate leaves the process, and `keyroster audit verify` checks the exported log end to end. Every change got there through a signed, reviewed, CI-gated PR on a public repository.

This is not a web app, so the template's layers map as follows:

| Template layer | keyroster equivalent |
|---|---|
| Routing | Versioned, length-prefixed message dispatch on the signer's Unix socket (`internal/wire`, `internal/signer`) |
| DB read + write | Signer state DB: serial high-water mark and issuance rows (01-02), Merkle leaves and checkpoints (01-05) |
| UI interaction | Admin CLI: `keyroster ca issue` (01-02), `keyroster audit verify` (01-05) |
| Deployment | A documented local run through WSL (`bash scripts/linux.sh '...'`, 01-02), then CI e2e on GitHub-hosted Linux runners (01-04); the systemd-sandboxed deployment arrives in 01-13 and the homelab VM in 01-14 |

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Name and module | `keyroster`, module `github.com/Labontese/keyroster`; binaries `keyroster` (CLI) and `keyroster-signer` in Phase 1; `keyroster-server`/`keyroster-agent` later | D-01 (one-way: published import path, pinned domain strings) |
| Language and build | Go toolchain 1.27.1, `go 1.26` directive, `CGO_ENABLED=0` for every default build; cgo only behind `-tags piv` | Locked stack (CLAUDE.md); static, reproducible binaries |
| Process boundary | `keyroster-signer` is a separate, Linux-only process. It listens only on a path-based Unix socket (`/run/keyroster-signer/signer.sock`, mode 0660, group `keyroster-admin`) and checks every peer with `SO_PEERCRED` + `SO_PEERGROUPS` against a uid/gid allowlist before reading a byte | KEY-01; "the server proposes, the signer disposes" |
| Wire format | uint32 big-endian frame length (max 64 KiB), version byte `0x01`, message type byte, `cryptobyte`-encoded body; strict decoding (no trailing bytes, hard limits), fuzzed. Issue requests carry request id, creation time, subject, principals, validity and an evidence list; their signing bytes are domain-separated with `keyroster/issue-request/v1` | D-13 (costly: the request format carries evidence from day one) |
| Signing rules | `internal/cert.Build` is the only caller of `SignCert` in the module (guard test + `forbidigo`). It validates principals (ASCII allowlist), key ID grammar `kr1/ca=…/sub=…/req=…/pol=…/ser=…`, validity cap, extensions from the role profile (user default `permit-pty` only), subject key type, and refuses certificate-type CA keys | CA-02, CA-04, CA-05, CA-06, CA-07 |
| Serials | Clock-floor high-water mark: `serial = max(last+1, now_µs)`, never ahead of the clock, fail-closed on clock regression; `issuance.serial` is a primary key | CA-03, restore-safe without external state |
| Keystore | `keystore.CAKey` = `ssh.Signer` + `Custody()` + `Algorithm()`; backends registered by name (`agent`, `tpm`, `piv`) and opened with `--backend-opt k=v`; keys always selected by pinned fingerprint; CA algorithms limited to `ssh-ed25519` and `ecdsa-sha2-nistp256` | D-09 (algorithm-agnostic; P-256 on TPM) |
| Data layer | `modernc.org/sqlite` (pure Go), one DB file per signer state dir, the signer is the only writer; WAL + `synchronous=FULL`; embedded `migrations/NNNN_*.sql` applied by `PRAGMA user_version` | Locked stack; atomic "state change + audit entry" |
| Audit log | RFC 6962 Merkle log with `github.com/transparency-dev/merkle` (`rfc6962` hasher, `compact.Range`); leaves domain-separated `keyroster/log-leaf/v1`; one C2SP checkpoint per append, signed via `golang.org/x/mod/sumdb/note` with the log key (Ed25519 type 0x01 or ECDSA P-256 type 0x02). Sign in memory → one `BEGIN IMMEDIATE` transaction (issuance row, serial, leaf, checkpoint) → release only after COMMIT | VIS-01, D-15 |
| Audit verification | `keyroster-signer export-log` → JSONL (leaves + final checkpoint); `keyroster audit verify` reads only leaf bytes and the checkpoint, never the informational `decoded` field | VIS-03 |
| Trust anchor | Offline roots sign canonical-JSON trust bundles and policies with detached SSHSIG (`keyroster/trust-bundle/v1`, `keyroster/policy/v1`); verification counts distinct roots among operator-pinned fingerprints against a threshold; roots never sign certificates | KEY-07, D-10, D-11 (plans 01-06, 01-07, 01-09) |
| Authorization | Phase 1: peer-credential allowlist (01-02) plus mandatory `admin-sshsig/v1` evidence verified against the admins in the root-signed genesis policy (01-07) | D-13 |
| CLI ergonomics | stdlib `flag` + `init()`-registered subcommand groups (`cmd/*/commands.go`), so plans add commands without editing `main.go`. Signer-side admin operations (`ca-init`, `install-bundle`, `export-log`, `doctor`) live in `keyroster-signer`, so keystore backends (TPM, PIV/cgo) link only into the signer | Discretion (CONTEXT): smaller CLI attack surface |
| Testing | Unit + table tests per package; native fuzz targets for every decoder (`scripts/fuzz.sh` discovers them); e2e via `os/exec` against non-root sshd/ssh/ssh-agent/ssh-keygen with build tags `e2e`, `e2e_pkcs11`, `e2e_tpm`; `ssh-keygen` is a test oracle only | Locked stack; no testcontainers |
| CI | GitHub Actions, every action pinned by full commit SHA, `permissions: {}` at top level, `contents: read` per job, `persist-credentials: false` | REPO-02 |
| Repository process | Public repo, PR-only `main` via two rulesets (integrity: no bypass; review: admin bypass in `pull_request` mode), squash merges with the PR title, Conventional Commits, SSH-signed commits; Claude works as `keyroster-bot`, the owner reviews at a declared merge gate per plan (`scripts/merge-gate.sh`, Delivery Protocol) | REPO-01, D-04, D-05, D-06 |
| Directory layout | `cmd/keyroster`, `cmd/keyroster-signer`, `internal/{wire,cert,keystore,serial,signer,signerclient,signerdb,tlog,audit,sshsig,trust,rootceremony,doctor}`, `test/{e2e,vectors,manual,capslock,systemd}`, `scripts/`, `deploy/`, `docs/`, `tools/go.mod` | Research "Recommended Project Structure" |

## Delivery Protocol (every plan)

`main` accepts changes only through signed, green, owner-approved PRs (rulesets from 01-01). Every plan therefore ends at a declared human gate, and every planning document reaches `main` inside a PR. 01-01 bootstraps `main` with the one direct push made before any ruleset exists; its CONTRIBUTING PR then follows steps 3-7.

**Execution mode (one open plan PR at a time).** `.planning/config.json` sets `workflow.use_worktrees: false`, so `/gsd-execute-phase 1` runs the executors one at a time in the main checkout, and each plan's PR is merged at its own merge gate before the next plan starts. Wave numbers express dependencies only. Consequences: same-wave plans never have open PRs at the same time, so their merges never race; every plan branch starts from a `main` that already holds every earlier plan's code and SUMMARY, so the checkout always shows GSD the true phase state; and no worktree merge-back exists, because GitHub is the only place where branches are integrated.

1. **Start.** The first task's `<precondition>` asserts that every dependency plan's SUMMARY is on `origin/main` (`git cat-file -e origin/main:.planning/phases/01-trust-core/01-NN-SUMMARY.md`), which holds exactly when that plan's merge gate passed. Then `git fetch origin && git switch -c p01/NN-slug origin/main`.
2. **Commits.** All commits are made by `keyroster-bot` (repo-local git identity set in 01-01), SSH-signed with the bot key in the Windows ssh-agent.
3. **Publish.** The plan's last implementation task pushes the branch, opens the PR with a Conventional Commits title via `scripts/gh-as-bot.sh pr create`, enables auto-merge (`scripts/gh-as-bot.sh pr merge --auto --squash`) and waits for every required check.
4. **Planning docs, before any approval is requested (same task).** Write `01-NN-SUMMARY.md` (per the plan's `<output>`, PR number included) and run GSD's tracking updates for this plan exactly once (STATE.md, ROADMAP.md, REQUIREMENTS.md); commit them as `docs(01-NN): complete <slug> plan`; push to the same PR branch; wait for the required checks again. The SUMMARY records pre-merge evidence only (PR number, check results, decisions, deviations). Merge facts (squash commit, merge time) are never committed; read them with `gh pr view N --json mergeCommit,mergedAt` when needed, so nothing is backfilled and nothing is pushed after the owner approves.
5. **Merge gate (terminal `checkpoint:human-action`, `gate="blocking-human"`).** The owner (`@Labontese`, code owner) reviews code and docs together and approves in the GitHub UI; auto-merge then squash-merges. Claude runs `bash scripts/merge-gate.sh p01/NN-slug` (created in 01-01; GitHub calls only through `scripts/gh-as-bot.sh`):
   - exit 0: the PR is merged and local `main` is fast-forwarded to `origin/main`; the plan is complete.
   - exit 2: approval still pending; present the checkpoint again.
   - exit 3: `main` moved meanwhile (for example a Dependabot or owner PR merged), so the script rebased the branch onto `origin/main` with signed commits, force-pushed with lease, re-enabled auto-merge and waited for green checks; GitHub dismissed the approval (`dismiss_stale_reviews_on_push`, `require_last_push_approval`), so present the checkpoint again for re-approval of the new head.
   - exit 4: rebase conflict, left in progress. For `.planning/` tracking files take `origin/main`'s version and re-apply only this plan's own entries; resolve code conflicts on their merits; `git rebase --continue`, then rerun the script.
   - exit 1: closed PR, failing check or merge timeout; fix on the branch, push, rerun.
   `bash scripts/merge-gate.sh --check p01/NN-slug` is the read-only form used in `<verify>`: exit 0 only when the PR is merged and local `main` equals `origin/main`.
6. **After the gate.** No further commit for that plan. GSD's SUMMARY and tracking steps already ran in step 4 and are on `main`; do not run them again.
7. **Prohibitions.** Claude never approves or merges a PR with the owner's `GH_TOKEN` (no `gh pr review`, no un-wrapped `gh pr merge`, no admin bypass of a bot PR). The owner never clicks "Update branch" on a bot PR: that makes the owner the last pusher, and `require_last_push_approval` then refuses the owner's own approval. Local `main` only fast-forwards; if any GSD step commits onto it by mistake, move the commit to a `p01/docs-<topic>` branch (`git switch -c p01/docs-<topic>`, then `git branch -f main origin/main`), push it and take it through steps 3-5 as a docs-only PR.

**Phase-closing docs.** When 01-15's merge gate passes, Claude switches to a new branch `p01/close` from `origin/main`. The phase-level artifacts written after the last plan (VERIFICATION.md, UAT.md, code review and security reports, phase completion in STATE.md and ROADMAP.md) are committed there; the bot opens `docs(01): close phase 1`, and the same merge gate applies (`bash scripts/merge-gate.sh p01/close`).

**Plan shape.** Each plan has at most three implementation tasks plus the terminal merge gate. The gate does no implementation work: a fresh continuation agent runs one script after the owner's approval, so it adds no implementation context to the plan's budget.

## Stack Touched in Phase 1

- [ ] Project scaffold (Go module, CLI dispatcher, build, lint, unit tests, govulncheck) — 01-01
- [ ] "Routing" — one real message type (`IssueRequest`) dispatched by the signer over its Unix socket — 01-02
- [ ] Database — real write (serial high-water mark, issuance row, Merkle leaf, checkpoint) and real read (startup recovery, export) — 01-02, 01-05
- [ ] "UI" — `keyroster ca issue` and `keyroster audit verify` wired to the signer and its log — 01-02, 01-05
- [ ] "Deployment" — documented local WSL run against real sshd 10.5p1 — 01-02; CI e2e against real sshd 9.5p1/10.5p1 — 01-04; systemd unit — 01-13; homelab VM — 01-14; Windows OpenSSH 9.5p2 manual check — 01-15

## Out of Scope (Deferred to Later Slices)

- `keyroster-server`, web UI, WebAuthn/passkeys, `keyroster login` (Phase 2)
- Host agent, KRL encoder and distribution, revocation, CA rotation, break-glass CA, host certificate renewal by the agent (Phase 3)
- Quorum-signed policy changes beyond the genesis policy, JIT approvals, witnessed checkpoints (Phase 4)
- Key inventory, login reconciliation, who-has-access overview, Windows/macOS/BSD agents (Phase 5)
- Release signing, reproducible-release verification, backups, external review (Phase 6)
- Encrypted software CA keys with UI warnings (KEY-06, Phase 2); in Phase 1 the `agent` custody with a plain key is a test/dev configuration that `doctor` flags

## Subsequent Slice Plan

Each later phase adds one vertical slice on top of this skeleton without changing the decisions above:

- Phase 2: a passkey-authenticated user runs `keyroster login` and gets a short-lived certificate in ssh-agent (`webauthn/v1` evidence joins `admin-sshsig/v1` through a policy update, not a signer bypass)
- Phase 3: enrolled Linux hosts pull root-signed CA sets, principals and KRLs (the `ops_key` already in the bundle becomes the KRL authority)
- Phase 4: policy changes need an admin quorum; agents and the CLI verify signed checkpoints with consistency proofs
- Phase 5: inventory and reconciliation surface access outside the CA
- Phase 6: signed, reproducible releases and recovery runbooks
