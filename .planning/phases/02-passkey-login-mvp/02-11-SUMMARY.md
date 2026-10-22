---
phase: 02-passkey-login-mvp
plan: 11
subsystem: authz
status: complete
tags: [roles, groups, host-groups, principals, AuthorizedPrincipalsFile, TrustedUserCAKeys, cli]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-01 directory types, Validate, roleGrants and Authorize; 02-09 editDirectory and fetchVerifiedDirectory (verified base, Validate, CheckPolicy, diff, confirmSign or --yes, SSHSIG, install or proposal); 02-06 serverclient.Trust; the e2e harness (startServerEnv, enroll, startSSHD, sshLogin)"
provides:
  - "directory.RenderPrincipalsFile and directory.AccountPrincipals: the one principals renderer (D-07), shared with the Phase 3 agent"
  - "directory.ErrUnknownHostGroup, directory.ErrNoDirectory; directory.ValidGroupName, ValidRoleName, ValidAccountName"
  - "keyroster role add|update|remove|grant|revoke, group add|remove|add-member|remove-member, host-group add|remove|map|unmap (every change an editDirectory mutation)"
  - "keyroster host principals GROUP ACCOUNT and keyroster host ca-key"
  - "docs/runbooks/host-setup.md"
  - "e2e TestRolesHostPrincipalsEndToEnd"
affects: [02-12, 02-13, 02-14, phase-3-agent, AUTHZ-01]

actuals:
  tokens: 21300
  tasks: 3
  commits: 4
plan_head_before: 4b7808bfb532f7f8d7c68bc5f93e4470df9ad65e
plan_head_after: ec927e8407ef3b80a998d5a7f3e0e0214bf9a812

tech-stack:
  added: []
  patterns:
    - "Every role, group and host-group change is a mutate func passed to editDirectory; refusals happen inside mutate or before the session opens, so no directory signature reaches the agent"
    - "Names that reach a rendered file are checked against the directory grammars first, so the header line cannot carry a forged principal line"
    - "A list flag that is given replaces the list; an omitted one keeps it (role update)"

key-files:
  created:
    - internal/directory/render.go
    - internal/directory/render_test.go
    - cmd/keyroster/role.go
    - cmd/keyroster/group.go
    - cmd/keyroster/hostgroup.go
    - cmd/keyroster/host.go
    - cmd/keyroster/role_test.go
    - test/e2e/roles_test.go
    - docs/runbooks/host-setup.md
  modified:
    - internal/directory/directory.go
    - cmd/keyroster/dirpipe_test.go

key-decisions:
  - "D-06 (owner, 2026-10-22, verbatim: \"role:<namn> och u:<användare> (Rekommenderas)\"): roles grant role:<name> by default; personal accounts use u:<username>"
  - "Header-only file for an unmapped account or roles [] in a known host group; ErrUnknownHostGroup for an unknown host group; ErrNoDirectory for a nil directory"
  - "The renderer refuses (ErrInvalid) a host group or account name outside the directory grammars, so a name with a newline cannot forge a principal line in the header"
  - "host-group remove is refused while the host group maps an account, so the header-only file can always be rendered first (T-02-100)"
  - "host ca-key needs the saved config but no admin key"

patterns-established:
  - "Directory edit command: parse flags (parseInterspersed), check names and argument-only rules, then editFlags.edit with a mutate that refuses no-ops and unknown references naming them"

requirements-completed: [AUTHZ-01]

coverage:
  - id: D1
    description: "A user's certificate carries exactly the principals of their roles (through a group); real sshd with keyroster's rendered principals file and CA line accepts it, and refuses it with the header-only file rendered after host-group unmap"
    requirement: AUTHZ-01
    verification:
      - kind: e2e
        ref: "test/e2e/roles_test.go#TestRolesHostPrincipalsEndToEnd"
        status: pass
    human_judgment: false
  - id: D2
    description: "Empty, wildcard, comma, whitespace, control-character and duplicate principals, a TTL above the cap or below 1m, an extension the profile does not allow, unknown users, groups and roles, uppercase accounts, removing a mapped role or a granted group, map with no role and --no-extensions with --extension are all refused before signing"
    requirement: AUTHZ-01
    verification:
      - kind: unit
        ref: "cmd/keyroster/role_test.go#TestRoleRefusals"
        status: pass
    human_judgment: false
  - id: D3
    description: "The renderer: union, header-only cases, unknown host group, nil directory, header SHA-256 of the installed bytes, names outside the grammars"
    requirement: AUTHZ-01
    verification:
      - kind: unit
        ref: "internal/directory/render_test.go#TestRenderPrincipalsFile"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-10-22
---

# Phase 2 Plan 11: Roles, groups, host groups and the shared principals renderer Summary

**Admins now define roles, groups and host groups through admin-signed directory versions. `keyroster host principals` renders an account's AuthorizedPrincipalsFile with the one renderer the Phase 3 agent will use, and `keyroster host ca-key` prints the TrustedUserCAKeys line. In CI, a real sshd accepts exactly what the rendered file lists, and refuses once the role is unmapped.**

PR: opened after this file was committed and pushed (one push), so its number and checks are in the merge-gate checkpoint, as in 02-09.

## D-06 (Task 1, one-way door)

- **Decision:** option `role-prefix`. Roles grant `role:<name>` by default, and personal accounts use `u:<username>`.
- **Owner's reply, verbatim (2026-10-22):** "role:<namn> och u:<användare> (Rekommenderas)"
- The default is the constant `rolePrincipalPrefix = "role:"` in cmd/keyroster/role.go. `role add ops` without `--principal` grants `role:ops`. Both `TestRoleEdits/role_add_default_principal` and the e2e assert that, through the diff line `+ role ops principals=[role:ops] ...`.
- Both forms pass `cert.ValidatePrincipals` for any valid role or user name, since the role and user name grammars are subsets of the principal alphabet. The CLI does not enforce `u:` for personal roles. The runbook documents the form.

## Commands

All the mutating subcommands take `--yes`, `--out DIR` and `--admin-key SHA256:...`, and run as `editDirectory` mutations.

| Command | Effect |
|---|---|
| `keyroster role add NAME --max-ttl D [--principal P]... [--extension E]... [--user U]... [--group G]...` | New role. Without `--principal` it grants `role:NAME`. `--max-ttl` takes Go duration syntax, is rounded to the second, and must be at least 1m. |
| `keyroster role update NAME [--max-ttl D] [--principal P]... [--extension E]... [--no-extensions]` | A list flag that is given replaces that list; an omitted one keeps it. `--no-extensions` empties the extensions and is refused together with `--extension`. Grants are unchanged. |
| `keyroster role remove NAME` | Refused while a host group maps the role; the error names the host groups. |
| `keyroster role grant\|revoke NAME [--user U]... [--group G]...` | Takes at least one `--user` or `--group`. Granting what is already granted, or revoking what is not, is refused. |
| `keyroster group add NAME [--member U]...`, `group remove NAME` | `remove` is refused while a role grants the group; the error names every granting role (02-11-F6). |
| `keyroster group add-member\|remove-member NAME U...` | Adding an existing member, or removing a non-member, is refused. |
| `keyroster host-group add NAME`, `host-group remove NAME` | `remove` is refused while the host group maps an account (deviation 3). |
| `keyroster host-group map NAME ACCOUNT ROLE...` | Sets the account's role list (at least one role). With none: "give at least one role; to revoke the account's access use host-group unmap". |
| `keyroster host-group unmap NAME ACCOUNT` | Removes the account's entry. An account with no entry is refused, by name. |
| `keyroster host principals GROUP ACCOUNT [--admin-key FP]` | `fetchVerifiedDirectory`, then `RenderPrincipalsFile`. stdout carries exactly the file. With version 0 it refuses with "no directory is installed on the server; nothing to render" (wraps `directory.ErrNoDirectory`) and prints nothing. |
| `keyroster host ca-key` | `Trust` against the saved root pins, then the active user CA entry printed as `<key> keyroster user CA (bundle vN)`. |

`keyroster host-group` prints `hostGroupUsage` for a missing or unknown subcommand and exits 2. The usage includes the sentence "Host groups only decide what keyroster host principals renders (the AuthorizedPrincipalsFile content); they do not restrict certificate issuance, and certificates are not host-scoped." (02-11-R2-F1).

## Renderer header format

```
# keyroster: generated AuthorizedPrincipalsFile; do not edit
# host group <g>, account <a>, directory version <n> sha256 <lowercase hex SHA-256 of d.Canonical()>
<principal>
...
```

- Principals are sorted, de-duplicated, one per line, each followed by a newline. sshd ignores the `#` lines.
- An unmapped account, or one whose role list is empty, gets the two header lines only.
- For an installed directory, the hash equals the SHA-256 of the stored bytes, which is the value `keyroster directory show` prints (`header_sha256_matches_installed_bytes`).

## Tasks

| Task | Name | Commit | Files |
|---|---|---|---|
| 1 | D-06 checkpoint | none (owner reply, recorded here) | none |
| 2 | Tracer: renderer, role/group/host-group/host commands, e2e | 06a51e2 | render.go, directory.go, role.go, group.go, hostgroup.go, host.go, roles_test.go |
| 3 | Refusals, renderer tests, runbook | 960d89f, ec927e8 (stdout and peer-text tests); docs 4e39012 | render_test.go, role_test.go, dirpipe_test.go, host-setup.md |
| 4 | Merge gate | not attempted (blocking-human) | none |

## Verification

- **Tracer gate (Task 2):** `TestRolesHostPrincipalsEndToEnd` passed in WSL against OpenSSH 10.5p1 (`--- PASS ... (5.14s)`), before any Task 3 work. Its steps:
  - the control login was accepted through keyroster's rendered file and CA line;
  - after the unmap, `host principals` exited 0 with the exact two-line header of version 8;
  - a fresh sshd fed that output refused the same certificate (exit 255, "Permission denied").
- **Task 3 verify:** `go test -count=1 -v -run 'Render|Role|Group|HostGroup|HostPrincipals' ./internal/directory/... ./cmd/keyroster/...` passes. That includes `TestRenderPrincipalsFile/unmapped_account_renders_header_only`, `empty_role_list_renders_header_only`, `nil_directory_errors` and `TestHostPrincipals/no_directory_refused`.
- **Full gate:** run in WSL from a script file, so gofmt is really checked (02-01's deferred row). Everything below passed (GATE rc=0):
  - `go test -race -count=1 ./...` (24 packages ok, no DATA RACE);
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/`;
  - `$(go env GOROOT)/bin/gofmt -l .` (empty);
  - `golangci-lint run ./...`;
  - `capslock-check.sh`: 91 pairs, baseline 91, unchanged;
  - `dep-firewall.sh` and `testonly-firewall.sh` (clean).
- **Windows:** `go test ./internal/directory/... ./cmd/keyroster/...` passes.
- **After ec927e8:** the full gate was re-run in WSL with golangci-lint also at GOOS=windows and GOOS=darwin, as CI's lint job does: GATE rc=0, capslock 91/91. The Windows unit tests pass.
- **Stdout and peer text:**
  - `TestHostPrincipals/software_custody_banner_on_stderr` runs both `host` commands under software custody. stdout is exactly the rendered file or the key line, and the KEY-06 banner appears once on stderr. A mutant that sends `host ca-key`'s banner to stdout is killed.
  - `TestRolePeerText` covers `host principals`, `role add` and `host-group map`: padded server errors on the directory routes reach stderr only contained, and stdout stays empty (T-02-93).
- **Acceptance greps (Task 2):**
  - `func RenderPrincipalsFile` is in render.go and is used in host.go;
  - `ErrNoDirectory` is defined in render.go and used in host.go;
  - `Version == 0` appears once in host.go;
  - `fetchVerifiedDirectory` is in host.go;
  - the comment-filtered fixed-string grep of hostgroup.go counts 1.
- **Mutants:** 11 temporary mutants, none committed, and each was killed by a named case:
  - the account check removed from the renderer (`names_outside_the_grammars_refused`);
  - a nil list for an unmapped account (`unmapped_account_renders_header_only`, `empty_role_list_renders_header_only`);
  - the wrong bytes hashed (`union_sorted_deduplicated`);
  - `map` with zero roles allowed (`map_zero_roles_refused`);
  - the `Version == 0` check removed (`no_directory_refused`);
  - `--no-extensions` ignored (`role_update_clears_extensions`);
  - only the first granting role named (`remove_granted_group_refused`);
  - the default principal without its prefix (`role_add_default_principal`);
  - unmap keeping the entry with `roles: []` (`unmap_removes_account`);
  - the CLI principal pre-check removed (`wildcard_principal_refused` and the other principal cases: the signer-side Validate still refuses, but its message does not name the principal);
  - the host-group usage text removed (`host_group_usage_states_scope`).

## Deviations from Plan

### Deferred items

**1. No deferred row is addressed to 02-11.** All 20 lines of deferred-items.md were read. The rows name 02-09, 02-10 and 02-12, or a Phase 6 todo. One row still bears on this plan's gate: 02-01's gofmt quirk. The plan's gate command, `bash scripts/linux.sh '... test -z "$(gofmt -l .)" ...'`, checks nothing in WSL. The gate here ran from a script file with `$(go env GOROOT)/bin/gofmt` instead. The gate command itself is not changed: no file of this plan holds it.

### Auto-fixed issues

**2. [Rule 2 - Security] The renderer validates the names it writes into the header.**
- **Found during:** Task 2.
- **Issue:** An unmapped account's name comes from the command line, not from the directory. Written into the header, a name such as `x\nrole:admin` would start a new line that sshd honours as a principal.
- **Fix:** `AccountPrincipals` and `RenderPrincipalsFile` refuse (ErrInvalid) a host group outside the group grammar and an account outside the account grammar. `host principals` checks both before it opens the session.
- **Tests:** `names_outside_the_grammars_refused` and `TestHostPrincipals/invalid_account_refused`.
- **Commit:** 06a51e2 / 960d89f.

**3. [Rule 2 - Security] `host-group remove` is refused while the host group maps an account.**
- **Found during:** Task 2.
- **Issue:** Once the host group is gone, `host principals` answers ErrUnknownHostGroup, so no header-only file can replace an account's old file. Stale access stays (T-02-100). The plan gave `host-group remove` no refusal rule.
- **Fix:** refuse, naming the accounts, with advice to unmap them, re-render and install first. This matches `role remove` being refused while mapped.
- **Tests:** `remove_host_group_with_accounts_refused`, plus the positive remove in `unmap_removes_account`.
- **Commit:** 06a51e2.

**4. [Rule 3 - Blocking] Exported name validators in internal/directory/directory.go.** That file is not in files_modified. `ValidGroupName`, `ValidRoleName` and `ValidAccountName` expose the existing grammars, so the CLI refuses a bad name with its own message before it opens a session. The renderer uses the same functions. No grammar changed.

**5. [Rule 3 - Blocking] e2e: the admin rate limit.** The e2e makes 22 admin requests in about a second; the server's per-client admin burst is 20 (`defaultAdminBurst`). The unmap's install POST was refused with 429. The refusal happens before any handler runs, so nothing was installed. The test's `kr` helper re-runs a command whose stderr carries the CLI's rate-limit text, after 2 s, up to 5 times, and logs each retry. The rerun builds a fresh base, so it cannot double-install. In the passing run it retried twice: the unmap and the following `host principals`. The server's limits are unchanged.

**6. [Rule 3 - Blocking] e2e: an assertion for the server env's origin.** `withAssertion` (login_signer_test.go) asserts for `https://keyroster.localhost` without a port, but `startServerEnv`'s policy origin carries the port. roles_test.go builds the request itself and asserts with `alice.Assert(serverRPID, env.URL, req.Digest())`. Its principals are those of `Authorize("alice", nil)` on the signer's installed directory, and the test asserts they are exactly `[role:ops]`.

**7. [Rule 3 - Blocking] Test helper `newDirEnvPolicy` in cmd/keyroster/dirpipe_test.go.** That file is not in files_modified. `role_update_clears_extensions` needs a role extension that the user CA profile allows. `root genesis-policy` has no flag for allowed extensions, so the helper edits the genesis policy before the root signs it. `newDirEnv` calls it with nil, so its behaviour is unchanged.

### Interpretations (choices the plan left open; listed for the owner's veto below)

**8. Additional refusals and tests beyond the plan's list:**
- duplicate role, group or host group;
- a grant that is already held, or a revoke of something not granted;
- a no-op `role update` (usage error, exit 2);
- unmap of an unmapped account;
- a duplicate `--principal`;
- an add-member of an unknown user;
- `role add --user` naming an unknown user;
- `TestHostCAKey`, run with no admin key in the agent;
- `TestRenderMatchesAuthorize` (T-02-53).

### Environment overrides (orchestrator)

**9. Delivery:**
- Auto-merge is not enabled (the plan's publish step says to; the orchestrator enables it after its review).
- One push, after this SUMMARY's commit. The PR number and the check results are in the merge-gate checkpoint, not here.
- ROADMAP is not marked complete, and `roadmap.update-plan-progress` was not run.
- `requirements-completed: [AUTHZ-01]` and `requirements.mark-complete AUTHZ-01`, as the plan's `<output>` says. 02-11 is the last plan that declares AUTHZ-01: 02-01 and 02-04 are merged.

**10. WSL resolver.** WSL did not resolve `keyroster.localhost` this session, as for 02-07 and 02-10. The e2e ran under a scratch wrapper, which is not committed: a private mount namespace with a copied `/etc/hosts` holding the name, then a nested user namespace mapped back to the caller's uid. CI resolves the name natively.

**Total deviations:** 10. That is:
- 1 deferred-row statement;
- 2 Rule 2 security additions;
- 4 Rule 3 blockers;
- 1 interpretation;
- 2 environment items.

**Impact on plan:** no new module, no capslock change, and no server file touched. The signer-side change is limited to two things: the renderer, and three exported grammar checks in internal/directory, which is in the signer's graph. The capslock pair count is unchanged.

## Open choices for the owner's veto

1. **Name checks in the renderer** (deviation 2). An invalid account or host group name is an error, never a header-only file.
2. **`host-group remove` refused while the group maps any account** (deviation 3). The alternative was to allow it and document "unmap first".
3. **`role grant` and `role revoke` take several `--user` and `--group` flags in one version**, not exactly one. A grant already held, or a revoke of something not held, refuses the whole command.
4. **`--max-ttl`** is rounded to the nearest second (`time.Duration.Round`), then must be at least 1m. The CLI checks it before the session opens. The user CA cap is left to `CheckPolicy` in the pipeline, whose error names the role and the cap.
5. **`host ca-key` needs no admin key.** It uses the saved config, `checkInviteConfig` and `Trust`, and prints only the **active** user CA entry. During a CA rotation a `next` key is not printed, so hosts would need a second `ca-key` run after the rotation (Phase 4/5 territory).
6. **`role update` with no flag** is a usage error (exit 2), not a pipeline "nothing changed" refusal.
7. **The CLI does not enforce `u:` for personal roles, or `role:` for an explicit `--principal`.** Any principal that `cert.ValidatePrincipals` accepts is allowed, as the signer allows. The convention is a default and a documented form.
8. **The e2e retry on the admin rate limit** (deviation 5). The alternative is a server flag for test limits, which would be a server change outside this plan.
9. **`host principals` and `host ca-key` print exactly the file or line on stdout.** The custody banner and errors go to stderr, so `> file` captures only the file (`software_custody_banner_on_stderr`).

## Not exercised (UNVERIFIED)

- **The host side on a real host:**
  - the copy into `/etc/ssh` and the `sshd -t` and reload steps of host-setup.md (steps 1-4, UNVERIFIED until 02-14);
  - re-rendering after a change on a real host (step 5, CI only).
- **Windows host setup** (Phase 5).
- **The interactive `Sign directory version N? [y/N]` prompt for these commands.** The tests and the e2e use `--yes`. The prompt is the shared `confirmSign`, which 02-09's `TestEditConfirm` covers.
- **`--out` and quorum-above-1 proposals for these commands.** They share `editDirectory`'s proposal path, tested in 02-09. No 02-11 test writes a role proposal.
- **`host principals` and `host ca-key` against a real server outside the e2e** (02-14).
- **CI-only:** govulncheck, the e2e 9.5p1 lane, the rest of the e2e suite, and the macOS and Windows lanes. They are reported in the checkpoint.

## Relation to the phase-4 todos

Not fixed here, and not made worse.

- Every change goes through 02-09's `editDirectory`: same verified base, same directory format and namespace, same install wording ("The server reports directory version N installed"), no new route.
- `host principals` reads through `fetchVerifiedDirectory`, so it renders what the admins signed and the server serves. That the signer installed it is still the server's word: install receipts are a Phase 4 todo.
- The deployment-binding, recovery-after-admin-change, witnessed-checkpoint and connection-cap todos are untouched.

## Known Stubs

None. Every command is wired to the directory pipeline or the verified trust bundle.

## Threat Flags

None beyond the plan's threat model. No new endpoint. `host ca-key` reads the existing `/api/v1/trust`, and the other commands use 02-09's admin directory routes.

- T-02-52: principals are checked in the CLI, by Validate and by the signer.
- T-02-53: one package renders and authorizes.
- T-02-55: every change is a diffed, admin-signed version.
- T-02-100: the header-only file, `map` needing at least one role, and deviation 3.

## User Setup Required

None for this plan. Host setup follows docs/runbooks/host-setup.md.

## Next Phase Readiness

- **02-12:** `keyroster login` requests the principals that `Authorize` computes. The rendered file lists the same principals for a mapped account (`TestRenderMatchesAuthorize`).
- **02-14:** runs host-setup.md steps 1-4 on the homelab host and lifts their UNVERIFIED labels. Step 5 stays CI only.
- **Phase 3 agent:** calls `directory.RenderPrincipalsFile` for each account it manages and writes the header-only file for an unmapped account.
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in `key-files.created` exists.
- Commits `06a51e2`, `960d89f`, `4e39012` and `ec927e8` are ancestors of HEAD and SSH-signed.
- The Task 2 and Task 3 acceptance greps and named cases were re-run and pass. The runbook has the four required strings, steps 1-4 carry "UNVERIFIED until 02-14", and step 5 carries the CI-only label.
- No private network detail in any file this plan changed (grep for 100.x, 10.x, 192.168.x, tailnet and host names: none).

## Pre-merge review fixes

**Owner decision, 2026-10-22 (Daniel, via the orchestrator):** the nine open choices under "Open choices for the owner's veto" are approved, verbatim reply "Godkänn (Rekommenderas)". They are owner-approved deviations.

- **Fixed, `6a8ea39`:** `host principals` and `host ca-key` render whatever validly signed (possibly older) directory or trust bundle the server serves, and step 5's staleness check read the same server. host-setup.md steps 1, 3 and 5 now say the version is the server's word. Before a rendered file is installed after a revocation or a CA change, they send the admin to the signer's log (enroll-user.md "Confirm on the signer host"): `directory installs N` must equal the header's version, and `trust bundle vN` must equal the `(bundle vN)` comment. Test: `TestHostSetupSignerCheck`, which failed with 9 errors before the fix and passes after it. No code change: the CLI high-water mark (or a stderr note) stays the Phase 4 todo, as enroll-user.md's residual risk says.
- **Fixed, `d29b387`:** the runbook said to append `TrustedUserCAKeys` and `AuthorizedPrincipalsFile` to sshd_config. A new section, "Where the sshd settings go", covers four things:
  - sshd uses the first value it reads, and lines after a `Match` line apply only to that block;
  - remove other values;
  - use a drop-in that is read first, or put the lines above the first `Match`;
  - step 4 checks the effective values with `sudo sshd -T -C user=<account>,host=<host>,addr=<address>`, and step 5 repeats that check.

  Test: `TestHostSetupEffectiveSshdConfig`, which failed before the fix and passes after it. The new checks run only on a real host and are labelled UNVERIFIED until 02-14. 02-14 Task 1 already uses a drop-in and `sshd -T -C`. The runbook now matches it, and the plan was not edited.
- **Skipped:** none.

Checks:
- `gofmt -l` is empty.
- `go vet ./...` passes for windows, linux and darwin.
- `go test -count=1 ./cmd/keyroster` passes.
- `go test ./...` passes all 21 packages that have tests. test/e2e is behind the `e2e` build tag and did not run here.
- `-race` was not run: there is no cgo on this Windows host.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-22 (before the merge gate)*
