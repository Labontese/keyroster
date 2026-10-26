---
phase: 03-linux-agent-and-revocation
plan: 04
subsystem: directory
tags: [directory, installation-id, hosts, machines, pop, policy, sshd, signer, audit]

requires:
  - phase: 03-linux-agent-and-revocation
    provides: "03-01: trust.Bundle installation_id (random-128, lenient transition answer), trust.IsInstallationID; 03-03/03-03b: the revoke-request/v2 installation binding pattern (refusal class unauthorized, CLI fills the ID from the root-pinned bundle)"
provides:
  - directory.Directory installation_id, hosts and machines (last three omitempty fields)
  - directory.Host, Machine, HostByName, HostForKey, MachineByName, HostPrincipals, ErrUnknownHost, CheckHostPrincipal
  - directory.CheckInstallation (install rule) and CheckStoredInstallation (lenient D-04 rule)
  - CheckPolicy role classes (user-facing by own grant lists, machine-only, mixed passes both)
  - trust.Policy.PoP, PoPPolicy, CheckPoPSuccessor, ErrPoPHostsRemoved (pop_hosts_removed) in checkSuccessorChain
  - signer refusals directory_installation_missing, directory_installation_mismatch, directory_installation_unknown
  - keyroster host add|remove|list, host principals --host, machine add|remove|list, directory rebind, root successor-policy --pop-hosts --pop-machines
  - test/vectors/directory_hosts_v1.json, test/vectors/policy_pop_v1.json
affects: [03-05, 03-07, 03-09, 03-11, 03-15, 03-16]

actuals:
  tokens: 35500
  tasks: 3
  commits: 3
plan_head_before: f118a05e3e01e7275969c8e25f9ba4ce4fef7183
plan_head_after: 1d78c41036bf7591093761e8e4b422e251face58

tech-stack:
  added: []
  patterns:
    - "A signed document gains a field as the last omitempty field, so earlier vectors keep their bytes and the empty value is refused as non-canonical"
    - "Installation binding: the ID lives in the signed bytes, the CLI copies it from the root-verified bundle, the signer refuses a mismatch as unauthorized, audit verify applies the same rule"
    - "Signed names are accepted only in their one canonical spelling and never rewritten"

key-files:
  created:
    - internal/directory/hosts.go
    - internal/directory/hosts_test.go
    - internal/trust/pop_test.go
    - cmd/keyroster/machine.go
    - cmd/keyroster/host_test.go
    - cmd/keyroster/machine_test.go
    - test/e2e/hosts_test.go
    - test/vectors/directory_hosts_v1.json
    - test/vectors/policy_pop_v1.json
    - docs/runbooks/machine-identities.md
  modified:
    - internal/directory/directory.go
    - internal/directory/verify.go
    - internal/directory/render.go
    - internal/directory/diff.go
    - internal/trust/policy.go
    - internal/trust/verify.go
    - internal/signer/directory.go
    - internal/signer/refusal.go
    - internal/audit/verify.go
    - internal/serverclient/admin.go
    - cmd/keyroster/dirpipe.go
    - cmd/keyroster/host.go
    - cmd/keyroster/hostgroup.go
    - cmd/keyroster/directory.go
    - cmd/keyroster/root.go
    - docs/runbooks/host-setup.md

key-decisions:
  - "03-04: the directory keeps SSHSIG namespace keyroster/directory/v1: installation_id is inside the signed JSON, so no namespace bump is needed (the revoke v1 bytes had no ID field, hence revoke-request/v2)"
  - "03-04: the signer checks the installation after Parse and before the chain and CheckPolicy; the three details are classified unauthorized, next to revoke_installation_*"
  - "03-04: lenient D-04 rule (03-01 answer) for stored directories: an ID-less directory stays authorized under a bundle with an ID, with a start-up warning; a stored directory naming another installation (or one while the bundle has none) is not authorized"
  - "03-04: every CLI directory edit copies the installation ID from the root-verified bundle, so the first edit after the bundle gains an ID binds the directory; directory rebind is the edit that changes nothing else"
  - "03-04: a role is user-facing when its own users or groups list is non-empty; machine-only roles take the machine CA cap; mixed roles pass both caps and both profiles"
  - "03-04: pop.hosts is one-way through trust.CheckPoPSuccessor inside checkSuccessorChain; root successor-policy prints the pop_hosts_removed note on stderr whenever the successor's pop.hosts is true"

patterns-established:
  - "Installation-bound signed documents: ID in the signed bytes, copied by the CLI, refused by the signer as unauthorized, re-checked by audit verify"

requirements-completed: []

coverage:
  - id: D1
    description: "Directory format: installation_id, hosts and machines as the last omitempty fields; directory_v1.json unchanged; empty values refused as non-canonical; host, machine and principal rules"
    verification:
      - kind: unit
        ref: "internal/directory/hosts_test.go#TestDirectoryHostsGoldenVector"
        status: pass
      - kind: unit
        ref: "internal/directory/hosts_test.go#TestHostsValidate"
        status: pass
      - kind: unit
        ref: "internal/directory/hosts_test.go#TestHostPrincipalSpelling"
        status: pass
      - kind: unit
        ref: "internal/directory/directory_test.go#TestDirectoryGoldenVector"
        status: pass
      - kind: other
        ref: "go test -fuzz FuzzParseDirectory -fuzztime 30s ./internal/directory/"
        status: pass
    human_judgment: false
  - id: D2
    description: "CheckPolicy role classes: user-facing by own grant lists (also an empty group), machine-only takes the machine cap, mixed passes both caps and both profiles; machine max TTL within the machine cap"
    requirement: "AUTH-06"
    verification:
      - kind: unit
        ref: "internal/directory/hosts_test.go#TestMachineRoleClasses"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/machine_test.go#TestMachineCommands/machine_only_role_takes_machine_cap"
        status: pass
    human_judgment: false
  - id: D3
    description: "Installation binding (D-04): the signer refuses directory_installation_missing, _mismatch and _unknown; audit verify applies the same rule; the lenient rule keeps a stored ID-less directory authorized; directory rebind installs by the ordinary rules"
    requirement: "AGENT-03"
    verification:
      - kind: unit
        ref: "internal/signer/directory_test.go#TestDirectoryInstallation"
        status: pass
      - kind: unit
        ref: "internal/signer/directory_test.go#TestDirectoryInstallationRebind/rebind_from_idless_accepted"
        status: pass
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyDirectoryInstallation"
        status: pass
      - kind: unit
        ref: "internal/directory/hosts_test.go#TestCheckInstallation"
        status: pass
    human_judgment: false
  - id: D4
    description: "Policy PoP: pop field last and omitempty, both-false and null refused, policy_genesis_v1.json unchanged, policy_pop_v1.json pinned; pop.hosts one-way in VerifySuccessor, BuildSuccessor, install-bundle and audit verify"
    verification:
      - kind: unit
        ref: "internal/trust/pop_test.go#TestPolicyPoP"
        status: pass
      - kind: unit
        ref: "internal/trust/pop_test.go#TestPolicyPoPGoldenVector"
        status: pass
      - kind: unit
        ref: "internal/trust/pop_test.go#TestPoPSuccessor"
        status: pass
      - kind: unit
        ref: "internal/signer/trust_test.go#TestInstallBundlePoP"
        status: pass
      - kind: unit
        ref: "internal/audit/verify_test.go#TestVerifyBundlePoP"
        status: pass
    human_judgment: false
  - id: D5
    description: "CLI: host add/remove/list, host principals --host, machine add/remove/list, directory rebind with its three refusals, host-group remove refused while a host names it, root successor-policy --pop-hosts --pop-machines"
    requirement: "AUTHZ-02"
    verification:
      - kind: unit
        ref: "cmd/keyroster/host_test.go#TestHostCommands"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/host_test.go#TestDirectoryRebind"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/machine_test.go#TestMachineCommands"
        status: pass
      - kind: unit
        ref: "cmd/keyroster/root_test.go#TestRootSuccessorPolicyPoP"
        status: pass
    human_judgment: false
  - id: D6
    description: "End to end: a signer with an installation ID installs CLI-made versions with a host and a machine, host principals --host equals RenderPrincipalsFile, another installation's and an ID-less directory are refused, audit verify passes"
    requirement: "AUTHZ-02"
    verification:
      - kind: e2e
        ref: "test/e2e/hosts_test.go#TestDirectoryHostsEndToEnd (local WSL, OpenSSH 10.5p1, namespace workaround)"
        status: pass
    human_judgment: false
  - id: D7
    description: "Runbooks: host-setup.md (registering a host, binding an existing directory, pop.hosts) and machine-identities.md, each step labelled run in CI or UNVERIFIED (D-20)"
    verification: []
    human_judgment: true
    rationale: "A runbook's clarity and its labels need a human reader; every homelab step is UNVERIFIED until 03-15 or 03-16"

duration: 62min
completed: 2026-10-26
status: complete
---

# Phase 3 Plan 04: Directory Hosts Summary

**Every admin-signed directory now names the installation it was signed for, and the signer and audit verify refuse one signed for another installation. The directory gains host entries (one host group, admin-typed canonical certificate principals, Ed25519/ECDSA host keys) and machine entries (key, roles, max TTL, checked against the machine CA cap). The root-signed policy gains a one-way `pop.hosts` switch and a `pop.machines` switch.**

## Performance

- **Duration:** about 62 min
- **Started:** 2026-10-26T07:45:33Z
- **Completed:** 2026-10-26T08:47Z (before the PR; CI and the merge gate follow)
- **Tasks:** 3 executed; Task 4 is the merge gate
- **Files modified:** 38 (code, tests, vectors, runbooks, todo)

## Owner's D-04 answer, as implemented here

03-01 recorded `random-128` with a **lenient** transition. This plan implements only that rule:
- **Install (strict, signer and audit verify):** while the bundle in force has an installation ID, a directory must carry the same; while it has none, the directory must have none.
- **Stored directory (lenient, signer start and audit verify after a bundle_install):** a directory without an ID stays authorized for logins under a bundle with an ID. The signer logs a warning at start. A stored directory that names another installation, or names one while the bundle has none, is not authorized.
- The strict alternative (`random-128-strict`) is not implemented and not tested.

## Accomplishments

- **Directory format (D-04, D-11, D-15, D-16).**
  - `Directory` gains `installation_id`, `hosts` and `machines`, in that order, after `host_groups`, each omitempty.
  - `test/vectors/directory_v1.json` is byte-identical. `"installation_id":""`, `"hosts":[]` and `"machines":[]` are refused as non-canonical.
  - A host names exactly one existing host group, and has 1 to 8 host keys (Ed25519 or ECDSA P-256/384/521, `trust.FormatKey` form, sorted). It has 1 to 8 principals, sorted. No key and no principal may appear on two hosts.
  - **Canonical host principals (`CheckHostPrincipal`):**
    - An IP literal is accepted only as `netip.ParseAddr(p).String()`, without a zone and not IPv4-mapped.
    - Anything else must be a lowercase RFC 1123 name of at most 253 bytes, without a trailing dot, whose last label is not all digits.
    - `*`, `?`, `,`, whitespace and control bytes are refused.
    - A refusal names the canonical form when one exists, including `192.0.2.01` (canonical `192.0.2.1`), which `netip` refuses.
  - **Machines:** a key of Ed25519, ECDSA or `sk-` type, unique among machines and not a host key. 1 to 16 existing roles. `max_ttl_seconds` at least 60.
  - **Lookups:** `HostByName`, `HostForKey`, `MachineByName`, and `HostPrincipals(d, host, account)`, which calls `RenderPrincipalsFile` for the host's group. There is no second renderer.
  - `Diff` shows `installation_id`, hosts and machines, with keys by type and SHA256 fingerprint.
- **CheckPolicy role classes.** A role is checked against every CA it is used under:
  - A role is user-facing when its own `users` or `groups` list is non-empty, also when the group has no members. It keeps the user CA cap even when machines name it.
  - A machine-only role (no user or group grants it, and a machine names it) takes the machine CA cap.
  - A mixed role must pass both caps and both profiles' extension sets.
  - Each machine's max TTL is at most the machine CA cap.
- **Policy PoP.**
  - `Policy.PoP *PoPPolicy` (`pop`, omitempty, the last field after `webauthn`). When present, at least one of `hosts` and `machines` must be true.
  - `policy_genesis_v1.json` is unchanged, and `policy_pop_v1.json` pins the genesis successor with both switches on.
  - `trust.CheckPoPSuccessor` refuses clearing `pop.hosts` with `ErrPoPHostsRemoved` (`pop_hosts_removed`). It is called from `checkSuccessorChain` when the policy changed, so `VerifySuccessor` (install-bundle, `trust verify --prev`, audit verify) and `BuildSuccessor` (`root sign --prev`) all refuse it.
- **Signer.**
  - `InstallDirectory` refuses `directory_installation_missing`, `directory_installation_mismatch` and `directory_installation_unknown` after Parse. All three are classified unauthorized (`CodeRefused`).
  - `loadDirectory` applies the lenient rule.
- **Audit verify.** `directoryInForce.install` applies the strict rule at each directory_install entry, and `recheck` applies the lenient rule after each bundle_install entry.
- **CLI.**
  - New commands: `keyroster host add|remove|list`, `host principals --host NAME ACCOUNT` and `keyroster machine add|remove|list`.
    - `machine add`: `--max-ttl` defaults to the machine CA cap of the verified policy.
  - `keyroster directory rebind` writes version n+1 with only `installation_id` set. It refuses when the bundle has no ID, when the directory is already bound, and when the directory names another ID (the message names both IDs).
  - `keyroster root successor-policy --pop-hosts --pop-machines` carries the previous pop over and prints `pop: <old> -> <new>`. It prints the one-way note whenever the successor's `pop.hosts` is true, and refuses a no-op.
  - Every directory edit copies the installation ID from the root-verified bundle, and the diff shows it.
  - `host-group remove` refuses while a host names the group.
  - The three new details get their own CLI messages.
- **End to end.** `TestDirectoryHostsEndToEnd`:
  - On a signer whose genesis bundle has an installation ID, the CLI installs versions 1 to 5: role ops, host group lab with deploy mapped to ops, host web1 with a generated host key and two principals, and machine ci at 24 h.
  - The signer holds version 5 bound to the installation.
  - `host principals --host web1 deploy` equals `RenderPrincipalsFile(lab, deploy)` byte for byte.
  - A version signed by the same admin for another installation is refused `directory_installation_mismatch`, and one without an ID is refused `directory_installation_missing`. The signer still holds version 5.
  - `audit verify` passes with `directory installs 5`.
- **Runbooks.**
  - `host-setup.md` gains "Registering a host in the directory" (host add, list, principals --host, the `pop.hosts` ceremony step and its one-way rule) and "Binding an existing directory to the installation" (directory rebind, its three refusals, logins until it installs).
  - The new `machine-identities.md` covers machine add, list, remove, the TTL rule and pop.machines.
- **Todo.** `2026-10-16-bind-admin-signed-directories-to-a-deployment.md` is resolved and moved to `todos/completed/`.

## Task Commits

1. **Task 1 (tracer): installation-bound directory with hosts and machines.** `3a50064` (feat)
2. **Task 2 (tdd): validation table, golden vectors and fuzz seeds.** `4682013` (test)
3. **Task 3: runbooks and todo closure.** `1d78c41` (docs)

**Plan metadata:** the `docs(03-04): complete directory-hosts plan` commit that carries this file.

## Refusal and format reference

| Detail | Where | Class |
|---|---|---|
| `directory_installation_missing` | signer InstallDirectory: directory has no ID, bundle has one | unauthorized (403 through keyroster-server) |
| `directory_installation_mismatch` | directory names another installation | unauthorized |
| `directory_installation_unknown` | directory names one, bundle has none | unauthorized |
| `pop_hosts_removed` (`trust.ErrPoPHostsRemoved`) | checkSuccessorChain: successor policy clears pop.hosts | refused by root sign --prev, trust verify --prev, install-bundle, audit verify, root successor-policy |

- **Golden vectors.**
  - `test/vectors/directory_hosts_v1.json` (sha256 `15ff5d5638496cefda98dad7d70bc6e4ee77bea04078db3be9375386aeeada3a`): installation `000102030405060708090a0b0c0d0e0f`, host web1 in lab with the Ed25519 key of seed 0x40 and principals web1 and web1.lab.example, and machine ci with the key of seed 0x60, role ops and 3600 s.
  - `test/vectors/policy_pop_v1.json`: version 2, prev is the SHA-256 of `policy_genesis_v1.json`, and `pop {hosts: true, machines: true}`.
- **Capslock pairs added:** none. `scripts/capslock-check.sh` reports 91 pairs against a baseline of 91. `net/netip` in internal/directory adds no capability. `scripts/dep-firewall.sh` passes, and `go.mod` and `go.sum` are unchanged.

## What ran and what did not

**Ran (2026-10-26):**
- **Windows:** `go test` of internal/directory, internal/trust, internal/audit and cmd/keyroster. `go vet` for windows and darwin.
- **Fuzzing:** `FuzzParseDirectory` for 30 s with the hosts seeds, PASS.
- **Linux full gate (WSL):**
  - `go test -race -count=1 ./...` passed.
  - `go vet ./...` and `go vet -tags e2e ./test/e2e/` passed, and `gofmt -l .` was empty.
  - golangci-lint reported 0 issues.
  - capslock found no new pairs, and dep-firewall passed.
- **Task 2 verify lines:** every PASS line the plan names is present, and under `-race` with no DATA RACE. `test/vectors` is clean after the golden tests.
- **e2e (WSL, OpenSSH 10.5p1, namespace workaround):**
  - `TestDirectoryHostsEndToEnd` PASS, run alone and in two full-suite runs.
  - In the second full run every test passed except `TestSSHDRejects/pty_allowed`, which fails only inside the local namespace (known since 03-01, deferred-items.md).
  - In the first full run `TestLoginEndToEnd` also failed in two subtests (1.3 s, details lost with the log). Run alone right after, and in the second full run, it passed. It is treated as a flake under load, not as a regression, and CI's e2e lanes are the authoritative evidence.
- **Mutants**, each killed by the named test and restored:
  - M1: the canonical-spelling check removed (TestHostPrincipalSpelling).
  - M2: user-facing that ignores group grants (TestMachineRoleClasses: mixed_role_keeps_user_cap, role_granted_to_empty_group_is_user_facing).
  - M3: no machine cap (TestHostsValidate/machine_ttl_above_machine_cap).
  - M4: a host key allowed on two hosts (TestHostsValidate/host_key_on_two_hosts).
  - M5: no CheckPoPSuccessor in checkSuccessorChain (TestPoPSuccessor, TestVerifyBundlePoP).
  - M6: audit install without the installation check (TestVerifyDirectoryInstallation, three refusal cases).
  - M7: audit recheck strict (rebind_leaf_accepted).
  - M8: the CLI does not copy the ID (TestHostCommands, TestDirectoryRebind).
  - M9: the signer install without the installation check (TestDirectoryInstallation).
  - M10: the signer load strict (rebind_from_idless_accepted).
- **Survived (run, not killed):**
  - M11, the `Is4In6` branch removed. `::ffff:192.0.2.1` is still refused, by the general canonical-form branch, and the message names the same canonical form `192.0.2.1`.
  - M12, the zone branch removed. `fe80::1%eth0` is still refused the same way, with canonical form `fe80::1`.
  - Both branches only choose the wording ("an IPv4-mapped IPv6 address", "an address with a zone"), and no test asserts that wording. The refusal itself is pinned.

**Not run here (UNVERIFIED):**
- **CI** (both e2e matrix lanes, 9.5p1 and 10.5p1, cli-windows, cli-macos) runs on the PR. Its results go in the handback, not in this file.
- **The e2e_pkcs11 and e2e_tpm build tags.** Not executed.
- **The CLI's own text for the three installation refusals over HTTP.** It is mapped in `installRefusal`, but no test posts such a refusal through a server. The server's generic passthrough of signer reason codes is unchanged.
- **`keyroster trust verify --prev`** with a policy that clears `pop.hosts`. It runs the same `VerifySuccessor`, but no test runs the command with such a policy.
- **Every homelab step** in both runbooks is UNVERIFIED until 03-15 or 03-16.

## Decisions Made

- **Namespace unchanged.** The directory keeps `keyroster/directory/v1`. The installation ID is a field of the signed canonical JSON, so the existing signatures cover it. 03-03 had to move revocation to `revoke-request/v2` because the v1 signing bytes had no ID field.
- **Order of the signer's checks:** quorum signatures, then chain bytes, Parse, installation, chain and CheckPolicy. The installation check needs the parsed document. All three details are classified unauthorized, as the revoke binding is.
- **Every edit binds.** The CLI sets the bundle's ID on every new version, so admins never type it. The first edit after the bundle gains an ID therefore binds the directory too, and `directory rebind` is the edit that changes nothing else.
- **The pop note goes to stderr,** next to the existing `rp_id` one-way warning. stdout keeps the machine-readable change lines.
- **Stored directories with another ID.** `CheckStoredInstallation` lets only an ID-less directory through. It is tested at unit level only (`TestCheckInstallation`): the signer cannot reach that state without a database edit that its own log check already refuses at start.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Hand-built test directories under bundles with an ID**
- **Found during:** Task 1 (signer race run).
- **Issue:** Every e2e genesis bundle and the signer's subject-revocation fixture carry an installation ID, so the strict install rule refused every hand-built directory: 26 signer revoke subtests failed with `directory_installation_missing`.
- **Fix:** Those directories now carry the installation ID of their own bundle: `subjectDirectory` in internal/signer/revoke_test.go, and `aliceDirectory` (one per bootstrapped signer, since each has its own ID) plus the directories in audit_login_test.go and login_signer_test.go.
- **Committed in:** 3a50064

**2. [Rule 3 - Blocking] Files outside the plan's list**
- **Found during:** Task 1
- **Issue:** The planned behaviour needs code the plan does not list.
- **Fix:**
  - internal/directory/diff.go: without the new fields in the diff, `host add` and `directory rebind` die with "the change leaves the directory as it is".
  - internal/serverclient/admin.go: the three refusal constants.
  - cmd/keyroster/dirpipe.go: the verified bundle on `verifiedDirectory`, the ID copy, `checkBaseInstallation` and a `CheckBase` hook for rebind.
  - cmd/keyroster/hostgroup.go: the refusal the plan asks for.
  - cmd/keyroster/dirpipe_test.go: the fixture keeps the root key, so a test can serve a bundle without an ID.
  - cmd/keyroster/role.go: the `role update --max-ttl` help names the machine cap.
- **Committed in:** 3a50064, 4682013

**3. [Plan detail] `root successor-policy` no longer requires `--webauthn-rp-id`**
- **Issue:** The plan adds PoP-only successors.
- **Fix:** One of `--webauthn-rp-id`, `--pop-hosts` and `--pop-machines` is required, and `--webauthn-origin` needs `--webauthn-rp-id`. The `missing_flags` assertion in root_test.go follows the new usage text. The RP warning is printed only when the RP changes.
- **Committed in:** 3a50064

**4. [Plan detail] e2e role TTL**
- **Issue:** The plan's e2e has role ops "granted only to machines, TTL 24 h above a 12 h user cap". A role that no machine names yet is checked against the user cap when `role add` creates it.
- **Fix:** ops is created at 1 h, and machine ci's own 24 h exercises the machine cap. The machine-only role above the user cap (`role update` to 20 h after a machine names it) is covered by `TestMachineCommands/machine_only_role_takes_machine_cap` and `TestHostsValidate/machine_only_role_above_user_cap_accepted`. The e2e also maps `deploy` to ops in lab, so the rendered file is not header-only.

**5. [Plan detail] Extra named cases**
- `TestHostsValidate`: empty_machines_list_noncanonical, installation_id_malformed, host_key_with_comment_refused, host_without_key_refused, host_principal_question_mark, host_principal_whitespace, host_too_many_principals, host_bad_status, host_bad_name, hosts_unsorted, machine_key_on_two_machines, machine_without_role, machine_ttl_below_minimum, ungranted_unnamed_role_keeps_user_cap.
- `TestHostPrincipalSpelling`: ipv6_leading_zero, label_hyphen and long_label refusals, plus three more accepted controls.
- `TestMachineRoleClasses`: mixed_role_within_both_caps_accepted, and the reverse extension case (one the user profile allows and the machine profile does not).
- `TestPoPSuccessor`: pop_machines_true_to_absent_accepted.
- Also: `TestHostLookups`, `TestCheckInstallation`, `TestDiffHostsAndMachines`, `TestInstallBundlePoP/pop_hosts_kept_installs`, and four more `TestRootSuccessorPolicyPoP` cases.

**6. [Plan detail] The todo names the branch, not "PR #N"**
- **Why:** The SUMMARY must be pushed before the PR opens. This follows the 03-02 and 03-03b precedent.
- **Where the number is:** in the handback.

---

**Total deviations:** 6. Of these, 2 are Rule 3 and 4 are plan details.
**Impact on plan:** No scope creep, no new module and no capslock change.

## TDD Gate Compliance

- **Order.** Task 2 is `tdd="true"`, but the tracer (Task 1) had implemented the behaviour first, so every Task 2 test passed on its first run. RED was not faked.
- **Evidence instead.** Ten mutants (M1 to M10 above), each killed by the named test, show that the tests check what they name. Two wording-only mutants (M11, M12) survive; see "What ran".
- **The classifier was not used.** Go's test output is not a format that `gsd-tools check tdd-red-evidence` reads, and `workflow.tdd_mode` is off.
- **Commit order:** `feat(03-04)` 3a50064 (the tracer), then `test(03-04)` 4682013.

## Issues Encountered

- **The WSL namespace workaround needed a change.** `unshare --user --map-current-user --mount` cannot bind-mount /etc/hosts here ("must be superuser"). The e2e ran in `unshare --user --map-root-user --mount` for the mount, then in a nested `unshare --user --map-user=<uid> --map-group=<gid>`, so the tests run as the same uid. The script was not committed.
- **Heredoc backslashes.** The Bash tool halves backslashes in heredocs, which broke two Go string literals once. They were fixed with the Edit tool before any commit, and later edits went through files written with the Write tool.

## Known Stubs

None. A machine entry issues nothing until 03-11, and a host entry is read only by `host principals --host` until 03-07 and 03-09. That is planned scope, and both runbooks say so.

## Threat Flags

None beyond the plan's threat model.

## User Setup Required

None.

## Next Phase Readiness

- **03-05 and 03-07:** the agent reads `Directory.Hosts` (`HostForKey`, `HostPrincipals`) and must refuse a directory without the installation ID (the agent pin of D-04).
- **03-09:** host certificates use `Host.Principals`, already canonical and unique across hosts, and are gated on `Policy.PoP.Hosts`.
- **03-11:** machine renewals read `Directory.Machines` and are gated on `Policy.PoP.Machines`.
- **03-15:** the homelab ceremony adds the installation ID and `--pop-hosts`, then runs `keyroster directory rebind` (host-setup.md).

## Self-Check: PASSED

- **Files:** every created file listed above exists, including both vectors and docs/runbooks/machine-identities.md.
- **Commits:** 3a50064, 4682013 and 1d78c41 are ancestors of HEAD.
- **Acceptance greps:**
  - The three json tags are the last three fields of `type Directory struct`.
  - `git diff origin/main` is empty for directory_v1.json and policy_genesis_v1.json.
  - `directory_installation_mismatch` is in both signer/directory.go and refusal.go.
  - `netip.ParseAddr` appears outside comments in hosts.go.
  - `pop_hosts_removed` is in policy.go, and `CheckPoPSuccessor` is called only in checkSuccessorChain and runRootSuccessorPolicy.
  - `keyroster directory rebind` is in host-setup.md, and `keyroster machine add` in machine-identities.md.
  - The todo is in completed/ and absent from pending/.

## Pre-merge review fixes

Findings of the PR #65 pre-merge review (Claude lenses plus Codex, verified). Each test was shown to fail with the fix disabled and to pass with it restored.

- **MEDIUM, read paths accept another installation's directory** (810be33): `fetchVerifiedDirectory` applies `directory.CheckStoredInstallation`, the signer's rule for an installed directory, so every verified read and edit refuses it; `checkBaseInstallation` is folded in. Test `TestReadCommandsCheckInstallation`. Proof: with the check disabled, all 10 command x case runs fail (`directory show`, `user list`, `host list`, `machine list`, `host principals`, each with a foreign ID and with an ID under a bundle that has none). The ID-less control passes either way.
- **MEDIUM, `directory sign` co-signs a foreign or ID-less proposal** (d8bb572): the strict `directory.CheckInstallation` runs before the agent is asked. Test `TestDirectorySignInstallation`. Proof: with the check disabled, the `other_installation` and `no_installation` subtests fail with exit 0 and a signature. The sign fixtures are now bound to the bundle's ID (`boundTo`).
- **LOW, inet_aton spellings pass as DNS names** (41cf445): `CheckHostPrincipal` refuses a name whose labels are all numbers (decimal, octal, 0x hex). Test `TestHostPrincipalSpelling`, which adds 7 refused cases and 1 accepted case (`0xdead.example`). Proof: with the check disabled, 8 cases fail. The hex spellings are accepted, and the rest are refused without the inet_aton reason.
- **LOW, `machine remove` refused for a machine-only role above the user cap** (7c7ef8c): the refusal stays (no cap loosened). It now names the role and both ways out, and the runbook gains a section on removal and rotation. Test `TestMachineCommands/machine_remove_machine_only_role_above_user_cap`. Proof: with the hint disabled, the test fails on the message. The rotation leg (add the new machine, then remove the old) passed before the fix too.

---
*Phase: 03-linux-agent-and-revocation*
*Completed: 2026-10-26*
