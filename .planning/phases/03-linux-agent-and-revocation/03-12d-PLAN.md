---
phase: 03-linux-agent-and-revocation
plan: 12d
type: execute
wave: 35
depends_on: ["03-12c"]
files_modified:
  - cmd/keyroster/knownhosts.go
  - cmd/keyroster/knownhosts_test.go
  - cmd/keyroster/login.go
  - cmd/keyroster/login_test.go
  - cmd/keyroster/machinerenew.go
  - cmd/keyroster/machinerenew_test.go
  - cmd/keyroster/host.go
  - cmd/keyroster/host_test.go
  - cmd/keyroster/init.go
  - cmd/keyroster/init_test.go
  - cmd/keyroster/hoststatus.go
  - cmd/keyroster/hoststatus_test.go
  - docs/runbooks/enroll-user.md
  - .planning/phases/03-linux-agent-and-revocation/03-12d-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [KEY-08]

estimate:
  tokens: 108000
  raw_tokens: 108000
  tasks: 3
  confidence: low

must_haves:
  truths:
    - "Early plan: scope, owner decisions and tests are fixed here; the tasks are planned out in full, and every path and line anchor reconciled against main, after 03-12c merges. Until then this file is a specification, not an executable plan"
    - "Clients follow the same trust rule as agents. The managed known_hosts block lists the host CAs that are trusted at the client's clock (`TrustedCAs(b, host, now)`, the slot reserved at cmd/keyroster/knownhosts.go:173-177), and every keyroster command that has verified a bundle narrows that block, even when its KRL fetch fails, and never adds a line"
    - "`keyroster login` accepts a certificate signed by any `IssuingCAs(bundle, user)` key (active or next), so a login whose bundle predates a switch accepts the new active key; `machine renew` keeps the issuing set for its answers and uses TrustedCAs for `--if-due`"
    - "`keyroster host status` shows, per bundle, how many hosts have the user CA keys of that bundle live, decided by the hash of the host's reported user_ca_keys, not by the bundle version, so a host that holds a `next` line back is not counted"
  artifacts:
    - path: "cmd/keyroster/hoststatus.go"
      provides: "the live count, the agent-version column and the bundle_behind column"
    - path: "cmd/keyroster/knownhosts.go"
      provides: "hostTrustCAs on TrustedCAs and the narrowing-only path"
  key_links:
    - from: "cmd/keyroster/knownhosts.go"
      to: "internal/trust/castate.go"
      via: "hostTrustCAs(b, now) is TrustedCAs(b, host, now), the only reader of CA state in the CLI besides login and renew"
      pattern: "TrustedCAs"
---

<objective>
The CLI readers of D-14 (KEY-08): a client's known_hosts, a login, a machine renewal and the admin's convergence view all use the same CA trust rule as the agents, so a rotation does not fail a login or a connection and the admin can see when it is safe to switch.

Purpose: the switch (03-12e) turns on a path every reader handles. This plan is the CLI half of the readers. Still no `draining` entry can exist, so nothing changes in production beyond narrowing (which only removes lines), accepting a certificate from the issuing set, and showing more in `host status`.

Output: known_hosts narrowing and the host-CA lines on the trust rule; login and machine renew on the issuing set; `host ca-key` and `init` showing every trusted user CA with its state; `host status` live count, agent-version and `bundle_behind` columns; the enroll-user runbook.
</objective>

## Before execution (read this first)

This is an early plan, written with 03-12 and its siblings against kr-main at d15f044 and published in 03-12's PR. It is planned out in full by `/gsd-plan-phase`, and reconciled against main, after 03-12c merges: every path, line anchor, count, test name and threat ID is re-read there. The scope, owner decisions and the test and mutant lists below are fixed; the tasks, commands and RED routes are not. Do not execute this file as it stands.

At the reconcile, check in particular: the anchors (hostTrustCAs at cmd/keyroster/knownhosts.go:173-193 with its comment naming this change, refreshHostTrust at :1024-1035 and the KRL-failure return at :1028-1032, the version floor at :484-498, activeUserCA at login.go:195-202 and checkLoginCert at :547-565, machineCAKeys at machinerenew.go:316-345, the discarded bundle at hoststatus.go:121, host ca-key at host.go:335-345, the init CA loop at init.go:231-236); and **whether one wrapper around serverclient.Trust can carry the narrowing hook for every caller** (login.go:183, knownhosts.go:1066, host.go:331, hoststatus.go:121, machinerenew.go and revoke.go): that is assumed, not checked, and if it is a new file the file count goes up by one.

## Scope

**In.**
- **known_hosts** (cmd/keyroster/knownhosts.go): `hostTrustCAs(b, now)` is `trust.TrustedCAs(b, host, now)`. **A narrowing-only path:** whenever a keyroster command has verified a bundle (serverclient.Trust with the pin) and the managed known_hosts file exists, it removes the `@cert-authority` lines whose key is not trusted at the client's clock in that bundle. It does so before the KRL fetch and whatever its result, unlike today's early return (:1028-1032), it never adds a line and never moves a floor, and it narrows only with a bundle whose version is at least host-trust.json's `bundle_version` (the T-03-347 floor), so an older served bundle removes nothing. One wrapper around serverclient.Trust in cmd/keyroster carries the hook so that every command that verifies a bundle narrows.
- **login:** checkLoginCert accepts a certificate signed by any key of `trust.IssuingCAs(bundle, user)`.
- **machine renew:** its answers keep the issuing set; `--if-due` checks the cached certificate against `TrustedCAs(b, machine, now)`, so a cached certificate of a draining CA is kept until it is due.
- **host ca-key:** prints every user CA in `TrustedCAs(b, user, now)` with its state, generation and trusted_until (hand-managed hosts must add `next` before ceremony 2). **init:** prints trusted_until next to a draining CA and `drained (ended <t>)` when past. A draining entry past its trusted_until is labelled `drained (ended <t>)` wherever entries are listed (presentation only).
- **host status:** "user CA keys of bundle vN live on X/M hosts": a host counts when its heartbeat's `user_ca_keys` SHA-256 equals the SHA-256 of `trust.UserCAKeysFile(bundle vN, now)`, no swap is pending and the host is not stale; this needs the bundle that hoststatus.go:121 discards today. An agent-version column (each heartbeat carries `agent_version`), a `bundle_behind` column (the CLI decodes the hosts-status answer leniently, so an older CLI only lacks the column), and each draining key with its end date from the bundle. Hosts outside the agent (Phase 2, hand-managed) are listed by the runbook's `host ca-key` check; convergence is still the server's word.
- **enroll-user.md:** the known_hosts refresh paragraph (:559-561) and the narrowing's residual: a client that never runs keyroster, or runs no command that verifies a bundle, or cannot reach the server, keeps the drained line; automation that only runs `ssh` never narrows; the client's clock governs.

**Out.** Narrowing without a verified bundle (offline narrowing would need per-CA deadlines in host-trust.json: not chosen), the switch, the agents (03-12c), the drain binding (03-12e).

## Owner decisions that bind this plan (Daniel, 2026-11-13 and 2026-11-14)

- Client known_hosts lines are narrowed on every keyroster run that verified a bundle, even when the KRL fetch fails; the residual is documented. A client narrows only with a verified bundle in hand (no offline narrowing, no format 2 of host-trust.json).
- `login` and `machine renew` keep the issuing set (active or next) for fresh answers: the proposal to accept only the active key, and a bounded refetch for a login that races a switch, were recorded and not adopted.
- Host-CA rotation has a runbook gate (03-12e): ceremony 2 for the host role waits for clients to refresh; a client that never refreshes cannot be rotated safely.
- Hardware is optional; every test uses software keys.

## Tests (fixed here)

- **TestKnownHosts** (existing): `next_and_draining_host_ca` (present at trusted_until minus 1 s, absent at trusted_until), `known_hosts_narrows_when_krl_fetch_fails`, `narrows_on_any_command_with_verified_bundle`, `narrowing_never_adds`, `narrowing_skipped_for_older_served_bundle`.
- **TestCheckLoginCertCAs** (new): `cert_by_next_user_ca_accepted`, `cert_by_retired_user_ca_refused`, `cert_by_draining_user_ca_refused`.
- **machine renew:** TestMachineRenewIfDue/`if_due_draining_cached_kept` and TestMachineRenewChecksAnswer/`answer_by_draining_refused`.
- **TestHostStatus** (existing): `held_addition_not_live`, `live_count_by_trust_file_hash`, `agent_version_column`, `bundle_behind_column`; output tests for host ca-key and init with the draining and drained labels.

## Mutants (M149 to M154)

- M149 known_hosts keeps a draining CA at trusted_until (`next_and_draining_host_ca`); M150 narrowing is skipped when the KRL fetch fails (`known_hosts_narrows_when_krl_fetch_fails`); M151 narrowing uses an older served bundle (`narrowing_skipped_for_older_served_bundle`); M152 login accepts a retired or draining CA (`cert_by_retired_user_ca_refused`, `cert_by_draining_user_ca_refused`); M153 machine renew `--if-due` ignores time (`if_due_draining_cached_kept`); M154 host status counts a held host (`held_addition_not_live`).

## Inherited duties (from 03-14b, 03-14c, 03-14d), which this plan carries

- Shared trust helpers are portable (internal/trust, from 03-12c), since cmd/keyroster builds on Windows and macOS; a helper used only on linux carries a build tag.
- Every runbook audit verify command passes `--installation-id` or `--any-installation`; the pinned CLI config means no step tells users to re-run `keyroster init`.
- Mutants continue from M149; threat IDs are the set's; the Q-09-3 test-time form (cmd/keyroster ran about 223 to 270 s under race at d15f044); the private-term and label scan; the stop guard and ROADMAP gate.

## Why it ships safely alone

Still no draining entry can exist. login accepts next-signed certificates, which only exist after 03-12b. The known_hosts narrowing only removes lines and respects the version floor. `host status` only reads.

## Size

20 files by the set's counting convention (12 code and test, 1 doc, 7 planning); one more if the Trust wrapper is a new file. About 108k estimated tokens raw (low confidence); the calibration has run 2x to 5x.

## Open owner questions

None open.

<tasks>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 1: Plan 03-12d out in full and reconcile it against main. Do not execute this file</name>
  <read_first>
    - The "Before execution" section above, and 03-12c-SUMMARY.md (the predecessor's SUMMARY, on main once it has merged)
  </read_first>
  <action>This is an early plan: a specification published in 03-12's PR so that the wave shift happens once. It carries no executable tasks. After 03-12c has merged, run the planner for it (`/gsd-plan-phase` on this plan's phase and number), which re-reads every path, line anchor, file count, test name and threat ID against main, writes the tasks with their verify commands and RED routes, and replaces this file. Do not run `/gsd-execute-phase` on this file as it stands.</action>
  <instructions>
    1. Confirm that 03-12c's SUMMARY is on origin/main.
    2. Plan this plan out in full, reconciled against main, and have it checked.
    3. Reply "planned" when the executable plan has replaced this file.
  </instructions>
  <verify>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-12c-SUMMARY.md</automated>
    <fails_when>non-zero exit: the predecessor has not merged, so this plan must not be planned out or executed yet</fails_when>
  </verify>
  <acceptance_criteria>
    - The executable plan has replaced this file, its tasks name every verify command, and its reconcile ledger records what differed from this specification at its base commit.
  </acceptance_criteria>
  <done>03-12d is planned out in full against main.</done>
  <resume-signal>Type "planned" after the executable plan has replaced this file</resume-signal>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| server → CLI | the bundle, KRL and host status answers the CLI verifies and displays |
| the user's machine → ssh | the managed known_hosts block decides which host CA a client believes |

## STRIDE Threat Register

Each ID below is defined only in this plan; the other IDs of the set are defined in the plan named in 03-12's register.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-76 | Denial of service | a switch before hosts trust the new CA | high | mitigate | ceremony 1 first; ceremony 2 gated on "user CA keys of bundle vN live on M/M hosts" decided by the trust-file hash, not the version; the widening wait and the probe proof stated correctly in the runbook; the end-to-end test with zero failures is 03-12e's |
| T-03-416 | Denial of service | a probe-held host counted as converged | high | mitigate | the live count reads the reported user_ca_keys hash (`held_addition_not_live`) |
| T-03-417 | Denial of service | a host-CA switch before clients refreshed | medium | mitigate | lazy renewal spreads the exposure over the two-thirds point of each host certificate; the client-refresh gate in the runbook; narrowing on every run; TestHostCARotation (03-12f) documents the failure |
| T-03-422 | Denial of service | a login or machine renewal spanning the switch is refused | low | mitigate | IssuingCAs in login; TrustedCAs for `--if-due` |
| T-03-430 | Elevation of privilege | a drained host CA stays in a client's known_hosts (a MITM after a host-CA compromise) | medium | mitigate (partial) | narrowing on every keyroster run that verified a bundle, even when the KRL fetch fails. Residual: dormant, offline and ssh-only clients; the client's clock governs |
| T-03-SC | Tampering | dependencies | low | mitigate | no module added |
</threat_model>

<success_criteria>
- A client's known_hosts and a login follow the same trust rule as an agent; the narrowing never adds a line and never narrows with an older bundle.
- `host status` shows when the new user CA keys are live on every host, from the hash of what the host reports.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-12d-SUMMARY.md` when the plan has been planned out and executed. Leave `requirements-completed` empty: KEY-08 completes in 03-13.
</output>
