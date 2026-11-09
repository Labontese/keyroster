---
created: 2026-11-08T12:00:00.000Z
title: Host-setup runbook and preflight hand-overs from 03-10c and 03-10d
area: agent
severity: minor
resolves_phase: 3
files:
  - docs/runbooks/host-setup.md
  - internal/agent/apply/preflight.go
  - internal/agent/apply/exclusion.go
---

## Problem

03-10c and 03-10d left five items for 03-16, which owns docs/runbooks/host-setup.md and the preflight. Neither plan could make them: host-setup.md is in 03-16's files_modified, and 03-10d touches no preflight or exclusion code.

1. **`--recover-to-last-good` re-grants removals.** After 03-10d every rollback of an in-flight apply and the start-up recovery keep a landed removal. The one exception is the operator's `keyroster-agent apply --once --recover-to-last-good` (host-setup.md near :1982). It keeps its documented target, RollbackTarget(current, last-good), so it can grant again an access removed since last-good. The newer KRL is kept (owner decision Q1 = A, 2026-11-08). The runbook does not say so.
2. **The rollback contract.** host-setup.md:2309-2311 says a failed self-test rolls the CA keys, principals and drop-in back to the last generation that passed one. Since 03-10d the target is the kept content: last-good intersected with current and the base, with the newest KRL. The start-up recovery keeps it too. A recovery whose marker names a generation that does not read stops with `stuck: pending_state_unknown`, and the way out is `--recover-to-last-good`. `current` can therefore differ from `last-good` at rest in more cases than the runbook names.
3. **The nsswitch.conf sentence.** host-setup.md:1853-1859 says an AllowGroups non-match is certain when the `group:` line lists `files` alone or "when the file is missing". The code treats any read error of nsswitch.conf as files only, not just a missing file (groupsFilesOnly, internal/agent/apply/exclusion.go:122-125).
4. **Preflight's report-only note.** `keyroster-agent check` lists the possible probe-account exclusions (a `user@host` entry, an AllowGroups list that NSS may satisfy) since 03-10c's fix round 1. Preflight lists only the certain ones. A report-only note for the possible ones belongs in preflight too.
5. **systemd userdb.** groupsFilesOnly treats `group: files systemd` as files only. A systemd userdb group-membership record could still give a local account a group that AllowGroups lists, so an AllowGroups non-match the check calls certain could be wrong. That is a false `account_excluded` hold, so the cost is liveness only and never fail-open. Not measured.

## Solution

In 03-16:
- add the warning sentence for `--recover-to-last-good` (item 1);
- rewrite the rollback contract to cover the kept state, the keeping start-up recovery and `pending_state_unknown` (item 2);
- make the nsswitch sentence say "missing or unreadable" (item 3);
- add the report-only note to preflight, with a test (item 4);
- measure systemd userdb on a distro that ships it, or keep it listed as UNVERIFIED (item 5).

Sources: 03-10d-PLAN.md ('Not done here', 'Reconcile (step 0) ledger' items 5 and 6, D6, D8) and 03-10c-SUMMARY.md.
