---
created: 2026-10-21T12:00:00.000Z
title: Recover the directory after an admin-set or quorum change
area: auth
severity: blocker
resolves_phase: 4
files:
  - cmd/keyroster/dirpipe.go
  - cmd/keyroster/directory.go
  - internal/signer/directory.go
  - cmd/keyroster-signer
  - docs/runbooks/root-ceremony.md
---

## Problem

Found in the pre-merge review of PR #49 (plan 02-09): one confirmed finding (medium) and two split findings.

A root-signed successor policy may change the admin set or raise `admin_quorum`. `trust.checkSuccessorChain` puts no constraint on either. After such a policy is in force:

- The signer marks the installed directory unauthorized and refuses every login with `directory_not_authorized` until a directory signed by the new admins is installed (02-03 T-02-15).
- The signer accepts that re-signed successor: `TestDirectoryRestart/restart_under_new_admins` (internal/signer/directory_test.go).
- The CLI cannot produce or install it. `fetchVerifiedDirectory` (cmd/keyroster/dirpipe.go) verifies the served base against the admins of the policy in force and refuses with `errUnsignedBase`. Every directory command goes through it: `user approve`, `disable`, `enable` and `list`, and `directory show`, `sign` and `install`. `directory install` refuses even a correctly chained successor signed under the new policy. `editDirectory` also refuses a version that changes nothing, so a pure re-sign is impossible.
- Today only a direct `signerclient.InstallDirectory` call on the signer socket can install it. No shipped command does that; `keyroster-signer` has no install command.
- The refusal also blames the server ("not signed by the policy admins"), which sends an operator hunting for a compromise.

The refusal itself is T-02-42 and intended. Phase 2 tooling cannot reach the state: `root successor-policy` changes only the WebAuthn RP and carries the admins and quorum over (root-ceremony.md). Only a hand-written successor policy reaches it, for example after a lost admin key. Phase 4 AUTHZ-03 reaches it with its first admin or quorum change (ROADMAP Phase 4, success criterion 1).

Owner decision F3 (2026-10-21, "Blocker för fas 4"): no code change in 02-09; this todo.

## Solution

Options to settle in Phase 4 planning:

- **Verify the old directory against the previous policy.** The CLI walks the root-verified bundle chain back to the policy the installed directory was signed under. The signer stores `PolicyVersion` with each directory. It accepts the base only if that policy's admins signed it, and the successor must still meet the new policy's admins and quorum.
- **Use the audit log.** The `directory_install` leaf records the `PolicyVersion` it was installed under. The CLI (or an admin with an export) checks the base against that.
- **A re-sign path.** `keyroster directory resign` (or a flag on `sign` and `install`) shows the whole content to be signed (`Diff(nil, next)`), asks through `confirmSign`, and builds version N+1 with prev = the SHA-256 of the served bytes, waiving the no-op refusal in that mode only. The signer's chain and quorum checks stay as they are.
- **Break-glass.** A `keyroster-signer` local install command, run on the signer host, for a fully signed directory file.

In every option, reword `errUnsignedBase` to name both causes: a policy change, or a server serving bytes the admins did not sign. Then document the step in root-ceremony.md's successor-policy section.
