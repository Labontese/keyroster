---
created: 2026-10-23T12:00:00.000Z
title: The runbooks say that disabling a user does not end certificates already issued
area: docs
severity: minor
resolves_phase: 3
files:
  - docs/runbooks/enroll-user.md
  - docs/runbooks/host-setup.md
---

## Problem

Phase 2 code review, finding F-IN-01 (Info; raised as medium, both skeptics upheld it at low; merged with the same report from area D). Filed after the phase 2 verification (owner decision 2026-10-23).

The runbooks call `keyroster user disable`, role revoke and group member removal a "revocation" (enroll-user.md about L192 and L212-226; host-setup.md about L236). In Phase 2 none of these touches certificates already issued:
- Phase 2 has no KRL or `RevokedKeys`.
- Disable only blocks new issuance.
- `AccountPrincipals` never reads the disabled status.

Example: a laptop is stolen with a fresh certificate (up to the 12 h user CA cap), and the admin runs `user disable`. The certificate keeps logging in to every host that lists its principal until ValidBefore. No runbook says so or gives an immediate cut-off.

## Solution

- In "Disabling a user" and in host-setup.md, state that these actions only stop new certificates, and that issued ones stay valid until ValidBefore.
- Give the immediate cut-off available today: revoke the role or unmap the account, then re-render and install the principals files on every host.
- Point to the Phase 3 KRL work (REVOKE-01..04), which removes the gap.

## Resolution

Resolved in 03-03b (PR from branch `p03/03b-revoke-cli`). enroll-user.md ("Disabling a user") and host-setup.md now say that disabling a user, revoking a role, removing a group member and unmapping an account stop only new certificates, and that issued ones stay valid until ValidBefore. Both name `keyroster revoke user NAME`, which revokes every live certificate of the user, disables the user and revokes again (revoke.md section 4, run in CI e2e by `TestRevokeUserEndToEnd`). A host enforces it once its sshd's `RevokedKeys` holds the KRL: by itself with the agent (03-07), by hand otherwise, which is UNVERIFIED. The calls of these changes a "revocation" are reworded.
