---
created: 2026-10-16T20:17:43.724Z
title: Bind admin-signed directories to a deployment
area: auth
severity: blocker
resolves_phase: 4
files:
  - internal/directory/directory.go:27
  - internal/directory/directory.go:61
  - internal/directory/verify.go:17
  - internal/directory/verify.go:43
  - internal/signer/directory.go:89
---

## Problem

The admin-signed directory (users, credentials, roles, host groups) carries nothing that names the keyroster instance it was signed for. The SSHSIG namespace `keyroster/directory/v1` is global. `Directory{Version, Prev, Users, Groups, Roles, HostGroups}` has no policy, bundle or log-origin binding. `VerifySignatures` only checks that the policy admins' quorum signed, and `CheckSuccessor` only checks the chain position.

Consequence: a v1 directory (all-zero prev), signed for one instance, can be installed on a fresh instance whose policy admins overlap. Example: staging and prod share the owner's admin keys. Any allowed socket peer can submit it, and the untrusted web server is an allowed peer. The version chain already blocks replay of v(n+1) unless the target holds byte-identical v(n), so only the genesis install, or instances cloned from the same v1, are exposed.

Found by the post-merge adversarial review of plan 02-01 (PR #33). Reviewers split, so it was not fixed in the review-fix PR #35. On 2026-10-16 the owner deferred it to phase 4 (Insider Resistance) and rated it **blocker**: it must be resolved before phase 4 can complete.

## Solution

Options:
- Add a deployment binding to the signed bytes: the SHA-256 of the genesis trust bundle, or of the root set or policy, or the audit log origin. Refuse install and load on mismatch.
- Or use a per-deployment SSHSIG namespace, e.g. `keyroster/directory/v1/<origin>`.

Trade-offs to settle in phase 4 planning:
- The identifier must be pinned and shown to co-signing admins.
- It adds friction for restore, re-bootstrap and promoting staging to prod.
- A format change needs a directory schema version bump and a migration story for already-signed directories.
