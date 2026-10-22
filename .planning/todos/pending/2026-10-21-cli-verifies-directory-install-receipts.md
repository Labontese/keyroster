---
created: 2026-10-21T12:00:00.000Z
title: The CLI verifies signer-signed receipts for directory installs
area: auth
severity: blocker
resolves_phase: 4
files:
  - cmd/keyroster/dirpipe.go
  - cmd/keyroster/directory.go
  - cmd/keyroster/user.go
  - internal/serverclient/client.go
  - internal/wire/directory.go
  - internal/signer/directory.go
  - internal/tlog/checkpoint.go
---

## Problem

Found in the pre-merge review of PR #49 (plan 02-09). Both skeptics upheld it.

keyroster-server is in the threat model as compromised, and nothing the CLI accepts about a directory install comes from the signer:

- `reportInstalled` (cmd/keyroster/dirpipe.go) checks the server's install answer only against the version and the SHA-256 of the bytes the CLI posted. A server that never forwarded the request can compute both. The answer's `leaf_index` is not checked. The signer's `InstallDirectoryResponse` (internal/wire/directory.go) is unsigned.
- `fetchVerifiedDirectory` checks the admins' signatures over whatever GET /api/v1/admin/directory serves. Nothing ties those bytes to the signer's state.

So a compromised server can withhold or delay any install, including `keyroster user disable` (a revocation), and answer it as installed. It can then serve the admin-signed but uninstalled version, which `directory show` and `user list` print, while the signer keeps issuing under the older version. It can also serve any older signed version.

The CLI also keeps no high-water mark. `serverclient.Trust` accepts any root-signed bundle and policy, with no minimum version, so a compromised server can serve an older policy. A key that the older policy names but a newer one has removed can then sign a directory that the CLI shows as verified.

What 02-09 did (owner decision F1, 2026-10-21, "Ärligt nu, kvitto i fas 4"):

- The CLI words an install as the server's report ("The server reports directory version N installed (SHA-256 ..., log leaf L)").
- `directory show` and `user list` describe what they print as the admin-signed directory the server serves.
- docs/runbooks/enroll-user.md ("Confirm on the signer host") has the admin export the log on the signer host after every revocation and check that `keyroster audit verify` prints `directory installs N`.
- The 02-09 SUMMARY records the threat rows (accept/document).

Related:
- [2026-10-17 serve refuses to start without a witnessed checkpoint](2026-10-17-serve-refuses-without-witnessed-checkpoint.md): the same checkpoint machinery, from the signer's side.
- ROADMAP Phase 4, success criterion 4: agents and the CLI verify signed checkpoints with consistency proofs.

## Solution

To settle in Phase 4 planning:

- **An install receipt.** The signer returns, in `InstallDirectoryResponse` and alongside `GetDirectory`, a checkpoint signed by the log key (`internal/tlog.SignCheckpoint` exists) and an inclusion proof of the `directory_install` leaf at `leaf_index`. Today there is no path for checkpoints or inclusion proofs from the signer through the server to the CLI.
- **The CLI verifies it.** It opens the checkpoint with `internal/tlog.OpenCheckpoint` against the log key in the root-verified trust bundle (`bundle.Log`, internal/trust/bundle.go). It checks that the leaf at `leaf_index` is the `directory_install` entry for exactly the posted version and SHA-256. Only then does it say "installed". `directory show` and `user list` do the same for the version they print.
- **High-water marks.** The CLI keeps the newest bundle, policy and directory versions and checkpoint it has verified, and refuses anything older. A consistency proof from the kept checkpoint (criterion 4) also detects a log that shrinks or forks.

Trade-offs:

- Where the CLI keeps state: the config file, or a separate state file next to it. More than one admin machine means more than one high-water mark.
- A deliberate restore of an older signer state then trips every admin's high-water mark. That needs a documented, logged override.
