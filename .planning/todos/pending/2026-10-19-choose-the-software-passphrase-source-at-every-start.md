---
created: 2026-10-19T08:00:00.000Z
title: Choose the software passphrase source at every start
area: auth
severity: minor
resolves_phase: 6
files:
  - internal/keystore/software/software.go
  - cmd/keyroster-signer/cainit.go
  - internal/signerdb/trust.go
  - docs/security/custody.md
---

## Problem

The software keystore backend (plan 02-05, KEY-06) stores `--backend-opt passphrase-file=...` in the signer's insert-only `backend_config` row at `ca-init`. Every later `serve` and `install-bundle` then reads the passphrase from that file. Two consequences:
- A signer set up with a plaintext passphrase file can never move to a sealed systemd credential (`LoadCredentialEncrypted=`, read from `$CREDENTIALS_DIRECTORY/keyroster-software-passphrase`), because the stored option always wins.
- An empty override (`passphrase-file=`) is refused.

docs/security/custody.md already says that the stored passphrase-file is permanent for that state directory. Found by the pre-merge review of PR #40 (reviewers split, so it was a design question). The owner deferred it to Phase 6 (hardening and operations) on 2026-10-19.

Related owner decision of the same day: symlinks to the passphrase file stay allowed (no O_NOFOLLOW), because secret managers and systemd credentials use them. The regular-file and mode checks apply to the target.

## Solution

Options considered in the review:
- **(a)** Prefer the systemd credential when it exists and log the source used. This allows migration, but the source can switch silently when a credential appears or disappears.
- **(b)** Let `passphrase-file=` mean "unset". This is explicit, but because the row is insert-only, every `serve` and `install-bundle` would have to pass the override forever, and forgetting it falls back to the plaintext file.
- **(c)** Stop storing passphrase-file at ca-init and require it, or the credential, on every `serve` and `install-bundle`. There is no hidden state, but the option goes on every command and in the unit file.

Suggested: **(c)**. Decide in Phase 6 together with backup and restore (OPS-01), and update custody.md and the server and signer runbooks.
