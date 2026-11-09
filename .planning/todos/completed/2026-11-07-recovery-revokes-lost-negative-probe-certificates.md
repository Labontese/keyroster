---
created: 2026-11-07T12:00:00.000Z
title: Recovery revokes lost negative probe certificates automatically
area: auth
severity: minor
resolves_phase: 3
files:
  - cmd/keyroster/recover.go
  - internal/krl/recovery.go
  - internal/signer/recovery.go
  - internal/audit/probeissue.go
---

## Problem

The 03-10 pre-merge review (PR #90) found that `keyroster revoke recover` keeps a lost negative probe certificate after a signer restore. A riding negative probe certificate whose probe_issue leaf no published KRL copy contained is carried as `keep` (Revoke=false): cmd/keyroster/recover.go revokes only user-role certificates and the serials named with `--revoke-lost`, and 03-10 carries a probe certificate like any other machine certificate (`recovery_collects_probe_certificate`). After the recovery the KRL no longer lists that negative, so sshd accepts it until it expires.

The exposure is small. A negative probe certificate is restricted to force-command /bin/false, a loopback source-address and the probe account, so accepting it opens no session. But it breaks the probe's promise that every negative is refused, so the probe self-test (03-10b) would see that negative accepted. The restore path is UNVERIFIED end to end (R9).

Owner decision D-R1 (2026-11-07) leaves the code as it is in 03-10 and records the gap in 03-10-SUMMARY.md next to R9. Owner: 03-10c.

## Solution

Revoke every lost negative probe certificate in recovery, the way every lost user certificate is revoked:
- In cmd/keyroster/recover.go, decide revoke as `user || negative || named`, where negative comes from the saved export's probe_issue entry (its Negative flag), never from the certificate alone.
- Keep audit parity: the signer and audit decide through krl.CheckCarriedLost, so a recovery that carries a lost negative as `keep` is refused by the signer (a new refusal, or the user-kept refusal widened) and fails `audit verify`.
- A lost positive probe certificate stays a machine certificate that may be kept.

Tests:
- a restore that loses a riding negative probe leaf: the recovery revokes it without `--revoke-lost`, and the published KRL lists its serial;
- a recovery request that carries a lost negative probe certificate as `keep` is refused by the signer and fails `audit verify`;
- a lost positive probe certificate can still be kept.

Sources: 03-10-PLAN.md (recovery_collects_probe_certificate, R9), 03-10-SUMMARY.md ("Pre-merge review", D-R1).

## Resolution

Resolved in 03-10d (PR from branch `p03/10d-no-regrant-recovery`; owner decisions Q-R option 1 and D-R1, 2026-11-08), by a rule wider than the Solution above. A probe certificate's polarity is in none of its bytes and the signer and `audit verify` see only the certificate, so the recovery revokes every lost probe certificate, positive and negative, recognised by its key ID (`krl.IsProbeKeyID`: kr3, ca=machine, subject `probe.*`). `krl.CheckCarriedLost` gained the `probe` flag and `ErrLostProbeKept`; the signer refuses a carried probe certificate that is not revoked as `recovery_probe_certificate_kept`, `audit verify` fails on it, and `keyroster revoke recover` revokes every lost probe certificate without `--revoke-lost` and counts them in its summary. A lost machine certificate that is not a probe may still be kept. A revoked lost positive makes its host ask for a new pair, so additions on that host wait up to about two hours (owner answer P4). No wire format changed. That an old log holds no recovery which kept a probe certificate is UNVERIFIED. Tests: TestIsProbeKeyID, TestCheckCarriedLost, TestRecoverRevocations/lost_probe_certificate_*, TestVerifyRecovery/recovery_probe_certificate_*, TestRevokeRecover/lost_*_probe_*.
