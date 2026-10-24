---
gsd_state_version: "1.0"
current_phase: 03
current_phase_name: linux-agent-and-revocation
status: planning
stopped_at: Phase 3 context gathered
last_updated: "2026-10-24T05:56:52.982Z"
last_activity: 2026-10-23
last_activity_desc: Phase 2 verification passed after the owner's decisions; phase 2 complete; next /gsd-discuss-phase 3
state_head: 17b9de60f41798103898ee7b068568507ee619dd
progress:
  total_phases: 6
  completed_phases: 1
  total_plans: 51
  completed_plans: 35
  percent: 17
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-10-04)

**Core value:** Full visibility: at any moment you know exactly who has access to what, and can revoke it immediately.
**Current focus:** Phase 02 — Passkey Login MVP

## Current Position

Phase: 03 (linux-agent-and-revocation) — READY TO EXECUTE
Plan: Not started
Status: Ready to discuss (next: /gsd-discuss-phase 3)
Last activity: 2026-10-23 — Phase 2 complete: code review (0 critical, 0 warning, 8 info) and verification passed after the owner's decisions (macOS real-browser leg UNVERIFIED by override; timed Windows expiry done). Phase 1: its report says human_needed (real hardware, issue #13), and gsd-tools now routes it as stale

Progress: [██░░░░░░░░] 17%

## Performance Metrics

**Velocity:**
- Total plans completed: 14
- Average duration: -
- Total execution time: 0.0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 2 | 14 | - | - |

**Recent Trend:**
- Last 5 plans: -
- Trend: -

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 01 P01 | 54 min | 4 tasks | 23 files |
| Phase 01 P02 | 31 min | 2 tasks | 32 files |
| Phase 01 P03 | 14 min | 2 tasks | 13 files |
| Phase 01 P16 | 22 min | 3 tasks | 11 files |
| Phase 01 P04 | 23 min | 2 tasks | 7 files |
| Phase 01 P05 | 41 min | 3 tasks | 37 files |
| Phase 01 P06 | 38 min | 3 tasks | 29 files |
| Phase 01 P07 | 35 min | 3 tasks | 28 files |
| Phase 01 P09 | 30 min | 2 tasks | 14 files |
| Phase 01 P08 | 25 min | 2 tasks | 8 files |
| Phase 01 P10 | 25 min | 2 tasks | 5 files |
| Phase 01 P11 | 40 min | 3 tasks | 19 files |
| Phase 01 P12 | 22 min | 2 tasks | 12 files |
| Phase 01 P13 | 47 min | 3 tasks | 26 files |
| Phase 01 P14 | 45 min | 3 tasks | 5 files |
| Phase 01 P15 | 35 min | 3 tasks | 6 files |
| Phase 01 P17 | 35 min | 2 tasks | 6 files |
| Phase 01 P19 | 10 min | 2 tasks | 5 files |
| Phase 01 P18 | 29 min | 3 tasks | 10 files |
| Phase 01 P20 | 60 min | 3 tasks | 6 files |
| Phase 01 P21 | 17 min | 3 tasks | 3 files |
| Phase 02 P01 | 47 min | 2 tasks | 48 files |
| Phase 02 P02 | 40 min | 3 tasks | 14 files |
| Phase 02 P03 | 40 min | 3 tasks | 21 files |
| Phase 02 P04 | 50 min | 2 tasks | 13 files |
| Phase 02 P05 | 45 min | 2 tasks | 22 files |
| Phase 02 P06 | 45 min | 3 tasks | 30 files |
| Phase 02 P07 | 5h40m | 2 tasks | 34 files |
| Phase 02 P08 | about 1h | 2 tasks | 31 files |
| Phase 02 P09 | about 40 min | 2 tasks | 21 files |
| Phase 02 P10 | about 40 min | 2 tasks | 16 files |
| Phase 02 P11 | 25 min | 3 tasks | 11 files |
| Phase 02 P12 | about 65 min | 2 tasks | 28 files |
| Phase 02 P13 | about 40 min plus owner checkpoints | 4 tasks | 8 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [Roadmap]: 6 coarse phases; Phase 2 is the MVP checkpoint (passkey, cert in ssh-agent, real SSH login)
- [Roadmap]: The KRL encoder ships with revocation in Phase 3 (REVOKE-02), not Phase 1 as research suggested; Phase 1 only defines the KRL authority in the trust-bundle format
- [Roadmap]: The who-has-access overview (VIS-04) lands in Phase 5 so it covers plain keys from inventory, not only certificates
- [Roadmap]: Break-glass access (BREAK-01) is in Phase 3, since a dogfooding lockout is the likeliest early incident; break-glass logging (BREAK-02) reuses login reconciliation (VIS-05) in Phase 5
- [Roadmap]: Log witnessing by agents and CLI (VIS-02) is an insider-resistance control in Phase 4
- [Phase 01]: Required status checks keep integration_id 15368 (GitHub Actions); accepted by the API and resolved on PR #1
- [Phase 01]: keyroster-bot (id 337682656) signs with ed25519 key 1218459 held only in the Windows ssh-agent; private key file deleted
- [Phase 01]: scripts/merge-gate.sh rebases with --autostash and an explicit lease so GSD's uncommitted working files cannot block the rebase loop
- [Phase 01]: IssueRequest variable fields use uint16 length prefixes (cryptobyte has no uint32 reader); the 64 KiB frame cap is unchanged
- [Phase 01]: keyroster-signer serve: umask 0077, empty allowlist refused, 32 concurrent connections, single DB connection, SetLastSerial only raises; socket group = first --allow-group
- [Phase 01]: Finding for 01-13: keyroster-signer has no net/http or crypto/tls in its deps but reaches os/exec transitively via modernc.org/libc; depguard only catches direct imports
- [Phase 01]: Admin-only repo settings are applied by the owner via scripts/apply-security-settings.sh; the API accepted all of them including sha_pinning_required=true
- [Phase 01]: Code of Conduct contact is @Labontese via GitHub report-abuse (no private messages on GitHub); flagged for the owner
- [Phase 01]: New third-party actions need a selected-actions allowlist entry (owner) plus a SHA pin; Scorecard publishes only from main, verified in 01-15
- [Phase 01]: IssueRequest.SigningBytes starts with the raw keyroster/issue-request/v1 tag (no uint16 length prefix), per the 01-02 contract; 01-07 signs these bytes
- [Phase 01]: The agent keystore backend skips certificate entries by the -cert-v01@openssh.com key type, since the x/crypto agent client returns entries as agent.Key, never ssh.Certificate
- [Phase 01]: gsd-tools tdd-red-evidence parses only TAP/Surefire; Go RED evidence is recorded in the plan SUMMARY
- [Phase 01]: 01-04: a ruleset that adds required checks is applied by the owner from the PR branch after the checks are green on that PR and before approval (Pitfall 10); Claude never applies rulesets
- [Phase 01]: 01-04: every sshd authentication refusal in e2e runs against its own sshd (OpenSSH >= 9.8 PerSourcePenalties; 9.5p1 lacks the option), and each refusal has a control that succeeds
- [Phase 01]: 01-04: the plan's -L 0:... forwarding case was replaced by -W (direct-tcpip) and -R with ExitOnForwardFailure, because ssh rejects -L 0:... before connecting
- [Phase 01]: 01-05: C2SP type 0x02 (P-256) log checkpoints use key ID = first 4 bytes of SHA-256(SPKI DER) without the key name and an ASN.1 DER signature over SHA-256 of the text (transparency-dev/witness); verified against the published Rekor and Pixel 6 checkpoints
- [Phase 01]: 01-05: A7 confirmed: SQLite documents synchronous=FULL as ACID-durable in WAL mode; TestDurabilityPragmas pins wal + synchronous=2 on the signer DB
- [Phase 01]: 01-05: log origin is keyroster/log/ + 16 hex of SHA-256(log key); the signer refuses to start when stored leaves do not reproduce the latest checkpoint signed by the pinned log key
- [Phase 01]: 01-05: every refusal goes through Signer.refuse (slog, then a refusal leaf within 10/min burst 10, else a count in the next refusal_summary leaf, flushed every minute and on shutdown); one clock_regression leaf per episode
- [Phase 01]: 01-05: duplicate_request stays CodeRefused (pinned by 01-16) although detected after cert.Build; every other post-Build failure returns unavailable and no certificate
- [Phase 01]: 01-06: signed documents are canonical JSON = json.Marshal(struct) + one newline; parsing requires byte equality after a DisallowUnknownFields decode; lists are never null and policy extension lists are sorted
- [Phase 01]: 01-06: internal/sshsig refuses RSA and certificate signers and a non-empty reserved field, emits and accepts sha512 only, and requires the sk user-presence flag explicitly
- [Phase 01]: 01-06: root custody fido is exactly the sk-* key types; a CA, ops or log key equal to a root key is refused at bundle validation (ErrKeyIsRoot)
- [Phase 01]: 01-06: VerifySuccessor needs both the previous and the new root threshold on bundle and policy, version prev+1, prev = SHA-256 of the previous canonical bundle, and issued_at not earlier
- [Phase 01]: 01-06: scripts/fuzz.sh passes -fuzzminimizetime 5s; with Go's 60s default FuzzParseBundle ran 123 execs in a 30s CI budget
- [Phase 01]: 01-06: keyroster root sign reaches ssh-agent via SSH_AUTH_SOCK Unix sockets only; a Windows ceremony needs named-pipe support (go-winio) first
- [Phase 01]: 01-07: IssueRequest gains a signed Extensions field (after CreatedAt, before Evidence) so admin evidence covers requested extensions; critical options have no request field in Phase 1
- [Phase 01]: 01-07: evidence refusals log under the new refusal class unauthorized (15); the detail names the reason (missing_evidence, evidence_not_admin, evidence_wrong_namespace, evidence_digest_mismatch, admin_quorum_not_met, ...)
- [Phase 01]: 01-07: install-bundle and serve read the backend from backend_config and accept --backend-opt overrides, but every key must keep the custody ca-init recorded; InstallBundle takes the backend (the bundle_install checkpoint is signed with the log key)
- [Phase 01]: 01-07: a policy admin key may not be a CA, ops or log key; a successor bundle refuses --pin/--threshold; ca-init requires an empty audit log so ca_init is leaf 0
- [Phase 01]: 01-07: install-bundle requires exactly one active CA entry per role equal to the ca-init key; CA rotation (next/retired entries) changes checkBundleKeys in Phase 3
- [Phase 01]: 01-09: software root file = armored age with one scrypt recipient at age's default work factor (logN 18) wrapping an OpenSSH Ed25519 key; OpenRoot refuses unarmored, non-scrypt and non-Ed25519 files
- [Phase 01]: 01-09: --passphrase-fd is read with syscall.Read on the raw descriptor/handle (no os.NewFile finalizer); passphrases need 20 runes and come only from a TTY or an inherited fd
- [Phase 01]: 01-09: root sign --key refuses a root that roots.pub labels anything but custody=software; every software-root init or sign prints the SOFTWARE ROOT banner, also for --agent-key roots labelled software
- [Phase 01]: 01-09: TestExportedAPI pins rootceremony methods (Type.Method) and fails on any exported result type that could carry a signer or private key
- [Phase 01]: 01-08: audit verify trusts only --pin/--threshold; the log key (checkpoint and --previous) and each role's active CA come only from bundle_install entries verified as genesis (pins) or successor (TUF); Phase 1 refuses a log-key change (log key change unsupported)
- [Phase 01]: 01-08: audit verify requires each issue leaf after the first bundle_install, signed by its role's active CA, a host certificate exactly for the host role, and key ID pol and leaf policy version equal to the policy in force; bundle_install's bundle_version must equal its bundle; --threshold is required
- [Phase 01]: 01-08: host certificates presented as user certificates are tested with an x/crypto/ssh client because the OpenSSH client never offers a non-user certificate; sshd refuses them (Certificate invalid: not a user certificate)
- [Phase 01]: 01-10: CA and root SoftHSM2 tokens use separate token directories and agents (T-01-47); PINs reach pkcs11-tool via env:NAME and ssh-add via SSH_ASKPASS, never argv
- [Phase 01]: 01-10: TestPKCS11Ed25519 asserts refusal on ssh-agent older than 10.1 instead of skipping; fingerprint_test.go (!e2e && (e2e_pkcs11 || e2e_tpm)) supplies fingerprint for hardware-backend e2e builds
- [Phase 01]: 01-11: CI runs the TPM lane on swtpm unixio, the only transport CI exercises; vtpm-proxy rejected (azure runner kernel has no tpm_vtpm_proxy, even in linux-modules-extra) and removed from swtpm-setup.sh by owner decision because it never ran to completion; production /dev/tpmrm0 path is first exercised by the 01-14 dogfood
- [Phase 01]: 01-11: swtpm-tcp transport not built (works with swtpm, but a TCP client in the signer conflicts with KEY-01; unixio needs no root)
- [Phase 01]: 01-11: TPM custody derived from TPM_PT_MANUFACTURER at open time (IBM/MSFT/GOOG = vtpm); the custody option can only weaken to vtpm
- [Phase 01]: 01-11: reserved keystore option state-dir is added by ca-init/install-bundle/serve at open time, never stored, refused as --backend-opt
- [Phase 01]: 01-12: the PIV backend keeps no files; Key() reads each slot's public key and origin through GET METADATA, so firmware below 5.3.0 is refused
- [Phase 01]: 01-12: only piv-go ErrNotFound counts as an empty slot; Provision checks all five slots before generating anything and refuses imported keys, default PIN and default management key
- [Phase 01]: 01-12: mgmt-key-file is needed only for provisioning; the guide moves it off the host after ca-init (serve/install-bundle use --backend-opt mgmt-key-file=)
- [Phase 01]: 01-12: the PIV backend verifies the PIN once at open and refuses on a wrong PIN; piv-go checks the PIN only inside Sign, so otherwise each signing request with a wrong PIN would use up a card PIN retry
- [Phase 01]: 01-13: the signer unit re-allows @chown after ~@privileged (socket chgrp to keyroster-admin); systemd-analyze exposure 0.7 SAFE, threshold 2.0 set in systemd.yml
- [Phase 01]: 01-13: capslock baseline is (package, capability) pairs from -output package (22 packages, 73 pairs); a name-only diff would miss almost everything
- [Phase 01]: 01-13: one dependency-firewall exception, os/exec <- modernc.org/libc (only libc.Xsystem, never referenced by modernc.org/sqlite)
- [Phase 01]: 01-13: doctor never reports vtpm, agent or software keys as hardware custody; capslock -tags piv deferred to 01-15
- [Phase 01]: 01-14: owner decision 'Testceremoni nu, riktig sen' - TEST software roots made on the networked workstation (WSL, unshare -r -n); homelab signer is dogfood only until a real offline ceremony plus successor rotation
- [Phase 01]: 01-14: KEY-07 stays open and must-have truth 2 is unmet; only KEY-04 and VIS-03 marked complete
- [Phase 01]: 01-14: the ceremony transcript is kept by the owner, not committed (runbook step 7 and template corrected)
- [Phase 01]: 01-15: the 9.5p2 check ran on a lab Windows Server 2025 (inbox OpenSSH_for_Windows_9.5p2, file version 9.5.5.1) instead of the owner's workstation, by owner choice; accept PASS, reject PASS
- [Phase 01]: 01-15: the ruleset listing all 17 checks is applied by the owner from the PR branch before approval (admin-only); REPO-01 is marked complete in p01/close after the live-rules check passes
- [Phase 01]: 01-15: capslock -tags piv re-deferred to the next plan that edits CI (needs libpcsclite-dev and must not change a check in the PR that makes it required)
- [Phase 01]: 01-15: KEY-07 stays open; the real offline ceremony means reinstalling the homelab signer until a successor-bundle builder exists
- [Phase 01]: 01-17: root sign --prev DIR builds successor bundles; --ca-pubkeys refused with --prev (CA rotation is KEY-08); a previous or a new root may sign; BuildSuccessor and VerifySuccessor share checkSuccessorChain
- [Phase 01]: 01-17: KEY-07 not marked complete; it closes in 01-21 after the owner's offline ceremony and destruction of the TEST roots
- [Phase 01]: 01-19: KEY-07 removed from requirements-completed in 01-06, 01-07 and 01-09 only; coverage rows and bodies unchanged (owner decision 3)
- [Phase 01]: 01-19: C-WR-06 part 2 and C-WR-01 remainder deferred to Phase 4 (VIS-02); D-WR-02 and D-WR-04 deferred to issue #13 before the Phase 6 external review (owner decision 4)
- [Phase 01]: 01-18: audit verify pins the anchor bundle (first bundle whose root set and threshold equal the pins); earlier bundles are authenticated by the prev-hash chain, no match fails closed
- [Phase 01]: 01-18: trust verify --prev checks a successor with VerifySuccessor, then MatchPins against the new roots' paper fingerprints before install
- [Phase 01]: 01-18: fork_under_old_pins is an accepted residual; after rotating away from exposed roots, auditors pin the new roots (runbook)
- [Phase 01]: 01-20: rehearsal rotation (owner decision 2026-10-09): TEST roots C and D made in WSL with simulated media; homelab signer moved to bundle v2 92dc8ef4; offline ceremony UNVERIFIED, KEY-07 stays open until a later v3 rotation onto offline roots
- [Phase 01]: 01-20: v2 carries policy v1 unchanged; requirements-completed is VIS-03 only and requirements.mark-complete is skipped
- [Phase 01]: 01-21: TEST roots A and B retired (owner shred -u, attested); KEY-07 stays open, real offline ceremony owed as v3 rotation co-signed by C or D, then C and D destroyed
- [Phase 02]: 02-01: audit verify refuses every leaf kind it has no check for (not verifiable by this version); kinds 7 and 8 reach that default until 02-04
- [Phase 02]: 02-01: cert.KeyID gains Directory and Roles (nil Roles = kr1); KeyID.Equal replaces struct comparison in cert.Build
- [Phase 02]: 02-01: InstallDirectory re-checks the trust bundle in force inside its transaction (trust_changed), like issuance
- [Phase 02]: 02-01: loadDirectory keeps a stored directory's bytes and version even when not authorized, so the next install still chains to it
- [Phase 02]: 02-01: capslock baseline moves CAPABILITY_ARBITRARY_EXECUTION from internal/cert to internal/directory (same ssh.PublicKey.Verify over-approximation); requirements-completed empty (KEY-02 in 02-04, AUTHZ-01 in 02-11)
- [Phase 02]: 02-02: A2 passed: inbox ssh.exe 9.5p2 honours a pipe agent only as //./pipe/<name> in IdentityAgent (backslash spelling fails); SSH_AUTH_SOCK takes both; keyroster agent prints the forward-slash spelling
- [Phase 02]: 02-02: A3 moved to 02-14 (laptop offline); 02-12 ships no gcr check, gcr-ssh-agent UNVERIFIED
- [Phase 02]: 02-02: winagent ensure confirms with List through a serial (non-Closer) client, since x/crypto NewClient on a net.Conn leaves a background reader; one retry only on a closing-agent transport error
- [Phase 02]: 02-02: owner decision 2026-10-17: keyroster advises only a host-scoped `Host <your keyroster hosts>` IdentityAgent block for the Windows agent pipe and no longer advises $env:SSH_AUTH_SOCK; 02-12 Task 1 step 11 must print the same form
- [Phase 02]: 02-03: the signer refuses to start when the latest stored directory is not the one the last directory_install leaf records (T-02-14)
- [Phase 02]: 02-03: frames are capped per message type (MaxDirectoryFrame for InstallDirectory and GetDirectoryResponse, MaxFrame otherwise); ReadFrame/WriteFrame removed
- [Phase 02]: 02-03 pre-merge review: readers pass the types they accept (wire.Caps); the signer reads only InstallDirectory at MaxDirectoryFrame, a client only its awaited type and errors; directory signatures are checked before parsing; refused installs log from their own refusal bucket; doctor runs the directory cross-check
- [Phase 02]: owner decision 2026-10-17: T-02-14 covers only the directory table rolled back or substituted alone; the log and tables rolled back together, or an older signer.db restored, is the C-WR-01 residual, and in Phase 4 keyroster-signer serve refuses to start without a witnessed checkpoint at least as new as the local one
- [Phase 02]: 02-04: audit verify re-proves every login_issue entry from the log; the (directory, policy) authorization is cached and recomputed only at directory_install and after each bundle_install
- [Phase 02]: 02-04: a login request ID used by any earlier issue or login_issue entry is refused as a replay; two issue entries are still not compared (Phase 1 unchanged)
- [Phase 02]: 02-04: a login certificate must carry exactly the profile defaults plus the requested extensions, no critical option, and span exactly ValidForSeconds + 300 s; freshness is compared in whole seconds
- [Phase 02]: 02-04: keyroster root successor-policy changes only the WebAuthn RP (version+1, prev hash), warns that rp_id is one-way, refuses a no-op
- [Phase 02]: 02-05: owner decision A (2026-10-18): the KEY-06 banner names a compromised signer host; one constant in internal/custodytext, quoted verbatim in custody.md
- [Phase 02]: 02-05: owner decision B (2026-10-18): capslock baseline accepts 11 pairs outside the plan's list as over-approximations (age WriterFunc, error dispatch); causes of MODIFY_SYSTEM_STATE widening and trust UNANALYZED UNVERIFIED
- [Phase 02]: 02-05: Status (0x04/0x84) reports custody from the signer only (D-18), refuses trust_changed after a foreign install; InstallBundle refuses a trust state whose Status reply exceeds MaxStatusFrame
- [Phase 02]: 02-05 pre-merge review, owner decisions 2026-10-19: the stored passphrase source (locked at ca-init) is deferred to Phase 6 (todo); symlinks to the passphrase file stay allowed (no O_NOFOLLOW), with the regular-file and mode checks on the target
- [Phase 02]: 02-06: keyroster-server takes RP, origins and custody only from the signer's Status through one 5 s fail-closed cache (currentStatus) with a dropStatus hook; the signerAPI interface in internal/server/signer.go is the only signer seam, fakeSigner the only test double
- [Phase 02]: 02-06: the /api/v1/trust document and the Keyroster-Custody header are defined once in internal/serverclient (the server imports them); a 2xx without Keyroster-Custody is refused (ErrNoCustody) and a 503 is never parsed for custody
- [Phase 02]: 02-06: serverclient.Trust also requires the bundle's policy_sha256 to match the served policy (ErrPolicyNotBundled); ErrTrustRootNotPinned never names the served roots
- [Phase 02]: 02-06: keyroster-server registers SIGHUP as the first statement of serve; every successful certificate load logs 'tls certificate loaded' (fingerprint, not_after, trigger start|file_change|sighup) as JSON on stderr
- [Phase 02]: 02-07: admin-api/v1 SSHSIG over method, raw request-target, body SHA-256, timestamp (+-120 s) and nonce; nonces kept 241 s (superseded by the pre-merge owner decisions below)
- [Phase 02]: 02-07 pre-merge review, owner decisions 2026-10-20: (1) the admin signature also covers the request origin, which must exactly match a webauthn origin of the root-signed policy (no fallback; cross-deployment replay refused); (2) the body SHA-256 travels in the signed Keyroster-Admin-Body-SHA256 header and the server verifies before the handler reads any body, with no global limiter on the admin route; (3) CodeQL go/log-injection #8-#11 dismissed as false positives. An earlier proposal (requests naming an admin key skip the global limiter) was withdrawn: admin keys are public
- [Phase 02]: 02-07: ParseServerURL accepts only letter-digit-hyphen DNS hosts and a non-empty port (found by FuzzParseInviteURL)
- [Phase 02]: 02-07: the CLI parses the server's invite URL as structured data and prints it rebuilt
- [Phase 02]: 02-08: go-webauthn v0.18.2 (server only) approved by the owner on 2026-10-21 together with hardening H1-H4: attestation none only before any verifier, RS256 2048-4096 bits and e=65537 in the shared verifier, enroll bodies capped (1 KiB begin, 64 KiB finish), no FIDO metadata
- [Phase 02]: 02-08: registration sessions keyed by (invite hash, challenge) and consumed with DELETE ... RETURNING; the invite is used only by an UPDATE conditioned on current, unused and unexpired; one pending credential per user
- [Phase 02]: 02-08 pre-merge review, owner decision E1 (2026-10-21): packed self-attestation (attStmt exactly {alg, sig}, alg equal to the key's and one of the offered three, zero AAGUID) is rewritten to "none" before go-webauthn sees it, without verifying the self-signature (WebAuthn L3 5.1.3: Chromium and Firefox forward it under attestation "none"; D-05 any authenticator); every other format stays refused before any verifier runs
- [Phase 02]: 02-08 pre-merge review: GET /api/v1/admin/users/{name}/pending answers serverclient.PendingAnswer {invite:{state open|expired|used, expires_at}, credentials} read from one transaction (invariant: used iff one pending credential); the finish route looks up the live invite before parsing the body; the enroll refusal log never carries go-webauthn's client-derived Details
- [Phase 02]: 02-09: one directory pipeline (verify trust and base, build, Validate, CheckPolicy, diff, confirmSign or --yes, SSHSIG under keyroster/directory/v1, install or proposal); proposals are directory.json + directory.json.sigs (+ base.sha256 note), default keyroster-directory-v<N> when quorum > 1
- [Phase 02]: 02-09: currentDirectory is the one directory mirror (replaces 02-07's dirCache): reads only through currentStatus, version 0 without a signer read, fails closed on a failed or mismatched refresh; the install handler drops the status cache after every InstallDirectory
- [Phase 02]: 02-09: POST /api/v1/admin/directory runs under pendingMu (also taken by a reinvite), refuses credential_not_pending, and cleans up with self-healing DeleteBound (ID and user matched); keyroster user list prints users from the verified directory, never the server's fingerprints
- [Phase 02]: 02-09 pre-merge review, owner decisions 2026-10-21: (F1) the CLI says only that the server reports a version installed (no signer receipt yet; check with keyroster audit verify on the signer host; receipts are a Phase 4 blocker todo); (F2) the executor's five unsettled choices approved; (F3) recovery after an admin-set or quorum change is a Phase 4 blocker todo. The pending check at install matches ID, user, alg and SPKI; the diff shows credential IDs and BE; directory display escapes control bytes. CodeQL go/log-injection #12 (directory.go, a Validate-checked user name) dismissed as a false positive
- [Phase 02]: 02-10: web sign-in is username-first with allowCredentials from the installed directory; begin, finish and every session request read only through currentStatus/currentDirectory and check the user is active and the credential bound; assertions verified by internal/webauthn.VerifyAssertion
- [Phase 02]: 02-10: __Host-keyroster-session is an opaque 32-byte ID stored as SHA-256 (sessions.id_hash) with the opening cred_id; 1 h idle and 12 h absolute in one conditional UPDATE ... RETURNING; a signer outage answers 503 and keeps the row; logout needs no signer state
- [Phase 02]: 02-10: sign-in route class: per client 20/min burst 10 with a 200/min burst 100 global backstop, plus one per-username bucket 10/min burst 10 (bounded LRU, valid names only, finish keyed on the challenge's user); one 'web sign-in' log line per event with no secrets
- [Phase 02]: 02-10 pre-merge review, owner decisions 2026-10-22: the per-username sign-in bucket is keyed on (user, client) so no client can lock another out (02-12's CLI login inherits this via deferred-items); the executor's 12 open choices approved; sign-in, sessions and /account fail closed when the signer reports the directory not authorized; CodeQL #13 dismissed as a false positive
- [Phase 02]: 02-11 Task 1, owner decision D-06 2026-10-22: principal convention confirmed as role:<name> for roles and u:<username> for personal accounts ("role:<namn> och u:<användare> (Rekommenderas)")
- [Phase 02]: 02-11: role add grants role:<name> by default (D-06 role-prefix, owner 2026-10-22); host principals renders a header-only file for an unmapped account or roles [], errors on an unknown host group, refuses with no directory installed
- [Phase 02]: 02-11: renderer refuses host group and account names outside the directory grammars (header-line injection); host-group remove refused while the group maps an account (T-02-100); host ca-key needs no admin key
- [Phase 02]: 02-11 pre-merge review, owner decision 2026-10-22: the executor's nine open choices approved; host-setup.md states that rendered files are the server's word (check `keyroster audit verify` on the signer host after revocations or CA changes) and puts the sshd settings where they take effect, verified with `sshd -T -C` including laddr and lport
- [Phase 02]: 02-12: keyroster login is the D-12 browser-loopback flow: options (from directory.Authorize per role), begin with PKCE S256 and state, approval page with the fingerprint computed from the stored request bytes, assertion pre-verified, redeem the only signer call (mint at redemption); code single-use in one conditional UPDATE after the verifier-format and PKCE checks; begin ±120 s, session CreatedAt + 240 s, code min(+120 s, CreatedAt + 290 s)
- [Phase 02]: 02-12: the CLI verifies the certificate (signature included) against the root-pinned user CA, its own key, exact principals, kr2 key ID, span <= TTL + 300 s, >= 60 s left; adds only the certificate identity with LifetimeSecs = remaining, never retries without the constraint or after a failed redeem; Windows uses keyroster agent via winagent.Ensure and prints only the host-scoped IdentityAgent block
- [Phase 02]: 02-12: login limiters are their own class with the sign-in values and a bucket per route; per client once per request, per (user, client) via signInUserKey; the fingerprint claim corrected: a compromised server can harvest an assertion for its own key (T-02-60), the CLI's own-key check keeps it out of the agent and the log shows the other key_fingerprint
- [Phase 02]: 02-12 pre-merge review, owner decision 2026-10-22: the executor's 13 open choices approved; each login route has its own global backstop; the CLI refuses a certificate whose roles, extensions or critical options differ from the request; agent lifetime and remaining validity use the measured skew; CodeQL #14 and #15 dismissed as false positives
- [Phase 02]: 02-13 Task 1, owner decision D-09 2026-10-22: the homelab RP ID is the signer VM's full MagicDNS FQDN (confirmed verbatim by the owner; the name and its hash are kept only outside the repository, in kr.env); the policy successor is bundle v3 signed by TEST root C, so the owed real offline ceremony becomes the v4 rotation and KEY-07 stays open. Tailscale was installed on the signer VM (official apt repository) and joined to the tailnet with the owner's approval
- [Phase 02]: 02-13: homelab runs bundle v3 (policy v2 with the RP) and keyroster-server with a tailscale cert; the owner (user name `owner`) enrolled with a synced Chrome passkey (ES256) and approved it with his admin key; directory v5 grants role homelab-admin (8 h) and maps zima in host group homelab; the owner ran user add and the directory commands himself because the permission classifier refused them for agents
- [Phase 02]: 02-13: audit verify anchors on the first bundle whose root set equals the pins, so C and D anchor on v2 while v3 is in force; 02-14's anchor_bundle_version==3 assertions must become bundle_version==3 and anchor_bundle_version==2 (phase 02 deferred-items.md)
- [Phase 02]: 02-14 Task 1, owner decision 2026-10-22: zima-srv has been offline for 16 days, so the SSH target is a Proxmox test VM (Ubuntu 26.04, OpenSSH 10.2p1) chosen by comparing the owner's public keys with the running VMs' authorized_keys over the guest agent; production VMs were excluded. Its account `daniel` is mapped to homelab-admin in host group homelab by directory v6, which the owner signed himself (classifier). The laptop is offline, so Task 4 waits for it
- [Phase 02]: 02-14: zima-srv came back online, so the laptop login (Task 4) went to zima-srv (account zima, KR_ZIMA_SINCE); the Windows serials are matched in the test VM's journal and the Linux serials in zima-srv's
- [Phase 02]: 02-14: A3 (02-14) passed on the laptop (gcr-ssh-agent keeps the lifetime and the certificate); the laptop login used gcr-ssh-agent; the first plain `ssh` used the laptop's own key from authorized_keys, so the certificate login was shown with PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com
- [Phase 02]: 02-14: requirements-completed AUTH-02 and AUTH-04 (order=ok on both OSes), and UI-01 after the pre-merge review (all six pages in a real browser: enroll in 02-13, login, account and login_approve in Tasks 2-4, index, the error page and sign-out by the owner in Chrome on 2026-10-23; strict CSP on every page by curl, no CSP violation in the console; a DevTools "1 issue" on the error page and /login not captured); AUTH-03 and PLAT-05 stay Pending (macOS UNVERIFIED); Windows removal at expiry not shown (listing times unrecorded)
- [Phase 02]: 02-14 pre-merge review, owner decision D2 (2026-10-23): a ruleset change is applied by the owner after its PR merges, from an up-to-date main checkout (the reviewed script and JSON), never from a PR branch; this replaces the 01-04 pattern of applying from the PR branch before approval. A new required check must already have reported success on its PR (CONTRIBUTING.md "Changing the rulesets")

- [Phase 02]: Phase 2 verification, owner decisions 2026-10-23: "Godkänn alla tre (Rekommenderas)" (overrides: 02-14 truth 9 cli-windows replaced by D1, 02-13 truth 8 anchor v2 by design, SC5 read through D-18); "Stäng med macOS UNVERIFIED (Rekommenderas)" (SC2 macOS clause by override; AUTH-03 and PLAT-05 stay Pending); "Kör testet nu (Rekommenderas)" (timed Windows expiry from a cold start: serial 1792752977539626 left the keyroster agent between 3.9 s before and 1.1 s after valid_before at 5 s resolution (Daniel-PC clock against server clock, skew unmeasured), audit verify ok with 18 entries); "Acceptera, lägg till tester senare (Rekommenderas)" (9 flagged prohibitions accepted, two negative tests as todos). The MVP goal format follows the Phase 1 precedent. Status passed, 5/5 and 145/145 with 4 overrides
- [Phase 02]: KEY-02 stays Pending: its Phase 2 clauses are complete, the required-approvals clause arrives with Phase 4 SC2. Advisory 4 (machine names in committed files outside the alias allow-list) has no owner decision yet

### Pending Todos

- [2026-10-16] [auth] Bind admin-signed directories to a deployment — [todo file](.planning/todos/pending/2026-10-16-bind-admin-signed-directories-to-a-deployment.md) — Needs Options:.
- [2026-10-17] [auth] Serve refuses to start without a witnessed checkpoint (blocker, Phase 4) — [todo file](.planning/todos/pending/2026-10-17-serve-refuses-without-witnessed-checkpoint.md) — owner decision taken; options: witness cosignatures checked at start, or an operator-supplied minimum checkpoint as an interim measure.
- [2026-10-19] [auth] Choose the software passphrase source at every start (minor, Phase 6) — [todo file](.planning/todos/pending/2026-10-19-choose-the-software-passphrase-source-at-every-start.md) — deferred by the owner; suggested option (c): store nothing at ca-init.
- [2026-10-20] [server] Cap keyroster-server connections and memory (minor, Phase 6) — [todo file](.planning/todos/pending/2026-10-20-cap-server-connections-and-memory.md) — found in the 02-07 pre-merge review: no listener connection cap, idle HTTP/1.1 and h2 connections and h2 receive windows; options listed.
- [2026-10-21] [auth] The CLI verifies signer-signed receipts for directory installs (blocker, Phase 4) — [todo file](.planning/todos/pending/2026-10-21-cli-verifies-directory-install-receipts.md) — found in the 02-09 pre-merge review: a compromised server can answer an install (even a disable) as done without forwarding it; owner decision F1: honest wording and a signer-host check now, a signed checkpoint plus inclusion proof and high-water marks in Phase 4.
- [2026-10-21] [auth] Recover the directory after an admin-set or quorum change (blocker, Phase 4) — [todo file](.planning/todos/pending/2026-10-21-recover-directory-after-admin-set-change.md) — found in the 02-09 pre-merge review: once a successor policy changes the admins or quorum, every CLI directory command refuses the old base, so no command can install the re-signed directory the signer waits for; owner decision F3; options: verify against the previous policy, the audit log's PolicyVersion, a re-sign command, a signer-local break-glass install.
- [2026-10-23] [docs] The signer restore runbook replays lost directory versions with directory install (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-restore-runbook-replays-lost-directory-versions.md) — review A-IN-01.
- [2026-10-23] [auth] The directory install pending check covers re-keyed and moved credentials (minor, Phase 4) — [todo file](.planning/todos/pending/2026-10-23-pending-check-covers-rekeyed-credentials.md) — review B-IN-01.
- [2026-10-23] [server] Show the software-custody banner on error, 404 and 429 pages (minor, Phase 4) — [todo file](.planning/todos/pending/2026-10-23-custody-banner-on-error-pages.md) — review B-IN-02.
- [2026-10-23] [server] A redeemed login code always reaches the signer inside its 300 s window (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-login-redeem-fits-the-signer-window.md) — review C-IN-01.
- [2026-10-23] [cli] keyroster login checks the ssh-agent before the certificate is issued (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-cli-checks-the-agent-before-issuance.md) — review E-IN-01.
- [2026-10-23] [cli] Recompute the agent lifetime immediately before the add (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-recompute-agent-lifetime-before-add.md) — review E-IN-02; not seen at 5 s resolution in the timed Windows run.
- [2026-10-23] [docs] The runbooks say that disabling a user does not end certificates already issued (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md) — review F-IN-01.
- [2026-10-23] [auth] The CLI takes software custody from the root-signed bundle, not only the server header (minor, Phase 4) — [todo file](.planning/todos/pending/2026-10-23-cli-custody-banner-from-the-root-signed-bundle.md) — review F-IN-02.
- [2026-10-23] [test] A negative test proves there is no non-passkey sign-in route (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-negative-test-no-non-passkey-sign-in-route.md) — owner decision 2026-10-23 (02-10 prohibition).
- [2026-10-23] [test] A negative test proves keyroster login never writes the ephemeral key to disk (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-negative-test-login-never-writes-the-key-to-disk.md) — owner decision 2026-10-23 (02-12 prohibition, disk half).
- [2026-10-23] [planning] Correct the 02-13 and 02-14 plan text that drifted from what was executed (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-correct-02-13-and-02-14-plan-text-drift.md) — anchor 3 and cli-windows; editing the plans stales the phase 2 verification.
- [2026-10-23] [docs] Record the timed Windows expiry run in needs-hardware.md (minor, Phase 3) — [todo file](.planning/todos/pending/2026-10-23-record-the-timed-windows-expiry-in-needs-hardware.md) — the doc still says the listing times were not recorded.

### Blockers/Concerns

- [Phase 1]: Ed25519 via PKCS#11/ssh-agent and TPM algorithm support unverified; decide CA key algorithm and custody together in phase research
- [Phase 2]: CLI WebAuthn transport undecided (browser loopback is the default); Windows CTAP access for non-admin users unverified
- [Phase 3]: Unknown whether sshd re-reads `RevokedKeys` without a reload; settle with an integration test
- [Phase 5]: Windows edge cases (principal case, domain/Entra accounts, `verify-required`, KRL on 9.5p2) at LOW-MEDIUM confidence
- [General]: HSM signing throughput under login storms not measured

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 261006-ixz | Fix flaky signer freshness-boundary tests with a deterministic test clock | 2026-10-06 | 66fd3c3 | [261006-ixz-fix-flaky-signer-test-created-301s-futur](./quick/261006-ixz-fix-flaky-signer-test-created-301s-futur/) |
| 261021-76k | Make internal/directory TestAuthorizeOneUser robust against one slow wall-clock sample (take the fastest of several Authorize runs; the R1 regression must still fail) | 2026-10-21 | 10ba623 | [261021-76k-make-internal-directory-testauthorizeone](./quick/261021-76k-make-internal-directory-testauthorizeone/) |
| 261021-8av | Bump the Go toolchain pin to go1.27.3 for GO-2026-6809 (crypto/x509), which fails govulncheck in CI | 2026-10-21 | 2fd917f | [261021-8av-bump-the-go-toolchain-pin-to-go1-27-3-fo](./quick/261021-8av-bump-the-go-toolchain-pin-to-go1-27-3-fo/) |

## Deferred Items

Items acknowledged and deferred at milestone close, most recent first:

| Category | Item | Status | Deferred At | Milestone |
|----------|------|--------|-------------|-----------|
| *(none)* | | | | |

## Session Continuity

Last session: 2026-10-23T19:09:42.183Z
Stopped at: Phase 3 context gathered
Resume file: .planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
