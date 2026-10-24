---
phase: 3
reviewers: [codex, ollama-nemotron, ollama-gemma]
reviewed_at: 2026-10-24T04:07:10Z
plans_reviewed: [03-01-PLAN.md, 03-02-PLAN.md, 03-03-PLAN.md, 03-04-PLAN.md, 03-05-PLAN.md, 03-06-PLAN.md, 03-07-PLAN.md, 03-08-PLAN.md, 03-09-PLAN.md, 03-10-PLAN.md, 03-11-PLAN.md, 03-12-PLAN.md, 03-13-PLAN.md, 03-14-PLAN.md, 03-15-PLAN.md, 03-16-PLAN.md]
plans_at_commit: 7f3bdad
models:
  codex: "gpt-6-luna (reasoning=high)"
  ollama-nemotron: "nemotron-3-ultra:cloud"
  ollama-gemma: "gemma4:31b-cloud"
model_sources:
  codex: "banner"
  ollama-nemotron: "explicit"
  ollama-gemma: "explicit"
---

# Cross-AI Plan Review — Phase 3

<!-- gsd:plan-revision-conflicts:begin -->
## Plan-Revision Conflicts
<!-- gsd:plan-revision-conflicts:end -->

**Lanes.** `/gsd-review --phase 3 --all` on Daniel-PC. Claude was skipped as the host runtime.

- **Codex** was prompt-fed with the full prompt (about 670 kB) and read the repository. Its citations point at real Go source (`internal/signer`, `internal/trust`, `internal/server`, `internal/audit`, `internal/wire`, `internal/directory`, `cmd/keyroster`). Absolute local paths in its links were rewritten as repo-relative.
- **nemotron** and **gemma** are Ollama cloud models, called directly through `/api/chat` streaming. They had **no repository access** and got the prompt without RESEARCH.md, because the full prompt does not fit their context. Both are down-weighted below.
- **Kimi** was dropped: the lane started but the provider answered "Quota exceeded". **OpenCode** and the built-in **Ollama** lane were not run because `jq` is missing. **LM Studio** was not used: the prompt is about 160k tokens and the local models are capped at 16k context.
- **Coverage:** every reviewer has a section for each of the 16 plan ids.

---

## Codex Review

### 03-01

**Summary** — A useful tracer: it ties a CLI revocation to signer state, the audit log, a signed KRL and real `sshd` behavior. The existing signer already commits issuance state and its leaf in one transaction, which is a good pattern to extend ([`issue.go:165–181`](../../../internal/signer/issue.go)).

**Strengths**

- Installation ID is added as an optional final bundle field, matching the existing canonical-document evolution pattern. The current bundle fields and validation are in [`bundle.go:57–67`](../../../internal/trust/bundle.go) and [`bundle.go:139–172`](../../../internal/trust/bundle.go).
- The plan recognizes that new audit leaf kinds must fail closed until their verifier lands. The current default branch does exactly that ([`verify.go:753–763`](../../../internal/audit/verify.go)).
- The proposed signer transaction and “publish only after commit” follow the existing transaction/log pattern ([`issue.go:165–181`](../../../internal/signer/issue.go)).

**Concerns**

- **MEDIUM** — The new KRL frame is larger than `MaxFrame`, but the plan does not explicitly name all frame-reader and client response-cap changes. Today only directory and status responses receive larger caps; ordinary requests and responses default to `MaxFrame` ([`frame.go:21–30`](../../../internal/wire/frame.go), [`frame.go:63–93`](../../../internal/wire/frame.go)). A KRL could encode successfully and still be rejected by the signer socket.
- **MEDIUM** — The request specifies `CARole string`, while the existing wire API uses the validated `CARole` enum ([`issue.go:44–68`](../../../internal/wire/issue.go)). Reuse the enum to avoid duplicate validation and divergent serialization.
- **LOW** — The zero-byte `RevokedKeys` behavior and KRL magic behavior are security-sensitive assumptions. They need real-`sshd` tests on each planned version, as the plan proposes; the repository does not currently contain those tests.

**Suggestions**

- Name `RequestCaps`, `ResponseCaps`, the signer client’s expected response cap, and any proxy/HTTP body caps as explicit implementation points.
- Keep the KRL wire format’s role representation aligned with `wire.CARole`; pin the new type encodings in golden vectors.

**Risk Assessment** — **HIGH**. The vertical slice is well chosen, but a frame-cap omission or KRL encoding defect could stop the feature or deny SSH access.

### 03-02

**Summary** — The login ordering and expiry fixes target real failure windows. The code currently opens the agent only when adding the certificate, after redeem and verification ([`login.go:311–320`](../../../cmd/keyroster/login.go), [`login.go:573–580`](../../../cmd/keyroster/login.go)). The server also reads time before a potentially slow status call and then redeems using that earlier value ([`login.go:732–755`](../../../internal/server/login.go)).

**Strengths**

- Checking agent availability before issuing avoids logging a certificate the client cannot store.
- The proposal adds negative tests for private-key persistence and for unexpected sign-in routes. The current login documents the intended memory-only behavior ([`login.go:237–243`](../../../cmd/keyroster/login.go)).
- The requirement wording changes are tied to owner decisions and are reflected in the plan’s stated scope.

**Concerns**

- **MEDIUM** — A `registeredPatterns` slice can drift from the mux if any registration path bypasses the wrapper. The current mux registers routes directly in `New` ([`server.go:121–155`](../../../internal/server/server.go)). The test should enumerate the actual `ServeMux` patterns where possible, or centralize registration so recording and registration cannot diverge.
- **MEDIUM** — The disk test’s proposed directory scan can miss writes outside the listed locations or private-key representations not covered by the seed/header checks. It should also inject a filesystem boundary or spy on key-writing APIs if the implementation offers one.
- **LOW** — Connecting to an agent before beginning login holds the connection through browser approval. Agent disconnection or socket timeout may still happen later; the test must distinguish “usable at preflight” from “available at Add.”

**Suggestions**

- Recheck the deadline immediately before `RedeemLogin`, then derive the signer context deadline from the stored request timestamp, as planned.
- Make the route test fail if any registration is not performed through the same registration helper.
- Add an injected agent that disconnects after the early check to document the remaining failure mode.

**Risk Assessment** — **MEDIUM**. The code changes are focused and supported by the existing flow, but the new negative tests need robust boundaries to prevent false confidence.

### 03-03

**Summary** — The plan completes the revocation model with strict parsing, pruning and audit re-derivation. That is important because audit verification currently rejects new, unhandled leaf kinds rather than skipping them ([`verify.go:753–763`](../../../internal/audit/verify.go)).

**Strengths**

- Subject revocation resolves certificates in the signer’s own issuance database; the current table stores serial, CA role, key ID, certificate and issue time ([`issuance.go:18–26`](../../../internal/signerdb/issuance.go)).
- It treats explicit-key revocation differently from certificate entries, so key revocation remains permanent while serial/key-ID entries can be pruned.
- The reverse oracle and fuzzing cover inputs emitted by OpenSSH, not only the project’s encoder.

**Concerns**

- **HIGH** — The subject-resolution statement mixes issue-time cutoff and certificate `ValidBefore` checks. The database does not store `valid_before`; it stores the certificate blob ([`issuance.go:18–26`](../../../internal/signerdb/issuance.go)). Parsing every candidate is necessary, and the audit verifier must independently reconstruct exactly the same subject and lifetime rules. Spell out clock rounding and the 300-second boundary.
- **MEDIUM** — The plan says subject revocation disables the user in a directory version “at once” for quorum 1, otherwise writes a proposal. Revocation and directory installation are separate transactions and authorities; define recovery behavior if revocation succeeds but the directory proposal/install fails.
- **MEDIUM** — The full KRL parser must bound nested counts and allocations, not just total file size. The plan names a file cap but should require section-count, subsection-count and string-length limits before allocation.

**Suggestions**

- Define one shared, testable function for “live issuance at timestamp T,” and have signer and audit implementations cross-check it with independent fixtures.
- Make the CLI report partial success explicitly when the KRL publish succeeds but directory disablement does not.
- Fuzz both parser and audit leaf decoders using malformed lengths and extreme counts.

**Risk Assessment** — **HIGH**. The security model is sound in outline, but signer/audit disagreement or an ambiguous partial subject-revoke can undermine the core promise.

### 03-04

**Summary** — This plan introduces the signed host and machine records needed by later plans and binds directories to the installation ID. The current directory has only users, groups, roles and host groups ([`directory.go:61–68`](../../../internal/directory/directory.go)); it already has a single principal renderer to preserve ([`render.go:65–87`](../../../internal/directory/render.go)).

**Strengths**

- Host names, keys and certificate principals are admin-signed directory data, rather than agent-supplied authority.
- It keeps the renderer as the sole source of principals files.
- It assigns installation binding checks to both signer and audit verification, rather than relying only on agent pins.

**Concerns**

- **HIGH** — `directory rebind` changes signed document bytes and is an essential migration for the homelab. The plan must define how it works when the stored directory is ID-less but the new bundle has an ID, including the exact signer acceptance rule chosen by 03-01. The existing signer checks signatures, successor bytes and policy before installation ([`directory.go:96–115`](../../../internal/signer/directory.go)).
- **MEDIUM** — The proposed machine role-cap logic distinguishes roles assigned to users/groups from roles assigned only to machines. The existing role model stores both memberships directly on each role ([`directory.go:94–103`](../../../internal/directory/directory.go)); make the transitive group calculation and mixed-use case explicit.
- **MEDIUM** — Host principal uniqueness across hosts is a deliberate restriction, but it also prevents a certificate principal shared by two hosts. Confirm that the intended name model requires that, and test duplicate IP/DNS spellings after canonicalization.

**Suggestions**

- Specify whether IPv4/IPv6 textual forms are normalized before duplicate detection.
- Add tests for one role used by both machine and user grants, and for directory rebind under both 03-01 transition choices.
- Keep format validation, canonicalization and signer authorization separate so errors remain actionable.

**Risk Assessment** — **HIGH**. This is a signed-format migration with consequences for every later host and machine operation.

### 03-05

**Summary** — The plan correctly builds the applier before transport and gates its executable sites. It also recognizes that the fetcher-written spool is untrusted. The current repository has no `internal/agent` package, so those mechanisms cannot be verified in existing implementation.

**Strengths**

- A single apply sequence with rollback is preferable to independent file updates.
- The applier verifies signed state itself, consistent with the current client trust model, which verifies served documents against pinned roots ([`client.go:771–820`](../../../internal/serverclient/client.go)).
- The plan keeps its completion claims limited while the full probe test is deferred to 03-10.

**Concerns**

- **HIGH** — The plan’s “one swap, one consistent state” assumption is not guaranteed by renaming a `current` symlink. `sshd` opens CA, principal and KRL files separately during authentication; each open follows `current` independently. A swap between opens can expose a mixed generation. The plan itself later describes those files being read separately. The “no reload” test needs a concurrent-swap case, or the design needs a mechanism that gives one authentication a consistent generation.
- **HIGH** — A rollback after a failed self-test is not sufficient if another authentication happens during the interval between swap and rollback. Define the safety invariant for that interval and test it under repeated connection attempts.
- **MEDIUM** — The spool’s state/version model must carry every bundle and directory successor when the agent has missed multiple versions; the plan’s standalone `Stored` design should be checked against 03-07’s chain catch-up requirements.

**Suggestions**

- Add a test that repeatedly authenticates while swapping CA, principals and KRL generations, checking for both transient lockouts and unintended acceptance.
- Consider immutable generation paths plus a single sshd reload when policy consistency matters, or document and constrain the mixed-generation outcomes.
- Define the self-test’s acceptance criteria for a first install where there is no previous `last-good`.

**Risk Assessment** — **HIGH**. The applier is the lockout-critical component, and atomic symlink replacement alone does not establish the stated cross-file consistency.

### 03-06

**Summary** — Distro detection, exact Phase 2 adoption and drift checks are a sensible follow-up to the core apply engine. Existing CLI registration uses direct mux routes ([`server.go:121–155`](../../../internal/server/server.go)); the new command registration should follow the repository’s current command patterns.

**Strengths**

- It refuses unsupported or foreign configurations rather than editing `sshd_config`.
- It requires effective-config checks after drop-in installation.
- It distinguishes container evidence from systemd/OpenRC and SELinux evidence.

**Concerns**

- **HIGH** — `account_excluded` is currently proposed as a “may exclude” heuristic for `AllowUsers`, `AllowGroups`, `DenyUsers` and `DenyGroups`. A heuristic can either falsely reject a manageable host or miss an exclusion. The requirement says evaluate sshd’s pattern semantics; use `sshd -T -C` with concrete accounts and test actual logins for the final decision.
- **MEDIUM** — Phase 2 adoption requires byte-identical principals files. The current renderer includes the directory version and canonical-directory hash in its header ([`render.go:65–87`](../../../internal/directory/render.go)). The plan should specify how an older but semantically equivalent directory is diagnosed and safely refreshed before takeover.
- **MEDIUM** — The plan’s “seven required checks” changes branch protection after merge via an owner action. Until that ruleset is applied, those checks are not actually required on `main`; the PR gate and post-merge action should be treated as a deployment dependency.

**Suggestions**

- Add an actual container login test for each account-pattern exclusion, not only fixture tests of pattern interpretation.
- Ensure adoption restores the original files if any step after removal fails.
- Pin distro image digests in the workflow and record the resolved digests in the summary.

**Risk Assessment** — **HIGH**. Distro-specific interpretation and takeover are both capable of breaking access if their behavior is inferred rather than exercised.

### 03-07

**Summary** — The two-listener design preserves the browser endpoint while adding agent enrollment and signed-state polling. The current browser and admin routes share one mux with explicit patterns ([`server.go:121–155`](../../../internal/server/server.go)), so separate agent routing is a meaningful isolation improvement.

**Strengths**

- Join tokens are one-time and stored by hash; host approval is separated from enrollment.
- The fetcher cannot issue commands to the applier; the applier re-verifies spool contents.
- State responses are ordered and bounded, addressing offline agents that miss several successors.

**Concerns**

- **HIGH** — The planned fetcher writes its enrollment response, identity and state through shared spool/outbox directories. The directory ownership and file permissions need a precise trust boundary: a compromised fetcher must not be able to overwrite the applier’s pins, accepted-state record, pending marker or status. The plan mentions path extensions but not a per-file ownership/rename policy.
- **MEDIUM** — The TLS certificate is intentionally self-signed and long-lived, while the server authenticates by SPKI. Specify certificate size, key rotation race behavior and whether concurrent identity rotation can leave the host unable to poll.
- **MEDIUM** — The plan returns the full directory to every enrolled host, including credential public keys and user metadata, as D-03 allows. This broad root-access disclosure should remain explicit in install documentation.

**Suggestions**

- Give the fetcher write access only to a staging area; have the root applier atomically copy validated content into accepted state.
- Test fetcher compromise cases: arbitrary filenames, symlinks, oversized files, path traversal and replacement of a pending enrollment response.
- Test the identity-rotation handshake through lost responses and retries.

**Risk Assessment** — **HIGH**. The signature checks are good, but the shared filesystem boundary is the main new privileged interface and needs stronger specification.

### 03-08

**Summary** — Heartbeats, status and hardened services are useful operational features. The plan correctly says convergence is the server’s report, not cryptographic proof.

**Strengths**

- Monotonic sequence numbers prevent older heartbeat replay from replacing newer status.
- Stale KRLs alert rather than fail closed, preserving service availability.
- Systemd and OpenRC evidence is labeled separately.

**Concerns**

- **MEDIUM** — The status file is written by the root applier and read by the unprivileged fetcher. The plan should define ownership, atomic replacement and symlink handling for `status.json`; otherwise a fetcher-controlled path may expose or redirect a privileged read.
- **MEDIUM** — `clock_offset_ms` is derived from the server’s HTTP `Date` header, which has one-second resolution. It cannot support precise millisecond offset claims; serialize the actual resolution or use a higher-resolution signed/transport time source.
- **LOW** — “Exactly three ReadWritePaths” is ambiguous because the applier also writes its state directory and a drop-in, while the fetcher needs its own config and outbox. Enumerate exact paths per unit.

**Suggestions**

- Treat heartbeat fields as untrusted even after mTLS; validate lengths, enumerations and file-list caps before storage.
- Test sequence overflow and agent reinstall/reset behavior so a fresh agent can re-enroll without permanently losing heartbeat acceptance.
- State whether the CLI renders data from the current directory or the heartbeat’s claimed host identity when names no longer match.

**Risk Assessment** — **MEDIUM**. Mostly operational scope, with permissions and identity-reset behavior needing precise handling.

### 03-09

**Summary** — Host certificates and exact-name client trust form a coherent end-to-end slice. The plan’s owner checkpoint is important because the existing admin directory endpoint is explicitly admin-protected ([`server.go:131`](../../../internal/server/server.go)).

**Strengths**

- The signer derives host certificate principals from the admin-signed directory and verifies proof of possession.
- Exact `@cert-authority` names reduce the impact of a mis-issued certificate.
- The plan requires a served-certificate check after reload and includes host revocation.

**Concerns**

- **HIGH** — The chosen `redeem-directory` option sends the full signed directory to every successful login. This widens the data audience beyond admins and enrolled host root. The plan correctly records it as an owner decision, but the code and documentation should make the response size and cache/privacy implications explicit. The current redeem flow returns the certificate after status validation and consumes the code ([`login.go:750–770`](../../../internal/server/login.go)).
- **MEDIUM** — Updating three files separately can leave a partially updated client configuration if the process fails between writes. The KRL-before-config order reduces one hazard, but there is no rollback or directory-level atomic switch.
- **MEDIUM** — The user receives host names from an admin-signed directory, but the plan should define removal semantics: a removed host name may remain in an existing managed known-hosts file until the next successful login or sync.

**Suggestions**

- Store generated files in a versioned directory and atomically switch a managed include, or add recovery logic for partial writes.
- Specify permissions, symlink policy and backup behavior for `~/.ssh` outputs.
- Test directory/KRL mismatch and partial write failures in addition to forged signatures.

**Risk Assessment** — **HIGH**. The trust design is strong, but the full-directory disclosure and multi-file update behavior deserve explicit treatment.

### 03-10

**Summary** — The positive and negative probes address a real blind spot: syntactic file validation does not prove that sshd enforces the KRL and principals mapping. The current renderer produces the normal account file only ([`render.go:65–87`](../../../internal/directory/render.go)).

**Strengths**

- The negative probe is revoked by explicit key, avoiding expiry as an alternative explanation for refusal.
- The plan tests `UsePAM yes` and `no`, and covers account exclusions and penalty behavior.
- Probe issuance is logged and included in audit reconstruction.

**Concerns**

- **HIGH** — The probe account is deemed safe because its password field is `*` and its shell is nologin. This is platform-dependent and must be tested on the actual target images, as the plan acknowledges. A misconfigured probe account with a usable shell could turn the probe certificate into a login credential.
- **MEDIUM** — The requirement to run a negative probe at most six times per hour is global to the host, but the plan says “once per apply” and the apply cadence can be driven by repeated state changes. The rate limiter must persist across restarts and failed applies.
- **MEDIUM** — `probe_pending` permits one poll before requiring probes. Define behavior if the signer is unavailable or probe issuance is repeatedly delayed; otherwise an enrolled host may remain indefinitely on last-good without clear convergence status.

**Suggestions**

- Persist probe attempt timestamps and test restart/reset behavior.
- Make the probe account check fail closed on unknown NSS/shadow formats and document that it must not be used for ordinary access.
- Include an explicit test that the probe private key cannot be used to open a session, not only that the client stops after PK_OK.

**Risk Assessment** — **HIGH**. This is security-critical self-test infrastructure, and a false positive would make rollback ineffective.

### 03-11

**Summary** — Machine proof-of-possession issuance and machine revocation complete the stated automation path. The existing certificate model already distinguishes user, host and machine CA roles ([`issue.go:44–68`](../../../internal/wire/issue.go)).

**Strengths**

- Role principals, extensions and TTL are computed by the signer from signed directory policy, not accepted from the request.
- Explicit-key revocation blocks both current certificates and future renewal.
- The plan tests that private keys remain local to the automation.

**Concerns**

- **HIGH** — “Smallest of machine cap, roles’ max TTLs and CA cap” is not enough to describe authorization if a machine is granted a role whose principals overlap a human role. The plan should establish whether machine-only principals are required or whether mixed role grants are intentional.
- **MEDIUM** — `machine renew --key FILE` introduces private-key parsing and passphrase handling into the main CLI. The plan says prompting happens on a terminal, but should require refusal when stdin is redirected and bounded reads/zeroing of decrypted key material.
- **MEDIUM** — Subject revocation must exclude probe identities by a reserved prefix. The plan does reserve `probe.` names, but should also prevent future identity formats from colliding with that namespace.

**Suggestions**

- Add cross-type tests for a machine key reused as a host key, a probe key or a revoked key.
- Test renewal with an expired/disabled machine and a stale directory on the signer.
- Keep all private-key file reads behind a narrow helper with permission checks and no key material in errors.

**Risk Assessment** — **HIGH**. The signer-owned authorization is appropriate, but role overlap and CLI private-key handling need explicit security rules.

### 03-12

**Summary** — The two-ceremony CA rotation model is a sound fit for the existing root-signed bundle chain. Current bundles allow only `active`, `next` and `retired`, require exactly one active CA per role, and reject duplicate keys ([`bundle.go:107–114`](../../../internal/trust/bundle.go), [`bundle.go:161–215`](../../../internal/trust/bundle.go)).

**Strengths**

- It requires next-key trust before switching signer issuance.
- The draining end time includes role TTL plus clock-skew allowance.
- It preserves old bundle vectors and covers boundary conditions.

**Concerns**

- **HIGH** — The signer schema currently has one key per role and `checkBundleKeys` requires each active key to match the initial key ([`trust.go:300–315`](../../../internal/signer/trust.go)). The plan’s generation table and fingerprint selection must be integrated into every backend and startup path, not only `PrepareGeneration`; otherwise install may succeed but signer restart will fail.
- **MEDIUM** — `trusted_until` is interpreted by agents’ local clocks. A host clock ahead can drop the old CA early. The plan should require clock-health gating or a safety margin beyond the claimed 300 seconds.
- **MEDIUM** — Agent/client behavior for a CA in `draining` is described in multiple plans. Ensure both use the same exact boundary and timestamp parser.

**Suggestions**

- Add signer restart tests for every backend and for a mixed active/next/draining bundle before the e2e.
- Reject a switch if any enrolled host reports a stale heartbeat, even though server convergence is not an authority proof.
- Add skewed-agent-clock tests around `trusted_until`.

**Risk Assessment** — **HIGH**. Rotation changes signer storage, trust bundle semantics and agent behavior simultaneously.

### 03-13

**Summary** — This plan extends rotation to log and ops keys and adds emergency CA replacement. The current checkpoint origin is derived from the log key ([`checkpoint.go:26–31`](../../../internal/tlog/checkpoint.go)); the current `appendLocked` signs every new checkpoint with the signer’s current checkpoint signer ([`logstate.go:395–433`](../../../internal/signer/logstate.go)).

**Strengths**

- It makes log-key transitions root-authorized and preserves audit verification across key generations.
- It plans to rotate the KRL signing authority and have the agent retain last-good state on mismatch.
- It limits emergency revocation of CA keys to retired keys.

**Concerns**

- **HIGH** — A log-key change creates a new checkpoint origin, not merely a new signature on the same origin ([`checkpoint.go:26–31`](../../../internal/tlog/checkpoint.go)). The plan must specify a cryptographic continuity statement that binds the old log’s final checkpoint to the new origin and tree size. A root-signed successor authorizes the key, but does not alone prove that the new checkpoint continues the old Merkle tree rather than starting another tree.
- **MEDIUM** — The plan describes the bundle-install leaf being checkpointed under the old key and later checkpoints under the new one. The current `InstallBundle` appends the bundle-install leaf through the existing log writer ([`trust.go:278–293`](../../../internal/signer/trust.go)); switching signer state must be atomic with the database commit and restart reconstruction.
- **MEDIUM** — “First start republishes with the new ops key” needs a clear transition when the stored KRL state is signed by the previous key and the new bundle is installed but not yet propagated to agents.

**Suggestions**

- Add a signed transition record containing old origin, old size/root, new origin and the same tree size, verified by both keys or by the root-signed successor.
- Test that a forged new checkpoint with a valid new log key but a different tree fails audit verification.
- Specify rollback behavior if the new log key is unavailable after bundle installation.

**Risk Assessment** — **HIGH**. The key transition may be root-authorized yet still fail to establish Merkle-history continuity unless the handoff is explicit.

### 03-14

**Summary** — The separate `Match User` trust scope is a strong way to isolate break-glass access. Existing bundle validation already tracks key reuse across bundle roles ([`bundle.go:161–172`](../../../internal/trust/bundle.go)), which the new field should extend.

**Strengths**

- Break-glass CA is excluded from global user CAs and receives its own principals and KRL files.
- The plan tests both account scoping and resilience to corrupt main trust files.
- Offline signing avoids making emergency access depend on the online signer.

**Concerns**

- **HIGH** — The plan’s test says break-glass remains available with an unparsable main CA line, relying on `Match`-scoped CA settings overriding the global setting. The tests must cover the actual packaged OpenSSH versions, not only configuration parsing or the current source behavior.
- **MEDIUM** — The proposed custody label is parsed from a public-key comment. Comments are not trustworthy metadata; the root ceremony must validate custody from an explicit operator choice rather than accepting an arbitrary `custody=` comment.
- **MEDIUM** — The agent only “reports” emergency-account problems and does not block apply. That is appropriate for normal availability, but status must make an unusable break-glass path prominent and distinguish “configured” from “usable.”

**Suggestions**

- Require an explicit custody flag when adding the break-glass key and compare it to the key’s selected backend.
- Test password-required sudo and account lock states on each distro image.
- Make preflight/status show a clear break-glass readiness state and its specific failed checks.

**Risk Assessment** — **HIGH**. The isolation model is strong, but its safety depends on `Match` semantics and trustworthy custody metadata.

### 03-15

**Summary** — The plan rehearses and then installs the one-way trust-root rotation, while keeping private ceremony material off the network. Existing bundle verification requires the successor chain and root signatures ([`verify.go:343–391`](../../../internal/trust/verify.go)).

**Strengths**

- A scratch rehearsal precedes the real ceremony.
- The install is approved by a bundle hash and re-verified on the signer host.
- It records the directory rebind and destroys superseded TEST roots only after verification.

**Concerns**

- **HIGH** — The plan asks Claude to prepare a next CA and a policy successor, then has the owner sign them offline. It should explicitly verify that the exact prepared public keys and policy hash are the ones included in the final bundle before the owner signs; the current trust verifier checks the policy hash and signature ([`verify.go:376–382`](../../../internal/trust/verify.go)).
- **MEDIUM** — Reinitializing client pins and rebinding the directory are separate owner actions after bundle installation. The transition rule must guarantee the old directory remains authorized until v7, or the sequence risks login outage.
- **MEDIUM** — The test command list is described as read from the runbook or generated from a shared list. Prefer a single generated source; otherwise rehearsal and operator instructions can drift.

**Suggestions**

- Have the rehearsal consume the exact checked-in command block and fail if it differs from the expected arguments.
- Capture bundle, policy, directory and root-set hashes in the offline transcript.
- Add an explicit recovery procedure if the signed bundle verifies but signer installation or directory rebind fails.

**Risk Assessment** — **HIGH**. The process is careful, but it is an irreversible trust migration with multiple post-signing steps.

### 03-16

**Summary** — The plan makes dogfood evidence a condition of phase completion and correctly separates reachable from offline hosts. It also has meaningful corroboration requirements across audit exports and sshd journals.

**Strengths**

- It records measured revocation delays rather than claiming a fixed sub-minute guarantee.
- It keeps host aliases and addresses out of committed documentation.
- It includes adoption, no-TOFU, corruption, break-glass, machine and optional rotation drills.

**Concerns**

- **HIGH** — Task 1 allows a `no_loopback_listener` preflight refusal to be recorded and handed to the owner, but Task 2 requires each enrolled host to apply state and pass self-tests. Under the chosen `loopback-only` decision, the refusal prevents those steps until the host’s sshd configuration is changed. Make this a blocking owner checkpoint before enrollment, not a note.
- **HIGH** — The Proxmox host is included in the dogfood set, but its special cluster SSH files are a known constraint. The plan relies on tests proving paths are untouched; require preflight and a rollback/console-access plan before enabling the unit there.
- **MEDIUM** — The corrupt-file drill directly overwrites the target of `current/revoked.krl`. Because generation directories are supposed to be immutable, this is an exceptional tampering simulation; restore and verify the exact prior bytes even if the apply does not create a new generation.
- **MEDIUM** — All hosts are described as reachable prerequisites in the automated checks, while the plan says offline hosts are skipped. The check should derive the expected host list from recorded availability rather than hard-code zima and the Proxmox nodes.

**Suggestions**

- Add a blocking preflight decision for every `no_loopback_listener` host and verify the manually changed listener before approval.
- Keep a console or out-of-band recovery route verified before Proxmox enrollment.
- Make dogfood evidence commands emit host alias, timestamp, serial and key ID into the private evidence directory automatically.

**Risk Assessment** — **HIGH**. The planned drills are comprehensive, but the loopback prerequisite and Proxmox lockout risk need explicit gates before applying changes.

### Overall Assessment

The sequence is coherent: revocation and signed formats first, apply engine before transport, then host/machine issuance, rotation, break-glass and dogfood. The main cross-plan risks are the applier’s claim of cross-file atomic consistency, shared spool permissions, log-key continuity across a changed checkpoint origin, and dogfood hosts that cannot reach sshd over loopback.

Repository inspection confirms that the plans build on real patterns: canonical signed documents, signer transactions, fail-closed audit verification and pinned client trust. The review is limited to the current source snapshot; the Phase 3 agent/KRL packages do not yet exist, so their proposed behavior remains unverified until implementation and integration tests. I did not run tests.

---

## nemotron (Ollama cloud) Review

> Ran without repository access (plan text only) — down-weighted.

REVIEWED-WITHOUT-REPO-ACCESS

# Cross-AI Plan Review: Phase 3 — Linux Agent and Revocation

### Plan Coverage Manifest
Total plans: 16  
Plan IDs: 03-01, 03-02, 03-03, 03-04, 03-05, 03-06, 03-07, 03-08, 03-09, 03-10, 03-11, 03-12, 03-13, 03-14, 03-15, 03-16

---

### 03-01 — Phase Tracer: Revocation End-to-End

#### Summary
This plan establishes the critical revocation path: CLI → server → signer → KRL → sshd enforcement without reload. It adds the installation ID to the trust bundle (D-04), builds the KRL encoder, wire formats, signer revocation logic, audit log leaf kinds (revoke, krl_publish), and an e2e test that proves `ssh-keygen -Q` and real sshd (9.5p1, 10.5p1) honor a KRL swapped via `rename(2)` with no signal. The plan explicitly defers strict parsing, key-ID/key/subject revocation, hourly re-publish, pruning, and full audit verify rules to 03-03.

#### Strengths
- **Correct architectural cut**: Proves the lockout-prone path before any agent exists. The e2e test `TestRevokeSerialEndToEnd` directly addresses the STATE blocker "unknown whether sshd re-reads RevokedKeys without a reload" on both CI OpenSSH versions.
- **Installation ID binding (D-04)**: The bundle field, manifest repetition, and successor chain rule (`ErrVersionChain` on change/drop) are pinned early, so later plans (03-04, 03-07, 03-15) can rely on a stable format.
- **Threat model alignment**: Revocation authorized only by policy-admin SSHSIG verified in the signer; server forwards bytes unchanged; KRL manifest signed by ops key with installation ID, version monotonicity, and digest check. Prohibitions block signature sections, extensions, bitmaps, and non-SSHSIG revocation.
- **Interim audit behavior**: `audit verify` refuses kinds 9/10 via the existing default branch until 03-03 adds real rules — no partial verify logic ships.

#### Concerns
- **HIGH — KRL encoder completeness for this tracer**: The plan encodes only certificate sections (type 1) with serial lists (0x20) and ranges (0x21). It explicitly omits key-ID (0x23), explicit-key (section 2), and bitmap (0x22) subsections. The e2e test only exercises serial revocation. If the encoder has a bug in range merging or CA-key ordering, it won't be caught until 03-03's oracle tests. *Open question: Does the tracer's `Encode` handle the adjacency edge (serials s and s+1 → one 0x21 range) correctly for all insertion orders? The plan asserts it does, but the test only covers one order.*
- **MEDIUM — `ssh-keygen -Q` oracle dependency**: The e2e runs `ssh-keygen -Q` on the candidate KRL *before* the swap. This assumes the oracle binary is present and behaves identically to sshd's internal KRL parser. The plan notes this settles the re-read question, but a divergence between `ssh-keygen -Q` and sshd's revocation check would be a silent gap. *Open question: Is there a test that `ssh-keygen -Q` and sshd's actual revocation decision agree on the same KRL file?*
- **MEDIUM — No network partition test**: The tracer assumes the server is reachable and the signer responds. A partition where the agent (later) cannot fetch a new KRL but the old one expires or is corrupted is not exercised here (deferred to 03-08/03-14).
- **LOW — Golden vector stability**: Five new vectors are added. The plan says they're built from "fixed literals" but doesn't specify the seed values. *Open question: Are the vector seeds documented so a future maintainer can regenerate them deterministically?*

#### Suggestions
1. Add a unit test in this plan that encodes a set with serials {5,6,9,10,11} and asserts the output has one 0x20 list [5,9] and one 0x21 range [10,11] — the adjacency edge called out in must_haves.
2. In the e2e, after the swap, also run `ssh-keygen -Q -f current/revoked.krl <B's cert>` to confirm the oracle still says "not revoked" for the control certificate.
3. Document the vector seed literals in the SUMMARY or a comment in the test file.

#### Risk Assessment: MEDIUM
The tracer proves the core revocation path end-to-end on real sshd, which is the highest-value validation for this phase. The missing parser strictness and other revocation targets are explicitly deferred to 03-03 with a clear boundary. The main risk is a subtle KRL encoding bug that only manifests with key-ID or explicit-key sections, but those are not used in this plan's scope.

---

### 03-02 — Phase 2 Follow-ups and Requirement Rewording

#### Summary
This plan closes eight folded Phase 2 todos: three code fixes (agent check before issuance, lifetime recomputed at `Add`, redeem window bound), two negative tests (no non-passkey sign-in, login never writes key to disk), three doc fixes (restore replay, Windows expiry timing, plan-drift correction), and the owner-approved rewording of AGENT-01, REVOKE-01, PLAT-01 plus ROADMAP updates. No new features; purely corrective.

#### Strengths
- **Closes verified gaps**: The three code fixes address real issues found in Phase 2 verification (E-IN-01, E-IN-02, C-IN-01). The negative tests enforce the prohibitions the owner accepted in 02-10/02-12 with mutant checks.
- **Honest documentation**: The restore runbook now says "replay lost directory versions from export" with the 409 `credential_not_pending` limit; `needs-hardware.md` records the measured Windows expiry window (3.9s before – 1.1s after `valid_before`, 5s resolution, skew unmeasured) without overclaiming.
- **Requirement texts match Phase 3 scope**: AGENT-01 now pins TLS root SPKI set + hostname + trust root + installation ID; REVOKE-01 is CLI-only (UI moves to Phase 4); PLAT-01 excludes RHEL 8 and FIPS mode per D-17/D-18.
- **Phase 2 plans left untouched**: The plan-drift todo is closed by noting 02-VERIFICATION.md overrides are the record, preserving the passed verification.

#### Concerns
- **HIGH — `connectLoginAgent` ordering change**: Moving the agent connection before the `begin` call changes the failure mode: a user with no usable agent now gets an error before any server request. The plan's mutant test (temporarily reverting the order) should confirm the old code would have issued a certificate nobody holds. *Open question: Does the Windows `winagent.Ensure` owner check + `List` correctly detect an unusable agent in all cases (e.g., agent running under different user, named pipe permissions)?*
- **MEDIUM — Redeem window deadline calculation**: The fix reads the clock after `currentStatus` and sets a signer deadline of `CreatedAt + 295s`. If `currentStatus` itself takes >5s (e.g., under load), the deadline could be in the past. The plan says "fail closed with the expired-code answer when that deadline has already passed" — but does the signer receive a context with a past deadline, or is the request refused before calling the signer? *Open question: Is the deadline check `now >= deadline` done before the signer RPC, or does the signer handle a past-deadline context?*
- **MEDIUM — `TestNoNonPasskeySignInRoute` pattern matching**: The test scans registered mux patterns for keywords (login, signin, password, totp, etc.). A future route like `/api/v1/auth/passkey` would pass the keyword filter but might still be a sign-in route. *Open question: Is the allowlist of permitted session-creating routes exhaustive and maintained?*
- **LOW — Eight todo moves**: Mechanical but must be done atomically in the PR. The verification step checks all eight are in `completed/` and none in `pending/`.

#### Suggestions
1. In the redeem fix, add an explicit `if now >= deadline { return expiredCodeError }` before creating the signer context, so the refusal is logged with the correct code and the signer is never called.
2. For `TestNoNonPasskeySignInRoute`, maintain the allowlist as a package-level `var permittedSessionRoutes = []string{...}` so additions are deliberate and visible in diffs.
3. Add a test case where `currentStatus` stalls for 300s (injected clock) and confirm the redeem is refused unburnt.

#### Risk Assessment: LOW
This is a cleanup plan with no new attack surface. The fixes are targeted, tested with mutants, and the requirement rewording reflects owner decisions already made. The main risk is a regression in the login flow on Windows, but the e2e matrix (9.5p1, 10.5p1) and the `TestLoginAgentUnix` order assertion mitigate this.

---

### 03-03 — KRL Complete: Parser, Oracle, All Targets, Re-publish, Audit Rules

#### Summary
This plan completes REVOKE-01/02/03: adds revocation by key-ID, explicit key, and subject (user); a strict KRL parser (`Parse`) that refuses signature sections, extensions, bitmaps, unknown types, trailing bytes, serial 0, bad ranges, unsorted/duplicate hashes; oracle tests in both directions (encode→`ssh-keygen -Q`, `ssh-keygen -k` spec→parse); hourly re-publish (D-10) with signed `issued_at`; safe pruning (serial/key-ID entries dropped after `ValidBefore + 300s`, explicit keys never); and full `audit verify` rules for kinds 9 (revoke) and 10 (krl_publish) that re-derive the KRL from the log and compare SHA-256.

#### Strengths
- **Strict parser with named refusals**: Every malformed KRL case has a sentinel error (`too_large`, `bad_magic`, `signature_section`, `unknown_subsection`, `serial_zero`, `range_lo_gt_hi`, `unsorted_sha256`, etc.). This makes fuzzing and debugging deterministic.
- **Oracle in both directions**: Forward (our KRL → `ssh-keygen -Q` refuses exactly the revoked set) and reverse (`ssh-keygen -k` spec with serial/id/key lines, including bitmap subsection 0x22 → our `Parse` yields same semantic set). This is the strongest possible validation of the encoder.
- **Pruning with 300s grace**: Entries leave the KRL only after `ValidBefore + 300s ≤ issued_at`, matching the signer's freshness window. Explicit-key entries (from `revoke key`) are never pruned. The audit verify applies the same rule.
- **Audit verify now proves KRLs**: `verifyKRLPublish` re-encodes from logged revocations with the same pruning rule and compares `krl_sha256` to the manifest. A tampered KRL or a skipped publish is detected.
- **Subject revocation (D-09)**: `keyroster revoke user <name>` finds all live serials from the signer's issuance table (within `maxTTL + 300s`), records them in one transaction, and disables the user in the directory.

#### Concerns
- **HIGH — Subject revocation completeness**: The signer resolves live certificates by scanning its own issuance rows (`ca_role=user`, `issued_at ≥ now - (maxTTL+300s)`, `key_id` parses to the user). A certificate issued by a *restored older signer state* or by a *CA key outside this installation* would not be found. The plan acknowledges this: "runbook tells the admin to revoke such a certificate by key." *Open question: Is there a test for the "certificate not found by subject" case, and does the CLI error message clearly direct the admin to `revoke key-id` or `revoke key`?*
- **HIGH — Re-publish loop interaction with pruning**: The `krlLoop` runs every 60s, publishes when `last_publish ≥ 3600s old`. If pruning removes entries between publishes, the KRL version increments but the revocation set shrinks. The manifest's `issued_at` is the publish time, so a certificate that expired 299s ago at publish T is included, but at T+3600 it's pruned. *Open question: Does the audit verify's pruning rule use the manifest's `issued_at` (correct) or the current time (wrong)? The plan says "at the manifest's issued_at" — this must be enforced in `verifyKRLPublish`.*
- **MEDIUM — Key-ID revocation semantics**: `TargetKeyID` uses KRL subsection 0x23 (key ID). The plan says "a key ID matches exactly one certificate (our key IDs contain the request ID)". But `ssh-keygen -Q` with a key-ID KRL entry: does it revoke *all* certificates with that key ID, or only the one matching the CA? *Open question: The OpenSSH KRL spec says key-ID subsections are per-CA-section. Does our encoder put the key-ID subsection under the correct CA section?*
- **MEDIUM — Fuzz coverage for new parser**: `FuzzParseKRL` is added, but the plan doesn't specify corpus seeds. *Open question: Are the 03-01 golden vectors and the new `krl_full_v1.hex` added as fuzz seeds?*
- **LOW — Runbook updates**: The folded todo `2026-10-23-runbooks-say-disable-does-not-end-issued-certificates.md` is closed here. The plan says enroll-user.md and host-setup.md must state that disable/role-revoke/unmap only stop *new* certificates, and `revoke user` cuts off issued ones. *Open question: Are both runbooks updated in the same PR, or is one missed?*

#### Suggestions
1. Add a test: `revoke user alice` where alice has a certificate issued by a CA key not in the current bundle (simulate by inserting a row with a different `ca_key` fingerprint). Verify the CLI prints "0 serials revoked" and suggests `revoke key`.
2. In `verifyKRLPublish`, explicitly assert that pruning uses `manifest.IssuedAt` (parsed from the manifest) not `time.Now()`.
3. Add a unit test for key-ID revocation: encode a KRL with a key-ID subsection under CA-A, verify `ssh-keygen -Q` revokes a cert with that key-ID under CA-A but not a cert with the same key-ID under CA-B (if such a case is possible).
4. Seed `FuzzParseKRL` with the golden vectors and with `ssh-keygen -k` generated KRLs containing bitmap subsections.

#### Risk Assessment: MEDIUM
This plan delivers the complete revocation machinery. The strict parser and bidirectional oracle are strong. The main risks are (a) subject revocation missing certificates from external/old CA keys (mitigated by runbook guidance), and (b) pruning/re-publish interaction causing a window where a revoked cert is temporarily absent from the KRL (mitigated by the 300s grace matching the signer's freshness window). Both are documented assumptions.

---

### 03-04 — Installation-Bound Directory with Hosts and Machines

#### Summary
This plan binds every admin-signed directory to the installation ID (D-04, pulled from the 2026-10-16 todo), adds `Hosts` and `Machines` arrays to the directory, adds a `PoP` field to the root-signed policy (D-15/D-16), and provides CLI commands `host add/remove/list`, `host principals --host`, `machine add/remove/list`, `directory rebind`. The signer enforces installation ID match on install; audit verify does the same. An e2e test proves a directory with the correct ID installs, a different ID is refused, and `host principals --host` renders the exact `AuthorizedPrincipalsFile` the agent will use.

#### Strengths
- **Installation ID as last field (omitempty)**: Maintains byte-identical parsing of Phase 1/2 directory vectors. Non-canonical empty arrays/strings are refused.
- **Host entry validation**: Exactly one host group (D-11), keys Ed25519/ECDSA only (RSA refused), 1-8 keys/principals sorted unique, no key or principal on two hosts. Principals are DNS names or IP literals, no wildcards.
- **Machine entry validation (D-15)**: Key unique across machines and distinct from host keys; roles checked against the CA each role is used under (user CA cap for user-granted roles, machine CA cap for machine-only roles); `max_ttl_seconds ≤ machine CA cap`.
- **Policy PoP switch**: `keyroster root successor-policy --pop-hosts --pop-machines` adds the field; successor never turns a flag off in Phase 3.
- **Single principals renderer**: `directory.RenderPrincipalsFile` is the only renderer (P2 D-07), used by `host principals --host` and later by the agent.

#### Concerns
- **HIGH — Host principals uniqueness across hosts**: The plan says "no principal appears on two hosts". This is enforced in `Validate`, but what about a principal like `deploy` that is a role principal granted to multiple hosts via host groups? The directory's `Host.Principals` are the *certificate principals* (host names for host certs), not the role principals for user certs. *Open question: Is the uniqueness check on `Host.Principals` (certificate principals) or on the rendered `AuthorizedPrincipalsFile` entries (role principals)? The plan says "host principals: 1-8, sorted, unique... no principal appears on two hosts" — this must mean certificate principals (host names), which is correct for REVOKE-04's exact-name trust.*
- **MEDIUM — Machine role TTL cap logic**: "A role granted to any user or group keeps the user CA cap; a role granted only to machines is checked against the machine CA cap." This requires scanning all directory entries (users, groups, hosts, machines) to determine if a role is "machine-only". *Open question: Is this check done at directory install time (signer) and at audit verify time? What if a role is granted to a user *and* a machine — does it use the user CA cap (more restrictive) or machine CA cap?*
- **MEDIUM — `directory rebind` only sets installation ID**: The plan says it "writes the next version with every list unchanged and only the installation ID set from the verified bundle". But if the installed directory already has a *different* installation ID (e.g., cloned staging), `rebind` refuses. The only way to change the ID is a new root-signed bundle with a successor that changes it — which `checkSuccessorChain` refuses (`ErrVersionChain: installation_id changed`). *Open question: How does a cloned staging instance get its own installation ID? The 03-01 answer (random-128) says "a staging instance cloned from the same genesis bundle shares whatever is derived from it" — so it must run its own genesis ceremony. Is that documented?*
- **LOW — Host group remove refusal**: "A host group named by a host cannot be removed (the hostgroup remove command refuses with the host's name)." This is a CLI check; what if the directory is edited manually and installed via the admin pipeline? The signer's `CheckSuccessor` should also refuse a directory that removes a host group still referenced by a host.

#### Suggestions
1. Clarify in the plan: `Host.Principals` are the *certificate principals* (host names/IPs for host certificates), not user role principals. The uniqueness constraint is correct for host cert trust (REVOKE-04).
2. Add a signer-side check in `CheckSuccessor` that no host group is removed while a host references it.
3. Document the staging-instance workflow: "To create a separate installation, run `keyroster root init` with new roots; the new genesis bundle gets a fresh installation ID."

#### Risk Assessment: LOW
The directory format changes are additive (omitempty last fields), backward-compatible with existing vectors, and the installation ID binding is the critical one-way decision already made in 03-01. The host/machine validation rules are strict and tested. The main open questions are about role cap logic and staging instances, which are operational concerns not security bugs.

---

### 03-05 — Apply Engine Offline: Atomic Generations, Self-Test, Rollback

#### Summary
This plan builds the agent's apply engine — the component that writes sshd config, CA keys, principals files, and KRL atomically, validates with `sshd -t`, reloads, self-tests, and rolls back on failure. It includes the owner decision checkpoint (Task 1) for D-05 vs D-06: how a root applier "without network access" reaches sshd for the self-test. The plan is written for the recommended answer `loopback-only` (applier dials only loopback for self-test; no HTTP/TLS/RPC code; systemd unit has `IPAddressDeny=any, IPAddressAllow=localhost`). The e2e test `TestAgentApplyEndToEnd` proves first apply (reload), revocation/principal change (no reload, enforced), and rollback on self-test failure (sshd stopped).

#### Strengths
- **Owner decision before code (Task 1)**: The D-05/D-06 collision is resolved by the owner *before* any applier code exists. The answer is recorded in `$HOME/keyroster-ceremony/phase3/d05-answer.txt` and the SUMMARY line `D-05 network answer: <id>`. Subsequent plans (03-06 through 03-10) check this line as a precondition.
- **Dead-man apply sequence**: Pending marker → write generation → `sshd -t` → swap `current` symlink (rename+fsync) → reload only if drop-in/paths changed → self-test → commit (point `last-good`) or rollback (restore previous drop-in, reload, self-test). Crash recovery: on start, a pending marker triggers rollback to `last-good` before anything else.
- **Concurrency control**: Exclusive `flock` on `<state>/apply.lock` serializes apply runs.
- **Pre-swap validation**: Every `user_ca_keys` line checked with `ssh-keygen -l -f`; non-empty `revoked.krl` checked with `krl.Parse` and `ssh-keygen -Q` against a fresh key.
- **sshd re-read matrix test (Task 3)**: `TestSshdRereadsTrustFiles` on 9.5p1 and 10.5p1 proves revoked serial, removed principal, removed CA, corrupt KRL, empty KRL, and CA line position effects — all with unchanged sshd PID and no signal.
- **Dependency firewall per binary**: `scripts/dep-firewall.sh` and `scripts/capslock-check.sh` extended for `keyroster-agent`; depguard rule `agent-apply-no-http` denies net/http, crypto/tls, net/rpc in internal/agent and cmd/keyroster-agent.

#### Concerns
- **HIGH — Owner decision checkpoint is blocking**: If the owner chooses anything other than `loopback-only`, Tasks 2-4 stop and the plan must be revised. The plan explicitly says "for any other answer, stop before Task 2... return `## CHECKPOINT REACHED`". This is correct process but means the plan cannot be executed until the owner responds. *Open question: Has the owner already provided the answer, or is this a future blocker?*
- **HIGH — Self-test dials loopback only**: The `loopback-only` answer means a host whose sshd listens *only* on a tailnet address (no `ListenAddress 127.0.0.1`) is refused with `no_loopback_listener`. The plan says "its owner must add `ListenAddress 127.0.0.1` to sshd_config by hand, because the agent never edits it (D-07)". *Open question: Do any of the dogfood hosts (laptop, zima, Proxmox test VM, Proxmox host) have sshd listening only on tailnet? The 02-14 SUMMARY and host-setup.md contain no ListenAddress; 03-16's preflight will show it.*
- **MEDIUM — `sshd -T` parsing for listen addresses**: The self-test gets listen addresses from `sshd -T`. If sshd has `ListenAddress 100.64.0.5` (tailnet) and no loopback, the agent refuses. But what if sshd has `ListenAddress 0.0.0.0` (wildcard)? The plan says "loopback 127.0.0.1 and ::1 when sshd listens on a wildcard; a configured loopback address as is". This assumes the wildcard includes loopback, which is true for OpenSSH. *Open question: Is this tested on all seven distro images?*
- **MEDIUM — Drop-in content is fixed**: Three lines (`TrustedUserCAKeys`, `RevokedKeys`, `AuthorizedPrincipalsFile`) with a header comment. The agent never writes `/etc/ssh/sshd_config`. This is correct per D-07, but what if a distro's sshd_config.d include order places another drop-in *after* 00-keyroster.conf that overrides these keywords? The plan says "after writing the drop-in, `sshd -T` does not show our three values; the drop-in is removed again before any reload" — this is the `no_dropin_dir` refusal in 03-06. Good.
- **LOW — Generation cleanup**: "Older generations beyond the newest 5 are removed." What if a rollback needs generation N-6? The plan says "a generation that `current` or `last-good` names is never deleted", so rollback always has at least those two. But if `last-good` points to N-6 and `current` to N-5, and a new apply creates N+1, then N-6 could be deleted while `last-good` still points to it. *Open question: Does the cleanup logic check `last-good` before deleting?*

#### Suggestions
1. In the generation cleanup, explicitly exclude the generation pointed to by `last-good` (read the symlink target) from deletion.
2. Add a test case: `last-good` points to gen 3, `current` to gen 4, apply creates gen 5 → gen 3 must not be deleted.
3. In the self-test, when dialing loopback, set `SSH-2.0-` banner read timeout to 5s (already in plan) but also handle the case where sshd accepts the connection but the handshake hangs (e.g., `MaxStartups` limit). The plan says "a 'no supported methods' end is success" — this is correct for a probe that stops at auth.

#### Risk Assessment: MEDIUM
The apply engine is the lockout-critical component. The design is sound: atomic generations, pre-swap validation with host tools, dead-man sequence with rollback, and the sshd re-read behavior pinned by test on both CI OpenSSH versions. The `loopback-only` decision is the key architectural choice; if the owner confirms it, the risk drops to LOW. The main residual risk is a host with no loopback listener, which is caught at preflight (03-06) with a clear fix.

---

### 03-06 — Distro Detection, D-07 Refusals, D-08 Takeover, Drift Checks

#### Summary
This plan makes the apply engine safe across distributions: detects sshd binary/config/reload path from the running service (systemd `systemctl show`, OpenRC `/etc/conf.d/sshd`), refuses unsafe layouts (D-07: no sshd_config.d, foreign trust settings, no loopback listener, missing ssh-keygen, account excluded by AllowUsers/DenyUsers), takes over *only* the exact Phase 2 runbook layout (D-08), and implements periodic drift detection via `sshd -T -C` per account (AGENT-05). A seven-image distro container matrix (debian:12, debian:13, ubuntu:24.04, ubuntu:26.04, almalinux:9, alpine, archlinux) runs in CI as required checks.

#### Strengths
- **Service detection from running system**: Uses `systemctl show -p ExecStart,Id,ActiveState` for ssh.service/sshd.service, parses binary path and `-f` config argument. Handles Ubuntu socket activation (ssh.socket active, ssh.service inactive → `Reload=none`).
- **D-07 refusals with explanations**: Each refusal code (`ssh_keygen_missing`, `no_dropin_dir`, `foreign_trust_setting`, `no_loopback_listener`, `account_excluded`, `rhel8_unsupported`, `fips_unsupported`) includes a human sentence with the fix.
- **D-08 exact takeover**: Only the precise Phase 2 layout (50-keyroster.conf with two runbook lines, keyroster_user_ca.pub with active user CA key, principals/ matching `RenderPrincipalsFile` byte-for-byte, no keywords in sshd_config) is adopted. Agent proves its settings win with `sshd -T -C` per account, reloads, self-tests, *then* removes old files. Any other layout refused with lines to change.
- **Drift detection (AGENT-05)**: `keyroster-agent check` runs `sshd -T` and `sshd -T -C user=<account>,host=127.0.0.1,addr=127.0.0.1,laddr=<l>,lport=<p>` for every managed account, compares keywords and re-hashes generation files. Reports drift, never fixes foreign files.
- **Distro matrix in CI**: Seven images, each pinned by sha256 digest, run `TestDistroApply`, `TestDistroDrift`, `TestDistroRefusals`, `TestDistroAdoptPhase2`, `TestDistroFacts`. Results recorded in SUMMARY. Required checks added to main-integrity ruleset (owner applies, D2).

#### Concerns
- **HIGH — RHEL 8 and FIPS exclusion (D-18)**: The plan documents these as unsupported. RHEL 8 lacks sshd_config.d; FIPS mode rejects Ed25519 CAs. This is an owner-approved scope reduction. *Open question: Is there a clear migration path for RHEL 8 users (upgrade to 9) or is this a permanent exclusion? The plan says "both exclusions are documented" — but does the documentation explain *why* and *what to do*?*
- **HIGH — `account_excluded` is report-only**: The plan says "an account they exclude is reported in the preflight and check output, never edited". But if `AllowUsers alice` excludes the managed account `bob`, the agent will still write a principals file for `bob` that sshd ignores. The user `bob` cannot log in via certificate, but the agent reports success. *Open question: Should `account_excluded` be a refusal (preflight fails) rather than a report? The plan says "report only" — but this could silently break access.*
- **MEDIUM — Drift check uses loopback client addresses**: `sshd -T -C user=<account>,host=127.0.0.1,addr=127.0.0.1,laddr=<l>,lport=<p>`. A `Match Address 100.64.0.0/10` block (tailnet) that overrides trust settings for remote clients would not be detected. The plan flags this as an assumption (AGENT-05 unclassified, unresolved). *Open question: Is there a plan to support per-host client address lists for drift checks in a later phase?*
- **MEDIUM — Systemd/OpenRC reload paths UNVERIFIED**: The container matrix exercises the `signal` strategy only. The systemd smoke test (03-08) runs on ubuntu-24.04 runner; OpenRC and other distros' service managers stay UNVERIFIED until 03-16 dogfood. *Open question: Will the Proxmox host (Debian 13, systemd) and zima (Ubuntu 26.04, systemd) cover the systemd path in 03-16?*
- **LOW — `TestDistroFacts` records `casignaturealgorithms`**: This is for assumption A5 (FIPS). The plan says "alma:9's `sshd -T` casignaturealgorithms is recorded in the SUMMARY". Good, but *open question: Is this value used to adjust the CA key algorithm choice, or just documented?*

#### Suggestions
1. Change `account_excluded` from report-only to a preflight refusal (exit 3) with a clear message: "Account <name> is excluded by AllowUsers/AllowGroups/DenyUsers/DenyGroups; add it or adjust the rule." Silent failure is worse than a loud refusal.
2. In the distro matrix, add a test case with a `Match Address` override to confirm it's *not* detected by the current drift check (documenting the gap).
3. Document the RHEL 8/FIPS exclusion with a "what to do" section: upgrade to RHEL 9, or use a non-FIPS kernel, or wait for a future P-256 CA generation (deferred idea).

#### Risk Assessment: MEDIUM
The distro matrix and exact takeover logic are strong. The `account_excluded` report-only behavior is a potential silent failure mode. The RHEL 8/FIPS exclusion is a known scope limit. The UNVERIFIED service managers are a gap for 03-16 dogfood but acknowledged.

---

### 03-07 — Agent Transport: Join Tokens, Enrollment, mTLS, Fetcher/Applier Split

#### Summary
This plan connects the agent to the fleet: one-time join tokens (`keyroster host join-token`), enrollment with host-key proof-of-possession (PoP), admin approval (`keyroster host approve`) that signs the host into the directory, a pull-only mTLS transport with a closed operation set (enroll, state), and the fetcher/applier split (D-05). The fetcher (`keyroster-agent-fetch`, unprivileged) handles all network I/O, writes only the spool; the applier (`keyroster-agent`, root) verifies everything against its own pins and applies. The server serves agents on a separate mTLS listener (`--agent-listen`) requiring a self-signed Ed25519 client cert; browser listener unchanged.

#### Strengths
- **Join token design**: 32 random bytes, stored as SHA-256 on server, TTL ≤ 3600s, single-use (conditional UPDATE marks used). CLI writes `kr-join-v1:` + base64url canonical JSON to a 0600 file, never stdout/logs.
- **Enrollment PoP**: Applier signs `EnrollPoP {domain, installation_id, token_sha256, identity_spki_sha256, host_keys, facts_sha256}` with *each* sshd host private key under SSHSIG `keyroster/agent-enroll/v1`. Server verifies token (unused, unexpired) and every signature. Nothing from the agent becomes a principal/name/group in the directory.
- **Approval = directory host entry**: `keyroster host approve` shows pending host's key fingerprints, identity fingerprint, facts for out-of-band comparison with `keyroster-agent identity` on the host. Server treats agent as approved only while installed directory has an active host entry with matching keys.
- **Separate mTLS listener**: Agent listener requires client cert (exactly one self-signed Ed25519); browser listener keeps `NoClientCert`. Disjoint route sets: agent mux only `/api/v1/agent/*`; browser mux no agent routes. `TestBrowserListenerUnchanged` ensures no regression.
- **Closed operation set**: Enroll (POST /api/v1/agent/enroll) and state (GET /api/v1/agent/state). No commands, scripts, paths, templates. Agent opens no listener. Only agent-initiated traffic to pinned server.
- **State response ordering**: Bundles and directories in ascending version order, at most 16 each, KRL when newer. Applier applies in order, refuses gaps/out-of-order, keeps last-good.
- **Installation ID enforcement**: Agent refuses any document (bundle, directory, KRL manifest) with a different installation ID.
- **Poll cadence (D-10)**: 60s ± 10s jitter. E2E test shows revocation refused within one poll after `keyroster revoke serial`.

#### Concerns
- **HIGH — Fetcher identity generation**: On first start, fetcher generates Ed25519 key + self-signed cert (CN=keyroster-agent, serial random, NotBefore now-1h, NotAfter +100y). Server ignores validity, pins SPKI. *Open question: What if the fetcher's clock is wildly wrong (e.g., 10 years off)? The cert's NotBefore/NotAfter are ignored by the server, but the key generation uses `crypto/rand` — is there any entropy concern on a fresh VM?*
- **HIGH — Enrollment host key readability**: Applier reads host private keys named by `sshd -T` hostkey lines to sign the PoP. The plan says "refusing `host_key_unreadable` for agent-held keys". But the agent runs as root; sshd host keys are typically root-readable only. *Open question: Is this tested on all distros where host key permissions might differ (e.g., sshd running as non-root on some configs)?*
- **MEDIUM — State response cap (16 versions)**: If an agent is offline for a long time and misses >16 bundle/directory versions, it will only get the latest 16. The applier refuses gaps (`bundle_chain_gap`). *Open question: How does an agent catch up if it misses more than 16 versions? The plan doesn't specify a "full sync" mode.*
- **MEDIUM — Server's `currentStatus` and `currentDirectory` for state response**: The tracer uses the server's cached current bundle/policy/directory/KRL. Chain catch-up (GetBundle, GetDirectoryVersion for older versions) is moved to Task 2. *Open question: Does the server's cache stay consistent with the signer's state under concurrent directory installs?*
- **LOW — Join token minting is owner-run**: The permission classifier refuses it for agents. This is correct (admin action) but means the homelab enrollment in 03-16 requires the owner to run commands manually.

#### Suggestions
1. Add a "full sync" endpoint or logic: if the agent's stored version is too far behind (gap > 16), the server could send a `full_sync` flag and the agent re-verifies from genesis. Or document that agents must not be offline that long.
2. In the fetcher, add a startup check: if the generated self-signed cert's NotBefore is in the future (clock skew), log a warning but continue (server ignores validity).
3. Test enrollment on a host where sshd host keys are not readable by root (if such a config exists) — or document that host keys must be root-readable.

#### Risk Assessment: MEDIUM
The transport design is solid: pull-only, mTLS with self-signed client certs, closed operation set, fetcher/applier privilege split. The main risks are operational (clock skew on fetcher cert, host key readability, long-offline catch-up) rather than security. The separate listener design avoids browser cert-picker risks. The e2e test proves the full enrollment→approval→apply→revocation loop.

---

### 03-08 — Agent Operations: Heartbeats, Status, Staleness, Units

#### Summary
This plan makes enrolled hosts operable: heartbeats with hashes of applied config (AGENT-07), `keyroster host status` convergence view, staleness/silence alerts (D-10: KRL age ≥24h alerts but never locks out; server flags silent after 180s), periodic drift checks (every 15min ±60s), identity rotation (POST /api/v1/agent/identity signed by old key), and hardened systemd/OpenRC units written by `install`. The systemd units have `IPAddressDeny=any, IPAddressAllow=localhost` (implementing the owner's `loopback-only` answer), `NoNewPrivileges`, `ProtectSystem=strict` with minimal `ReadWritePaths`. A real-systemd smoke test runs in CI.

#### Strengths
- **Heartbeat design**: Monotonic `seq` per agent; server upserts only on higher `seq` (refuses stale/replay with `stale_heartbeat`). Body includes versions, SHA-256s of every file in current generation, drop-in hash, `sshd -V`, effective config keywords, last apply/check results, `krl_stale` flag.
- **Convergence view**: `keyroster host status` shows per-host heartbeat age, applied versions vs current, drift, last apply result, stale flags, and header lines like `KRL v17 on 3/3 hosts`. Footer states "run `keyroster-agent check` on a host to verify it there."
- **KRL staleness never locks out**: At 24h age, applier logs error (journald priority 3) and sets `krl_stale` in heartbeat; KRL stays installed, logins work.
- **Identity rotation**: Fetcher generates new key, POSTs `{new_spki, sig by old key over keyroster/agent-identity/v1 + new_spki}` over mTLS with old cert. Old cert then gets 403 `unknown_agent`.
- **Hardened units**: Fetcher runs as `keyroster-agent` user, empty `CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict` with ReadWritePaths only for its dir/spool. Applier runs as root with `IPAddressDeny=any, IPAddressAllow=localhost`, same hardening. `systemd-analyze security` gated in CI.
- **Real-systemd smoke test**: Runs both units under real systemd against runner's ssh.service, applies via `systemctl reload`, logs in with certificate, passes `systemd-analyze security`.

#### Concerns
- **HIGH — Heartbeat is the server's word only**: A compromised host can fake its heartbeat (reporting clean while actually drifted). The plan acknowledges: "Convergence is the server's word; a compromised server can lie." *Open question: Is there a plan for Phase 4 witnesses (VIS2-03) to cosign checkpoints and provide external verification?*
- **MEDIUM — `krl_stale` at 24h is logged at error level**: This will spam journals if a host is offline for days. The plan says "logs at error level on every check". *Open question: Should this be rate-limited or downgraded to warning after the first alert?*
- **MEDIUM — Drift check every 15min ±60s**: The plan says "after every apply" and "every 15min with ±60s jitter". If an apply takes >15min (unlikely but possible on slow hardware), drift checks could overlap with apply. The `apply.lock` flock serializes apply runs, but drift check (`Check`) doesn't take the lock. *Open question: Does `Check` read `current` symlink atomically? If apply swaps `current` mid-check, `Check` could see a mixed generation.*
- **LOW — OpenRC scripts UNVERIFIED**: The plan writes OpenRC scripts but they're only tested in containers (03-06 matrix uses `signal` strategy). Real OpenRC hosts (Alpine, Gentoo) not in dogfood. *Open question: Will 03-16 include an OpenRC host?*

#### Suggestions
1. Rate-limit the `krl_stale` error log: first occurrence at 24h, then at most once per hour.
2. Make `Check` take a shared (read) lock on `apply.lock` or read `current` via `os.Readlink` once at start to avoid seeing a mid-swap state.
3. Document the heartbeat trust boundary: "The server's convergence view is advisory; run `keyroster-agent check` on a host for proof."

#### Risk Assessment: LOW
Operational visibility features with no new attack surface. The heartbeat cannot cause lockout (staleness only alerts). The hardened units are gated by `systemd-analyze security` in CI. The main gap is OpenRC verification, but that's acknowledged as UNVERIFIED until dogfood.

---

### 03-09 — Host Certificates: PoP Issuance, CLI-Managed Host Trust, Revoke Host

#### Summary
This plan removes the TOFU prompt: enrolled agents obtain/renew host certificates by proof-of-possession of their host keys (D-16), users' SSH clients trust exact admin-signed names via `keyroster known-hosts sync` (D-19) and `keyroster login` (under the owner's Task 1 answer `redeem-directory`), and `keyroster revoke host` cuts off a host's certificates, keys, and enrollment. The owner decides T-03-100 in Task 1: who receives the signed directory for host trust. The plan is written for `redeem-directory` (successful login redeem answer carries the directory, CLI verifies it).

#### Strengths
- **Host certificate PoP**: Agent builds `HostIssueRequest {host_name, host_key, valid_for, request_id, created_at}`, signs with host private key under `keyroster/host-pop/v1`. Signer requires `policy.pop.hosts`, directory host entry with that name/key, valid PoP, TTL ≤ min(30d, host CA cap). Principals = admin-typed from directory entry (request has no principal field). Key ID `kr3/ca=host/sub=<host>/req=.../pol=.../dir=.../ser=...`.
- **Renewal at 2/3 lifetime + jitter**: Agent renews when cert missing, expired, within last third of life (minus up to 1h jitter), principals differ, or signing CA not active/next. Installs at `/etc/ssh/keyroster/host/<type>-cert.pub`, extends drop-in with `HostCertificate` lines, `sshd -t`, reload, self-test checks served cert matches installed bytes.
- **Client trust (REVOKE-04, D-19)**: `keyroster known-hosts sync` writes `~/.ssh/keyroster_known_hosts` with `@cert-authority <exact names> <key>` per active/next host CA, names = principals of active host entries, comma-joined, no wildcards. `~/.ssh/keyroster_revoked_hosts.krl` from verified KRL. `~/.ssh/keyroster_ssh_config` Host block for those names with `UserKnownHostsFile`, `RevokedHostKeys`, `StrictHostKeyChecking yes`. Prints one `Include` line for `~/.ssh/config`.
- **Revoke host (D-09)**: Revokes all live host certs (kr3 subject) + all host keys as explicit-key entries, disables host in directory. Agent gets 403 `not_approved`; clients with refreshed KRL refuse host.
- **Owner decision T-03-100 (Task 1)**: Recorded before code. Plan stops if answer ≠ `redeem-directory`.
- **E2E `TestHostCertNoTOFU`**: Empty known_hosts, `StrictHostKeyChecking=yes`, ssh succeeds with no prompt; revoked host refused after `known-hosts sync`.

#### Concerns
- **HIGH — T-03-100 disclosure (owner decision)**: The `redeem-directory` answer means *every user who completes a passkey login receives the full admin-signed directory* (user names, roles, host names, public credential data). The owner accepted this in Task 1, widening D-03's "admins and enrolled hosts' root only" audience. *Open question: Is the directory's public credential data (WebAuthn credential IDs, public keys) considered sensitive? The plan says "no secrets" — but credential IDs can be used for tracking.*
- **HIGH — Host certificate renewal trigger**: "when the certificate is missing, expired, not matching the directory's principals or signed by a CA no longer active or next". What if the directory's host entry is *disabled*? The agent should stop renewing and remove the cert. *Open question: Does the agent handle host entry disable → cert removal?*
- **MEDIUM — `@cert-authority` line sorting**: "Sorted by CA role generation and their name lists sorted, so repeated syncs write byte-identical files." Good for idempotency. *Open question: What if two host CAs (active and next) have overlapping name lists? The line would have duplicate names. Does the writer dedupe?*
- **MEDIUM — `keyroster login` writes host trust files**: The plan says "unless `--no-known-hosts`". A user who logs in on a shared machine gets host trust files written to their `~/.ssh`. *Open question: Is there a `--no-known-hosts` default for non-interactive/CI use?*
- **LOW — RSA host keys skipped**: "RSA host keys are skipped and reported". A host with only RSA keys gets no certificate. *Open question: Is this reported in `host status` or heartbeat?*

#### Suggestions
1. In `writeKnownHosts`, dedupe names across all host CAs before writing the `@cert-authority` line.
2. Add a check in the agent's host cert renewal: if the host entry is disabled, remove the cert file and the `HostCertificate` line from the drop-in.
3. Document the T-03-100 disclosure in `needs-hardware.md` or a security considerations doc: "Every user who logs in receives the full directory (user names, roles, host names, public credential IDs). This is acceptable for single-organisation deployments."

#### Risk Assessment: MEDIUM
The host certificate path is well-designed with PoP, admin-signed names, and client trust limited to exact names. The `redeem-directory` decision is a deliberate disclosure trade-off recorded by the owner. The main risk is operational: host cert renewal edge cases (disabled host, CA rotation) and the `@cert-authority` dedupe. Both are testable.

---

### 03-10 — Probe Certificates and Full Self-Test

#### Summary
This plan completes the agent's self-test (D-06): after every change, prove sshd accepts a positive probe certificate and refuses a revoked probe certificate for account `keyroster-probe`. Probe certs come from the machine CA by PoP: `ProbeIssueRequest` signed by host key (`host-pop/v1`) and probe key (`probe-pop/v1`). Negative probe key becomes an explicit-key revocation (never pruned) in the same transaction. Probe account checks: exists, nologin shell, password field `*` (not `!`), not excluded by AllowUsers/DenyUsers. Distro matrix tests UsePAM yes/no and measures PerSourcePenalties (assumption A9).

#### Strengths
- **Proves KRL enforcement on every host**: The negative probe key is revoked by explicit-key entry (never pruned, never expiry-confounded). If sshd accepts it, the KRL is not enforced → rollback.
- **Probe account checks before self-test**: Agent verifies the account exists, has nologin shell, `*` password, no expiry, not excluded. Host failing any check is refused with runbook instruction — no endless rollback.
- **Rate-limited negative probe**: At most once per apply, at most 6/hour. Distro matrix records whether refused probes count toward `PerSourcePenalties` (A9).
- **UsePAM tested both ways**: Distro matrix runs `TestDistroProbe` under packaged UsePAM and with `UsePAM no` (Alpine).
- **Audit and restart coverage**: `rebuildLogFrom` counts `probe_issue` as issuance; `verifyProbeIssue` re-proves both signatures, host entry, principal, TTL cap, machine CA; audit revocation set includes negative probe keys.

#### Concerns
- **HIGH — Probe account password `*` vs `!`**: The plan insists on `*` (not `!`, not empty, not locked). On some distros, `usermod -p '*'` may not work as expected (shadow utils differences). *Open question: Is the runbook's per-distro create command tested on all seven images? The plan says "Alpine: adduser then sed /etc/shadow to set `*`" — this is fragile.*
- **HIGH — PK_OK without signing implementation**: The agent's probe signer records "PK_OK received" when asked to sign and returns an error instead of a signature. This relies on `golang.org/x/crypto/ssh` client behavior (sends key query, gets PK_OK, then signs). *Open question: Is this tested against all seven distro sshd versions? A version that doesn't send PK_OK for probe keys would break the self-test.*
- **MEDIUM — `probe_pending` state**: Until both probe certs exist, self-test runs 03-09 checks and reports `probe_pending`; apply never commits a later change while probes pending for >1 poll. *Open question: What if probe issuance fails permanently (e.g., policy.pop.hosts not set)? The agent would stall on `probe_pending` forever. Is there a timeout or alert?*
- **MEDIUM — Distro matrix runs as root**: `TestDistroProbe` creates real `keyroster-probe` account with nologin shell and `*` password. On Alpine, `adduser -S -D -H -s /sbin/nologin` then `sed` on `/etc/shadow`. *Open question: Does the `sed` reliably produce `*` on all Alpine versions?*

#### Suggestions
1. Add a timeout/alert for `probe_pending`: if probes not issued after N polls (e.g., 5), log a warning and include in heartbeat.
2. In the distro matrix, verify the `sed` command for Alpine produces `keyroster-probe:*:...` in `/etc/shadow`.
3. Test PK_OK behavior on OpenSSH 9.5p1 and 10.5p1 explicitly in the e2e (already in matrix, but confirm the probe signer's "return error on sign" works).

#### Risk Assessment: MEDIUM
The probe self-test is the ultimate proof that KRL enforcement works on each host. The design is clever (negative probe = explicit-key revocation, never pruned). The main risks are probe account setup fragility across distros and the PK_OK implementation depending on x/crypto/ssh client behavior. The distro matrix mitigates the former; the latter is a library dependency risk.

---

### 03-11 — Machine Identities: Day-Scale Certs by PoP, Revoke Machine

#### Summary
This plan delivers AUTH-06 (machine/automation identities) and completes REVOKE-01 (all targets). A machine in the admin-signed directory renews day-scale certs via `keyroster machine renew` (signs `MachineIssueRequest` with machine key from ssh-agent or key file, under `machine-pop/v1`). Signer requires `policy.pop.machines`, active machine entry with matching key, valid PoP, TTL ≤ min(entry max_ttl, roles' max TTL, machine CA cap). Principals = union of roles' principals. Revoke machine: all live certs (kr3 subject) + machine key as explicit-key entry, disable in directory. CLI never writes/transmits private key (tested with mutant).

#### Strengths
- **PoP renewal**: Machine proves possession of its key each renewal; private key never leaves automation (ssh-agent or key file read into memory, passphrase prompted on terminal).
- **Cap enforcement**: TTL bounded by three caps (entry, roles, machine CA). Roles' principals/extensions computed by signer from directory; audit re-proves.
- **Revocation completeness**: `revoke machine` adds live certs (serial) + key (explicit-key) to KRL, disables machine in directory. Renewal refused with `machine_key_revoked`.
- **Probe name reservation**: Directory validation refuses machine names starting with `probe.` so probe certs (subject `probe.<host>`) never collide with machine subjects.
- **Unauthenticated server route**: POST /api/v1/machine/renew has no session/admin auth; server forwards under its own limiter (30/min, burst 10, global backstop). Signer decides.

#### Concerns
- **HIGH — Machine key in ssh-agent vs key file**: The CLI supports `--agent-key SHA256:...` (ssh-agent) or `--key FILE` (private key file). For automation, a key file is more likely. *Open question: Does the CLI correctly handle an encrypted private key file (prompt for passphrase)? The plan says "prompting for a passphrase on a terminal" — but automation often runs non-interactively.*
- **MEDIUM — Role principal union**: "Principals = sorted union of the roles' principals". If two roles grant overlapping principals, the union dedupes. But what if roles grant conflicting extensions? The plan says "extensions = union of the roles' extensions within the machine CA profile". *Open question: Is there a test for conflicting extensions (e.g., role A permits `permit-X11-forwarding`, role B doesn't)?*
- **MEDIUM — Machine cert is user-type from machine CA**: The certificate is a *user-type* certificate (not host-type) issued by the machine CA. This means it's validated against `TrustedUserCAKeys` (which includes machine CA keys). *Open question: Does the agent's `user_ca_keys` include the machine CA key? Yes, 03-05 render.go says "active and next entries of roles user and machine". Good.*
- **LOW — `TestMachineRenewNeverWritesKey` mutant test**: Good pattern from 03-02. *Open question: Does the test also check that the key file's passphrase is not logged or written anywhere?*

#### Suggestions
1. For non-interactive automation, support a `--passphrase-stdin` or `--passphrase-env` flag to avoid terminal prompt.
2. Add a test: two roles with overlapping principals and conflicting extensions; verify the union respects the machine CA profile.
3. Document the machine key storage recommendation: "Use ssh-agent for interactive/short-lived; for long-running automation, use a dedicated key file with a strong passphrase and `--passphrase-env`."

#### Risk Assessment: LOW
Machine identities are a clean extension of the host certificate PoP pattern. The unauthenticated route is rate-limited and the signer enforces all caps. The private key handling is tested with a mutant. The main operational concern is non-interactive passphrase handling, which is a UX issue not a security flaw.

---

### 03-12 — CA Rotation: Next + Draining Generations, No Failed Logins

#### Summary
This plan implements KEY-08 (CA rotation without fleet outage) per D-14: two root ceremonies. `keyroster-signer ca-rotate prepare --role R` creates/selects generation g+1 in keystore, logs `ca_generation` leaf (kind 14). First successor (`--ca-next R=FILE`) adds it as `next`; agents trust active+next together; `host status` shows convergence. Second successor (`--ca-switch R`) makes next→active, old active→`draining` with `trusted_until = issued_at + profile_max_TTL + 300s`. Signer issues with new generation; agents drop draining CA at `trusted_until` on their own clock. `--ca-drop R:G` removes drained entry. `root sign --prev` no longer refuses CA changes; summary lists every CA change for root holders.

#### Strengths
- **Two-ceremony design**: Next trusted first (parallel trust), then switch with drain period. No failed logins because old CA stays trusted until all its certificates expire (`trusted_until ≥ switch + maxTTL + 300s`).
- **Keystore generation support**: All backends (agent, pkcs11-agent, software, TPM, PIV) support `ProvisionGeneration`. Software writes `<role>-g<N>.age` (gen 1 keeps existing name). TPM creates P-256 key per generation. PIV uses next free retired key-management slot.
- **Bundle format**: `CAEntry.TrustedUntil` (omitempty, last field), state `draining`. `checkSuccessorChain` allows only: add next (gen > all previous), switch next→active with old→draining (trusted_until ≥ next.IssuedAt + maxTTL + 300s), drop draining after trusted_until. Key never moves role or reappears with another generation.
- **Audit verify across rotation**: `anchor.install` accepts multi-entry roles and draining; active CA per role updates at each bundle_install, so issuance before/after switch checks against CA active at that leaf.
- **E2E `TestCARotationNoFailedLogin`**: Login loop (1 cert/sec) through prepare, next-bundle install, convergence, switch, drain, drop — zero failures. Certificates issued before switch work until expiry.

#### Concerns
- **HIGH — `trusted_until` boundary exactness**: "At trusted_until the draining CA is dropped by agents and allowed to be removed, one second earlier it is kept." The agent's clock drives this. *Open question: What if an agent's clock is skewed (e.g., +2s)? It drops the draining CA 2s early, potentially refusing a certificate that is still valid. The 300s grace in trusted_until calculation helps, but clock skew is unbounded.*
- **HIGH — PIV generation uses retired slots**: "Refuses when none is free, never overwrites an occupied slot." PIV has limited slots (typically 20). If many rotations occur, slots exhaust. *Open question: Is there a slot reuse policy after a generation is fully retired (drained and dropped)? The plan says "never overwrites" — this limits total rotations per PIV device.*
- **MEDIUM — Client known-hosts with next/draining host CAs**: Moved to Task 2. The plan says "clients' known-hosts lines and agents' user_ca_keys include next and draining CAs until trusted_until". *Open question: Does `keyroster known-hosts sync` write @cert-authority lines for next/draining host CAs? The tracer (03-09) only did active/next. Draining host CAs need their own line until trusted_until.*
- **MEDIUM — TPM lane test**: Uses swtpm in CI. Real TPM hardware UNVERIFIED. *Open question: Is the TPM key generation (P-256 per generation) compatible with the host CA profile (which may be Ed25519)? The plan says TPM creates P-256 — but the host CA profile might require Ed25519. This could cause a mismatch.*

#### Suggestions
1. Add a clock-skew tolerance in the agent: drop draining CA at `trusted_until + 5s` (or configurable) to absorb small skew. The 300s grace already provides buffer, but explicit tolerance is safer.
2. For PIV, add a "slot recycle" rule: after a generation is dropped (via `--ca-drop`), its slot becomes free for a future generation. Document the max rotations per PIV device (e.g., 20 slots - 3 roles = ~17 rotations).
3. In `knownhosts.go`, write @cert-authority lines for active, next, *and draining* host CAs (while now < trusted_until). Remove draining line at trusted_until.

#### Risk Assessment: MEDIUM
The rotation design is correct and proven by the login-loop e2e. The clock-skew boundary is the main technical risk (mitigated by 300s grace). PIV slot exhaustion is a long-term operational limit. The TPM algorithm mismatch (P-256 vs Ed25519) needs verification — if the host CA profile requires Ed25519, a P-256 TPM key won't work for host certs.

---

### 03-13 — Log-Key and Ops-Key Rotation, Emergency CA Replacement

#### Summary
This plan completes KEY-08: rotates the audit log key and ops (KRL) key through root-signed successors, with `audit verify` following across the change. Log key: `ca-rotate prepare --role log` → `--log-rotate FILE` puts new key with new origin in bundle; at install-bundle, signer writes bundle_install leaf with old key's checkpoint, then switches to new key for later checkpoints. Ops key: `--ops-rotate FILE`; signer republishes KRL signed by new ops key at next start; agents accept only manifests signed by the ops key of the bundle in force. Emergency CA rotation: `--ca-emergency ROLE=FILE` makes prepared generation active and old active→`retired` in one successor (no next/drain); `revoke key <old-ca-key.pub>` then allowed for retired CA key (explicit-key in KRL), cutting off all its certificates.

#### Strengths
- **Log key rotation with audit verify continuity**: `anchor.install` records `(fromSize, logKey, origin)` segments. Final checkpoint verified under last segment's key; `--previous` checkpoint under segment covering its size. The "log key change unsupported" refusal is removed.
- **Ops key rotation without gap**: Signer republishes KRL at start after ops-key change. Agents refuse manifest signed by old ops key (`ErrSigner`), keep last-good, then accept new one. E2E `TestOpsKeyRotation` shows host following with no lockout.
- **Emergency path**: One ceremony (`--ca-emergency`) retires compromised CA; `revoke key` of retired CA key accepted (explicit-key section in KRL). Active CA/ops/log/root keys still refused as revoke targets. E2E `TestEmergencyCARotation`: old CA cert refused after emergency bundle + revoke; new CA cert works.
- **Transition refusals**: `log_origin_mismatch`, `log_key_equals_other_key`, `ops_key_equals_ca_key`, `log_rotate_without_generation`.

#### Concerns
- **HIGH — Log key rotation requires signer restart**: "At install-bundle the signer writes the bundle_install leaf with its checkpoint still signed by the old log key, then signs every later checkpoint with the new key... the signer restarts on that state." The plan says the signer restarts *after* the bundle install. *Open question: Is the restart automatic (signer watches bundle file) or manual? If manual, there's a window where the signer runs with the new bundle but old log key.*
- **HIGH — Emergency CA rotation skips drain**: `--ca-emergency` moves old active → `retired` directly (no `next`, no `draining`). This is correct for compromise, but *open question: What about certificates issued by the compromised CA that are still within their validity period? The `revoke key` puts the CA key in the KRL's explicit-key section, so sshd refuses *all* certificates signed by that key. This is the intended "emergency brake" — but it also revokes legitimate certificates. Is this documented as the expected behavior?*
- **MEDIUM — Agent KRL manifest verification**: "Agents accept a KRL manifest only when signed by the ops key of the bundle they have in force, keeping their last-good KRL meanwhile." *Open question: What if the agent hasn't yet applied the new bundle (with new ops key) but the server publishes a KRL signed by the new ops key? The agent would refuse it (ErrSigner) and keep the old KRL. This is correct — the agent must apply the bundle first. But the server's hourly re-publish (03-03) will sign with the *current* bundle's ops key. If the bundle and ops key change in the same successor, there's a race. The plan says "after installing such a bundle the signer publishes a new KRL version signed by the new ops key at its next start" — so the signer waits for the bundle install (which includes the new ops key) before republishing. Good.*
- **LOW — `keyroster audit verify` across log key change**: The plan says it "checks the final checkpoint against the log key of the last bundle_install, checks a --previous checkpoint against the log key in force at its size". *Open question: Does it also verify that the log key change itself was authorized by a root-signed successor? Yes, "a log-key change is accepted only inside a verified successor" — VerifySuccessor checks the bundle chain.*

#### Suggestions
1. Make the signer's log-key switch atomic with the bundle install: in `InstallBundle`, if the log key changes, write the bundle_install leaf with old key, *then* switch the writer, *then* commit the transaction. No restart needed if the writer is swapped in-memory. If a restart is required for other reasons, document it.
2. Document the emergency rotation behavior clearly: "Emergency rotation immediately retires the compromised CA and revokes its key via KRL explicit-key entry. ALL certificates signed by that CA (including legitimate ones) are refused by sshd. Users must obtain new certificates from the new CA."
3. Add a test: agent has old bundle (old ops key), server publishes KRL with new ops key (simulating race). Agent refuses, keeps last-good. Then agent applies new bundle, next poll accepts new KRL.

#### Risk Assessment: MEDIUM
The log/ops key rotation design is sound and audit verify continuity is proven. The emergency path is a necessary "break glass" but has the side effect of revoking all certificates from the compromised CA — this must be clearly documented. The signer restart on log-key change is a minor operational concern.

---

### 03-14 — Offline Break-Glass CA Scoped to Emergency Account

#### Summary
This plan delivers BREAK-01 (D-13): an offline break-glass CA in the root-signed bundle (`breakglass` field: key, alg, custody, account, principal). The agent's drop-in ends with a `Match User <account>` block containing its own `TrustedUserCAKeys` (break-glass CA only), `AuthorizedPrincipalsFile` (break-glass principal only), and `RevokedKeys` (own empty KRL). So the global user_ca_keys never contains the break-glass CA, and a broken main KRL/CA file cannot lock out the emergency account. `keyroster breakglass init` creates the key offline (age-encrypted software or FIDO/PIV); `keyroster breakglass sign` signs a user cert offline (TTL ≤1h, principal = bundle's, key ID `kbg1/...`), never through the signer. Emergency account created by runbook, not agent; agent only reports account state. Tested on 9.5p1, 10.5p1, and all seven distro images.

#### Strengths
- **Match-block isolation**: Break-glass CA only in `Match User` block; never in global `TrustedUserCAKeys`. Proven by configuration B test (break-glass cert refused for normal account).
- **Survives main corruption**: Tested with corrupt main `revoked.krl` (unknown section) and garbage line at top of main `user_ca_keys` — break-glass login still works.
- **Offline signing**: `breakglass sign` uses `cert.Build` directly, never the signer. Key ID `kbg1/sub=<operator>/at=<unix>/ser=<random>`.
- **Account reporting**: Agent checks emergency account in preflight/check/heartbeat (exists, executable shell, not locked, not excluded). Sudo requires offline password (runbook).
- **Per-version and per-distro testing**: `TestBreakglassMatch` on both OpenSSH versions in CI e2e; `TestDistroBreakglass` on all seven images with real accounts.

#### Concerns
- **HIGH — Match block ordering in sshd_config**: The plan says "the agent's drop-in ends with `Match User <account>`". OpenSSH processes `Match` blocks in order; the first matching block wins. If another drop-in (or sshd_config) has a `Match User` for the same account *before* the agent's block, the break-glass settings might not apply. *Open question: Does the agent ensure its Match block is last? The drop-in is `00-keyroster.conf`; if another drop-in is `99-other.conf`, it comes after. But `Match` blocks in the same file are processed in order. The agent's block is at the end of its drop-in — but what if another drop-in included later has a Match for the same user?*
- **HIGH — PAM stack interaction**: The emergency account has a real password (set by `passwd`) and sudo requires it. But if the host's PAM stack (e.g., `pam_faillock`, `pam_tally2`) locks the account after failed attempts, the break-glass login could be blocked. The agent checks "not locked" via shadow field ≠ `!`, but PAM locks are not in shadow. *Open question: Is this tested? The distro matrix runs `sudo -n true` fails (password required) but doesn't test PAM lockout.*
- **MEDIUM — Break-glass key custody**: "age-encrypted software key with the root key rules, or an existing FIDO or PIV key named by fingerprint; hardware is optional". Software key on offline media is the minimum. *Open question: Is there a recommendation for hardware (FIDO/PIV) for the break-glass key? The plan says "hardware is optional" — but for a break-glass key, hardware custody is strongly preferred.*
- **MEDIUM — `keyroster breakglass sign` TTL ≤ 1h**: Enforced by CLI. But the certificate is a standard SSH user cert; nothing in the cert itself enforces the 1h limit except the `ValidBefore` field. *Open question: What prevents an operator from manually creating a longer-lived cert with the break-glass key? The runbook must emphasize the 1h policy.*

#### Suggestions
1. In the agent's drop-in, ensure the `Match User` block is the *last* Match block in the file. If another drop-in could add a Match block after, consider naming the agent's drop-in `99-keyroster.conf` (but this conflicts with D-07's "drop-in precedence" — the plan says 00-keyroster.conf). *Better: document that no other drop-in should add Match blocks for the emergency account.*
2. Add a PAM lockout check to the agent's account reporting: `pam_tally2 -u keyroster-breakglass` or `faillock --user keyroster-breakglass` if available.
3. Recommend FIDO/PIV for break-glass key in the runbook; software key only for evaluation.

#### Risk Assessment: MEDIUM
The break-glass design is strong: isolated Match block, own files, offline signing, tested on all distros/versions. The main risks are Match block ordering (mitigated by drop-in naming convention) and PAM interactions (not fully tested). The runbook must emphasize the 1h TTL policy and hardware custody recommendation.

---

### 03-15 — V4 Ceremony: Real Offline Roots, Homelab Migration

#### Summary
This plan moves the homelab onto real offline roots in one ceremony (D-01): the owed v4 rotation from TEST roots C/D, signing a bundle with every Phase 3 field (installation ID, break-glass CA, PoP policy, optional next user CA). Claude rehearses the exact ceremony first (`TestV4CeremonyRehearsal` with scratch roots), prepares the kit, owner runs the real ceremony offline, Claude installs after owner approves by hash, owner re-initializes CLIs and signs directory v7 (rebind), owner destroys TEST roots C/D (attested), KEY-07 marked complete.

#### Strengths
- **Rehearsal first**: `TestV4CeremonyRehearsal` builds the same successor from a copy of the homelab's chain shape with scratch roots, verifies, installs on scratch signer, enrolls agent. Owner's real ceremony follows the exact validated command list.
- **Owner approval by hash**: "After the owner approves the install by bundle hash, the homelab signer runs bundle v4." The install is one-way; hash approval prevents substitution.
- **Directory rebind**: Owner signs directory v7 with `keyroster directory rebind` so installed directory carries the installation ID agents will pin. Logins keep working through the change (03-01 transition rule: lenient for random-128).
- **TEST roots destruction**: Owner destroys C and D after passing audit; post-destruction audit passes with new pins only. KEY-07 complete.
- **Guard literals**: No homelab hostnames/FQDNs/addresses in committed files; aliases only (`keyroster-signer-vm`, `zima`, `ub-daniel`). Guard list checked on every added line.

#### Concerns
- **HIGH — Owner-run ceremony steps**: The owner must execute `keyroster root init` ×N, `breakglass init`, `root successor-policy`, `ca-rotate prepare` (if next CA), `root sign` with multiple flags, `trust verify`, copy v4 to signer VM, store break-glass key/passphrase/sudo password offline, re-initialize CLIs, `directory rebind`, destroy C/D. *Open question: Is the command list in the runbook complete and tested by the rehearsal? The plan says "the runbook's command list is the one the rehearsal executes" — good.*
- **HIGH — Next CA optional**: If owner chooses `any-no-next`, the rotation drill stays CI-only (UNVERIFIED on homelab). *Open question: Does the owner have three FIDO keys for the recommended `fido-2of3-next` option?*
- **MEDIUM — Evidence files outside repo**: `$HOME/keyroster-ceremony/phase3/kr.env` holds non-secret values (KR_ROOTS, KR_THRESHOLD, KR_ROOT_CUSTODY, KR_BG_CUSTODY, KR_NEXT_CA, KR_V4_SHA16, KR_INSTALLATION_ID, KR_NEW_PINS, KR_SERVER, KR_TLS_ROOT_PEM). *Open question: Is this directory backed up? If the owner's machine fails, the ceremony evidence is lost (though the signed documents are in the repo).*
- **LOW — Phase 2 hosts (Proxmox test VM, zima-srv) adoption**: They are taken over in 03-16, not here. This plan only installs the new bundle and rebinds the directory.

#### Suggestions
1. Add a "ceremony checklist" to the runbook that the owner can tick off step by step, with the exact commands and expected outputs (summary lines, hash prefixes).
2. Document the break-glass key/sudo password offline storage procedure: "Store on separate offline media from the root keys; label clearly."
3. In the rehearsal test, also verify that the directory rebind works (directory v7 carries installation ID, agent enrolls with it).

#### Risk Assessment: MEDIUM
This is a one-time operational ceremony with irreversible steps (root key creation, TEST root destruction). The rehearsal and hash approval mitigate substitution risk. The main risk is owner error during the offline ceremony — the runbook must be extremely precise. The guard literal check prevents accidental disclosure.

---

### 03-16 — Homelab Dogfood: Enrollment, Drills, Platform Record

#### Summary
This plan dogfoods the entire phase on the owner's real hosts: enroll laptop (ub-daniel), Proxmox test VM, zima-srv (when online), Proxmox host (Debian 13); take over the two Phase 2 hosts (02-14) via exact layout adoption; run drills (revocation timing, no-TOFU from Daniel-PC and laptop, corrupt file, break-glass with server down, machine identity, rotation if chosen); corroborate every claim with signer log (audit verify) + host sshd journals (serials, key IDs); label runbook steps run/UNVERIFIED honestly; write platform record in `needs-hardware.md`. README quickstart follows on `p03/close` after verification.

#### Strengths
- **Real-host validation**: All success criteria tested on actual hardware (Ubuntu 26.04, Debian 13, OpenSSH 9.5p2/10.2p1/10.0p2), including Windows inbox OpenSSH 9.5p2 on Daniel-PC for no-TOFU.
- **Two independent records for every claim**: Signer's exported log (audit verify with new pins) + host sshd journals (serials, kr2/kr3/kbg1 key IDs). No claim without both.
- **Honest labeling**: Runbook steps changed from UNVERIFIED to "run on <alias>, <date>" only for steps that actually ran. `needs-hardware.md` records what's UNVERIFIED (OpenRC, SELinux EL9, Arch/Alpine/RHEL real hosts, zima if offline, Windows client if not run, rotation if not chosen).
- **Corrupt-file drill**: Local corruption of `current/revoked.krl` → `check` reports file drift, break-glass unaffected, next apply restores signed KRL.
- **Break-glass drill with server stopped**: Proves offline capability.
- **Guard literal check**: No homelab names/addresses in committed files; IPv4 regex check on diff.

#### Concerns
- **HIGH — zima-srv often offline**: The plan says "zima-srv when online... a host that was offline is listed as not exercised". If zima is offline during 03-16, its enrollment, drills, and platform record are missing. *Open question: Is there a fallback (e.g., run drills on the Proxmox test VM twice) or is zima's absence accepted as a gap?*
- **HIGH — Windows client no-TOFU**: Daniel-PC runs Windows inbox OpenSSH 9.5p2. The plan says "the Windows result is recorded either way, replacing the earlier UNVERIFIED label only if it ran". *Open question: Does the Windows `keyroster login` + `known-hosts sync` work on 9.5p2? Phase 2 verification noted Windows removal at expiry was timed but macOS browser leg was UNVERIFIED. The Windows ssh client behavior with `@cert-authority` and `RevokedHostKeys` may differ.*
- **MEDIUM — Proxmox cluster SSH**: "Never touch root's authorized_keys, /etc/pve or cluster known_hosts (research Pitfall 14)." The agent's preflight on the Proxmox host must not mistake cluster-managed SSH config for foreign trust settings. *Open question: Does the preflight correctly distinguish Proxmox's cluster SSH config from a conflicting local config?*
- **MEDIUM — Revocation timing measurement**: "Time from CLI's answer to first refused attempt on each host is recorded and is within the D-10 bound of about one minute plus jitter." The poll is 60s ±10s. *Open question: Is the measurement done from the CLI's timestamp or the server's KRL publish timestamp? The plan says "from the CLI's answer" — this includes network latency to the server.*
- **LOW — README quickstart on p03/close**: Not in this plan. The SUMMARY must include the hand-off line.

#### Suggestions
1. If zima-srv is offline, document it clearly in the platform record and run the break-glass/machine drills on the Proxmox test VM instead (which is Ubuntu 26.04 like zima).
2. For Windows no-TOFU, test `ssh -o StrictHostKeyChecking=yes` with the generated `keyroster_ssh_config` Include line. Verify the `@cert-authority` line works with Windows OpenSSH 9.5p2 (known to have some cert-authority bugs fixed in 10.3).
3. In the revocation timing drill, record both the CLI answer time (client-side) and the server's KRL publish time (from the log) to separate network latency from poll interval.

#### Risk Assessment: MEDIUM
This is the ultimate validation of Phase 3. The drills are comprehensive and corroborated. The main risks are environmental (zima offline, Windows 9.5p2 quirks, Proxmox cluster config) and are acknowledged with honest UNVERIFIED labels. The platform record will accurately reflect what was actually exercised.

---

# Cross-Plan Analysis

### Overall Architecture Coherence
The 16 plans form a logical sequence from revocation tracer (03-01) through homelab dogfood (03-16). Each plan builds on the previous:
- 03-01/03-02/03-03: Revocation core (KRL, signer, audit)
- 03-04: Directory format (hosts, machines, installation ID)
- 03-05/03-06: Apply engine + distro safety
- 03-07/03-08: Agent transport + operations
- 03-09/03-10: Host certs + full self-test
- 03-11: Machine identities
- 03-12/03-13: Key rotation (CA, log, ops, emergency)
- 03-14: Break-glass
- 03-15/03-16: Ceremony + dogfood

Dependencies are correctly encoded in `depends_on` and wave ordering.

### Recurring Strengths
1. **Owner decisions before code**: Three checkpoints (03-01 Task 1: D-04 form; 03-05 Task 1: D-05/D-06; 03-09 Task 1: T-03-100) resolve architectural collisions before implementation.
2. **E2E tests on real sshd**: Every critical path has an e2e test against OpenSSH 9.5p1 and 10.5p1 in CI.
3. **Strict parsing + oracle testing**: KRL, wire formats, join tokens all have strict parsers with named refusals and `ssh-keygen` oracle agreement.
4. **Audit verify continuity**: Every new leaf kind gets audit rules in the same plan (or next), with fuzz coverage.
5. **Dependency firewall + capslock per binary**: Signer, agent (applier), agent (fetcher) each have gated imports and capabilities.
6. **Documentation convention**: Every operator step labeled "run in CI e2e (plan)" or "UNVERIFIED until 03-16".

### Recurring Concerns
1. **Clock skew assumptions**: Multiple plans assume agent/server clocks are roughly synchronized (probe account checks, KRL staleness 24h, CA rotation `trusted_until`, break-glass TTL 1h). No NTP/time sync requirement is enforced.
2. **Distro matrix gaps**: Systemd/OpenRC reload paths, SELinux, Proxmox cluster SSH, Windows 9.5p2 client — all UNVERIFIED until 03-16. The seven-image container matrix covers sshd behavior but not service manager integration.
3. **Fuzzing corpus seeds**: Multiple plans add fuzz targets but don't specify seed corpus. Golden vectors should be seeds.
4. **Error message clarity for admins**: Several refusals (e.g., `host_keys_in_use`, `machine_key_revoked`) need clear CLI messages directing the admin to the correct recovery action.

### Phase Goal Achievement
The phase goal: *"Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout."*

**Evidence from plans:**
- ✅ Automatic sync: Agent pull (60s ±10s), applies signed state atomically (03-05, 03-07)
- ✅ Trusted CAs: Bundle with active/next/draining, installation-bound (03-01, 03-04, 03-12)
- ✅ Principals: `AuthorizedPrincipalsFile` from signed directory via single renderer (03-04, 03-05)
- ✅ KRL: Own encoder, oracle-tested, hourly re-publish, atomic install, last-good rollback (03-01, 03-03, 03-05)
- ✅ Host certificates: PoP issuance, renewal, client trust via exact names (03-09)
- ✅ No hand-edited sshd_config: Agent writes only drop-in + allowlisted paths (03-05, 03-06)
- ✅ No lockout: Self-test with probe certs + negative probe proves KRL enforcement; rollback on failure; break-glass isolated (03-05, 03-10, 03-14)
- ✅ Revocation within ~1 minute: Poll cadence + e2e proof (03-07, 03-16)
- ✅ CA rotation without failed logins: Two-ceremony next/drain, login loop test (03-12)
- ✅ Break-glass with server down: Offline CA, Match-block isolation (03-14)

**Gaps:**
- ⚠️ Windows/macOS/BSD agents: Phase 5 (PLAT-02/03/04)
- ⚠️ Inventory (INV-01..04): Phase 5
- ⚠️ Web UI for revocation/host management: Phase 4 (UI-02, REVOKE-01 UI part)
- ⚠️ Login reconciliation (VIS-05): Phase 5
- ⚠️ Convergence view beyond `host status`: Phase 4 (VIS-06)

These are correctly scoped to later phases per ROADMAP.

### Overall Risk Assessment: MEDIUM

**Justification:**
- **High-value validation**: Every critical path has an e2e test on real sshd (both versions). The apply engine, revocation, host certs, break-glass, and rotation are all proven in CI.
- **Owner decisions recorded**: Three architectural checkpoints resolved before code, with verbatim owner wording in SUMMARYs.
- **Security-first design**: Fetcher/applier split, mTLS with self-signed certs, no inbound ports, closed operation sets, strict parsing, audit log with Merkle proofs.
- **Known gaps are documented**: UNVERIFIED labels, flagged assumptions in edge coverage, deferred items in ROADMAP.
- **Residual risks**: Clock skew, Windows 9.5p2 client behavior, Proxmox cluster SSH, zima-srv availability, PIV slot exhaustion, TPM algorithm mismatch. These are operational/environmental, not design flaws.

The phase is well-structured, appropriately scoped, and the plans provide sufficient detail for implementation with clear verification criteria. The main execution risk is the owner-dependent checkpoints (03-01, 03-05, 03-09, 03-15) which require timely owner responses.
---

## gemma (Ollama cloud) Review

> Ran without repository access (plan text only) — down-weighted.

REVIEWED-WITHOUT-REPO-ACCESS

### 03-01
**Summary**
This plan establishes the foundational revocation path. It introduces the installation ID to bind the CA to a specific deployment and implements the basic "revoke by serial" flow, including a custom KRL encoder and a detached signature manifest.

**Strengths**
- **Installation Binding**: D-04 prevents a KRL or bundle from one installation being accidentally or maliciously applied to another.
- **Atomic Swap**: The use of `rename(2)` for the KRL file ensures that `sshd` never reads a partially written file.
- **Oracle Testing**: Using `ssh-keygen -Q` as a ground-truth oracle for the custom encoder is a high-assurance approach.

**Concerns**
- **Audit Gap (LOW)**: The plan explicitly defers the audit verification of revoke/publish leaves to 03-03. While acceptable for a tracer, there is a window where the log is not fully verifiable.
- **KRL Size (LOW)**: While `MaxKRL` is defined, the plan doesn't specify how the signer handles a revocation set that exceeds this limit.

**Suggestions**
- Define the behavior when the revocation set exceeds `MaxKRL` (e.g., refuse the revoke request or trigger an emergency CA rotation).

**Risk Assessment: LOW**
The plan is a narrow tracer that proves the most critical "fail-safe" path (revocation) before building the agent.

---

### 03-02
**Summary**
This plan focuses on "cleaning up" Phase 2, addressing specific edge cases in the login flow, and updating requirements to match the Phase 3 architectural decisions.

**Strengths**
- **Agent-First Login**: Moving the agent check before the `begin` call prevents "ghost" certificates from being logged when the user has no usable agent.
- **Negative Testing**: The inclusion of tests to prove that keys are never written to disk and that no non-passkey routes exist is excellent security hygiene.

**Concerns**
- **Clock Skew (LOW)**: The plan mentions a 5s resolution for Windows expiry; it remains an open question if this is sufficient for all target environments.

**Suggestions**
- Ensure the `minLoginRemaining` check is strictly enforced on the client side to avoid a race condition where the cert expires exactly as it is added to the agent.

**Risk Assessment: LOW**
Primarily a refinement and documentation plan.

---

### 03-03
**Summary**
This plan completes the revocation system by adding support for revoking by key ID and public key, implementing a strict KRL parser, and adding the hourly re-publish logic.

**Strengths**
- **Strict Parsing**: Implementing a strict parser that refuses unknown sections/subsections prevents "parser differential" attacks.
- **Pruning Logic**: The logic to remove expired serials from the KRL while keeping explicit-key revocations is correct and prevents KRL bloat.
- **Audit Closure**: Completes the audit verification for revocation, ensuring the KRL can be re-derived from the log.

**Concerns**
- **Re-publish Storm (LOW)**: Hourly re-publishing across a large fleet could create a spike in traffic, though the 60s ± 10s jitter in the fetcher (03-07) mitigates this.

**Suggestions**
- Add a check to the re-publish logic to skip the update if the KRL bytes haven't changed, only updating the `issued_at` timestamp in the manifest.

**Risk Assessment: LOW**
Completes a critical security feature with high test coverage.

---

### 03-04
**Summary**
This plan extends the admin-signed directory to include host and machine entries, enabling the "signed host policy" required for the agent.

**Strengths**
- **PoP Policy**: Introducing `PoPPolicy` in the root-signed bundle allows the signer to toggle Proof-of-Possession requirements for hosts and machines.
- **Strict Validation**: Refusing RSA keys for hosts and enforcing unique principals/keys across the fleet prevents ambiguity.
- **Machine Identity**: Correctly separates machine CA caps from user CA caps.

**Concerns**
- **Directory Size (LOW)**: As the number of hosts grows, the full directory sent to every agent (D-03) may become large. The plan acknowledges this as a deferred "per-host extract" idea.

**Suggestions**
- Ensure the `directory rebind` command is clearly documented as the primary way to move a deployment to a new installation ID.

**Risk Assessment: LOW**
Standard data model extension with strong validation.

---

### 03-05
**Summary**
This plan implements the "Apply Engine," the root process responsible for translating signed state into `sshd` configuration and files.

**Strengths**
- **Privilege Split**: The separation of the network-less applier from the unprivileged fetcher is a strong security boundary.
- **Atomic Generations**: The use of `gen/<N>` directories and symlink swaps prevents `sshd` from reading inconsistent state.
- **Self-Test/Rollback**: The "dead-man" sequence (apply $\rightarrow$ test $\rightarrow$ commit or rollback) is the primary defense against fleet-wide lockouts.

**Concerns**
- **Sshd-T Performance (LOW)**: Running `sshd -t` and `sshd -T` on every apply is safe but can be slow on systems with many include files.
- **Loopback Dependency (MEDIUM)**: The self-test depends on `sshd` listening on loopback. If a host is configured with `ListenAddress` only on a tailnet IP, the agent will refuse to apply.

**Suggestions**
- In the `no_loopback_listener` refusal, provide the exact `ListenAddress 127.0.0.1` line the admin needs to add to `sshd_config`.

**Risk Assessment: MEDIUM**
This is the most dangerous part of the system. The risk is mitigated by the strict rollback logic and the "loopback-only" network constraint.

---

### 03-06
**Summary**
This plan adapts the apply engine to real-world Linux distributions, implementing service detection, preflight checks, and drift detection.

**Strengths**
- **Distro Matrix**: Testing against seven different images (including Alpine and RHEL) ensures the `sshd` behavior is consistent.
- **Phase 2 Adoption**: The "exact layout" requirement for taking over hand-set hosts prevents the agent from accidentally deleting unrelated SSH configurations.
- **Drift Detection**: Using `sshd -T -C` to detect overrides (like a manual `Match` block) provides the "full visibility" promised in the core value.

**Concerns**
- **Socket Activation (LOW)**: The plan notes that Ubuntu's socket activation might mean `Reload none`. This needs careful verification to ensure the agent doesn't assume a reload happened when it didn't.

**Suggestions**
- In the drift report, clearly distinguish between "file drift" (hash mismatch) and "effective drift" (`sshd -T` mismatch).

**Risk Assessment: LOW**
Adds necessary environmental awareness to the apply engine.

---

### 03-07
**Summary**
This plan implements the agent's transport layer: join tokens, mTLS enrollment with PoP, and the pull-only state fetcher.

**Strengths**
- **mTLS without CA**: Using self-signed client certificates pinned by SPKI at enrollment avoids the complexity of an agent CA.
- **Host-Key PoP**: Requiring the agent to sign the enrollment request with the actual host keys prevents a compromised fetcher from enrolling a fake host.
- **Closed Operation Set**: The strict limit on agent routes (enroll, state) minimizes the server's attack surface.

**Concerns**
- **Join Token Leak (LOW)**: While the token is 0600, it is a "bearer" token until the first enrollment. The 30m TTL is a good mitigation.
- **mTLS Listener (LOW)**: Adding a second listener for agents increases the server's port footprint.

**Suggestions**
- Ensure the `host approve` command prints the identity fingerprint clearly so the admin can verify it against the host's `keyroster-agent identity` output.

**Risk Assessment: LOW**
Secure, pull-only architecture.

---

### 03-08
**Summary**
This plan adds operational visibility (heartbeats, status view), periodic drift checks, and hardened systemd/OpenRC units.

**Strengths**
- **Convergence View**: The `host status` command allows the admin to see exactly which hosts are lagging behind a CA or KRL update.
- **Hardened Units**: Using `IPAddressDeny=any` and `ProtectSystem=strict` for the applier enforces the "no network" and "limited write" constraints at the OS level.
- **Identity Rotation**: Allowing the agent to rotate its mTLS identity without re-enrollment is a good operational detail.

**Concerns**
- **Heartbeat Noise (LOW)**: Frequent heartbeats from a large fleet could clutter the server logs, though the database upsert handles the state.

**Suggestions**
- Add a "last seen" timestamp to the `host status` output to quickly identify dead agents.

**Risk Assessment: LOW**
Operationalizes the agent without introducing new security risks.

---

### 03-09
**Summary**
This plan implements host certificates, removing the TOFU prompt for users and allowing the admin to revoke hosts.

**Strengths**
- **PoP Issuance**: Host certificates are only issued if the agent proves possession of the host key.
- **Client-Side Trust**: The `@cert-authority` and `RevokedHostKeys` management in the CLI allows users to trust the fleet without TOFU.
- **Host Revocation**: The "revoke host" flow (disable in directory + explicit-key KRL entry) is a complete kill-switch.

**Concerns**
- **Directory Disclosure (MEDIUM)**: Giving the full signed directory to every logged-in user (T-03-100) discloses the full list of hosts and roles. The plan accepts this based on the "single organization" assumption.

**Suggestions**
- In the `known-hosts sync` logic, ensure the `Include` line is added to the top of the config to avoid being overridden by later `Host` blocks.

**Risk Assessment: LOW**
Achieves a major roadmap goal (No TOFU) using native OpenSSH features.

---

### 03-10
**Summary**
This plan completes the self-test by adding "probe" certificates that prove `sshd` is actually enforcing the CA and KRL.

**Strengths**
- **Positive/Negative Probes**: Proving both that a valid cert is accepted and a revoked cert is refused is the only way to be sure the KRL is active.
- **Nologin Shell**: Using a `*` password and nologin shell for the probe account ensures the probe cannot be used for actual access.
- **Rate Limiting**: Limiting negative probes prevents the agent from triggering `PerSourcePenalties` and locking itself out.

**Concerns**
- **Probe Account Management (LOW)**: The agent depends on the probe account existing. If an admin deletes the account, the agent will enter a "probe_pending" state and stop applying changes.

**Suggestions**
- The `preflight` check should explicitly warn the admin if the probe account is missing or has a shell that isn't nologin.

**Risk Assessment: LOW**
Adds a critical "trust but verify" layer to the apply engine.

---

### 03-11
**Summary**
This plan implements machine identities for automation, allowing them to obtain day-scale certificates via PoP.

**Strengths**
- **Role-Based Caps**: Correctly applies the most restrictive TTL among the machine's roles, the machine entry, and the CA profile.
- **Unauthenticated Route**: The `/machine/renew` route is correctly limited by a dedicated rate-limiter since it cannot use session auth.
- **Revocation Integration**: Machine identities are fully integrated into the existing revocation and audit systems.

**Concerns**
- **Private Key Handling (LOW)**: The plan relies on the user providing a key file or using an agent. It must be strictly verified that the private key never touches the server.

**Suggestions**
- Add a "machine-identity" section to the audit report to show which automation is renewing most frequently.

**Risk Assessment: LOW**
Extends the CA's utility to automation without weakening the security model.

---

### 03-12
**Summary**
This plan implements the complex "two-ceremony" CA rotation process to ensure zero-downtime transitions.

**Strengths**
- **Draining State**: The `trusted_until` field allows a graceful overlap where both old and new CAs are trusted until all certificates have expired.
- **Keystore Generations**: Supporting multiple generations per role in the keystore allows the signer to handle the transition.
- **Convergence Tracking**: Using `host status` to verify the fleet has the `next` CA before switching is the correct way to avoid outages.

**Concerns**
- **Complexity (MEDIUM)**: The state machine for CA transitions (active $\rightarrow$ next $\rightarrow$ draining $\rightarrow$ retired) is complex and prone to implementation errors.

**Suggestions**
- Add a "rotation-status" command to the CLI that shows the current state of any ongoing CA rotation (e.g., "User CA: Switching to g2, 45/50 hosts converged").

**Risk Assessment: MEDIUM**
High complexity, but the "two-ceremony" approach is the industry standard for zero-downtime CA rotation.

---

### 03-13
**Summary**
This plan completes the rotation suite by adding log-key and ops-key rotation and an emergency CA replacement path.

**Strengths**
- **Log-Key Segments**: The audit verify logic that follows log-key changes via segments is the only way to maintain a tamper-evident chain across rotations.
- **Emergency Path**: The `ca-emergency` flag allows an immediate switch to a new CA, combined with an explicit-key revocation of the compromised one.
- **Ops-Key Sync**: Ensuring the signer republishes the KRL immediately after an ops-key change prevents agents from rejecting the new KRL.

**Concerns**
- **Audit Complexity (LOW)**: The `anchor.install` logic becomes significantly more complex with log-key segments.

**Suggestions**
- Ensure the emergency rotation runbook emphasizes that the "old" CA key must be revoked immediately after the switch.

**Risk Assessment: LOW**
Completes the "lifecycle" requirements for all CA keys.

---

### 03-14
**Summary**
This plan implements the "break-glass" emergency access path, ensuring a root-signed offline CA can always grant access to a dedicated account.

**Strengths**
- **Match-Block Isolation**: Placing the break-glass CA inside a `Match User` block ensures it cannot be used to access any other account.
- **Offline Signing**: The `breakglass sign` command allows the operator to create a certificate without the server being online.
- **Sudo Integration**: Requiring an offline password for sudo ensures that even a stolen break-glass certificate doesn't grant immediate root.

**Concerns**
- **Sudoers Management (LOW)**: The agent does not manage the sudoers file; the runbook must be followed exactly.

**Suggestions**
- The agent's `CheckBreakglassAccount` should report if the sudoers rule for the emergency account is missing (if it can read the file).

**Risk Assessment: LOW**
Provides a critical safety valve without introducing a permanent backdoor.

---

### 03-15
**Summary**
This plan manages the transition of the homelab from TEST roots to real offline roots, closing KEY-07.

**Strengths**
- **Rehearsal**: The `TestV4CeremonyRehearsal` ensures the exact command sequence is proven before the owner performs the one-way ceremony.
- **Hash Approval**: The "install by hash" pattern prevents the signer from installing a bundle that was tampered with during transfer.
- **Attestation**: The destruction of TEST roots is recorded as a formal event.

**Concerns**
- **One-Way Door (MEDIUM)**: Once the real roots are installed and TEST roots destroyed, there is no going back. The rehearsal is the only mitigation.

**Suggestions**
- Ensure the `directory rebind` is performed *after* the bundle install to ensure the installation ID is correctly pinned.

**Risk Assessment: LOW**
A procedural plan for a high-stakes event, mitigated by a full rehearsal.

---

### 03-16
**Summary**
The final plan of the phase: dogfooding the entire system on the owner's real hosts and running the final drills.

**Strengths**
- **Full-Spectrum Testing**: Covers everything from enrollment and adoption to revocation timing and break-glass.
- **Honest Labeling**: The "UNVERIFIED" labels for non-exercised paths (e.g., OpenRC) prevent overclaiming.
- **Corroboration**: Matching the signer's log against the host's sshd journals provides high-assurance evidence.

**Concerns**
- **Homelab Variance (LOW)**: The Proxmox host's specific SSH layout might differ from the test VM; the preflight check is the primary defense.

**Suggestions**
- The "Revocation timing" record should include the network latency between the server and the host to isolate the "poll interval" delay.

**Risk Assessment: LOW**
The final verification step.

---

### Overall Risk Assessment: LOW

The Phase 3 plans are exceptionally thorough. The "Security-First" approach is evident in:
1. **The Privilege Split**: The root applier is network-less, and the fetcher is unprivileged.
2. **The Self-Test**: The use of probe certificates to prove KRL enforcement on every apply.
3. **The Atomic Layout**: Using generations and symlinks to prevent `sshd` from reading partial state.
4. **The Root-Signed Chain**: Every piece of state (bundle, policy, directory, KRL) is verified against a root of trust.

The most significant risk is the complexity of the CA rotation and the "one-way" nature of the root ceremony, both of which are mitigated by extensive rehearsal and a "two-ceremony" transition. The decision to disclose the directory to logged-in users (T-03-100) is a calculated trade-off for simplicity in a single-tenant environment.
---

## Consensus Summary

Only one reviewer (Codex) checked the plans against the source. nemotron and gemma read the plan text only, so their verdicts are not weighted as full reviews. "Agreed" below therefore means **Codex plus at least one ungrounded model**. Every point is a finding still to be verified, not an established consensus. The overall verdicts differ widely: Codex rates 14 of 16 plans HIGH, nemotron rates the phase MEDIUM, and gemma rates it LOW.

Four Codex claims were spot-checked against the plans while this file was written:
- **03-01 frame cap.** Already covered. The plan defines `MaxKRLFrame = krl.MaxKRL + 64<<10` for GetKRLResponse (03-01-PLAN.md, Wire paragraph). The concern shrinks to the client-side response cap.
- **03-12 one key per role.** The source fact is true (`internal/signer/trust.go:300-316`). The plan already names `checkBundleKeys`, `loadTrust` and migration `0006_ca_generations.sql`.
- **03-13 log origin.** The source fact is true: a new log key means a new origin (`internal/tlog/checkpoint.go:26-31`). The plan records `(fromSize, logKey, origin)` segments. Whether that fully answers the continuity point is still open.
- **03-03 issuance rows.** True: issuance rows store no `valid_before` (`internal/signerdb/issuance.go:18-26`).

All other findings are unverified.

### Agreed Strengths
- **Order of the plans.** Revocation and signed formats come first, then the offline apply engine, then transport, then host and machine identities, rotation, break-glass and dogfood. All three reviewers named this.
- **Fetcher/applier split.** The fetcher is unprivileged and the root applier has no network. The applier re-verifies everything against its pins.
- **KRL testing.** The KRL parser and encoder are strict, tested against `ssh-keygen` in both directions, and fuzzed.
- **Real sshd.** End-to-end tests run against real sshd 9.5p1 and 10.5p1.
- **Owner checkpoints before code.** D-04, D-05 and T-03-100 are decided before implementation, and the UNVERIFIED labels are honest.
- **Break-glass isolation.** A separate `Match User` scope and an offline CA isolate break-glass access (Codex, nemotron).

### Agreed Concerns
1. **Loopback-only self-test vs real hosts (03-05, 03-16).** All three raised this; Codex and nemotron rate it HIGH. A host whose sshd listens only on a tailnet address is refused with `no_loopback_listener`. In 03-16 this is a note, but Task 2 requires every enrolled host to pass its self-test. Make it a blocking preflight and owner checkpoint before enrollment.
2. **T-03-100 `redeem-directory` disclosure (03-09).** All three raised this. Every user who logs in receives the full signed directory. That widens D-03's audience (credential IDs, host names, roles). The owner decided it, but response size, caching and privacy should be stated in code and docs.
3. **Agent clock skew (03-12; recurring in nemotron).** `trusted_until`, KRL staleness and probe timing all use the agent's local clock. A clock running ahead drops the draining CA early. Options: clock-health gating, a margin above 300 s, and skewed-clock tests.
4. **`account_excluded` (03-06).** Codex (HIGH) calls the check a heuristic; it should use `sshd -T -C` per account and be backed by real logins. nemotron (HIGH) asks whether a report-only exclusion lets the agent claim success for an account that cannot log in.
5. **Probe account safety (03-10).** Codex and nemotron, both HIGH. Whether a `*` password plus a nologin shell is safe depends on the platform, and Alpine's `sed /etc/shadow` step is fragile. Run it on all seven images and fail closed on unknown shadow formats. Codex also wants the negative-probe rate limit (6 per hour) to survive restarts.
6. **Break-glass `Match` semantics (03-14).** Codex and nemotron, both HIGH. The claim that break-glass survives a broken main CA line rests on `Match`-scoped CA settings. Test it on the packaged OpenSSH versions. nemotron adds `Match` order across drop-ins, and PAM lockout (`pam_faillock`), which a shadow check cannot see.
7. **`machine renew --key FILE` (03-11).** Codex MEDIUM, nemotron HIGH. Passphrase handling when the CLI runs non-interactively: refuse when stdin is not a terminal, read with bounds, zero the key material. Codex also raises role overlap between machine and human principals (HIGH).
8. **Log-key rotation handoff (03-13).** Codex says the root-signed successor authorizes the new key but does not prove Merkle continuity under a new origin. nemotron asks whether the signer restart is automatic or leaves a window.
9. **v4 ceremony (03-15).** All three. It is a one-way change with several steps after signing. Codex suggests checking the prepared CA key and policy hash before the owner signs, and having one generated command list shared by the rehearsal and the runbook.
10. **Subject revocation boundaries (03-03).** Codex: `valid_before` is not stored, so the candidate certificates must be parsed, and signer and audit must use exactly the same time and boundary rule. nemotron: the pruning rule must use the manifest's `issued_at`, and the CLI must explain itself when a certificate is not found by subject.
11. **Host certificate principals unique across hosts (03-04).** Codex asks for normalisation of IP and DNS spellings. nemotron asks whether the uniqueness is on certificate principals or role principals.

### Divergent Views
- **Atomic generation swap (03-05).** Codex (HIGH, Codex only): sshd opens the CA, principals and KRL files separately, so one `current` symlink swap does not guarantee one consistent generation per authentication. A login during swap→rollback can also see the bad state. It asks for a concurrent-swap test. gemma and nemotron list the generation layout as a strength. **This is the most important point to verify.**
- **Spool/outbox trust boundary (03-07, 03-08).** Codex only, HIGH: a compromised fetcher must not be able to overwrite the applier's pins, accepted state, pending marker or `status.json` through shared directories. It asks for a per-file ownership and rename policy, plus symlink and path-traversal tests.
- **Rotation storage (03-12).** Codex HIGH: generations must reach every backend and startup path. The spot check shows the plan names these paths, so this is probably mostly covered.
- **Overall risk.** Codex HIGH, nemotron MEDIUM (residual risks are "operational, not design flaws"), gemma LOW. gemma cites no evidence and rates almost everything LOW, the same pattern as in earlier rounds.
- **nemotron-only HIGHs worth checking.** PIV slot exhaustion across many rotations (03-12). Disabling a host entry should remove its host certificate (03-09). PK_OK behavior on all distro sshd versions (03-10).

**Recommended next step.** Verify adversarially before `/gsd-plan-phase 3 --reviews`, as in earlier rounds, when 70–90 % of reviewer findings were refuted or already covered. At minimum verify the 03-05 swap consistency, the 03-07 spool boundary, Agreed Concerns 1, 4, 5 and 6, and 03-13 continuity.

---

## Verification Round (Codex gpt-6-astra, xhigh, read-only) — 2026-10-24

The twelve main findings above (F1–F12) were rechecked by Codex on **gpt-6-astra at xhigh effort**, read-only, against the plan text, the Go source and OpenSSH 9.5p1/10.5p1 source. The first review lane ran on gpt-6-luna. Afterwards Claude rechecked the one CONFIRMED finding and every HIGH that Codex dismissed (F4, F6, F7, F8, F10) against the plans and the source. All of Codex's verdicts held up:

- **F1:** 03-05 sends all three paths through one `current` symlink and does not reload on content changes.
- **F7:** `internal/audit/verify.go:795-818` rebuilds the root from every leaf, independent of the origin.
- **F9:** the clamp is at `internal/signer/logstate.go:409`.
- **F8:** agent and sshd share the host clock, so the refutation stands.

Result: **CONFIRMED 1 · PARTIAL 6 · ALREADY-COVERED 3 · REFUTED 2.**

| ID | Plan | Verdict | Severity | Required plan change |
|---|---|---|---|---|
| F1 | 03-05 | CONFIRMED | HIGH | A mixed generation can let through a certificate that neither generation allows. Each authentication must see one consistent generation, and an interleaving test is needed. **Owner design decision required** (see below). |
| F2 | 03-05, 03-07 | PARTIAL | MEDIUM | The permissions are already specified: pins root 0600, spool `keyroster-agent:root 0750`, outbox `root:keyroster-agent 0750`. Missing: dirfd-relative opens with no symlink following, a regular-file check that does not block on a FIFO, verify-and-install from the same captured bytes, root ownership of the state parent, and adversarial spool tests. |
| F3 | 03-16 | PARTIAL | MEDIUM | 03-06 already refuses apply on `no_loopback_listener`. However, 03-16 Task 1 checks `test $? -ne 2`, which lets refusal exit 3 through, so a host can be enrolled without ever passing a self-test. Fix: Task 2 runs only on hosts with a successful preflight, after the manual `ListenAddress 127.0.0.1` fix. |
| F4 | 03-06 | ALREADY-COVERED | — | `account_excluded` is report-only by design, and per-account `sshd -T -C` is already required. |
| F5 | 03-10 | PARTIAL | MEDIUM | The account checks and distro tests are already there. Missing: a negative-probe budget that persists under the apply lock (7 separate processes or restarts in the test), and explicit session restrictions on the probe certificate (`force-command`, no `permit-pty`/forwarding, optional `source-address`). `internal/cert/builder.go:113,152` keeps the profile defaults, and nologin does not stop forwarding. |
| F6 | 03-14 | ALREADY-COVERED | — | Effective-path checks with rollback; login despite corrupt main files on 9.5p1, 10.5p1 and all seven images. PAM is a flagged assumption. |
| F7 | 03-13 | REFUTED | — | The new origin does not reset the tree. Verification rebuilds the whole root and checks the previous checkpoint against its prefix. |
| F8 | 03-12 | REFUTED | — | 300 s margin, and agent and sshd share the host clock. Certificates within the drain bound have already expired in sshd when `trusted_until` is reached. |
| F9 | 03-03 | PARTIAL | MEDIUM | Parsing and pruning on `issued_at` are covered. Remaining: if the clock steps back, `appendLocked` raises the revoke leaf's time, so audit evaluates at a later time than the signer did and rejects an honest entry. Fix: one defined resolution timestamp (record it in the leaf), plus tests at equality, sub-second boundaries and clock rollback. |
| F10 | 03-09 | ALREADY-COVERED | — | The privacy trade-off is documented, and the 1 MiB directory and 4 MiB HTTP caps already exist. Disabling a host entry keeps last-good (03-05). `revoke host` is the way to remove a host's access. |
| F11 | 03-11 | PARTIAL | MEDIUM | Bounded key reads, immediate refusal when a passphrase is needed without a terminal (reuse `internal/rootceremony/passphrase.go:26`), clearing of buffers, and tests. Shared roles between machines and humans are intended. |
| F12 | 03-01, 03-07 | PARTIAL | MEDIUM | The signer socket cap is covered (`ResponseCaps`, `internal/wire/frame.go:99`). Remaining: a 4 MiB KRL in base64 is about 5⅓ MiB, which exceeds the client's 4 MiB HTTP cap (`internal/serverclient/client.go:161`). The fetcher's catch-up of up to 16 versions has no total byte bound. Fix: an explicit KRL HTTP bound including encoding overhead, plus aggregate or paginated fetch limits with max and max+1 tests. |

The other findings in the reviews above were not verified one by one in this round. Treat them as input to the planner, not as confirmed defects.

### Codex verification report (verbatim, links made repo-relative)

| ID | Verdict | Severity | Evidence (short) |
|---|---|---|---|
| F1 | **CONFIRMED** | **HIGH** | [03-05, Task 2 — `internal/agent/apply`](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:214) puts all three paths through `current`. OpenSSH checks revocation, then CA trust, then principals through separate reads; a mixed generation can **accept**, not merely refuse. Details below. |
| F2 | **PARTIAL** | **MEDIUM** | The shared-write premise is substantially wrong: [03-07, Task 1 — “Applier side”](../../../.planning/phases/03-linux-agent-and-revocation/03-07-PLAN.md:182) specifies pins `root 0600`, spool `keyroster-agent:root 0750`, and outbox `root:keyroster-agent 0750`. However, [03-05, Task 2 — “internal/agent/spool”](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:205) specifies size caps without a regular-file/no-symlink opening contract; parent-state ownership is also insufficiently explicit. |
| F3 | **PARTIAL** | **MEDIUM** | There is a blocking **apply** gate: [03-06, Task 1 — `preflight.go`](../../../.planning/phases/03-linux-agent-and-revocation/03-06-PLAN.md:127), “refuses on any refusal code,” including `no_loopback_listener`. There is no equivalent pre-enrollment gate: [03-16, Task 1 verification](../../../.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md:116) checks `test $? -ne 2`, which permits refusal exit **3**. |
| F4 | **ALREADY-COVERED** | — | [03-06, must-haves](../../../.planning/phases/03-linux-agent-and-revocation/03-06-PLAN.md:41) explicitly requires per-account `sshd -T -C`; [Task 1 — `preflight.go`](../../../.planning/phases/03-linux-agent-and-revocation/03-06-PLAN.md:127) explicitly makes `account_excluded` “report only” and `user@host` “may exclude.” This is an intentional diagnostic limitation. `-T -C` dumps effective configuration; it does not prove login. SSH access restrictions remain enforced. [OpenSSH `sshd(8)`](https://man.openbsd.org/sshd.8#C), [`sshd_config(5)`](https://man.openbsd.org/sshd_config#AllowUsers). |
| F5 | **PARTIAL** | **MEDIUM** | Account safety and platform testing are already substantial: [03-10, must-haves](../../../.planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md:55) requires exclusive probe-principal mapping and checks before every probe; [Task 2](../../../.planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md:184) tests real accounts under packaged PAM settings and `UsePAM no`. The six/hour limit lacks explicit persistence and restart coverage; its [named test](../../../.planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md:179) only describes seven applies. |
| F6 | **ALREADY-COVERED** | — | [03-14, Task 1 — “Agent” and “e2e”](../../../.planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md:125) requires effective-path checks with rollback and login despite corrupt main files; [verification](../../../.planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md:132) names **9.5p1 and 10.5p1**. [Task 2](../../../.planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md:147) repeats this on all seven distro images. First matching value wins, but the effective-path check detects interference. PAM limitations are explicitly acknowledged under [“Flagged assumption, BREAK-01”](../../../.planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md:225). [OpenSSH Match/UsePAM mechanisms](https://man.openbsd.org/sshd_config#Match). |
| F7 | **REFUTED** | — | Changing origin does not reset the Merkle tree. [03-13, Task 1 — “Signer”/“Audit”](../../../.planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md:116) switches the checkpoint signer and records `(fromSize, logKey, origin)` segments. Existing verification reconstructs the complete root and checks the previous checkpoint against the corresponding prefix: [internal/audit/verify.go:795](../../../internal/audit/verify.go:795), [verify.go:813](../../../internal/audit/verify.go:813). Tree hashing is independent of origin: [internal/tlog/log.go:18](../../../internal/tlog/log.go:18). |
| F8 | **REFUTED** | — | A **300-second margin exists**: [03-12, Task 1 — “Bundle”](../../../.planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md:151). No clock-health gate is specified. However, the agent and local sshd use the same host clock: for certificates within the stated drain bound, an ahead clock reaching `trusted_until` has already expired those certificates in sshd. It does not establish an additional CA-removal lockout. OpenSSH’s `sshkey_cert_check_authority_now()` uses `time(NULL)` and rejects `verify_time >= valid_before`. [Tagged OpenSSH source](https://github.com/openssh/openssh-portable/blob/V_9_5_P1/sshkey.c). |
| F9 | **PARTIAL** | **MEDIUM** | Parsing and ordinary boundaries are explicitly covered: [03-03, Task 1 — “Signer”](../../../.planning/phases/03-linux-agent-and-revocation/03-03-PLAN.md:136) says “parses each … stored certificate,” uses `ValidBefore + 300 s > now`, and prunes against `issued_at`. The residual issue is that [“Audit verify”](../../../.planning/phases/03-linux-agent-and-revocation/03-03-PLAN.md:143) uses `leafMicros`, while existing append logic can advance that timestamp: [internal/signer/logstate.go:409](../../../internal/signer/logstate.go:409). |
| F10 | **ALREADY-COVERED** | — | Privacy is explicit in [03-09, Task 1 — `redeem-directory` cons](../../../.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md:163). The numeric byte budget is not restated, but existing bounds suffice: directory **1 MiB**, signatures **64 KiB** ([internal/wire/directory.go:14](../../../internal/wire/directory.go:14)); HTTP response **4 MiB**, enforced before decoding ([internal/serverclient/client.go:452](../../../internal/serverclient/client.go:452)). **Disable does not remove an installed host certificate**: [03-05’s explicit last-good rule](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:52) preserves state. [03-09, Task 3](../../../.planning/phases/03-linux-agent-and-revocation/03-09-PLAN.md:248) separately defines host revocation. |
| F11 | **PARTIAL** | **MEDIUM** | [03-11, Task 1 — “CLI”](../../../.planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md:143) says “prompting for a passphrase on a terminal,” but does not specify bounded key reads, buffer clearing, or the nonterminal error path. Shared roles are deliberate authorization, not an escalation: [03-04, Task 1 — `CheckPolicy`](../../../.planning/phases/03-linux-agent-and-revocation/03-04-PLAN.md:146) explicitly covers roles used under both CAs. |
| F12 | **PARTIAL** | **MEDIUM** | The signer-client allegation is refuted: [03-01, Task 2 — “Wire”](../../../.planning/phases/03-linux-agent-and-revocation/03-01-PLAN.md:265) assigns the response type its cap; [internal/signerclient/client.go:119](../../../internal/signerclient/client.go:119) uses `ResponseCaps`, which derives the same per-type cap ([internal/wire/frame.go:99](../../../internal/wire/frame.go:99)). HTTP needs separate treatment: base64 of a maximum-size KRL already exceeds the existing 4 MiB response limit. |

This was read-only verification. References to planned tests describe required coverage, not evidence that those future tests have run. Upstream OpenSSH references identify tagged files and functions; repository references use actual source line numbers.

**F1 — Mixed generations can authorize a certificate that neither generation authorizes**

OpenSSH calls `user_key_allowed()` for both unsigned public-key queries and signed authentication requests. That function checks revocation first; `user_cert_trusted_ca()` subsequently reads the CA file and principals file. These are repeated authorization-time reads, not one connection-wide snapshot. The mechanism appears in both [9.5p1](https://github.com/openssh/openssh-portable/blob/V_9_5_P1/auth2-pubkey.c) and [10.5p1](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/auth2-pubkey.c). `sshkey_in_file()` opens the supplied pathname with `fopen()`. [OpenSSH authfile.c](https://github.com/openssh/openssh-portable/blob/V_9_5_P1/authfile.c).

Concrete interleaving:

- Generation A trusts CA C, does not revoke certificate X, but does not authorize X’s principal for account U.
- Generation B still trusts C, revokes X, and adds that principal to U.
- A **signed authentication request** checks A’s KRL; `current` changes; it then reads B’s CA/principals files. X can authenticate although both complete generations refuse it.

The missing contract is in **03-05 Task 2, `swap.go`/`apply.go`**, with missing reader-interleaving coverage in **Task 3**. The apply flock only serializes writers. [Plan locations](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:212), [existing concurrency test](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:239).

The broader “bad state during rollback” claim needs qualification: malformed CA/KRL candidates already have [pre-swap validation](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:48). Nevertheless, post-swap rollback cannot retroactively undo an accepted authentication.

**Minimal change:** require a generation consistent across each authentication—for example, immutable `gen/N` paths in the loaded configuration, reload per generation, and sufficient old-generation retention. Add a deterministic signed-authentication interleaving test and explicitly document candidate exposure before rollback.

**F2 — Filesystem hardening remains underspecified; arbitrary overwrite is unproven**

The specified outbox permissions do not let the fetcher replace `status.json`; signed spool data also cannot simply replace trusted pins or accepted documents. [03-05 Task 2 — “internal/agent/state”](../../../.planning/phases/03-linux-agent-and-revocation/03-05-PLAN.md:200) requires independent verification against stored pins. Heartbeat claims are separately acknowledged as untrusted host reports in [03-08, “Trust Boundaries”](../../../.planning/phases/03-linux-agent-and-revocation/03-08-PLAN.md:254).

The remaining concrete failure is a recognized spool filename implemented as a FIFO, or a symlink to one: an ordinary blocking open/read could stall the root apply/check loop before byte limits help. This is a missing opening contract, not a demonstrated arbitrary-write exploit.

**Minimal change:** in **03-07 Task 1**, specify and verify root ownership/non-writability of the state parent, accepted state, and pending-marker destinations. In **03-05 Tasks 2–3**, require descriptor-relative, no-follow opens, regular-file checks without blocking on special files, and verification/install from the same captured bytes; add adversarial spool tests.

**F3 — Enrollment can proceed into an apply refusal**

A tailnet-only host can pass 03-16’s procedural check because exit 3 is allowed, then receive a token and approval, but never satisfy Task 2’s generation/self-test requirement. Existing SSH configuration remains protected by the apply refusal; this is an enrollment workflow failure, not demonstrated lockout. [03-16 Task 2 action and verification](../../../.planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md:131).

**Minimal change:** **03-16 Task 1** must require successful preflight on every host proceeding to Task 2, after the documented manual loopback fix. Merely recording the refusal must not satisfy that gate.

**F5 — Preserve the rate limit across processes**

The account-check criticism largely fails: a real shell, missing nologin executable, wrong shadow password field, expiry, and account exclusion all have explicit refusal cases. [03-10 Task 2](../../../.planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md:178). Packaged `*` behavior still needs execution of the required distro tests; the plan does not establish their results.

A probe certificate is not intrinsically “PK_OK-only.” Full authentication additionally requires its private key. The plan scopes its principal and protects the keys, but its [Signer paragraph](../../../.planning/phases/03-linux-agent-and-revocation/03-10-PLAN.md:149) does not mandate `force-command`, removal of `permit-pty`, or `source-address`. The generic builder preserves profile defaults and adds only explicitly requested critical options. [internal/cert/builder.go:113](../../../internal/cert/builder.go:113), [builder.go:152](../../../internal/cert/builder.go:152). Nologin also does not independently disable forwarding; OpenSSH checks forwarding permissions separately. [OpenSSH serverloop.c, `server_request_direct_tcpip()`](https://github.com/openssh/openssh-portable/blob/V_10_5_P1/serverloop.c).

The concrete uncovered limiter case is repeated `apply --once` executions or daemon restarts resetting an in-memory allowance. Whether this actually triggers packaged OpenSSH penalties remains the plan’s unresolved A9 test.

**Minimal change:** **03-10 Task 1** must persist the negative-probe budget under the apply lock; **Task 2** must exercise seven separate process invocations/restarts. Also make the probe’s intended session/forwarding restrictions explicit instead of crediting protections that are not specified.

**F9 — Resolve the timestamp before computing the live set**

The missing `valid_before` database column is already handled: issuance stores the certificate blob ([internal/signerdb/issuance.go:19](../../../internal/signerdb/issuance.go:19)), and the plan explicitly parses it. Pruning against manifest `issued_at` is also covered.

The residual scenario is a clock rollback across boundary `E = ValidBefore + 300s`: signer resolution uses wall time just before E and includes the serial, but `appendLocked()` raises the revoke leaf’s time to a previous timestamp after E. Audit resolves at that later `leafMicros` and rejects the honest entry set. The clamp is explicit at [internal/signer/logstate.go:405](../../../internal/signer/logstate.go:405).

**Minimal change:** **03-03 Task 1** must define one resolution timestamp and its relationship to the log timestamp clamp—recording the resolution time explicitly is one option. **Task 2** should test equality, subsecond boundaries, and clock rollback. This is an audit false-rejection risk, not evidence of a successful audit forgery.

**F11 — Complete the private-key input contract**

The planned disk-write test checks that private material is not written; it does not cover input size, noninteractive prompting, or memory cleanup. [03-11 Task 2 — `TestMachineRenewNeverWritesKey`](../../../.planning/phases/03-linux-agent-and-revocation/03-11-PLAN.md:168).

A scheduled renewal with an encrypted key needs a deterministic error when interactive input is unavailable. An unbounded key-file read can exhaust memory. Existing terminal-checking helpers exist, but the new path is not required to use them. [internal/rootceremony/passphrase.go:26](../../../internal/rootceremony/passphrase.go:26).

**Minimal change:** **03-11 Tasks 1–2** should specify bounded key reads, immediate nonterminal refusal when a passphrase is required, clearing of owned sensitive buffers, and corresponding tests. Shared human/machine roles need no prohibition: the plan expressly makes those grants admin-controlled.

**F12 — Separate binary-frame and HTTP limits**

The binary socket cap is already shared by writer and reader. The remaining issue is HTTP representation: a 4 MiB KRL becomes approximately **5⅓ MiB** in base64 before manifest/signature/JSON overhead, exceeding [the existing response cap](../../../internal/serverclient/client.go:161).

The new agent fetcher also lacks an explicit aggregate HTTP bound. Its state endpoint may return up to sixteen bundle and directory versions, so a spool-file cap alone does not define transport allocation limits. [03-07 Task 2 — “Chain catch-up”](../../../.planning/phases/03-linux-agent-and-revocation/03-07-PLAN.md:225).

**Minimal change:** **03-01 Task 2** should define a KRL HTTP response bound including encoding overhead; **03-07 Tasks 1–2** should define aggregate fetch limits or byte-budgeted pagination. Test maximum legitimate responses and limit-plus-one rejection.

Counts: **CONFIRMED 1 · ALREADY-COVERED 3 · REFUTED 2 · PARTIAL 6**.
### Owner decision on F1 (2026-10-24): two-step swap, no reload

Daniel chose the **two-step swap with no reload** over immutable `gen/N` paths with a reload per apply, and over accepting the window.

**The rule.** Applying generation B over A happens in two steps:
1. Swap `current` to an intermediate generation **M = (KRL_B, CA_A ∩ CA_B, P_A ∩ P_B)**. The CA sets are compared per key; the principal sets are compared per account file and per line.
2. Wait longer than sshd's `LoginGraceTime`, read from `sshd -T`, then swap to B.

**Why it is safe.** sshd reads the KRL first, then the CA keys, then the principals. Any mix of A and M is therefore no more permissive than A, and any mix of M and B is no more permissive than B. A mix of A and B cannot happen, because no pre-authentication step outlives `LoginGraceTime`. Revocations and removals take effect at step 1; additions take effect at step 2.

**Rules the planner must carry into 03-05, and wherever the swap is reused (03-09, 03-12, 03-14):**
- **No mixed KRL.** `KRL_M = KRL_B` is valid only because a KRL loses entries solely through 03-03's pruning of certificates past ValidBefore + 300 s, and explicit-key entries are permanent. If any path can drop a live entry, M must use the union of both KRLs instead. State this assumption and test it.
- **Unbounded `LoginGraceTime`.** A value of `0` means sshd has no bound, so the preflight refuses with a new code such as `login_grace_unbounded`. 03-06 is where the refusal set is documented.
- **Rollback.** Rollback from B to last-good goes through the same kind of intermediate generation, built from B and last-good. A crash between the steps is recovered through the pending marker, which records the step. A rollback from M to A is safe directly.
- **Self-test.** The self-test runs after the final step. A failure rolls back through the intermediate generation.
- **Interleaving test.** A deterministic test of signed authentications interleaved with the swap: the read order is KRL, then CA, then principals, plus the A→M→B and B→M→A sequences. The tracer and AGENT-03 claims that revocation applies "at once with no reload" still hold, because revocation is live at step 1.
- **Timing.** The roughly 2-minute delay for additions is documented in the runbook. The REVOKE-02 measurement in 03-16 records it.

### Owner decisions on planner questions (2026-10-24, round 1 replanning)

1. **Swap timing.** Daniel accepted planner B's generalised rule for 03-05:
   - Narrowing swaps, which only remove or revoke, happen at once.
   - Widening swaps (a new CA key or principal line) wait until `LoginGraceTime` + 5 s after the *previous* swap of `current`. That time is recorded in `<state>/last_swap.json` as boot_id plus CLOCK_BOOTTIME.

   A→M→B is one case of the rule. Reason: under the literal rule, a revoke-only apply followed by an add-only apply one poll later would recreate the forbidden mix. Additions go live at most `LoginGraceTime` + 5 s after the last swap, and at once when there was no swap in that window.

2. **The KRL in M stays KRL_B,** with a clock-skew alert. The agent raises a host-status alert `clock_skew` when |`clock_offset_s`| exceeds 300 (03-08). A host whose clock lags by more than that already accepts expired certificates in steady state, so the root cause is clock health. A union KRL was rejected: it would put the encoder in the root applier.

3. **`pop.hosts` is mandatory for host agents.** Under locked D-06, revocations must never stall because probe certificates are unavailable. Therefore:
   - Enrolment (join token, enrol and `host approve`) refuses `host_pop_not_enabled` while the installed root-signed policy lacks `pop.hosts`, and the agent's install and preflight check the pinned policy (03-07).
   - A successor policy cannot turn `pop.hosts` from true to false (`pop_hosts_removed`). The signer, `trust verify` and audit all enforce this (03-04).
   - The "one grace apply, then stuck on last-good" path for a policy without `pop.hosts` becomes unreachable (03-10).
   - The v4 policy carries `pop.hosts` (03-15).

### Owner decisions after plan-checker iteration 1 (2026-10-24)

1. **LoginGraceTime residual (03-05): accepted.** The agent waits for the largest `LoginGraceTime` it has observed. It observes at start, on every apply and on every drift check, and keeps the value across its own reloads (`ObserveLoginGrace`, `<state>/login_grace.json`). What remains is a value that host root raises, reloads and reverts between two observations. Daniel accepted it as a residual, because host root is already trusted with its own sshd in the threat model. Pinning `LoginGraceTime` in the drop-in, and tracking pre-auth children through /proc, were both rejected.
2. **Context budgets: all recorded Budget Exceptions are accepted** for the Phase 3 plans as revised in round 1, with no further splits. 03-03's optional split into a separate parser plan was declined.
