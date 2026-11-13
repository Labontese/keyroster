---
phase: 03-linux-agent-and-revocation
plan: 14c
type: execute
wave: 30
depends_on: ["03-14b"]
files_modified:
  - internal/audit/verify.go
  - internal/audit/revoke.go
  - internal/audit/export.go
  - internal/audit/installation_test.go
  - internal/audit/verify_test.go
  - internal/audit/forget_test.go
  - internal/audit/export_test.go
  - cmd/keyroster/audit.go
  - cmd/keyroster/audit_test.go
  - internal/serverclient/client.go
  - internal/serverclient/client_test.go
  - cmd/keyroster/config.go
  - cmd/keyroster/init.go
  - cmd/keyroster/init_test.go
  - cmd/keyroster/dirpipe.go
  - cmd/keyroster/host.go
  - cmd/keyroster/hoststatus.go
  - cmd/keyroster/login.go
  - cmd/keyroster/knownhosts.go
  - cmd/keyroster/machinerenew.go
  - cmd/keyroster/revoke.go
  - cmd/keyroster/user.go
  - cmd/keyroster/recover.go
  - cmd/keyroster/trust.go
  - cmd/keyroster/installpin_test.go
  - cmd/keyroster/dirpipe_test.go
  - cmd/keyroster/host_test.go
  - cmd/keyroster/login_test.go
  - cmd/keyroster/user_test.go
  - cmd/keyroster/recover_test.go
  - cmd/keyroster/peer_text_test.go
  - cmd/keyroster/remote_text_test.go
  - cmd/keyroster/ceremony_golden_test.go
  - cmd/keyroster/testdata/ceremony/successor_unchanged.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/successor_added_admin.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/successor_pop.trust_verify.golden
  - cmd/keyroster/testdata/ceremony/genesis_pop.trust_verify.golden
  - test/e2e/audit_test.go
  - test/e2e/pkcs11_test.go
  - test/e2e/tpm_test.go
  - test/e2e/restore_test.go
  - test/e2e/revoke_test.go
  - docs/runbooks/signer-install.md
  - docs/runbooks/server-install.md
  - docs/runbooks/host-setup.md
  - docs/runbooks/revoke.md
  - docs/runbooks/root-ceremony.md
  - docs/runbooks/ceremony-transcript-template.md
  - docs/runbooks/enroll-user.md
  - docs/runbooks/machine-identities.md
  - docs/format-registry.md
  - .planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md
  - .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md
  - .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md
  - .planning/ROADMAP.md
  - .planning/STATE.md
autonomous: false
requirements: [AGENT-01, REVOKE-01]

estimate:
  tokens: 280000
  raw_tokens: 280000
  tasks: 5
  confidence: low

must_haves:
  truths:
    - "Owner decisions (Daniel, 2026-10-29 and 2026-11-05): this plan fixes F05, F06, F10 and the PR #75 review follow-ups on audit verify's export lines; F15 moved to 03-14d (Q-C9). Every installation has its own roots, so F05 and F06 stay low. Q-C1 A, Q-C3 A, Q-C4 B, Q-C5 A, Q-C6 A and Q-C7 are decided. The plan lands right after 03-14b and before 03-14d and 03-12, at the wave origin/main's 03-12 holds at execution (30 at 3da914f, 03-14b merged as #98)"
    - "F05 and Q-C7. `keyroster audit verify` prints the installation ID of the trust bundle in force at the end of the log, in text and as `installation_id` in --json, and `none` when it names none. With `--installation-id <id>` (audit.Options.InstallationID) it refuses an export whose bundle in force names another installation, or none, naming both. When the bundle in force names an installation and neither `--installation-id` nor `--any-installation` is given, the CLI refuses and names the ID (Q-C7); the two flags together are a usage error. The comparison is with the bundle in force, not the anchor, because trust.VerifySuccessor carries an ID unchanged once set. Every runbook audit verify command passes `--installation-id`"
    - "F06 and Q-C3 A. `keyroster init` saves the installation ID of the bundle its root pins verified (Config.installation_id) and prints it. serverclient.Trust takes the pinned ID, so a command that acts on the served bundle refuses, before it signs a directory, revoke or forget request or mints a join token: a bundle of another installation under the same roots, an ID-less bundle once an ID is pinned, and a bundle that names an ID while the config pins none. Admin-API reads that run before Trust are origin-bound and read-only, and their error diagnosis names a pin error. ErrInstallationNotPinned and every runbook remedy give the full re-pin form, `--user` and `--admin-key` included, and ErrInstallationNotPinned and machine-identities.md also give the form without `--user` for an automation host's config. `keyroster revoke recover` keeps `recovery_installation_lost` first, then applies the same pin rule, telling a re-init from an escalation. Only init calls the unpinned variant. trust verify prints root sign's installation id line after the summary, in both modes (render-05)"
    - "F10 and Q-C4 B. With audit.Options.Now set, Verify refuses any entry whose leaf time is more than krl.PruneMargin (300 s) after the verifier's clock, with audit.ErrEntryAhead. The allowance is krl.PruneMargin by definition, pinned by a test, so within it an accepted KRL can leave out only certificates already expired at the verifier's clock. Both `keyroster audit verify` and `keyroster revoke recover` set Now; recover refuses `recovery_clock_ahead`. The refusal names the time it clears (the last entry's time minus 300 s) and says that correcting the signer's clock does not clear it. audit verify prints the last entry's time. Now 0 disables the bound for library callers"
    - "Export-line hardening (PR #75 review follow-ups). Verify refuses on every line any key, at any depth, that is not lowercase ASCII letters, digits and underscores, which is all Export writes. The parsed `version`, `directory`, `sigs`, `bundle_version`, `import_krl_versions` and `policy_version` must be the leaf's own where the kind has them, and are refused on kinds the byte checks refuse them on (policy_version on kinds whose decoder does not render it, a list derived from export.go at execution). Each of the ten forget-only keys has its own refusal case, with a real backslash-u escape in the line's bytes"
    - "Outputs: root sign's output, rootceremony.Summary, the trust bundle format and its field order are unchanged; trust verify gains one line, by addition only to four of 03-14b's goldens; audit verify gains two lines and two JSON fields, init one line. This plan allocates no leaf kind, wire message type, domain tag or signer refusal detail. No hardware is needed by any test or step"
  artifacts:
    - path: "internal/audit/verify.go"
      provides: "Options.InstallationID and Options.Now, ErrEntryAhead, the bundle-in-force check, the leaf-time bound, the parsed bound values and the key charset rule"
      contains: "InstallationID string"
    - path: "cmd/keyroster/audit.go"
      provides: "audit verify's --installation-id and --any-installation, the unbound refusal (Q-C7), the installation id and last entry time lines and their JSON fields"
      contains: "any-installation"
    - path: "internal/serverclient/client.go"
      provides: "Trust with the pinned installation ID, TrustUnpinned for init, CheckInstallationPin, ErrInstallationNotPinned with the full re-pin form, ErrInstallationMismatch"
      contains: "func CheckInstallationPin("
    - path: "cmd/keyroster/recover.go"
      provides: "the pin check after recovery_installation_lost, its two refusals, and Now on every Verify"
      contains: "recovery_clock_ahead"
    - path: "internal/audit/export_test.go"
      provides: "the syntactic gate on every key internal/audit writes"
      contains: "func TestExportKeysLowercase("
  key_links:
    - from: "cmd/keyroster/audit.go"
      to: "internal/audit/verify.go"
      via: "runAuditVerify passes --installation-id as Options.InstallationID and its clock as Options.Now"
      pattern: "InstallationID:"
    - from: "cmd/keyroster/revoke.go"
      to: "internal/serverclient/client.go"
      via: "openRevocation verifies the served bundle against the pinned installation, so the request and the KRL check use the pinned ID"
      pattern: "cfg.InstallationID)"
    - from: "cmd/keyroster/trust.go"
      to: "cmd/keyroster/root.go"
      via: "trust verify prints root sign's installationLine after the summary"
      pattern: "installationLine("
    - from: "cmd/keyroster/recover.go"
      to: "internal/audit/verify.go"
      via: "recover sets Options.Now and maps ErrEntryAhead to recovery_clock_ahead"
      pattern: "audit.ErrEntryAhead"
  prohibitions:
    - statement: "This plan changes no signed format, no trust bundle field or field order, no audit-log leaf format, no KRL, manifest or directory format, and no output line of root sign or rootceremony.Summary. It allocates no leaf kind, message type, domain tag or signer refusal detail, and adds no module. 03-14b's goldens change by added lines only. No test or step needs hardware"
      status: resolved
      verification: test
---

<objective>
An auditor and an admin's CLI each know which installation they are dealing with, and refuse another one's log or bundle even if the same roots signed it. audit verify names the installation of the log it verified, binds to it by default where the log has one, and refuses an entry dated past the auditor's clock. The CLI pins the installation ID at init and refuses a server that serves another installation's bundle; recover applies the same pin and the same clock bound. Export lines bind every value a JSON reader reads.

Purpose:
- **F05.** Today audit verify's verdict names a root set, not an installation: an export of another installation whose bundle chain has the same root set verifies as OK and anchored, and the output never shows an installation ID.
- **F06.** Today the CLI pins only the root set. A hostile server can serve another root-sharing installation's bundle, and the revoke confirmation, the directory checks and the join token's installation ID follow it.
- **F10.** Today audit verify bounds an entry's time only by the previous entry, so a krl_publish dated past a revoked certificate's prune time drops a revocation of a certificate that is still valid; the export still verifies, and `revoke recover` would import that KRL and publish without the revocation.
- **Export-line hardening (PR #75 review follow-ups).** A reader that matches keys without regard to case (Go's encoding/json struct decoding) reads keys checkLineKeys does not refuse; an optional bound key, or a key the byte checks forbid on a kind, written escaped or spaced, passes them; policy_version is bound on no line but host_forget's.
- **Requirements.** AGENT-01 (the agent pins the installation ID; its join token's ID now comes from the CLI's pin) and REVOKE-01 (the CLI's revocation, its confirmation and its recovery are bound to one installation). The plan also hardens VIS-03 (audit verify), outside Phase 3's IDs.

Output:
- audit.Options.InstallationID and Options.Now, ErrEntryAhead, and the CLI's two flags and lines;
- the CLI's installation pin through serverclient.Trust, init and recover, and trust verify's installation line;
- the export-line key rules;
- named tests committed RED first, with mutants;
- runbook updates (every audit verify command passes `--installation-id`), the transcript's Installation ID line, a registry step, six pointer sentences (03-12, 03-13, three in 03-15, 03-16) plus the 03-08c SUMMARY pointer (Q-C6 A), the publish edits and a PR.
</objective>

## Owner decisions (recorded, do not ask again)

- **Fix home (Daniel, 2026-10-29).** F05, F06 and F15 were planned together in 03-14c, before 03-15, so that the v4 ceremony's real roots and installation ID are made with the binding in place. F10 and the PR #75 review follow-ups were folded in because they change the same audit verify code.
- **Roots are per installation (Daniel, before planning).** Every installation has its own roots and roots were never shared, so F05 and F06 stay low and this plan stays before 03-15.
- **The answers after plan check 1 (Daniel, 2026-11-05).**
  - **Q-C1 = A: the slot.** Directly after 03-14b and before 03-12, with a wave guard. Facts: 03-14b's Task 1 precondition stops 03-14b if `cmd/keyroster/trust.go` changed since f7eb018, and this plan changes it, so it lands after 03-14b. 03-09's split (03-09b) and 03-14b's depends_on ["03-11"] (Q-B3) both shift the waves, so `wave: 25` is the value at f7eb018 with only 03-14b merged. The publish edits always take origin/main's 03-12 values. (Re-read at 3da914f: 03-11 was split into 03-11 and 03-11b (OQ-1, 2026-11-10), so 03-14b depends on ["03-11b"]; 03-14b re-based its frozen-file precondition from f7eb018 to b4e6b4c before it ran, and merged at 3da914f. The slot Q-C1 names is now wave 30, with 03-12 at 30 on main; the stop guard of Task 1's precondition 1 and publish edit 0 still takes origin/main's 03-12 values, and only refuses to absorb an unexpected shift silently.)
  - **Q-C3 = A: refuse an unpinned config on an installation that has an ID.** The remedy is a re-init. Facts and costs:
    - every genesis bundle gets an ID (cmd/keyroster/root.go, trust.NewInstallationID), so only a pre-D-04 bundle can gain one later (`root sign --prev ... --installation-id new`);
    - after that transition every CLI refuses until it is re-initialised, every command of every CLI user included (`keyroster login`, not only `directory rebind`), and every CLI user re-inits once; every automation host's config too, which `keyroster init` made without `--user` (machine-identities.md): its `keyroster machine renew` exits 1 until it is re-initialised without `--user` (re-read at 3da914f, where 03-11b's machine renew landed);
    - the error and every runbook remedy give the full re-pin form, `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]`, because --force replaces the whole config and TestRepinInstructionsKeepIdentity enforces --user and --admin-key;
    - 03-15's re-init (03-15-PLAN.md Task 4 instruction 2) runs init without --force, which init refuses on an existing config; this plan's pointer makes it pass --force and the full flag set;
    - 03-09 decided against a TOFU fallback for client host trust (D2).
  - **Q-C4 = B: both audit verify and `revoke recover` refuse entries more than 300 s ahead of the clock.** Facts:
    - `revoke recover` imports the saved export's last KRL (cmd/keyroster/recover.go), and the signer re-derives revocations logged after the backup only from the imported KRLs (krl.RecoveryEntries, internal/signer/recovery.go). Without Now, an F10-shaped saved export passes recover's Verify, waits out `recovery_version_not_above_import`, and then publishes a KRL without the still-valid revocation;
    - the signer clamps each leaf time forward (`max(leaf.TimeMicros, s.pendingMicros)`, internal/signer/logstate.go), so after an honest fast-clock episode every later entry carries at least the forward time; the refusal lasts until the verifier's clock reaches the last entry's time minus 300 s, and correcting the signer's clock does not clear it;
    - an honest fast clock stalls a restore under A and B alike, since restore step 2's audit verify sets Now under both and the recovery KRL version is time-derived (the signer refuses a publish not above the import); B can add up to one republish interval (krlRepublishAfter, 1 h). This fact was corrected in plan check 2; the decision stands;
    - the allowance is coupled to krl.PruneMargin and the relation is pinned by a test: within it, an accepted KRL can leave out only certificates already expired at the verifier's clock.
  - **Q-C5 = A: the host-side bound on a KRL's issued_at is deferred.** Corrected facts:
    - the rule that a refused bundle or directory step never stops the KRL is the PR #71 review F5 D-R2 (internal/agent/apply/apply.go, 03-07-PLAN.md T-03-280);
    - a host does compare issued_at with its clock: KRLStale is set when `now - issued_at >= KRLStaleAfter` (24 h, internal/agent/apply/status.go), so a forward-dated issued_at silences a host's krl_stale alert for the forward offset plus 24 h (T-03-352's residual);
    - the options were A (defer), B (refuse on hosts) and C (a report-only status flag for a future issued_at that never holds back the KRL).
  - **Q-C6 = A: one fixed pointer sentence in the landed 03-08c SUMMARY,** worded to say what is new: its "A in detail" block already records Go's case-insensitive match of the top-level `Decoded` key (03-08c-SUMMARY.md, four lines after the anchor), but not of nested keys. Task 4's verify keeps a branch for B.
  - **Q-C7 = yes: audit verify binds by default.** When the bundle in force names an installation ID and neither `--installation-id` nor an explicit `--any-installation` is given, audit verify refuses and names the ID. The runbooks pass the flag. It costs nothing on the ID-less homelab before 03-15.
  - **Q-C9 = split.** This plan keeps F05, F06, F10 and the PR #75 carry-overs. F15 (IssueRequest v2, `ca issue --installation-id`, and the table of every signed request type) is 03-14d, directly after this plan and before 03-12. Q-C2 and Q-C8 belong to 03-14d.
- **The PoP request types (03-09 owner decision D5).** The installation ID in HostIssue, ProbeIssue and MachineIssue is 03-09's, 03-10's and 03-11's; 03-14d checks them.
- **03-14b's expectations (03-14b-PLAN.md, Cross-plan notes).** 03-14c lands after 03-14b, extends its goldens by additions only, owns the installation-ID line in trust verify (render-05), and keeps TestCeremonyGolden, TestPolicyFieldsCovered, TestSummaryFieldsCovered and TestRootCeremonyPolicyChecks green.
- **Delivery (owner, 2026-10-29 and 2026-11-02).**
  - The plan lands in the repository in the same PR as its fix, with its ROADMAP and STATE rows, the wave shift of the plans after it and its pointer sentences.
  - The PR title, every commit and the SUMMARY describe the change neutrally, as hardening, and name the issues only as F05, F06 and F10.
  - Pushing the branch and opening the PR before the merge is allowed; the PR's diff is public while it is open.
  - Branch commits are signed and authored as Daniel, with keyroster-bot as committer, signer and pusher. The bot opens the PR without auto-merge, and Daniel squash-merges it himself.
- **Outside review.** A reviewer outside Claude (Codex) may review this PR. Its input is the repository diff and the PR's text only, never a ceremony folder, a passphrase file, `~/.ssh` or any planning file outside the repository.
- **Security levels (owner).** Hardware is optional and never required. Every test uses software keys, and no step needs a token.

## Open owner questions

None open.

## Planner decisions (Claude's discretion), recorded with their reasons
- *F05: the bundle in force, not the anchor.* trust.VerifySuccessor refuses an installation ID that changes once set, so if the bundle in force names X, every earlier bundle that names one names X. The anchor may predate the ID, as the homelab's v1 to v3 do. Requiring the anchor to carry it would refuse every log anchored on pre-D-04 roots.
- *Q-C7 is enforced by the CLI, not the library.* audit.Options.InstallationID "" stays "not checked", so recover (which applies the pin itself, after its own checks) and the library's fixtures keep today's semantics. runAuditVerify refuses after Verify returns and before `verifyResultOf`, so before printing anything in text or `--json`, when the bundle in force names an ID and neither flag was given.
- *F06: the pin is enforced by Trust's signature.* `(*serverclient.Client).Trust` gains an `installationID` parameter, so every call site must pass the pin and the build finds any it misses, including the two added since f7eb018 (knownhosts.go's known-hosts sync, 03-09b; machinerenew.go's machine renew, 03-11b). `TrustUnpinned` is the one variant without the check, documented for init only, and a grep gate pins its single caller. CheckInstallationPin is exported so recover applies the same rule. Only Trust's signature fails the build; audit.Options' new fields and the export-line rules are met through tests.
- *F06: recover's structure.* `recovery_installation_lost` stays first; CheckInstallationPin then runs on both paths; nothing-to-recover is printed only after it passes. A pinned config with ID-less exports is refused (another installation's exports), so the existing nothing-to-recover case pins "" (a moved setup, assertion unchanged).
- *F06: recover tells a re-init from an escalation.* ErrInstallationNotPinned becomes `recovery_installation_not_pinned` (keep the hold, compare the ID, re-init with the full flag set, run recover again); ErrInstallationMismatch and a malformed pin become `recovery_installation_other` (escalate, do not release the hold). These are CLI refusal names, not signer refusal details.
- *F06: init gets no `--installation-id` flag.* It prints the ID it saves; the runbooks say to compare it with the transcript's new Installation ID line, or, for an invited user, with the ID their admin gives them. `keyroster user add`'s invite text is unchanged: the admin gives the ID with the invite (enroll-user.md).
- *render-05: the line is printed in cmd/keyroster/trust.go, with root sign's installationLine.* Putting it into rootceremony.Summary would print it twice in root sign, and removing root sign's own line would break 03-14b's additions-only rule.
- *F10: the allowance is krl.PruneMargin.* An entry may be left out of a KRL issued at T only if T ≥ ValidBefore + PruneMargin, and issued_at ≤ leaf time ≤ Now + allowance, so with allowance = PruneMargin an accepted KRL omits only certificates with ValidBefore ≤ Now. Tying it to the request-freshness window would let a later change of that window silently reopen F10.
- *Charset rule last.* checkLineKeys refuses a non-conforming key only after its existing checks, over the keys in sorted order, so no existing refusal message moves and every message is deterministic.
- *Bound values parsed, not grepped.* For every key a byte check binds or forbids by kind (version, directory, sigs, bundle_version, import_krl_versions) and for policy_version, the parsed value must be the leaf's where the kind has the key, and the key is refused where the byte checks refuse it. A JSON number's text must equal the decimal Export writes, and a string's unescaped value the base64 Export writes. The byte checks stay as they are.
- *The export key gate is syntactic and covers the decoders.* A go/parser test walks every non-test .go file in internal/audit, but looks only inside the bodies of the functions that render decoded fields (and counts as a map index only an index of an identifier the function declares with a map type): `Decode`, `decodeLeaf` and every function whose name starts with `decode`, wherever 03-09 to 03-11 put theirs. There it collects every string-literal map key written in an assignment or a composite literal, requires `[a-z0-9_]+`, and fails on any map key that is not a string literal, except the one recorded `counts[tlog.ReasonName(c.Reason)]` site, whose names it checks through tlog.ValidReason. Verification bookkeeping maps elsewhere in the package (walkKeys' `seen` and `keys`, revoke.go's `rs.certs`, recovery.go's `map[uint8]uint8{krl.EntrySerial: ...}` and others) are out of scope: they never reach an export line. A data-derived key in a decoder needs its own charset proof or an allowlist entry.
- *Now is opt-in for library callers.* Options.Now 0 disables the bound, so the library's fixtures, which move hours or days past the wall clock, are unaffected. The CLI reads its clock through the package variable `auditClock`, shared by audit verify and recover, which tests set.
- *The e2e helpers.* auditVerify(env) passes `--installation-id env.InstallationID`. auditVerifyPins, which gets pins only, passes `--any-installation` unless its caller passed one of the two flags, so the restore and recovery e2e tests keep testing what they test. The binding is tested by a new subtest, `binds_installation`, of TestAuditVerifiesIssuance (test/e2e/audit_test.go), on that test's own signer and export, so no new bootstrapSigner adds e2e lane time; its unbound case calls runKeyroster directly, because both helpers now inject a flag.

## The output contract

These lines are byte for byte.
- **trust verify (render-05).** Right after the summary (its last line is `Bundle SHA-256: ...`), and before 03-14b's policy block and the signer lines, exactly the line root sign prints (installationLine):
  - `installation id: <id>` for a successor that carries it;
  - `installation id: <id> (new in this version)` for a genesis, or for a successor whose previous bundle had none;
  - `installation id: none (no KRL can be published under this bundle)`.
- **init.** After the WebAuthn RP line, and before `saved <path>`:
  - `installation id: <id> (saved with your pins; compare it with the installation ID on record: the ceremony transcript's Installation ID line, or the one your admin gives you)`;
  - `installation id: none (the trust bundle names none yet; run keyroster init again once it does)`.
- **audit verify, text.** After the `anchored:` line and before the `not checked:` line, two lines, both printed by runAuditVerify (never by printVerifyOK, whose OK, host, machine and probe certificate lines stay byte for byte as TestVerifyOutput pins them):
  - one of `installation id: <id> (checked against --installation-id)`, `installation id: <id> (not checked: --any-installation)` and `installation id: none (the trust bundle in force names none)`;
  - `last entry time: <time> (entry <n>)`, with time as `time.UnixMicro(us).UTC().Format(time.RFC3339Nano)` and n the last entry's index.
- **audit verify, JSON.** Two fields, by addition after `pending_negative_probes` (03-10c's field, omitted when zero, so the new fields then follow `anchor_bundle_version`): `"installation_id"` (the ID, or `""`; no omitempty) and `"last_entry_time_micros"`. Both are set in verifyResultOf.
- **Refusals** (the parts tests match):
  - audit.Verify:
    - `names installation <other>, not the expected <id>`;
    - `names no installation ID, but <id> is expected`;
    - ErrEntryAhead, `is more than 300 s after this verifier's clock`, with `it clears when this clock reaches <time>`.
  - audit verify (Q-C7): `names installation <id>: pass --installation-id`, naming `--any-installation`; and the usage error `--installation-id and --any-installation exclude each other`.
  - serverclient.Trust and CheckInstallationPin:
    - ErrInstallationMismatch, `names installation <served>, but your config pins installation <pinned>`;
    - ErrInstallationNotPinned, whose own text holds the full re-pin form with `--user` and `--admin-key`, and the form for an automation host whose config has no user;
    - `names no installation ID, but your config pins <pinned>`.
  - recover: `recovery_installation_not_pinned`, `recovery_installation_other`, `recovery_clock_ahead`.
  - checkLineKeys:
    - `its key %q is not lowercase ASCII letters, digits and underscores (<kind>)`;
    - `its decoded <key> field is not the one of its <kind> leaf`, the same wording as checkGrepFields.

## Budget

files_modified lists 60 files (re-counted at 3da914f):
- 38 code and test files, two of them new (internal/audit/installation_test.go and cmd/keyroster/installpin_test.go). cmd/keyroster/audit_test.go and internal/audit/export_test.go exist on main and are extended;
- four golden files, eight runbook files and the registry;
- nine planning files for the publish edits.

Per task:
- Task 1 touches about 9 files (the e2e helpers included), Task 2 about 26 (most a one-line call-site or helper change; knownhosts.go and machinerenew.go are the two call sites added since f7eb018), Task 3 about 10, and Task 4 the runbooks, the registry and the planning files.
- Tasks 1 and 3 share internal/audit/verify.go, verify_test.go, cmd/keyroster/audit.go and audit_test.go; Tasks 2 and 3 share cmd/keyroster/recover.go and recover_test.go. Each task is self-contained, so the executor can drop a task's read_first context once it is done.

About 280k tokens raw, at low confidence (the estimate calibration has no samples, so the projection is not scaled). It covers two sessions:
- the plan itself, about 229 KB or roughly 95k tokens (at about 2.4 bytes per token, as measured in plan check 2), read once per session, so about 190k with the continuation;
- about 100 KB read through the function-scoped read_first lists, roughly 28k tokens;
- about 32k written;
- about 30k of test, mutant, gate and e2e-gate output.

That is well over the 100k smart-zone budget. Comparable runs went much higher: 03-14b was estimated at 165k with an expected 330k to 800k and needed a continuation, and 03-11 took about 950k over two runs. This plan has three RED/GREEN pairs, 33 mutants and 38 code and test files, so the expected range is about 500k to 1.1M (about 2x to 4x of the estimate; 03-11b ran about 2x and 03-11 about 5x). Budget one continuation after Task 1: the executor hands over through the SUMMARY draft (R1, T1, the RED lines, the test-time base, the mutant records so far), and the continuation starts at Task 2. If the continuation's context is about half used before Task 3 starts, it may hand over once more after Task 2, the same way. Each continuation is another session, so its delta gate re-measures the test-time base first (below). Each task is self-contained: a continuation reads the plan's shared sections (frontmatter to `</context>`) and its own tasks only. The task count and the files are unchanged.

**Test time (Q-09-3, owner decision, 03-09-PLAN.md; it replaces the fixed 400 s and 480 s caps of 03-08k).**
- **Timeout.** Every go test command of this plan carries `-timeout 15m`, and every mutant command `-timeout 5m`. CI's build-test already runs with `-timeout 15m` (ci.yml). A timeout is not a kill.
- **Base.** Task 1 measures a quiet base on unchanged origin/main, before any edit and with no other heavy job on the machine: `go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/audit/ ./internal/serverclient/` through `bash scripts/linux.sh`. It records one SUMMARY line, `test-time base: cmd=<s> audit=<s> serverclient=<s> at=<epoch seconds>`, each time read from that package's `ok` line in seconds without the trailing `s`. There is exactly one such line.
- **The rule.** Task 4's delta gate runs the same command and stops if any of the three packages adds more than 90 s to its base. If the base is more than 24 h (86400 s) old, re-measure it on origin/main in a detached worktree outside the repository, immediately before; a re-measure REPLACES the base line in place, never appends a second one. Stop and report only if the fresh delta is still above 90 s.
- **Another session.** If the delta gate runs in a different session or WSL boot from the one that measured the base, re-measure the base first on origin/main in a detached worktree outside the repository, as 03-11b's continuation did, and replace the line in place. After the continuation following Task 1 that is always the case. The 24 h age check still applies. The base line keeps its format: the delta gate reads `at=` at the end of the line, so no session or boot field is added.
- **The whole module.** `go test -race -count=1 -timeout 15m ./...` in the full gate is pass or fail only, and is never compared with a base. internal/agent/apply and internal/signer read about 440 s to 515 s under load on main (03-09's `./...` run and the multi-package bases of 03-10c and 03-10d), in packages this plan does not touch, so no per-package cap is applied to them.
- **Expected.** For orientation, the recent bases on main read cmd/keyroster at about 227 to 270 s under -race (03-10c to 03-14b), internal/audit at about 82 to 91 s and internal/serverclient at about 4 s. The new tests use software keys and in-memory fixtures. A reading near the 15-minute timeout is a stop-and-report, not a reason to raise it.

## Phase Goal

> Enrolled Linux hosts are kept in sync automatically (trusted CAs, principals, KRL and host certificates), so access granted, revoked or rotated centrally takes effect across the fleet without hand-edited sshd config and without risking lockout. (ROADMAP Goal, verbatim.)

<execution_context>
@~/.claude/gsd-core/workflows/execute-plan.md
@~/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/03-linux-agent-and-revocation/03-CONTEXT.md
@.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-11b-SUMMARY.md
@.planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md
@.planning/phases/01-trust-core/01-SKELETON.md

Delivery protocol: 01-SKELETON.md, with phase 03 names. Since PR #79, its steps 2, 3 and 5 carry the owner's authorship and merge rules of 2026-11-02, which the points below restate. The one override is merge-gate.sh's plain form, as in 03-08f.
- **Branch.** Create `p03/14c-installation-binding` from origin/main in Task 1. This plan file is placed untracked in the phase directory at the start, and Task 4 commits it.
- **Staging.** Stage files by path only, never with `git add -A` or `git add .`. Never stage `.planning/config.json`, `.planning/milestone.lock`, `.planning/state.json` or any `.review-diagnostics` directory.
- **Authorship (01-SKELETON step 2).** Every `git commit` of this plan is signed (`-S`) and authored as Daniel, with keyroster-bot as committer, SSH signer and pusher. Put the two variables on the same command line as the commit, because shell state does not persist between commands: `GIT_AUTHOR_NAME="Daniel Gustafsson" GIT_AUTHOR_EMAIL=121555671+Labontese@users.noreply.github.com git commit -S ...`. Push with `env -u GITHUB_TOKEN -u GH_TOKEN git push`.
- **No auto-merge (01-SKELETON steps 3 and 5).** The bot opens the PR through scripts/gh-as-bot.sh and never enables auto-merge or waits for it. Daniel reviews, approves and squash-merges the PR in the GitHub web UI, and replies "merged".
- **merge-gate.sh.** Before the merge it runs only as `--check`, which is read-only. Its plain form may rebase and force-push (exit 3), and this plan rebases by hand, so the plain form runs only after Daniel has merged (Task 5).
- **Shells.**
  - The go test, gate and mutant commands run through `bash scripts/linux.sh '...'`. Its single-quoted argument reaches WSL's login shell unexpanded (wsl.exe --exec), so `$(...)` and `$VAR` inside it expand in WSL. A command string run in a worktree runs no git: the worktree's `.git` file holds a Windows path that git inside WSL cannot follow.
  - The git checks run in Git Bash. Every `git show`, `git cat-file` or `git grep` of an `origin/main:path` or `FETCH_HEAD:path` argument is prefixed with `MSYS_NO_PATHCONV=1`.
  - scripts/gh-as-bot.sh and scripts/merge-gate.sh always run in Git Bash without MSYS_NO_PATHCONV.
  - e2e runs in CI (the PR's e2e job), as in 03-08i: local e2e does not run on this machine.
- **Commit references.** `$R1`, `$T1` and so on in the commands below are the SHAs of the commits the SUMMARY records under those names. Set them as shell variables on the same command line before running a check.
- **Escapes in test bytes.** Where this plan writes a JSON escape such as `\u006e`, the test's injected bytes hold those six characters (a backslash, `u` and four hex digits), written inside a Go raw string (backquotes), so the escape reaches the export line unexpanded. The escape is what hides a key from the byte checks, and a JSON reader unescapes it. The executor's own tool layer may decode a backslash-u sequence in its tool input before it reaches a file, as it did while this plan was written. So after writing the test files, confirm the backslash bytes with `od -c` on one escaped line of each file and with `grep -c '[\]u00' internal/audit/verify_test.go internal/audit/forget_test.go`, and record both readings in the SUMMARY. The patterns in this plan's commands bracket the backslash (`[\]`) for the same reason.
- **Wording.** Conventional Commits with neutral wording and the F-numbers. No attribution lines, no IP addresses, no real host names.
- **Code comments** cite `(03-14c, F05)` and so on, or `(03-14c; PR #75 review)` for the export-line rules.
- **SUMMARY.** `.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md`, a draft from Task 1 on. The final docs commit is `docs(03-14c): complete installation-binding plan`.
- **The mutant rule** (as 03-14b). Every mutant compiles. Its record is: the unmutated `-run` passing; `go vet` of the mutated package exiting 0; the named `--- FAIL:` lines, with no `[build failed]` or `[setup failed]`. Each mutant is applied to the working tree, run with its exact command, and the file restored and hash-checked before the next. Every mutant command carries `-timeout 5m` (Q-09-3), and a timeout is not a kill. The numbering is local: this plan allocates no global M-IDs (03-11 and 03-11b use M1-M110), and 03-12 starts at M111.
- **RED first.** In each of Tasks 1 to 3, commit R holds the new tests, plus only the declarations they need to build (struct fields, a flag, constants, a sentinel error, a parameter passed through without effect), with behaviour unchanged. The RED is re-run from a worktree of R and must end in the named `--- FAIL:` lines. Commit T is the fix. The SUMMARY lists every declaration R added.

**What this plan builds on:**
- **D-04 (03-01, 03-04):** the bundle's installation ID, carried unchanged once set (trust.VerifySuccessor); directory.CheckInstallation and CheckStoredInstallation; the KRL manifest's ID; the agent's pin; the signer's revoke, forget and recovery rules.
- **03-08c and the PR #75 review:** checkGrepFields, checkReplayFields, checkForgetFields, checkLineKeys and forgetOnlyKeys, with TestVerifyForgetKeysOnOtherKinds and TestVerifyGrepFields.
- **03-14b:** TestCeremonyGolden with checkGolden, checkInvariants and the `-update-golden` flag; the four trust_verify goldens; the additions-only rule; installationLine in root sign; TestRootCeremonyPolicyChecks.
- **03-09, 03-09b, 03-10, 03-10b, 03-10c, 03-10d, 03-11 and 03-11b (landed, #88 to #97, with the quick tasks #87 and #96 and the dependency bump #94):** their two Trust call sites (03-09b's `keyroster known-hosts sync` in knownhosts.go, 03-11b's `keyroster machine renew` in machinerenew.go; `revoke host` and `revoke machine` go through openRevocation in revoke.go), their audit leaf kinds and decoders (host_issue, probe_issue and machine_issue, all in internal/audit/export.go), checkForgetFields' byte binding of those three kinds, and cmd/keyroster/audit_test.go (TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine, unit tests of printVerifyOK and verifyResultOf).
- **03-14b (landed, #98, 3da914f):** its goldens, checkInvariants, TestPolicyFieldsCovered, TestPolicyFieldLines, TestSummaryFieldsCovered and TestRootCeremonyPolicyChecks with sectionWindow are on main.

**The code this plan changes, as read on main at f7eb018 and re-read at 3da914f** (docs/format-registry.md is on main, so Task 4's registry step applies; its `## Installation binding` section ends with the join-token paragraph and the HostIssue/ProbeIssue/MachineIssue paragraph. Between the two commits, internal/serverclient/client.go, config.go, init.go, host.go and user.go are byte-identical; recover.go's steps 2 to 4 are unchanged; trust.go gained 03-14b's policy block after the successor Summary. Three things changed, each noted below: the Trust call sites, audit.go's structure, and checkForgetFields' kinds)**:**
- internal/audit/verify.go: Options has Pins, Threshold, Previous and CertificatesFrom. anchor.install anchors on trust.MatchPins only. Verify bounds a leaf's time only by the previous leaf's. Report.Bundle is the bundle in force; nothing compares its InstallationID. checkLineKeys refuses duplicates after unescaping, unexpected top-level keys, a wrong parsed kind and forget-only keys on other kinds, all by exact key. At 3da914f checkForgetFields also requires host_issue, probe_issue and machine_issue lines to equal exportLeafLine byte for byte, and runs its approved_once/host_gone substring check only on the other kinds.
- internal/audit/revoke.go: verifyKRLPublish accepts any issued_at with issued_at·10⁶ ≤ the leaf time.
- cmd/keyroster/audit.go (about 7.3 KB at 3da914f): runAuditVerify builds `audit.Options{Pins, Threshold}`, calls Verify, then `res := verifyResultOf(rep)`, which feeds both outputs; `--json` encodes res; the text output is printVerifyOK (the OK line, then the `host certificates:`, `machine certificates:` and `probe certificates:` lines), then runAuditVerify's own `anchored:` and `not checked:` lines. verifyResult has no installation field; its last field is PendingNegativeProbes (`pending_negative_probes,omitempty`). runAudit's usage line names `keyroster audit verify --pin ...`.
- internal/serverclient/client.go: Trust(ctx, rootPins, threshold) checks the root set, the root signatures, MatchPins, the policy hash, the version echo and admins-not-roots; nothing about the installation.
- cmd/keyroster/config.go: Config has no installation field. init.go saves none and prints none.
- Trust call sites at 3da914f, twelve (ten at f7eb018): dirpipe.go, host.go (two), hoststatus.go, init.go, knownhosts.go (new, 03-09b: `keyroster known-hosts sync`, an admin session that writes the trust files under ~/.ssh and host-trust.json), login.go, machinerenew.go (new, 03-11b: `keyroster machine renew`, which signs a MachineIssue request whose InstallationID is the served bundle's), revoke.go, user.go (three, two of them diagnostic: `terr == nil` only).
- cmd/keyroster/recover.go: step 2 verifies both exports without a clock; step 4 takes the installation from the restored bundle, and inside `if installation == ""` refuses `recovery_installation_lost` or prints nothingToRecover.
- cmd/keyroster/trust.go: trust verify prints the summary and the signer lines, and no installation line.
- test/e2e: auditVerify and auditVerifyPins (audit_test.go), pkcs11AuditVerify and tpmAuditVerify build `audit verify` without an installation flag; restore_test.go pins the runbook's audit verify line as `restoreVerify`.
</context>

<tasks>

<task type="tracer">
  <name>Task 1: End-to-end "an auditor runs keyroster audit verify on an export → audit.Verify compares the installation ID of the trust bundle in force with --installation-id → another installation's export under the same roots is refused naming both IDs, an export of an installation is refused unbound unless --installation-id or --any-installation is given (Q-C7), and the text and JSON output show the ID" (F05), committed RED first and then fixed</name>
  <reversibility rating="costly">audit verify now refuses, on an installation that has an ID, every invocation without `--installation-id` or `--any-installation`, so scripts and runbooks must pass a flag. No stored or signed format changes; a revert restores today's verdicts.</reversibility>
  <precondition>All nine checks hold:
    - `git fetch origin` succeeds, and `P=.planning/phases/03-linux-agent-and-revocation && fw() { awk 'NR>1 && /^---$/{exit} /^wave: /{sub(/^wave: /,""); print}'; } && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-14b-SUMMARY.md" && X12=$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md") && test "$(printf '%s\n' "$X12" | fw)" = 30 && printf '%s\n' "$X12" | grep -qx 'depends_on: \["03-14b"\]' && W29=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if [ "$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw)" = 29 ]; then basename "$f"; fi; done) && test "$W29" = 03-14b-PLAN.md` exits 0. This is the stop guard (Q-C1 A, re-read at 3da914f): this plan's dependency, 03-14b, has its SUMMARY on main; origin/main's 03-12 holds wave 30, the slot this plan takes, and depends on ["03-14b"]; and 03-14b is the only plan at wave 29. Each wave is read from the frontmatter only. Otherwise main moved since the reconcile of 2026-11-11 (another plan was slotted in, or 03-12 moved): stop and report for a re-reconcile. Never re-slot this plan silently.
    - `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14b-SUMMARY.md` exits 0, and both `! MSYS_NO_PATHCONV=1 git grep -q -e '"any-installation"' origin/main -- cmd/keyroster/audit.go` and `! MSYS_NO_PATHCONV=1 git grep -q -e 'func (c \*Client) TrustUnpinned(' origin/main -- internal/serverclient` exit 0: 03-14b is on main, and this plan is not.
    - Each code anchor exists on origin/main: `MSYS_NO_PATHCONV=1 git grep -q -e '^type Options struct' origin/main -- internal/audit/verify.go`, and the same for `^func checkLineKeys(` and `^var forgetOnlyKeys` (internal/audit/verify.go), `^func runAuditVerify(` (cmd/keyroster/audit.go), `^func installationLine(` (cmd/keyroster/root.go), `^func checkInvariants(` (cmd/keyroster/ceremony_golden_test.go), `^func TestRepinInstructionsKeepIdentity(` (cmd/keyroster/init_test.go), `^const restoreVerify = ` (test/e2e/restore_test.go); and `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:cmd/keyroster/testdata/ceremony/<g>.trust_verify.golden` for g in successor_unchanged, successor_added_admin, successor_pop and genesis_pop. If one is missing, stop and report which.
    - Every pointer anchor occurs exactly once on origin/main: `` P=.planning/phases/03-linux-agent-and-revocation; c(){ test "$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/$1" | grep -oF -- "$2" | wc -l)" -eq 1 || { echo "anchor not exactly once: $1: $2"; return 1; }; }; c 03-12-PLAN.md 'See 03-14b-PLAN.md.)' && c 03-13-PLAN.md 'See 03-14b-PLAN.md.)' && c 03-15-PLAN.md 're-initialise the CLIs with the new root pins' && c 03-15-PLAN.md 'exports the log and runs `keyroster audit verify` with the new pins' && c 03-15-PLAN.md 'on the laptop the same with `~/.local/bin/keyroster init ...`.' && c 03-16-PLAN.md '(audit verify with the new pins)' && c 03-08c-SUMMARY.md 'jq, Python and Go unescape keys and keep the last of repeated ones.' `` exits 0. Otherwise stop and report which anchor.
    - The threat IDs are free as definitions: `! MSYS_NO_PATHCONV=1 git grep -qE '^\| T-03-35[0-6] \|' origin/main -- .planning` exits 0. It matches only threat-register rows (`| T-03-35x |` at the start of a line), never a mention such as 03-09's forward note or a mapping table, whose rows start with a draft ID and a parenthesis. Otherwise renumber this plan's register from the highest T-03 ID that starts a register row on origin/main, + 1, keep the order, and record the mapping in the SUMMARY.
    - The format registry's presence is recorded in the SUMMARY: `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md` exits 0 (present) or 128 (absent). Either answer is fine; Task 4's registry step follows it.
    - `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:cmd/keyroster/audit_test.go` exits 0 (it holds TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine at 3da914f); Task 1 extends it.
    - The test-time base (Budget, Q-09-3) is measured on unchanged origin/main before any edit and recorded as the SUMMARY draft's single `test-time base:` line (Task 1's first action step); its format check is in Task 1's acceptance criteria. The base itself never stops the plan; only Task 4's delta over it does.
    - `awk '/^## Open owner questions/{f=1;next} f && NF{print; exit}' .planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md | grep -qx 'None open.'` exits 0.
  </precondition>
  <files>internal/audit/verify.go, internal/audit/installation_test.go (new), cmd/keyroster/audit.go, cmd/keyroster/audit_test.go (extended), test/e2e/audit_test.go, test/e2e/pkcs11_test.go, test/e2e/tpm_test.go, and every other test that runs `keyroster audit verify` on an export whose bundle names an installation (found by grep at execution)</files>
  <read_first>
    Read functions, not files. Find each with `grep -n` and read only that range.
    - internal/audit/verify.go: from `type Options struct` to `type anchor struct` (Options and Report, about 4 KB); `func (a *anchor) install(` (3 KB); the end of `func Verify(`, from `if trustState.anchorVersion == 0` to `return rep, nil` (2 KB); Verify's doc comment, the bullet list only (4 KB).
    - internal/trust/verify.go: the installation_id carry rule (`grep -n 'installation_id changed'`, 10 lines). internal/trust/bundle.go: `func IsInstallationID(` and `func NewInstallationID(`.
    - internal/audit/verify_test.go: `func newBareFixtureAt(`, `func newFixture(`, how a fixture sets its bundle's installation ID (`grep -n 'InstallationID' internal/audit/verify_test.go`), and `func TestVerifyAnchorsOnLaterBundle(` for a successor bundle_install (about 6 KB).
    - cmd/keyroster/audit.go: the whole file (7.3 KB). cmd/keyroster/audit_test.go: `func TestVerifyOutput(`, `func TestAuditVerifyProbeLine(` and `func TestVerifyOutputMachineLine(` (unit tests of printVerifyOK and verifyResultOf; none runs `audit verify` on an export).
    - cmd/keyroster/recover_test.go: `func bundleDocs(`, `func newLogBuilder(`, `func (b *logBuilder) issue(`, `func (b *logBuilder) export(` and `func noIDBundles(` (about 5 KB). cmd/keyroster/dirpipe_test.go: `func newDirEnv(` (2 KB). cmd/keyroster/root_test.go: `func run(`.
    - test/e2e/audit_test.go: `func auditVerify(`, `func auditVerifyPins(` and `func TestAuditVerifiesIssuance(`; test/e2e/pkcs11_test.go: `func pkcs11AuditVerify(`; test/e2e/tpm_test.go: `func tpmAuditVerify(`. Then `git grep -n -e '"audit", "verify"' -- test/e2e cmd/keyroster` for every other caller.
  </read_first>
  <behavior>
    - Two installations whose genesis bundles share one root key and differ in installation ID: the second's export, verified on the shared root's pin with InstallationID set to the first's ID, is refused, and the error names both IDs (F05's shape).
    - The same export without InstallationID verifies in the library as today, and the report carries the second's ID.
    - An export whose bundle in force names no installation is refused when an ID is expected; a log whose anchor names none and whose later bundle adds one verifies against that ID.
    - The CLI refuses an export of an installation that has an ID unless `--installation-id` or `--any-installation` is given, and refuses both together (Q-C7). It prints the ID on every OK, in text and JSON, and `none` without any flag on an ID-less log.
    - The e2e helpers pass the flag, and the e2e suite proves the CLI binding against a real signer.
  </behavior>
  <action>
**The test-time base (Q-09-3, Budget).** Before any edit, while the tree still equals origin/main and no other heavy job runs, run `bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/audit/ ./internal/serverclient/'`. Create the SUMMARY draft with one line `test-time base: cmd=<s> audit=<s> serverclient=<s> at=<epoch seconds>`, the three times read from the `ok` lines without the trailing `s`, and `at=` from `date +%s`. A later re-measure uses a detached worktree of origin/main outside the repository and replaces this line in place.

**RED first: commit R1.**
- R1's only non-test changes are declarations: `InstallationID string` in audit.Options, documented; an unvalidated `--installation-id` string flag passed into Options; and a `--any-installation` bool flag that is parsed and not used. Verify ignores the field, and the output is unchanged.
- **internal/audit/installation_test.go (new, `(03-14c, F05)`).** TestVerifyInstallationBinding. Its subtests are not parallel.
  - Fixtures: two installations, X and Y, that share one root signer and differ in installation ID (two fresh trust.NewInstallationID values) and in their log, CA, ops and admin keys. Each logs its root-signed genesis bundle_install and one issue entry, and is exported with its own checkpoint.
  - `own_export_ok`: X's export, X's pins, InstallationID X. No error; rep.Bundle.InstallationID is X.
  - `other_installation_refused`: Y's export, the shared root's pin, InstallationID X. The error contains `names installation <Y>, not the expected <X>`. RED: no error.
  - `unchecked_verifies_and_reports`: Y's export on the shared root's pin, no InstallationID. No error, and rep.Bundle.InstallationID is Y: the library's "" means not checked; the CLI refuses this unbound (Q-C7).
  - `id_less_bundle_refused`: an export whose genesis names no installation, InstallationID X. The error contains `names no installation ID, but <X> is expected`. RED: no error.
  - `id_added_after_anchor_ok`: a genesis without an ID (the anchor), then a successor bundle_install that adds X, as `root sign --installation-id new` does; the genesis roots' pins; InstallationID X. No error, and AnchorVersion is 1. It passes on R1 and pins the rule against the anchor (mutant M1-2).
  - `malformed_expected_refused`: InstallationID `ABC` on an empty reader. The error contains `is not 32 lowercase hex digits`. RED: the empty-log error.
- **cmd/keyroster/audit_test.go (`(03-14c, F05)`).** TestAuditVerifyInstallation runs `run(t, "audit", "verify", ...)` on exports from recover_test.go's logBuilder over newDirEnv(t, 1, 1), whose bundle names e.bundle.InstallationID:
  - `unbound_refused` (Q-C7): no flag. A non-zero exit, stderr contains `names installation <id>: pass --installation-id` and `--any-installation`, and stdout is empty. RED: exit 0 with `OK:`.
  - `any_installation_prints_unchecked`: `--any-installation`, exit 0, and `installation id: <id> (not checked: --any-installation)` as the line after `anchored:`.
  - `checked_ok`: `--installation-id <id>`, exit 0, and the `(checked against --installation-id)` line.
  - `other_refused`: `--installation-id ffffffffffffffffffffffffffffffff`, a non-zero exit, stderr names both IDs, and stdout has no `OK:` line.
  - `both_flags_usage`: both flags, exit 2 (errUsage), stderr `--installation-id and --any-installation exclude each other`.
  - `json_carries_id`: `--json --installation-id <id>` decodes with `installation_id` equal to the ID.
  - `id_less_needs_no_flag`: on an export over noIDBundles with no flag, exit 0, the `none` line, and `"installation_id":""` with `--json`.
  - `malformed_flag_usage`: `--installation-id ABC` exits 2, with no `OK:`.
- **Existing callers.** Every test that runs `keyroster audit verify` on an export whose bundle names an installation (`git grep -n -e '"audit", "verify"' -- cmd/keyroster test/e2e` at execution) passes `--installation-id` with its env's ID. Only the arguments move; record each, with its assertions unchanged. At 3da914f no cmd/keyroster test runs `audit verify` on an export: cmd/keyroster/audit_test.go's TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine call printVerifyOK and verifyResultOf directly, move no arguments, and must stay green unchanged (TestVerifyOutput's `existing_output_unchanged` pins printVerifyOK's output byte for byte, which is why the two new lines are printed by runAuditVerify). At f7eb018 no test decodes audit verify's JSON strictly or checks that `not checked:` follows `anchored:` (`git grep -n -e 'DisallowUnknownFields' -e 'not checked:' -e 'anchored:' -- test/e2e cmd/keyroster` finds only strings.Contains checks in test/e2e/audit_test.go and rotation_test.go); re-run that grep at execution and record any hit as a moved assertion.
- **e2e (`(03-14c, F05)`; runs in CI).**
  - auditVerify(env) passes `--installation-id`, env.InstallationID.
  - auditVerifyPins passes `--any-installation` unless its extra arguments already hold `--installation-id` or `--any-installation`.
  - pkcs11AuditVerify and tpmAuditVerify pass `--installation-id`, env.InstallationID.
  - TestAuditVerifiesIssuance (audit_test.go) gains the subtest `binds_installation`, run on that test's own signer and export after its existing audit verify, so no new bootstrapSigner adds lane time (the main e2e lanes ran about 769 s and 804 s against the house 900 s stop at 3da914f): no flag, called through runKeyroster directly because both helpers now inject one, exits 1 naming env.InstallationID; `--installation-id` with it exits 0 with the checked line; `ffffffffffffffffffffffffffffffff` is refused; `--any-installation` exits 0 with the unchecked line.
- Commit R1 (`test(audit): pin installation binding of audit verify (F05)`) and record it. Then take the RED from a worktree of R1 (second verify command).
  - Expected `--- FAIL:`: `other_installation_refused`, `id_less_bundle_refused` and `malformed_expected_refused`, and all eight TestAuditVerifyInstallation cases.
  - Expected to pass on R1: `own_export_ok`, `unchecked_verifies_and_reports` and `id_added_after_anchor_ok`. The SUMMARY records why.

**GREEN: commit T1** (`fix(audit): bind audit verify to one installation and print its ID (F05)`).
- **internal/audit/verify.go (`(03-14c, F05)`).**
  - Options.InstallationID's doc comment: the installation ID the auditor expects (a trust bundle's installation_id, from the ceremony transcript's Installation ID line); empty means not checked by Verify, and `keyroster audit verify` then refuses an installation-bound log unbound (Q-C7). With it, Verify refuses a log whose trust bundle in force names another installation or none. The comparison is with the bundle in force, because trust.VerifySuccessor carries an installation ID unchanged once it is set.
  - At Verify's start, after trust.CheckPins: a non-empty InstallationID that is not trust.IsInstallationID is refused, `audit: the expected installation ID %q is not 32 lowercase hex digits`.
  - After the `opts.Previous` block and before rep is filled, so that every other verification error comes first and this refusal means a valid log of another installation:
    - bundle in force without an ID: `audit: the trust bundle in force (v%d) names no installation ID, but %s is expected`;
    - another ID: `audit: the trust bundle in force (v%d) names installation %s, not the expected %s: this export is the log of another installation`.
  - Verify's doc comment gains a bullet for the check.
- **cmd/keyroster/audit.go (`(03-14c, F05, Q-C7)`).**
  - `--installation-id`'s usage: the installation ID this export must be the log of, 32 lowercase hex digits from the ceremony transcript's Installation ID line. `--any-installation`'s usage: verify without binding the result to one installation; the output still names the installation.
  - A non-empty `--installation-id` that is not trust.IsInstallationID: stderr `audit verify: --installation-id wants 32 lowercase hex digits`, errUsage. Both flags: stderr `audit verify: --installation-id and --any-installation exclude each other`, errUsage.
  - After Verify returns and before `res := verifyResultOf(rep)`, so that `--json` is covered too, when rep.Bundle.InstallationID is not empty and neither flag was given: return `audit verify: the trust bundle in force (v%d) names installation %s: pass --installation-id with the installation ID you have on record (the ceremony transcript's Installation ID line), or --any-installation to verify without binding the result to one installation`, printing nothing on stdout.
  - verifyResult gains `InstallationID string` with tag `installation_id` (no omitempty), declared after PendingNegativeProbes, by addition; verifyResultOf sets it from rep.Bundle.
  - runAuditVerify prints the installation id line of the output contract right after its `anchored:` line; printVerifyOK is not changed.
  - runAudit's usage line (audit.go:29 at 3da914f) names `[--installation-id ID | --any-installation]`. It is this edit's text, not a test constant (Task 4's constant grep leaves audit.go out).
- T1 changes no test file.

**Mutants** (the mutant rule):
- M1-1: delete the installation comparison in Verify. Killed by `TestVerifyInstallationBinding/other_installation_refused`, `/id_less_bundle_refused` and `TestAuditVerifyInstallation/other_refused`.
- M1-2: compare the anchor bundle's installation ID instead of the bundle in force's (keep it in anchor.install). Killed by `/id_added_after_anchor_ok`.
- M1-3: runAuditVerify leaves opts.InstallationID empty. Killed by `TestAuditVerifyInstallation/other_refused`.
- M1-4: drop the unbound refusal (Q-C7). Killed by `/unbound_refused`.
- M1-5: accept both flags together. Killed by `/both_flags_usage`.

Commands: `bash scripts/linux.sh 'go vet ./internal/audit/ && go test -count=1 -timeout 5m -v -run "^TestVerifyInstallationBinding$" ./internal/audit/'` and `bash scripts/linux.sh 'go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^TestAuditVerifyInstallation$" ./cmd/keyroster/'`.

**The SUMMARY** records R1 and T1, the RED lines, the cases that pass on R1 and why, the mutants, and every existing caller whose arguments moved.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^TestVerifyInstallationBinding$" ./internal/audit/ && go test -race -count=1 -timeout 15m -v -run "^TestAuditVerifyInstallation$" ./cmd/keyroster/ && go test -race -count=1 -timeout 15m ./internal/audit/ ./cmd/keyroster/ && go vet ./internal/audit/ ./cmd/keyroster/ && go vet -tags e2e ./test/e2e/ && go vet -tags e2e_pkcs11 ./test/e2e/ && go vet -tags e2e_tpm ./test/e2e/ && test -z "$(gofmt -l internal/audit cmd/keyroster test/e2e)"'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing (the two extra vets compile pkcs11_test.go and tpm_test.go, which build only under `e2e_pkcs11` and `e2e_tpm`, so that pkcs11AuditVerify's and tpmAuditVerify's edits are compiled locally; both files are pure Go with no cgo import at 3da914f): "--- PASS: TestVerifyInstallationBinding/own_export_ok", "--- PASS: TestVerifyInstallationBinding/other_installation_refused", "--- PASS: TestVerifyInstallationBinding/unchecked_verifies_and_reports", "--- PASS: TestVerifyInstallationBinding/id_less_bundle_refused", "--- PASS: TestVerifyInstallationBinding/id_added_after_anchor_ok", "--- PASS: TestVerifyInstallationBinding/malformed_expected_refused", "--- PASS: TestAuditVerifyInstallation/unbound_refused", "--- PASS: TestAuditVerifyInstallation/any_installation_prints_unchecked", "--- PASS: TestAuditVerifyInstallation/checked_ok", "--- PASS: TestAuditVerifyInstallation/other_refused", "--- PASS: TestAuditVerifyInstallation/both_flags_usage", "--- PASS: TestAuditVerifyInstallation/json_carries_id", "--- PASS: TestAuditVerifyInstallation/id_less_needs_no_flag", "--- PASS: TestAuditVerifyInstallation/malformed_flag_usage"</fails_when>
    <automated>D=$(git diff --name-only origin/main...$R1) && ! printf '%s\n' "$D" | grep -vE '(_test\.go|^internal/audit/verify\.go|^cmd/keyroster/audit\.go)$' | grep -q . && W=$(mktemp -d) && git worktree add --detach "$W/r1" "$R1" >/dev/null && { ( cd "$W/r1" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^TestVerifyInstallationBinding$" ./internal/audit/ ; go test -count=1 -timeout 15m -v -run "^TestAuditVerifyInstallation$" ./cmd/keyroster/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/r1"; } && L="$W/red.log" && ! grep -qE '\[(build|setup) failed\]' "$L" && for c in TestVerifyInstallationBinding/other_installation_refused TestVerifyInstallationBinding/id_less_bundle_refused TestVerifyInstallationBinding/malformed_expected_refused TestAuditVerifyInstallation/unbound_refused TestAuditVerifyInstallation/any_installation_prints_unchecked TestAuditVerifyInstallation/checked_ok TestAuditVerifyInstallation/other_refused TestAuditVerifyInstallation/both_flags_usage TestAuditVerifyInstallation/json_carries_id TestAuditVerifyInstallation/id_less_needs_no_flag TestAuditVerifyInstallation/malformed_flag_usage; do grep -qF -- "--- FAIL: $c " "$L" || { echo "no RED: $c"; exit 1; }; done && for c in own_export_ok unchecked_verifies_and_reports id_added_after_anchor_ok; do grep -qF -- "--- PASS: TestVerifyInstallationBinding/$c " "$L" || exit 1; done</automated>
    <fails_when>non-zero exit: R1 changed a non-test file other than verify.go and audit.go, R1 did not build, or its RED is not exactly the eleven named failures with the three named passes. R1 is the commit recorded in the SUMMARY</fails_when>
    <automated>D=$(git diff --name-only origin/main...$T1) && ! printf '%s\n' "$D" | grep -vE '(_test\.go|^internal/audit/verify\.go|^cmd/keyroster/audit\.go|^\.planning/.*)$' | grep -q . && test -z "$(git diff --name-only $R1 $T1 -- '*_test.go')"</automated>
    <fails_when>non-zero exit: Task 1 changed a production file outside verify.go and audit.go, or the fix commit T1 changed a test</fails_when>
  </verify>
  <acceptance_criteria>
    - The fourteen named subtests pass, and the RED of the eleven is recorded with the three cases that pass on R1.
    - The five mutants each compile and are killed by their named tests.
    - Every moved caller's arguments are listed in the SUMMARY with unchanged assertions; the e2e helpers pass a flag.
    - `test "$(grep -c '^test-time base: ' .planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md)" -eq 1 && grep -Eqx 'test-time base: cmd=[0-9]+(\.[0-9]+)? audit=[0-9]+(\.[0-9]+)? serverclient=[0-9]+(\.[0-9]+)? at=[0-9]+' .planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md` exits 0 (the base line exists once, in the format Task 4's delta gate reads).
  </acceptance_criteria>
  <done>An auditor sees which installation a verified log belongs to, gets a refusal for another installation's log signed by the same roots, and cannot verify an installation-bound log without saying which installation it is or that any will do. Committed as R1 and T1.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: The CLI pins the installation (F06, Q-C3 A): init saves the ID it verified, serverclient.Trust takes the pin at every call site, the diagnostics name a pin error, recover compares it after its own installation check, and trust verify prints the installation line (render-05)</name>
  <reversibility rating="costly">A config saved before this plan refuses on an installation that has an ID until `keyroster init --force` is run again with the full flag set. The pin is a new config field, ignored by older binaries, so a revert restores today's behaviour, but users who re-ran init keep the field.</reversibility>
  <precondition>T1 is committed on the branch.</precondition>
  <files>internal/serverclient/client.go, internal/serverclient/client_test.go, cmd/keyroster/config.go, cmd/keyroster/init.go, cmd/keyroster/init_test.go, cmd/keyroster/dirpipe.go, cmd/keyroster/host.go, cmd/keyroster/hoststatus.go, cmd/keyroster/login.go, cmd/keyroster/knownhosts.go, cmd/keyroster/machinerenew.go, cmd/keyroster/revoke.go, cmd/keyroster/user.go, cmd/keyroster/recover.go, cmd/keyroster/trust.go, cmd/keyroster/installpin_test.go (new), cmd/keyroster/dirpipe_test.go, cmd/keyroster/host_test.go, cmd/keyroster/login_test.go, cmd/keyroster/user_test.go, cmd/keyroster/recover_test.go, cmd/keyroster/peer_text_test.go, cmd/keyroster/remote_text_test.go, cmd/keyroster/ceremony_golden_test.go, cmd/keyroster/testdata/ceremony/*.trust_verify.golden (4), test/e2e/revoke_test.go, and every other file that holds a Trust call site on origin/main at execution (the build lists them)</files>
  <read_first>
    - internal/serverclient/client.go: `func (c *Client) Trust(` and `func pinnedRoots(` (4 KB); `var ErrTrustRootNotPinned` and `var ErrTLSRootNotPinned` (2 KB), whose re-pin form ErrInstallationNotPinned follows.
    - internal/serverclient/client_test.go: `func TestClientTrust(`, its stub and its cases.
    - cmd/keyroster/config.go (the whole file, 4 KB); cmd/keyroster/init.go: `func runInit(` and `func printTrustSummary(` (5 KB); cmd/keyroster/init_test.go: `func TestRepinInstructionsKeepIdentity(` (1 KB).
    - Every Trust call site: `git grep -n -e '\.Trust(' -- '*.go' ':!internal/serverclient/client.go'`, five lines around each. cmd/keyroster/user.go: the AdminJSON call before the diagnostic Trust in the approve path, and `func (s *adminSession) diagnose(`.
    - cmd/keyroster/recover.go: `func runRevokeRecover(` from `// 2. Both exports` to `// 5.` (3 KB).
    - cmd/keyroster/trust.go: `func runTrustVerify(` and `func verifySuccessorBundle(`, as 03-14b left them (4 KB); cmd/keyroster/root.go: `func installationLine(`.
    - cmd/keyroster/ceremony_golden_test.go: `func checkInvariants(`, the fixed installation ID of the bundle in force, and the genesis normalisation (`grep -n 'INSTALLATION_ID\|00112233445566778899aabbccddeeff'`).
    - The test helpers and the cases that strip or change the served ID: `git grep -n -e 'resignBundle(' -e 'noIDBundles(' -e 'InstallationID = ""' -- 'cmd/keyroster/*_test.go'` (authoritative at execution); host_test.go's `func resignBundle(` (or the method of that name) and `func roleEnv(`; dirpipe_test.go's `e.cfg = &Config{` block in `func newDirEnvPolicy(`; login_test.go's `saveConfig(&Config{` call; user_test.go's `e.cfg = &Config{` block; recover_test.go's `func newRecoverScenario(`; the counting keyring (`grep -n 'func useCountingKeyring(\|type countingAgent' cmd/keyroster/*_test.go`, dirpipe_test.go at 3da914f). For the two call sites added since f7eb018: knownhosts_test.go's `func TestKnownHostsSync(` with `hostEnv` and `useSSHDir`, and machinerenew_test.go's `func newRenewEnv(`, `func renewAnswer(` and `func (e *dirEnv) renewCount(`.
    - cmd/keyroster/revoke.go: `func openRevocation(`; cmd/keyroster/host.go: `func requireHostPoP(` and the join-token block that reads `bundle.InstallationID`; cmd/keyroster/host_test.go: `func TestDirectoryRebind(` (four cases); cmd/keyroster/directory.go: the rebind check (`grep -n 'rebindCheck'`).
  </read_first>
  <behavior>
    - CheckInstallationPin(pinned, served, version): equal passes; a pin with another served ID refuses ErrInstallationMismatch naming both; a pin with an ID-less bundle refuses; no pin with a served ID refuses with ErrInstallationNotPinned, whose text gives the full re-pin form (Q-C3 A); no pin and no served ID passes; a malformed pin refuses.
    - Trust applies it after every existing check; TrustUnpinned does not, and only init calls it.
    - init saves the served ID and prints the contract line; an ID-less bundle saves none.
    - With a bundle re-signed by the same root under another installation ID (F06's shape), `revoke serial`, `host join-token` and a directory command refuse before any admin signature and before any state-changing request, `known-hosts sync` before it writes any trust file, and `machine renew` before it sends a request or writes a certificate; an admin-auth failure's diagnosis names the pin error instead of hiding it.
    - recover keeps `recovery_installation_lost` first, then refuses an installation other than the pin (`recovery_installation_other`) or an unpinned config with an ID (`recovery_installation_not_pinned`), and prints nothing-to-recover only after the pin check passes.
    - trust verify prints installationLine after the summary in both modes; 03-14b's goldens change by that one added line.
    - Every existing case that strips the bundle's ID keeps its assertion, because the helper that re-signs the bundle re-saves the config's pin to the re-signed bundle's ID.
  </behavior>
  <action>
**RED first: commit R2.** R2 holds the tests, the four hand-edited goldens, the checkInvariants rule and the test helpers, plus these declarations only:
- Config.InstallationID;
- Trust's new parameter, passed at every call site and ignored;
- TrustUnpinned with Trust's old body, called by init;
- CheckInstallationPin returning nil;
- ErrInstallationMismatch, and ErrInstallationNotPinned with a short placeholder text (T2 gives it the full re-pin form, which TestRepinInstructionsKeepIdentity checks).

**internal/serverclient/client.go (`(03-14c, F06)`).**
- Today's Trust body becomes the unexported `func (c *Client) verifiedTrust(ctx context.Context, rootPins []string, threshold int) (*trust.Bundle, *trust.Policy, error)`, unchanged.
- `func (c *Client) Trust(ctx context.Context, rootPins []string, threshold int, installationID string) (*trust.Bundle, *trust.Policy, error)` calls verifiedTrust, then CheckInstallationPin(installationID, b.InstallationID, b.Version). Its doc comment says that every command passes the config's pin, so a bundle of another installation under the same roots is refused (F06).
- `func (c *Client) TrustUnpinned(ctx context.Context, rootPins []string, threshold int) (*trust.Bundle, *trust.Policy, error)` calls verifiedTrust only. Its doc comment says that only `keyroster init`, which saves the ID it returns, may call it.
- `var ErrInstallationNotPinned = errors.New(...)`, in the style of ErrTrustRootNotPinned: your saved config pins no installation ID, but the server's root-verified trust bundle names one; it was saved before keyroster pinned installations, or before this installation had an ID. Compare the ID with the installation ID on record (the ceremony transcript's Installation ID line, or the one your admin gives you), then run `` `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]` `` (--force replaces the whole config); on an automation host whose config has no user: `` `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n>` `` (machine-identities.md). The user form stays first, so TestRepinInstructionsKeepIdentity still finds `--user` and `--admin-key`; the automation-host form extends the remedy, not the rule (Q-C3 A).
- `var ErrInstallationMismatch = errors.New("the server's trust bundle is not the installation your config pins")`.
- `func CheckInstallationPin(pinned, served string, version uint64) error`, in this order:
  1. a pin that is not empty and not trust.IsInstallationID: `the saved config's installation_id %q is not an installation ID; run keyroster init again`, wrapping ErrInstallationMismatch;
  2. pinned equal to served (both empty included): nil;
  3. no pin: `the server's root-verified trust bundle v%d names installation %s: %w`, with ErrInstallationNotPinned;
  4. no served ID: `%w: the server's trust bundle v%d names no installation ID, but your config pins %s`, with ErrInstallationMismatch;
  5. otherwise: `%w: the server's root-verified trust bundle v%d names installation %s, but your config pins installation %s: it is another installation's bundle under your roots`, with ErrInstallationMismatch.

  The served ID has passed the root signatures and trust.Bundle's validation by then, so printing it repeats no unauthenticated server text (T-02-93).

**cmd/keyroster (`(03-14c, F06)`).**
- config.go: `InstallationID string` with tag `installation_id,omitempty`, documented as the installation ID of the bundle init verified, which every command requires the served bundle to name.
- init.go: call TrustUnpinned, set cfg.InstallationID to the bundle's ID before saveConfig, and have printTrustSummary print the init line of the output contract after the WebAuthn RP line.
- Every Trust call site passes `cfg.InstallationID` (or `s.cfg.InstallationID`): at 3da914f dirpipe.go, host.go (two), hoststatus.go, knownhosts.go, login.go, machinerenew.go, revoke.go and user.go (three), eleven besides init's. The build finds a missed one.
- user.go, the approve path's diagnostic Trust and adminSession.diagnose: when terr is ErrInstallationMismatch or ErrInstallationNotPinned (errors.Is), return terr instead of the admin-auth error, so the cause is named. Other terr values keep today's behaviour.
- recover.go, step 4, spelled out:
  1. if installation is empty and the saved export's bundle names one or a `--krl` document was given: refuse `recovery_installation_lost`, unchanged;
  2. then, on both paths, `serverclient.CheckInstallationPin(cfg.InstallationID, installation, restored.Bundle.Version)`. On ErrInstallationNotPinned: `recoverRefusal("recovery_installation_not_pinned", "the restored export's trust bundle: %v. Keep the hold, re-run keyroster init as the error says, then run keyroster revoke recover again", err)`. On any other error: `recoverRefusal("recovery_installation_other", "the restored export's trust bundle: %v; escalate, do not release the hold", err)`;
  3. then, if installation is empty, print nothingToRecover and return.

  Steps 1 to 3 of the command and their Options stay as they are in this task (Task 3 adds Now).
- trust.go (render-05): write `installationLine(nil, b)` right after `rootceremony.Summary(b, p)` in runTrustVerify, and `installationLine(prev, next)` right after `rootceremony.Summary(next, p)` in verifySuccessorBundle, before 03-14b's policy block. Doc comments say so.

**Goldens and invariants (R2).**
- Hand-edit the four trust_verify goldens. Insert one line right after the `Bundle SHA-256:` line:
  - in successor_unchanged, successor_added_admin and successor_pop: `installation id: <the fixed ID of the bundle in force>`, which is `00112233445566778899aabbccddeeff` in 03-14b's plan;
  - in genesis_pop: `installation id: <INSTALLATION_ID> (new in this version)`, as 03-14b's normalisation writes the ID.
  - If the test's fixed ID or placeholder differs from these, use the test's and record it.
- checkInvariants gains one rule, reported with `invariant:` like the others: every root_sign and trust_verify output has exactly one line that starts `installation id: `, after the `Bundle SHA-256:` line, and before any `Policy in force:` line and the first line that starts `signed by `.

**Tests (R2, `(03-14c, F06)`).**
- **TestClientTrust** (internal/serverclient) gains:
  - `installation_pinned_ok`;
  - `other_installation_refused`, where the stub serves a bundle re-signed by the same root with another ID: errors.Is ErrInstallationMismatch, and the message names both;
  - `id_less_bundle_refused_when_pinned`;
  - `unpinned_config_refused`: errors.Is ErrInstallationNotPinned, and the text holds `keyroster init --force`, `--user`, `--admin-key` and `on an automation host whose config has no user`;
  - `unpinned_id_less_ok`;
  - `malformed_pin_refused`;
  - `unpinned_variant_accepts_any`: TrustUnpinned returns the served bundle with its ID.

  The existing calls pass the stub bundle's ID, or "" for an ID-less stub.
- **TestRepinInstructionsKeepIdentity** (init_test.go): its error list gains serverclient.ErrInstallationNotPinned. RED: R2's placeholder text has neither flag.
- **cmd/keyroster/installpin_test.go (new): TestInstallationPinned.** Each case uses the env that command's existing tests use, and a handler hook that serves a bundle and policy re-signed by the env's own root with another installation ID, ops key and CA keys (F06's shape), without re-saving the config:
  - `revoke_serial_refused_before_signing`: `keyroster revoke serial 1729 --admin-key <fp>` exits non-zero, stderr names both IDs, the counting keyring made no signature, and no request reached the server's revoke route;
  - `join_token_refused`: `keyroster host join-token` exits non-zero, writes no file and posts nothing;
  - `directory_command_refused`: one dirpipe command that verifies through Trust (for example `keyroster directory show`) exits non-zero naming both IDs;
  - `old_config_refused`: a config without installation_id and the env's own bundle, which names one, refuses with ErrInstallationNotPinned's text;
  - `rollback_to_id_less_refused`: the pin set, and the stub serving an ID-less bundle under the same root;
  - `rebind_needs_reinit`: on TestDirectoryRebind's env, a config that pins none, a bundle that names an ID and a directory that names none (the rebind transition). `keyroster directory rebind --yes` refuses with ErrInstallationNotPinned's text and signs nothing; after the config is saved again with the bundle's ID through saveConfig, as `keyroster init --force` writes it (TestInit covers init's save), the same rebind succeeds and installs `+ installation_id <id>`;
  - `admin_error_names_installation`: `keyroster user approve <name>` against a server that answers the admin call with admin-auth refused and serves another installation's bundle; stderr names the installation mismatch, not only the admin-auth error;
  - `known_hosts_sync_refused` (03-09b's call site): on TestKnownHostsSync's env (hostEnv with useSSHDir), `keyroster known-hosts sync` exits non-zero naming both IDs, and no file is written under the test HOME's .ssh and no host-trust.json;
  - `machine_renew_refused` (03-11b's call site): on newRenewEnv with renewAnswer, `keyroster machine renew ci --key <file> --out <path>` exits 1 naming both IDs, renewCount stays 0 (no request reaches the renew route), and no certificate file is written;
  - `own_installation_ok`: the control, the same directory command with the right pin, succeeds.
- **TestInit** gains `saves_installation` (the config file's installation_id is the bundle's, and stdout has the init line) and `id_less_bundle_saves_none` (the none line, and no installation_id key in the file).
- **TestRevokeRecover** gains:
  - `other_installation_refused`: the config pins another ID; `recovery_installation_other` with `escalate`, and no request written;
  - `unpinned_config_refused`: the config pins none, the exports name an ID; `recovery_installation_not_pinned` with `Keep the hold` and `--user`, and no request;
  - `id_less_exports_with_pin_refused`: the config pins an ID, the exports (noIDBundles) name none; `recovery_installation_other`;
  - `lost_still_first`: the existing `recovery_installation_lost` case passes unchanged with a pinned config.
- **Helpers and moved setups.** The execution-time grep in read_first is authoritative.
  - dirEnv's (and so roleEnv's), login_test's, user_test's and newRecoverScenario's configs pin their stub bundle's ID.
  - The helper that re-signs the served bundle (the dirEnv method resignBundle in host_test.go) also re-saves the config with InstallationID set to the re-signed bundle's ID. So every existing case that strips the ID keeps exercising its own downstream check with its assertion unchanged: at f7eb018, TestDirectoryRebind/rebind_refused_without_bundle_id (rebind's own no-ID check), TestReadCommandsCheckInstallation/bundle_without_id (CheckStoredInstallation) and TestHostForget/no_installation_id_refused_locally (forget_no_installation_id); since then, TestEditRevokesLossesBeforeInstall/no_installation_id_warns_and_installs (dirpipe_test.go, krl_no_installation_id) and TestMachineRenew/no_installation_id_refused (machinerenew_test.go, machine renew's own no-ID check). TestMachineRenewChecksAnswer/retired_ca_refused's resignBundle edits the CAs and keeps the ID, so its pin is unchanged.
  - knownhosts_test.go's two ID-stripping sites (the `d.InstallationID = ""` and `b.InstallationID = ""` edits of its htFix input, about lines 130 and 665 at 3da914f) feed the host-trust writer directly and bypass Trust: record them as reviewed, not moved.
  - Cases built on noIDBundles pin "", so TestRevokeRecover/no_installation_id_nothing_to_recover keeps its nothing-to-recover assertion.
  - TestDirectoryRebind's four cases keep their assertions.
  - peer_text_test.go, remote_text_test.go and test/e2e/revoke_test.go pass the ID they expect.
  - The grep also finds root_test.go's idlessGenesis (about line 1643 at f7eb018). It feeds root sign only and needs no pin change: record it as reviewed, not moved.
  - Record every moved setup in the SUMMARY by case name.

Commit R2 (`test(cli): pin the CLI's installation pin and trust verify's installation line (F06)`), then take the RED from a worktree of R2 (second verify command).
- Expected `--- FAIL:`:
  - TestClientTrust/{other_installation_refused, id_less_bundle_refused_when_pinned, unpinned_config_refused, malformed_pin_refused};
  - TestRepinInstructionsKeepIdentity;
  - TestInstallationPinned/{revoke_serial_refused_before_signing, join_token_refused, directory_command_refused, old_config_refused, rollback_to_id_less_refused, rebind_needs_reinit, admin_error_names_installation, known_hosts_sync_refused, machine_renew_refused};
  - TestInit/{saves_installation, id_less_bundle_saves_none};
  - TestRevokeRecover/{other_installation_refused, unpinned_config_refused, id_less_exports_with_pin_refused};
  - TestCeremonyGolden/{successor_unchanged, successor_added_admin, successor_pop, genesis_pop}/trust_verify.
- Record the cases that pass on R2: the `_ok` controls, `unpinned_variant_accepts_any`, `lost_still_first`, and every moved setup.

**GREEN: commit T2** (`fix(cli): pin the installation ID at init and refuse another installation's bundle (F06)`). T2 changes no test and no golden.

**Mutants** (the mutant rule):
- M2-1: CheckInstallationPin passes when the pin is empty (TOFU). Killed by `TestClientTrust/unpinned_config_refused` and `TestInstallationPinned/old_config_refused`.
- M2-2: Trust skips CheckInstallationPin. Killed by `TestClientTrust/other_installation_refused`, `TestInstallationPinned/revoke_serial_refused_before_signing`, `/known_hosts_sync_refused` and `/machine_renew_refused`.
- M2-3: CheckInstallationPin passes an ID-less served bundle. Killed by `/id_less_bundle_refused_when_pinned` and `/rollback_to_id_less_refused`.
- M2-4: init does not save the ID. Killed by `TestInit/saves_installation`.
- M2-5: recover skips the pin check. Killed by `TestRevokeRecover/other_installation_refused`.
- M2-6: recover answers ErrInstallationNotPinned with the escalation text. Killed by `/unpinned_config_refused`.
- M2-7: diagnose swallows the pin error again. Killed by `TestInstallationPinned/admin_error_names_installation`.
- M2-8: runTrustVerify omits the line. Killed by `TestCeremonyGolden/genesis_pop/trust_verify`.

Commands: `bash scripts/linux.sh 'go vet ./internal/serverclient/ && go test -count=1 -timeout 5m -v -run "^TestClientTrust$" ./internal/serverclient/'` and `bash scripts/linux.sh 'go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^(TestInstallationPinned|TestInit|TestRevokeRecover|TestCeremonyGolden)$" ./cmd/keyroster/'`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^TestClientTrust$" ./internal/serverclient/ && go test -race -count=1 -timeout 15m -v -run "^(TestInstallationPinned|TestInit|TestRepinInstructionsKeepIdentity|TestRevokeRecover|TestCeremonyGolden|TestTrustVerifySuccessor|TestRootCeremonyPolicyChecks|TestDirectoryRebind|TestReadCommandsCheckInstallation|TestHostForget|TestEditRevokesLossesBeforeInstall|TestMachineRenew|TestKnownHostsSync)$" ./cmd/keyroster/ && go test -race -count=1 -timeout 15m -v -run "^(TestSummaryGolden|TestSummaryFieldsCovered)$" ./internal/rootceremony/ && go test -race -count=1 -timeout 15m ./internal/serverclient/ ./cmd/keyroster/ && go vet ./... && go vet -tags e2e ./test/e2e/ && test -z "$(gofmt -l .)"'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestClientTrust/installation_pinned_ok", "--- PASS: TestClientTrust/other_installation_refused", "--- PASS: TestClientTrust/id_less_bundle_refused_when_pinned", "--- PASS: TestClientTrust/unpinned_config_refused", "--- PASS: TestClientTrust/unpinned_id_less_ok", "--- PASS: TestClientTrust/malformed_pin_refused", "--- PASS: TestClientTrust/unpinned_variant_accepts_any", "--- PASS: TestRepinInstructionsKeepIdentity", "--- PASS: TestInstallationPinned/revoke_serial_refused_before_signing", "--- PASS: TestInstallationPinned/join_token_refused", "--- PASS: TestInstallationPinned/directory_command_refused", "--- PASS: TestInstallationPinned/old_config_refused", "--- PASS: TestInstallationPinned/rollback_to_id_less_refused", "--- PASS: TestInstallationPinned/rebind_needs_reinit", "--- PASS: TestInstallationPinned/admin_error_names_installation", "--- PASS: TestInstallationPinned/known_hosts_sync_refused", "--- PASS: TestInstallationPinned/machine_renew_refused", "--- PASS: TestInstallationPinned/own_installation_ok", "--- PASS: TestInit/saves_installation", "--- PASS: TestInit/id_less_bundle_saves_none", "--- PASS: TestRevokeRecover/other_installation_refused", "--- PASS: TestRevokeRecover/unpinned_config_refused", "--- PASS: TestRevokeRecover/id_less_exports_with_pin_refused", "--- PASS: TestRevokeRecover/lost_still_first", "--- PASS: TestRevokeRecover/no_installation_id_nothing_to_recover", "--- PASS: TestDirectoryRebind/rebind_refused_without_bundle_id", "--- PASS: TestReadCommandsCheckInstallation/bundle_without_id", "--- PASS: TestCeremonyGolden/successor_unchanged/trust_verify", "--- PASS: TestCeremonyGolden/successor_added_admin/trust_verify", "--- PASS: TestCeremonyGolden/successor_pop/trust_verify", "--- PASS: TestCeremonyGolden/genesis_pop/trust_verify", "--- PASS: TestRootCeremonyPolicyChecks", "--- PASS: TestEditRevokesLossesBeforeInstall/no_installation_id_warns_and_installs", "--- PASS: TestMachineRenew/no_installation_id_refused", "--- PASS: TestSummaryGolden", "--- PASS: TestSummaryFieldsCovered", or no "--- PASS: TestHostForget/" line ending in "no_installation_id_refused_locally" (the names as on origin/main; a renamed case is recorded with its new name)</fails_when>
    <automated>W=$(mktemp -d) && git worktree add --detach "$W/r2" "$R2" >/dev/null && { ( cd "$W/r2" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^TestClientTrust$" ./internal/serverclient/ ; go test -count=1 -timeout 15m -v -run "^(TestInstallationPinned|TestInit|TestRepinInstructionsKeepIdentity|TestRevokeRecover|TestCeremonyGolden)$" ./cmd/keyroster/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/r2"; } && L="$W/red.log" && ! grep -qE '\[(build|setup) failed\]' "$L" && for c in TestClientTrust/other_installation_refused TestClientTrust/id_less_bundle_refused_when_pinned TestClientTrust/unpinned_config_refused TestClientTrust/malformed_pin_refused TestRepinInstructionsKeepIdentity TestInstallationPinned/revoke_serial_refused_before_signing TestInstallationPinned/join_token_refused TestInstallationPinned/directory_command_refused TestInstallationPinned/old_config_refused TestInstallationPinned/rollback_to_id_less_refused TestInstallationPinned/rebind_needs_reinit TestInstallationPinned/admin_error_names_installation TestInstallationPinned/known_hosts_sync_refused TestInstallationPinned/machine_renew_refused TestInit/saves_installation TestInit/id_less_bundle_saves_none TestRevokeRecover/other_installation_refused TestRevokeRecover/unpinned_config_refused TestRevokeRecover/id_less_exports_with_pin_refused TestCeremonyGolden/successor_unchanged/trust_verify TestCeremonyGolden/successor_added_admin/trust_verify TestCeremonyGolden/successor_pop/trust_verify TestCeremonyGolden/genesis_pop/trust_verify; do grep -qF -- "--- FAIL: $c " "$L" || { echo "no RED: $c"; exit 1; }; done</automated>
    <fails_when>non-zero exit: R2 did not build, or one of the twenty-three named cases did not fail on R2. R2 is the commit recorded in the SUMMARY</fails_when>
    <automated>( for s in 'has no installation ID, so there is nothing to bind the directory to' 'but the root-verified trust bundle names none' 'forget_no_installation_id'; do a=$(MSYS_NO_PATHCONV=1 git show origin/main:cmd/keyroster/host_test.go | grep -cF -- "$s"); b=$(grep -cF -- "$s" cmd/keyroster/host_test.go); test "$a" -ge 1 && test "$a" -eq "$b" || { echo "assertion moved: $s"; exit 1; }; done ) && ( c(){ a=$(MSYS_NO_PATHCONV=1 git show "origin/main:cmd/keyroster/$1" | grep -cF -- "$2"); b=$(grep -cF -- "$2" "cmd/keyroster/$1"); test "$a" -ge 1 && test "$a" -eq "$b" || { echo "assertion moved: $1: $2"; exit 1; }; }; c dirpipe_test.go "has no installation ID, so the signer revokes nothing (krl_no_installation_id)" && c machinerenew_test.go "the trust bundle has no installation ID; machine renewal needs one" ) && for g in successor_unchanged successor_added_admin successor_pop genesis_pop; do F=cmd/keyroster/testdata/ceremony/$g.trust_verify.golden; O=$(MSYS_NO_PATHCONV=1 git show origin/main:$F) || exit 1; DF=$(diff <(printf '%s\n' "$O") "$F"); test "$(printf '%s\n' "$DF" | grep -c '^<')" -eq 0 && test "$(printf '%s\n' "$DF" | grep -c '^> installation id: ')" -eq 1 && test "$(printf '%s\n' "$DF" | grep -c '^>')" -eq 1 || { echo "not one added installation line: $g"; exit 1; }; done && test -z "$(git diff --name-only origin/main...HEAD -- cmd/keyroster/testdata/ceremony | grep -v '\.trust_verify\.golden$')" && test -z "$(git diff --name-only origin/main...HEAD -- internal/rootceremony/testdata/summary)" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -run "^TestCeremonyGolden$" ./cmd/keyroster/ -args -update-golden' && git diff --exit-code -- cmd/keyroster/testdata/ceremony && test -z "$(git ls-files --others --exclude-standard -- cmd/keyroster/testdata/ceremony)"</automated>
    <fails_when>non-zero exit: an existing ID-less assertion string changed count in host_test.go, dirpipe_test.go (krl_no_installation_id) or machinerenew_test.go (machine renew's no-ID refusal), a trust_verify golden differs from origin/main's by anything but one added `installation id:` line, a root_sign golden or one of 03-14b's three internal/rootceremony/testdata/summary goldens changed, or regenerating the goldens from T2 changed a committed one. Restore with `git checkout -- cmd/keyroster/testdata` before investigating</fails_when>
    <automated>test "$(git grep -n -e 'TrustUnpinned(' -- '*.go' ':!*_test.go' | grep -vE ':[0-9]+:[[:space:]]*//' | wc -l)" -eq 2 && git grep -q -e '\.TrustUnpinned(' -- cmd/keyroster/init.go && git grep -q -e 'func (c \*Client) TrustUnpinned(' -- internal/serverclient/client.go && test -z "$(git diff --name-only $R2 $T2 -- '*_test.go' '*.golden')"</automated>
    <fails_when>non-zero exit: TrustUnpinned has a caller other than init, or T2 changed a test or a golden</fails_when>
  </verify>
  <acceptance_criteria>
    - Every named result passes, and the RED of the twenty-three is recorded with the passing controls and the moved setups.
    - The eight mutants each compile and are killed.
    - The four trust_verify goldens differ from origin/main's by one added line each; no root_sign golden changed; regeneration is a no-op.
    - The three ID-less assertion strings in host_test.go, and the ones in dirpipe_test.go and machinerenew_test.go, keep their origin/main counts; the 13 goldens of 03-14b change only by the four added trust_verify lines.
  </acceptance_criteria>
  <done>A CLI pinned at init to one installation refuses a server that serves another installation's bundle under the same roots, before any admin signs; its diagnostics name a pin error; recover refuses another installation's exports and tells a re-init from an escalation; trust verify shows the installation ID to every verifier. Committed as R2 and T2.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: audit verify and recover bound entry times by the verifier's clock (F10, Q-C4 B) with the allowance tied to krl.PruneMargin, audit verify prints the last entry time, and export lines bind what a JSON reader reads (PR #75 review follow-ups)</name>
  <reversibility rating="reversible">audit verify and recover refuse more shapes, and audit verify prints one more line. No stored format changes; a revert restores today's verdicts.</reversibility>
  <precondition>T2 is committed on the branch.</precondition>
  <files>internal/audit/verify.go, internal/audit/revoke.go (doc comment only), internal/audit/export.go (doc comment only), internal/audit/verify_test.go, internal/audit/forget_test.go, internal/audit/export_test.go, cmd/keyroster/audit.go, cmd/keyroster/audit_test.go, cmd/keyroster/recover.go, cmd/keyroster/recover_test.go</files>
  <read_first>
    - internal/audit/verify.go: Verify's loop from `want := tree.Size()` to the `checkLineKeys(sc.Bytes(), &leaf)` call (2 KB); `func checkGrepFields(`, `func checkReplayFields(`, `func checkImportVersions(`, `func checkLineKeys(`, `func walkKeys(` and `var forgetOnlyKeys` (7 KB); Options and Report as Task 1 left them.
    - internal/audit/revoke.go: `func verifyKRLPublish(`, up to the issued_at check, and its doc comment (1 KB). internal/krl/krl.go: `PruneMargin`, `func EntryLive(` and `func Prunable(`.
    - internal/audit/export.go and every other non-test .go file in internal/audit that renders decoded fields (03-09 adds decoders): each decoded map's keys (`grep -n '\["' internal/audit/*.go`), and every decode function that renders `policy_version` (`grep -n 'policy_version' internal/audit/*.go`), about 5 KB.
    - internal/audit/verify_test.go: `func TestVerifyGrepFields(` with its `edit` and `raw` helpers, and `func TestVerifyRevocations(` with `newRevokeFixture`, `rf.publish`, `rf.checkpoint` and `rf.micros` (about 6 KB).
    - internal/audit/forget_test.go: `func TestVerifyForgetKeysOnOtherKinds(` (the whole function, 5 KB).
    - internal/tlog/leaf.go: `func ReasonName(` and `func ValidReason(`. internal/signer/logstate.go: the forward clamp in `appendLocked` (`grep -n 'pendingMicros'`).
    - cmd/keyroster/recover.go: step 2's and step 3's audit.Verify calls; cmd/keyroster/recover_test.go: `func (b *logBuilder) revokeSerial(`, `func (b *logBuilder) publish(` and `func newRecoverScenario(`.
  </read_first>
  <behavior>
    - With Options.Now set, a log whose last entry is more than 300 s after it is refused with ErrEntryAhead, naming the time it clears: the last entry's time minus 300 s. Leaf times never go back, so this is the same as any entry being ahead, and the named time is the one after which the same log verifies. Exactly 300 s passes; Now 0 bounds nothing. F10's shape is refused even with --previous of the honest prefix.
    - The allowance equals krl.PruneMargin in microseconds, and within it a KRL that leaves out a certificate still valid at the verifier's clock is refused by the re-derivation.
    - Report.LastTimeMicros is the last entry's time; the CLI prints it and refuses a log dated past its clock; recover refuses an F10-shaped saved export with `recovery_clock_ahead` and writes no request.
    - The parsed version, directory and sigs of a directory_install line, written escaped or spaced, must be the leaf's; written escaped on another kind, they are refused, and so are bundle_version off bundle_install and import_krl_versions off revocation_recovery. A parsed policy_version must be the leaf's own on kinds that render it and is refused elsewhere.
    - Any key, at any depth, that is not lowercase ASCII letters, digits and underscores is refused: `KIND`, `Kind`, the Kelvin sign and the long s included. Go's struct decoding reads such a line as a host_forget, which a control pins as the reason.
    - Each of the ten forget-only keys has its own refusal case, and the list of keys is pinned.
    - Every key internal/audit writes is in the charset, and no data-derived map key is added unrecorded.
    - No existing refusal message moves.
  </behavior>
  <action>
**RED first: commit R3.** R3 holds the tests, plus these declarations only: Options.Now; `var ErrEntryAhead = errors.New(...)`; `const maxLeafAheadMicros = krl.PruneMargin * 1_000_000`; Report.LastTimeMicros (never set); and the package clock variable `auditClock` in cmd/keyroster (unused).

**F10 (`(03-14c, F10)`).**
- **Options.Now**, a uint64: the verifier's clock in Unix microseconds; 0 disables the bound. Its doc comment states the property: an entry may be left out of a KRL issued at T only if T ≥ ValidBefore + krl.PruneMargin, and an accepted issued_at is at most Now + allowance, so with the allowance equal to PruneMargin an accepted KRL leaves out only certificates already expired at the verifier's clock. It also says the bound is detective, and that a signer whose clock ran ahead writes the same entries and keeps writing them at least that late (appendLocked clamps leaf times forward).
- **maxLeafAheadMicros** is defined from krl.PruneMargin, with a comment that it must not exceed it.
- Once, after the loop and the scanner's error check: when opts.Now is not 0 and the last leaf's time (lastTime) is above opts.Now + maxLeafAheadMicros, refuse, wrapping ErrEntryAhead: `audit: entry %d (%s), the last, is more than %d s after this verifier's clock %s (its time is %s): a KRL published at that time could leave out revocations of certificates that are still valid. The signer never dates a later entry before an earlier one, so correcting its clock does not clear this: it clears when this clock reaches %s. Check the signer's journal and the log's clock_regression entries for a clock episode; without one, treat the signer as compromised`. Verify refuses a leaf time that goes back, so a check of the last leaf equals a check of every leaf, and the named clear time, lastTime minus the allowance, is the one after which the same log verifies. Keep the last leaf's index and kind for the message. The times are RFC 3339 in UTC.
- **Report.LastTimeMicros** is the last leaf's time.
- Verify's doc comment names the bound, and adds to the list of what a holder of the CA and log keys can get past audit: an entry dated in the future once the verifier's clock is within 300 s of it, or always with Now 0.
- verifyKRLPublish's doc comment: its claim that a KRL which prunes an entry early fails holds for entry times bounded by the verifier's clock (Options.Now).
- **cmd/keyroster/audit.go:** `var auditClock = time.Now`, which tests set; `opts.Now = uint64(auditClock().UnixMicro())`, with the G115 nolint comment the codebase uses; the `last entry time:` line of the output contract, printed by runAuditVerify after the installation id line (never by printVerifyOK); `LastEntryMicros uint64` with tag `last_entry_time_micros` in verifyResult, declared after InstallationID and set in verifyResultOf from Report.LastTimeMicros.
- **cmd/keyroster/recover.go (Q-C4 B):** every audit.Verify call of steps 2 and 3 sets `Now: uint64(auditClock().UnixMicro())`. An error that is ErrEntryAhead (errors.Is) becomes `recoverRefusal("recovery_clock_ahead", "the %s export: %v. Keep the hold. If the signer's journal shows a clock episode, wait until this clock passes the time named and run keyroster revoke recover again; otherwise escalate", which, err)`, naming the saved or restored export. Other errors keep their messages.

**Export-line hardening (`(03-14c; PR #75 review)`).** checkLineKeys gains two checks after its forget-only check, in this order.
1. **Bound values.** A new helper, `checkBoundValues(decoded map[string]json.RawMessage, leaf *tlog.Leaf) error`, mirrors every byte check at the parsed level:
   - directory_install: a parsed `version` must be a JSON number whose text is strconv.FormatUint(body.Version, 10). A parsed `directory` or `sigs` must be a JSON string whose value is the standard base64 of body.Directory or body.Sigs.
   - A parsed `version`, `directory` or `sigs` on any other kind is refused; so is a parsed `bundle_version` on any kind but bundle_install (where it must equal body.BundleVersion), and a parsed `import_krl_versions` on any kind but revocation_recovery.
   - `policy_version`: on the kinds whose decode function renders it, a parsed value must be a JSON number whose text is the decimal of the leaf body's PolicyVersion; absent is allowed (older exports). At f7eb018 those kinds were issue, directory_install, revoke, revocation_recovery, login_issue and host_forget; at 3da914f they are nine, those six plus host_issue, machine_issue and probe_issue (export.go's decodeLeaf, decodeRevoke, decodeRecovery, decodeHostForget, decodeLoginIssue, decodeHostIssue, decodeMachineIssue and decodeProbeIssue). Derive the list at execution from the decode functions in internal/audit (`grep -n 'policy_version' internal/audit/*.go` and the kind of each function), with those nine as the expected result, and record it in the SUMMARY. On a line of any other kind it is refused.
   - Each refusal reads `its decoded <key> field is not the one of its <kind> leaf`.
   - A body that does not decode returns nil, and is left to the kind's own check, as in checkImportVersions.
   - On host_issue, probe_issue and machine_issue lines, checkForgetFields (at 3da914f) already requires the line to equal exportLeafLine byte for byte, so checkBoundValues and the charset rule are redundant there. They still run and must pass, because honest lines of those kinds conform: they carry no forget-only key, no `version`, `directory`, `sigs` or `bundle_version` (decodeHostIssue's doc), and only lowercase keys. The forget-only and bound-value cases stay on bundle_install and directory_install lines, where no byte-equality check pre-empts their message.
2. **The key charset, last.** Every key walkKeys collected, at any depth, is checked in sorted order. A key that is not one or more of `a`–`z`, `0`–`9` and `_` is refused with `its key %q is not lowercase ASCII letters, digits and underscores (<kind>)`, where kind is `checkpoint` on the checkpoint line.
- **checkLineKeys' doc comment** says what it now refuses. It also says that Go's encoding/json struct decoding matches keys without regard to case, with Unicode simple folding (the Kelvin sign folds to k, the long s to s), at every depth, so exact-key checks alone do not cover such a reader. Replace the sentence that lists Go among readers that only unescape keys and keep the last of repeated ones.
- **export.go's package doc comment** says that the bound decoded values must also be the leaf's as a JSON reader parses them, that policy_version is bound, and that every key is lowercase ASCII.

**Tests (R3).** Every escape below is the six characters in the test's Go raw string; see the delivery protocol.
- **TestVerifyLeafTimeBound** (verify_test.go):
  - `forward_dated_republish_refused` (F10's shape): on newRevokeFixture, issue c, revoke it by serial, publish, and take prev = the checkpoint. Set `rf.micros = (c.ValidBefore + krl.PruneMargin + 1) * 1_000_000` and publish again. Verify with Previous prev and Now the wall clock at the test start: errors.Is ErrEntryAhead, and the message contains `is more than 300 s after this verifier's clock` and `it clears when this clock reaches`. RED: it verifies, and LastKRL leaves c out.
  - `zero_now_unbounded`: the same export with Now 0 verifies (the bound is opt-in).
  - `at_allowance_ok`: last leaf exactly at Now + 300 s.
  - `past_allowance_refused`: Now + 300 s + 1 µs.
  - `within_allowance_cannot_drop_valid`: c revoked with ValidBefore Now + 1 s; a publish at Now + 300 s whose KRL leaves c out is refused by the KRL re-derivation. It passes on R3 and pins the property the allowance relies on.
  - `allowance_is_prune_margin`: maxLeafAheadMicros equals krl.PruneMargin × 10⁶. It passes on R3 (a declaration) and kills mutant M3-2.
  - `two_ahead_leaves_names_last`: two forward-dated entries, the second later than the first; the error names the second leaf's time minus 300 s as the clear time (computed in the test). RED: it verifies.
  - `last_time_reported`: Report.LastTimeMicros is the last leaf's time.
- **TestAuditVerifyClock** (cmd/keyroster/audit_test.go). It sets auditClock, restores it with t.Cleanup, and is not parallel.
  - `prints_last_entry_time`: the line, and the JSON field.
  - `clock_behind_refused`: auditClock set to one hour before the export's last entry gives a non-zero exit; stderr names the clear time, and stdout has no `OK:`.
- **TestRevokeRecover/forward_dated_saved_export_refused** (recover_test.go): the logBuilder revokes c after the restored prefix, then publishes past `c.ValidBefore + krl.PruneMargin`, so the saved export's last KRL leaves c out. recover refuses `recovery_clock_ahead` with `Keep the hold` in its text, and writes no request. RED: recover writes a request whose imports lack c.
- **TestVerifyBoundValues** (verify_test.go), on TestVerifyGrepFields' fixture (its bundle_install and directory_install lines, and an issue line where the fixture has one; record which line each case uses). Each `escaped` case replaces the plain key, so the escape hides it from the byte checks:
  - `escaped_version_refused`: replace the directory_install line's `"version":N` with `"versio\u006e":` followed by N+1;
  - `spaced_version_refused`: replace it with `"version" :` followed by N+1;
  - `escaped_version_same_value_ok`: replace it with `"versio\u006e":N`;
  - `spaced_replay_pair_refused`: write both `"directory":` and `"sigs":` with a space before the colon, and the directory value another directory's base64;
  - `escaped_directory_on_bundle_install_refused`: add `"d\u0069rectory":"<a directory's base64>"` to the bundle_install line's decoded object;
  - `escaped_version_on_bundle_install_refused`: add `"versio\u006e":99` there;
  - `escaped_bundle_version_on_directory_install_refused`: add `"bundle\u005fversion":1` to the directory_install line;
  - `escaped_import_versions_on_bundle_install_refused`: add `"import\u005fkrl_versions":[1]` to the bundle_install line;
  - `policy_version_edited_refused`: replace a line's `"policy_version":V` with V+1;
  - `policy_version_escaped_refused`: replace `"policy_version":V` with `"policy_versio\u006e":` followed by V+1;
  - `policy_version_on_bundle_install_refused`: add `"policy_version":1` to the bundle_install line;
  - `policy_version_missing_ok`: delete it from a line that renders it;
  - `number_form_refused`: replace `"policy_version":V` with V written as `V.0`.
- **TestVerifyForgetKeysOnOtherKinds** (forget_test.go) gains:
  - one subtest per forget-only key, `forget_only_<key>_refused`, injecting the key onto the bundle_install line with its first letter escaped, so that checkForgetFields' byte check cannot see approved_once or host_gone either: `\u0069dentity`, `\u0065xpected_name`, `\u0065nrolled_at_us`, `\u0068ost_key_fingerprints`, `\u0061pproved_once`, `\u0068ost_gone`, `\u0072emoval_version`, `\u0063onfirmed_version`, `\u0063onfirmed_sha256` and `\u0061dmin_fingerprints`, each with a value of its rendered type. Each wants `its decoded <key> field is not one of a host_forget leaf (bundle_install)`;
  - `forget_only_keys_pinned`: a list of the ten keys that must equal forgetOnlyKeys' keys, failing with the difference;
  - charset cases, each wanting the charset message for its first non-conforming key in sorted order, built in the test with `%q`:
    - `upper_kind_refused`: `"KIND":"host_forget"` plus `"IDENTITY":` and an identity (the message names `IDENTITY`);
    - `title_kind_refused`: `"Kind":"host_forget"`;
    - `kelvin_kind_refused`: `"\u212aind":"host_forget"` (the Kelvin sign, U+212A);
    - `long_s_host_gone_refused`: `"ho\u017ft_gone":true` (the long s, U+017F);
    - `nested_upper_refused`: `"x":{"Identity":"…"}`;
  - `go_reader_folds_case`, the premise kept as a control: the decoded object of `upper_kind_refused`, unmarshalled into a struct with a `Kind string` field tagged `kind`, reads `host_forget`. For the Kelvin line, record what this Go version reads; if it does not fold the Kelvin sign, the charset case still stands, and the SUMMARY says so.
- **TestExportKeysLowercase** (export_test.go): go/parser over every non-test .go file in internal/audit, looking only inside the bodies of the functions named `Decode` or `decodeLeaf`, or whose name starts with `decode` (export.go's decoders and any that 03-09 to 03-11 added):
  - collects every string literal used as the index of an assignment's left side (`m["k"] = ...`, `r["k"] = ...`, `e["k"] = ...`) and every string-literal key of a composite literal of a map type; each must match `^[a-z0-9_]+$`;
  - fails on any map index or composite-literal map key in those bodies that is not a string literal, except the one recorded site `counts[tlog.ReasonName(c.Reason)]`, whose names it checks: tlog.ReasonName(r) for every r with tlog.ValidReason(r) must match too. A map index is an index on the left of an assignment whose indexed identifier the same function declares with a map type (a `map[...]` parameter such as decodeRevoke's `m`, a map composite literal, or `make(map[...])`); a slice index is not one, because go/parser alone cannot tell the two apart. As read at 3da914f (export.go, from Decode to the end of decodeProbeIssue; at f7eb018 the decoders ended with decodeLoginIssue), every other index write in the decoders is `m["..."]` or `e["..."]` with a string literal, every map composite literal has string-literal keys, and there is no slice index write, so the test passes at 3da914f. The message says a data-derived key needs its own charset proof or an allowlist entry;
  - requires the collected set to include `kind`, `policy_version`, `directory` and `admin_fingerprints`, and requires that decodeLeaf, decodeRevoke, decodeRecovery, decodeHostForget, decodeLoginIssue, decodeHostIssue, decodeMachineIssue and decodeProbeIssue were found, so that a scope that matches nothing fails;
  - leaves out, by design, the verification bookkeeping maps elsewhere in internal/audit (walkKeys' `seen` and `keys`, revoke.go's `rs.certs`, recovery.go's `map[uint8]uint8{krl.EntrySerial: ...}` and others), which never reach an export line. It passes at 3da914f, on R3 and on T3.

Commit R3 (`test(audit): pin the verifier-clock bound and the export-line key rules (F10)`), then take the RED from a worktree of R3 (second verify command).
- Expected `--- FAIL:`:
  - TestVerifyLeafTimeBound/{forward_dated_republish_refused, past_allowance_refused, two_ahead_leaves_names_last, last_time_reported};
  - TestAuditVerifyClock/{prints_last_entry_time, clock_behind_refused};
  - TestRevokeRecover/forward_dated_saved_export_refused;
  - TestVerifyBoundValues/{escaped_version_refused, spaced_version_refused, spaced_replay_pair_refused, escaped_directory_on_bundle_install_refused, escaped_version_on_bundle_install_refused, escaped_bundle_version_on_directory_install_refused, escaped_import_versions_on_bundle_install_refused, policy_version_edited_refused, policy_version_escaped_refused, policy_version_on_bundle_install_refused, number_form_refused};
  - TestVerifyForgetKeysOnOtherKinds/{upper_kind_refused, title_kind_refused, kelvin_kind_refused, long_s_host_gone_refused, nested_upper_refused}.
- Expected to pass on R3, recorded with why: the `_ok` cases, `zero_now_unbounded`, `within_allowance_cannot_drop_valid`, `allowance_is_prune_margin`, every `forget_only_<key>_refused` and `forget_only_keys_pinned` (forgetOnlyKeys already holds all ten; their value is in the mutants), `go_reader_folds_case`, and TestExportKeysLowercase.

**GREEN: commit T3** (`fix(audit): refuse entries dated past the verifier's clock and export keys a reader would fold (F10)`). T3 changes no test.

**Mutants** (the mutant rule; production code only):
- M3-1: drop the Now check. Killed by `TestVerifyLeafTimeBound/forward_dated_republish_refused` and `/past_allowance_refused`.
- M3-2: define the allowance as 600 s. Killed by `/allowance_is_prune_margin`.
- M3-3: compare without the allowance (`> opts.Now`). Killed by `/at_allowance_ok`.
- M3-4: the CLI leaves Now at 0. Killed by `TestAuditVerifyClock/clock_behind_refused`.
- M3-5: recover leaves Now at 0. Killed by `TestRevokeRecover/forward_dated_saved_export_refused`.
- M3-6: drop the charset check. Killed by the five charset cases.
- M3-7: drop checkBoundValues' directory_install version branch. Killed by `TestVerifyBoundValues/escaped_version_refused` and `/spaced_version_refused`.
- M3-8: drop its other-kind branch. Killed by the four `escaped_*_on_*_refused` cases.
- M3-9: drop its policy_version branch. Killed by the four policy_version refusals.
- M3-10 to M3-19: delete one forgetOnlyKeys entry at a time, ten mutants. Each is killed by its `forget_only_<key>_refused`. Also record each mutant's result on origin/main's own TestVerifyForgetKeysOnOtherKinds, applied in a worktree of origin/main: killed there for identity and admin_fingerprints, which origin/main's cases inject, and surviving for the other eight. That is the gap the per-key cases close.
- M3-20: in decodeHostForget, write one key through a variable (`k := "identity"; m[k] = ...`). The key's value is unchanged, so only the gate sees it: killed by TestExportKeysLowercase.

Commands: `bash scripts/linux.sh 'go vet ./internal/audit/ && go test -count=1 -timeout 5m -v -run "^(TestVerifyLeafTimeBound|TestVerifyBoundValues|TestVerifyForgetKeysOnOtherKinds)$" ./internal/audit/'` and `bash scripts/linux.sh 'go vet ./cmd/keyroster/ && go test -count=1 -timeout 5m -v -run "^(TestAuditVerifyClock|TestRevokeRecover)$" ./cmd/keyroster/'`; for M3-20, `bash scripts/linux.sh 'go vet ./internal/audit/ && go test -count=1 -timeout 5m -v -run "^TestExportKeysLowercase$" ./internal/audit/'`.
  </action>
  <verify>
    <automated>bash scripts/linux.sh 'go test -race -count=1 -timeout 15m -v -run "^(TestVerifyLeafTimeBound|TestVerifyBoundValues|TestVerifyForgetKeysOnOtherKinds|TestVerifyGrepFields|TestVerifyReplayFields|TestVerifyRevocations|TestExportKeysLowercase|TestVerifyInstallationBinding)$" ./internal/audit/ && go test -race -count=1 -timeout 15m -v -run "^(TestAuditVerifyClock|TestAuditVerifyInstallation|TestRevokeRecover)$" ./cmd/keyroster/ && go test -race -count=1 -timeout 15m ./internal/audit/ ./cmd/keyroster/ && go vet ./internal/audit/ ./cmd/keyroster/ && test -z "$(gofmt -l internal/audit cmd/keyroster)"'</automated>
    <fails_when>non-zero exit, "FAIL" or "DATA RACE" in the output, or any of these lines missing: "--- PASS: TestVerifyLeafTimeBound/forward_dated_republish_refused", "--- PASS: TestVerifyLeafTimeBound/zero_now_unbounded", "--- PASS: TestVerifyLeafTimeBound/at_allowance_ok", "--- PASS: TestVerifyLeafTimeBound/past_allowance_refused", "--- PASS: TestVerifyLeafTimeBound/within_allowance_cannot_drop_valid", "--- PASS: TestVerifyLeafTimeBound/allowance_is_prune_margin", "--- PASS: TestVerifyLeafTimeBound/two_ahead_leaves_names_last", "--- PASS: TestVerifyLeafTimeBound/last_time_reported", "--- PASS: TestAuditVerifyClock/prints_last_entry_time", "--- PASS: TestAuditVerifyClock/clock_behind_refused", "--- PASS: TestRevokeRecover/forward_dated_saved_export_refused", "--- PASS: TestVerifyBoundValues/escaped_version_refused", "--- PASS: TestVerifyBoundValues/spaced_version_refused", "--- PASS: TestVerifyBoundValues/escaped_version_same_value_ok", "--- PASS: TestVerifyBoundValues/spaced_replay_pair_refused", "--- PASS: TestVerifyBoundValues/escaped_directory_on_bundle_install_refused", "--- PASS: TestVerifyBoundValues/escaped_version_on_bundle_install_refused", "--- PASS: TestVerifyBoundValues/escaped_bundle_version_on_directory_install_refused", "--- PASS: TestVerifyBoundValues/escaped_import_versions_on_bundle_install_refused", "--- PASS: TestVerifyBoundValues/policy_version_edited_refused", "--- PASS: TestVerifyBoundValues/policy_version_escaped_refused", "--- PASS: TestVerifyBoundValues/policy_version_on_bundle_install_refused", "--- PASS: TestVerifyBoundValues/policy_version_missing_ok", "--- PASS: TestVerifyBoundValues/number_form_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/forget_only_keys_pinned", "--- PASS: TestVerifyForgetKeysOnOtherKinds/upper_kind_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/title_kind_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/kelvin_kind_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/long_s_host_gone_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/nested_upper_refused", "--- PASS: TestVerifyForgetKeysOnOtherKinds/go_reader_folds_case", "--- PASS: TestExportKeysLowercase", "--- PASS: TestVerifyInstallationBinding", "--- PASS: TestAuditVerifyInstallation", or fewer than ten "--- PASS: TestVerifyForgetKeysOnOtherKinds/forget_only_" lines ending in "_refused"</fails_when>
    <automated>W=$(mktemp -d) && git worktree add --detach "$W/r3" "$R3" >/dev/null && { ( cd "$W/r3" && bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^(TestVerifyLeafTimeBound|TestVerifyBoundValues|TestVerifyForgetKeysOnOtherKinds|TestExportKeysLowercase)$" ./internal/audit/ ; go test -count=1 -timeout 15m -v -run "^(TestAuditVerifyClock|TestRevokeRecover)$" ./cmd/keyroster/ ; true' ) > "$W/red.log" 2>&1; git worktree remove --force "$W/r3"; } && L="$W/red.log" && ! grep -qE '\[(build|setup) failed\]' "$L" && for c in TestVerifyLeafTimeBound/forward_dated_republish_refused TestVerifyLeafTimeBound/past_allowance_refused TestVerifyLeafTimeBound/two_ahead_leaves_names_last TestVerifyLeafTimeBound/last_time_reported TestAuditVerifyClock/prints_last_entry_time TestAuditVerifyClock/clock_behind_refused TestRevokeRecover/forward_dated_saved_export_refused TestVerifyBoundValues/escaped_version_refused TestVerifyBoundValues/spaced_version_refused TestVerifyBoundValues/spaced_replay_pair_refused TestVerifyBoundValues/escaped_directory_on_bundle_install_refused TestVerifyBoundValues/escaped_version_on_bundle_install_refused TestVerifyBoundValues/escaped_bundle_version_on_directory_install_refused TestVerifyBoundValues/escaped_import_versions_on_bundle_install_refused TestVerifyBoundValues/policy_version_edited_refused TestVerifyBoundValues/policy_version_escaped_refused TestVerifyBoundValues/policy_version_on_bundle_install_refused TestVerifyBoundValues/number_form_refused TestVerifyForgetKeysOnOtherKinds/upper_kind_refused TestVerifyForgetKeysOnOtherKinds/title_kind_refused TestVerifyForgetKeysOnOtherKinds/kelvin_kind_refused TestVerifyForgetKeysOnOtherKinds/long_s_host_gone_refused TestVerifyForgetKeysOnOtherKinds/nested_upper_refused; do grep -qF -- "--- FAIL: $c " "$L" || { echo "no RED: $c"; exit 1; }; done && grep -qF -- '--- PASS: TestVerifyForgetKeysOnOtherKinds/go_reader_folds_case ' "$L" && grep -qF -- '--- PASS: TestExportKeysLowercase ' "$L" && grep -qF -- '--- PASS: TestVerifyLeafTimeBound/allowance_is_prune_margin ' "$L"</automated>
    <fails_when>non-zero exit: R3 did not build, a named case did not fail on R3, or the premise control, the export key gate or the allowance pin did not pass on R3. R3 is the commit recorded in the SUMMARY</fails_when>
    <automated>( set -e; for f in internal/audit/forget_test.go internal/audit/verify_test.go; do MSYS_NO_PATHCONV=1 git show "origin/main:$f" | grep -E '^[[:space:]]+\{"[a-z0-9_]+_(ok|refused)",' | while IFS= read -r l; do grep -qxF -- "$l" "$f" || { echo "moved: $l"; exit 1; }; done; done ) && test "$(grep -c 'versio[\]u006e' internal/audit/verify_test.go)" -ge 2 && test "$(grep -c '[\]u0068ost_gone' internal/audit/forget_test.go)" -ge 1 && D=$(git diff --name-only $T2...$T3) && ! printf '%s\n' "$D" | grep -vE '^(internal/audit/(verify|revoke|export)\.go|internal/audit/(verify|forget|export)_test\.go|cmd/keyroster/(audit|recover)(_test)?\.go|\.planning/.*)$' | grep -q . && test -z "$(git diff --name-only $R3 $T3 -- '*_test.go')"</automated>
    <fails_when>non-zero exit: a case row of TestVerifyForgetKeysOnOtherKinds or TestVerifyGrepFields on origin/main changed (an existing refusal message moved), the tests do not hold the real escapes, Task 3 changed a file outside its ten and .planning, or T3 changed a test</fails_when>
  </verify>
  <acceptance_criteria>
    - Every named result passes; the RED of the twenty-three is recorded with the cases that pass on R3 and why.
    - The twenty mutants each compile and are killed; the origin/main result of all ten forget-key mutants is recorded (killed for identity and admin_fingerprints, surviving for the other eight).
    - No case row of the two existing tables changed, and the test files hold the escapes as bytes.
    - The derived list of kinds that render policy_version is in the SUMMARY.
  </acceptance_criteria>
  <done>audit verify and recover refuse a log dated past the auditor's clock, audit verify shows the last entry's time, and every export line reads the same to grep, to jq and to a case-folding Go reader. Committed as R3 and T3.</done>
</task>

<task type="auto">
  <name>Task 4: The runbook updates, the transcript line, the registry step, the pointer sentences, the publish edits, the gates, the PR, the pre-merge review and the SUMMARY</name>
  <precondition>T3 is committed on the branch, and the pointer anchors are re-checked: Task 1's anchor check, run again against origin/main after `git fetch origin`, exits 0. If an anchor no longer occurs exactly once, stop and report which.</precondition>
  <files>docs/runbooks/signer-install.md, docs/runbooks/server-install.md, docs/runbooks/host-setup.md, docs/runbooks/revoke.md, docs/runbooks/root-ceremony.md, docs/runbooks/ceremony-transcript-template.md, docs/runbooks/enroll-user.md, docs/runbooks/machine-identities.md, cmd/keyroster/init_test.go (TestRepinInstructionsKeepIdentity's runbook list), test/e2e/restore_test.go (the pinned audit verify line), docs/format-registry.md (on origin/main since #87), .planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md, .planning/phases/03-linux-agent-and-revocation/03-12-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-13-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-14-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-15-PLAN.md, .planning/phases/03-linux-agent-and-revocation/03-16-PLAN.md, .planning/ROADMAP.md, .planning/STATE.md</files>
  <read_first>
    - Every audit verify command in the runbooks: `grep -n 'keyroster audit verify' docs/runbooks/*.md` (ten command lines at f7eb018 and at 3da914f: signer-install.md eight, root-ceremony.md one, enroll-user.md one), with the paragraph around each.
    - docs/runbooks/signer-install.md: the paragraph that begins with the check that holds being `keyroster audit verify --pin` (`grep -n 'The check that holds'`); restore step 2 and the recovered verifies, with the strings test/e2e/restore_test.go pins there (`grep -n 'restoreVerify\|restoreRestoredStop\|restoreSavedVerifyIf\|restoreSavedStop\|restoreRecoveryChecks' test/e2e/restore_test.go` and each constant's text); each `keyroster revoke recover` instruction (`grep -n 'revoke recover'`). About 6 KB.
    - docs/runbooks/server-install.md: `## 5. First admin client: keyroster init` to the next `## ` (3 KB).
    - docs/runbooks/host-setup.md: the join-token paragraph that names the installation ID (`grep -n 'installation ID of the'`), the rebind paragraph (`grep -n 'directory rebind'`), and the forget-check paragraph that lists the forget-only keys (`grep -n 'parser lists'`), about 4 KB.
    - docs/runbooks/revoke.md: the refusal table with `revoke_installation_mismatch` (`grep -n 'revoke_installation'`, 2 KB).
    - docs/runbooks/root-ceremony.md: the root sign step of each signing section (`grep -n 'keyroster root sign'`) and each place a custodian runs `keyroster trust verify` (`grep -n 'trust verify'`); docs/runbooks/ceremony-transcript-template.md (the whole file, 2 KB); docs/runbooks/enroll-user.md: the invite section (`grep -n 'keyroster init'`) and the audit verify command.
    - docs/runbooks/machine-identities.md: `## Renew a machine certificate` to the next `## ` (about 4 KB), and the heading `## Renewal needs pop.machines`, whose section this plan does not touch.
    - cmd/keyroster/runbook_test.go: `successorSigningSections`, `func sectionWindow(` and TestRootCeremonyPolicyChecks' windows and anchors (03-14b), which must stay green; cmd/keyroster/init_test.go: TestRepinInstructionsKeepIdentity's runbook list. The runbook tests that read the files this task edits: TestHostTrustRunbooks (hosttrust_runbook_test.go), TestProbeAccountRunbook (probeaccount_runbook_test.go) and internal/agent/apply's TestProbeHoldReasonsDocumented (account_test.go); all of them are additions-safe at 3da914f.
    - docs/format-registry.md on origin/main, if present: `## Installation binding` to the next `## `.
    - .planning/phases/03-linux-agent-and-revocation/03-08c-SUMMARY.md: the "A in detail" line only (`grep -n 'A in detail'`).
    - 03-12-PLAN.md: its frontmatter, its first `<precondition>` line and the line holding `See 03-14b-PLAN.md.)`. 03-13-PLAN.md: the line holding `See 03-14b-PLAN.md.)`. 03-15-PLAN.md and 03-16-PLAN.md: the lines holding the anchors below. The `wave:` and `depends_on:` lines of 03-13 to 03-16.
    - .planning/ROADMAP.md: Phase 3's Plans line, its wave blocks and the Progress row (`grep -n 'Wave\|Plans:\|^| 3\. Linux Agent'`); .planning/STATE.md: the frontmatter and the `Plan:` line.
  </read_first>
  <action>
**Runbooks (CONTEXT D-20).** Each new prose text names the CI tests that run it and carries an UNVERIFIED label (on the homelab, whose bundle names no installation until 03-15, or on a real host). Change a fenced block that a test pins only together with that test, in the same commit, and record it; add prose outside pinned blocks and after the strings TestRestoreRunbookChecks orders, so none is split and their order stays.
1. **Every audit verify command** in the runbooks (signer-install.md, root-ceremony.md, enroll-user.md, and any other found by the grep) gains ` --installation-id <installation id>` right after its `--threshold <n>` argument, on the same line. test/e2e/restore_test.go's `restoreVerify` constant, and every other test constant that quotes such a line (found by the grep below), change to the same text in the same commit. The usage line in cmd/keyroster/audit.go is T1's edit, not a test constant, so the grep is `git grep -n -e 'keyroster audit verify --pin' -- test cmd ':!cmd/keyroster/audit.go'`. Once per runbook section that holds such commands, add: on an installation whose trust bundle names no installation ID (pre-D-04; the homelab until 03-15), leave out --installation-id, and audit verify prints `installation id: none`.
2. **signer-install.md.**
   - In the paragraph about what audit verify checks, add:
     - `--installation-id` binds the result to one installation, and audit verify refuses a log whose trust bundle names an installation unless you pass it or `--any-installation`, which verifies without binding;
     - the `installation id:` and `last entry time:` lines;
     - audit verify refuses an entry more than 300 s after the verifier's clock. A signer whose clock ran ahead writes such entries and keeps writing later ones at least as late, so correcting its clock does not clear the refusal: it lasts until this machine's clock reaches the last entry's time minus 300 s. Check the signer's journal and the log's clock_regression entries; without a clock episode, treat the signer as compromised.

     Run in CI: TestVerifyInstallationBinding, TestAuditVerifyInstallation, TestAuditVerifiesIssuance/binds_installation (e2e), TestVerifyLeafTimeBound and TestAuditVerifyClock.
   - At the end of restore step 2, and after the recovered verifies, one sentence each: if audit verify refuses an entry ahead of the clock here, keep the hold and do not release it before this machine's clock passes the time the message names; escalate unless the signer's journal shows a clock episode.
   - At the first `keyroster revoke recover` instruction: recover refuses a restored export of another installation than your config pins (`recovery_installation_other`: escalate, do not release the hold), refuses on a config that pins no installation while the export names one (`recovery_installation_not_pinned`: keep the hold, compare the ID with the transcript's Installation ID line, re-run `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]`, then run recover again), and refuses an export dated ahead of the clock (`recovery_clock_ahead`: keep the hold; if the signer's journal shows a clock episode, wait until this machine's clock passes the time named and run recover again; otherwise escalate). Run in CI: TestRevokeRecover; UNVERIFIED in a real restore.
3. **root-ceremony.md.** At the root sign step of each signing section: Record the installation id line that root sign prints in the transcript's Installation ID line; every later `keyroster init`, `keyroster audit verify --installation-id` and recovery compares against that record. Where a custodian runs `keyroster trust verify`: trust verify prints the same installation id line as root sign, right after the summary (03-14c); it must equal the recorded one. Run in CI: TestCeremonyGolden; UNVERIFIED in a real ceremony. TestRootCeremonyPolicyChecks must stay green: both insertions are plain prose sentences appended to an existing paragraph or set as their own paragraph, never a line that starts with one of 03-14b's sectionWindow markers (`3. **Sign the successor bundle`, `4. **Verify against the paper`, `3. **Build the successor`, `4. **Sign with a current root`, `5. **Verify against the paper`, `You need everything from`, `0. **Prepare.**` and the others its windows name), and never a `- **` bullet or a numbered-step line inside "Change the policy" step 3, because two windows end at the next such line. Each marker must still occur exactly once in its window.
4. **ceremony-transcript-template.md.** Right after the line that starts `Bundle SHA-256 prefix typed at each signing`, add the line `` Installation ID (root sign's `installation id:` line): `________________________________` ``.
5. **server-install.md, section 5.** Add that init also saves the installation ID of the trust bundle it verified and prints it, to compare with the transcript's Installation ID line. Every later command refuses a bundle of another installation, and refuses a bundle naming an ID while the config pins none, until init is run again as `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]` (the literal command, which TestRepinInstructionsKeepIdentity checks). Run in CI: TestInit, TestInstallationPinned and TestClientTrust; UNVERIFIED on the homelab until 03-15.
6. **enroll-user.md.** In the invite section: the admin gives each user the installation ID with the invite. If keyroster refuses with `your saved config pins no installation ID`, the user compares the printed ID with the one the admin gave, and re-runs init as `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]`. Run in CI: TestInstallationPinned; UNVERIFIED for a real user.
7. **host-setup.md.**
   - In the join-token paragraph: the join token's installation ID is now the installation ID your config pins (03-14c). Run in CI: TestInstallationPinned (`join_token_refused`); UNVERIFIED on the homelab until 03-15.
   - In the rebind paragraph, before the rebind command: since 03-14c, before you run keyroster directory rebind, run `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]` with the pins of the bundle now in force, and compare the installation id line it prints with the transcript; until the config pins the new ID, rebind and every other command refuse. At 03-15 the CLIs are re-initialised for the new roots anyway. Run in CI: TestInstallationPinned (`rebind_needs_reinit`, which saves the config as init does; TestInit covers init's save) and TestDirectoryRebind. The init-then-rebind sequence is UNVERIFIED end to end.
   - In the forget-check paragraph, replace the sentence that ends with what the parser lists. The new text says that audit verify also refuses any key that is not lowercase ASCII letters, digits and underscores, and binds the parsed version and policy_version. So a JSON parser, also one that matches keys without regard to case, reads a host_forget only on a verified host_forget line (PR #75 review; 03-14c). Add `TestVerifyForgetKeysOnOtherKinds` (its charset cases) and `TestVerifyBoundValues` to that paragraph's Run in CI line.
8. **revoke.md.** In the refusal table, add two rows for the CLI's own refusals, each before anything is signed:
   - `... another installation's bundle under your roots`: the server serves another installation's bundle; treat the server as compromised and escalate;
   - `... your saved config pins no installation ID`: compare the printed ID with the transcript, then re-run `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n> --user <name> [--admin-key <your admin key>]`.

   Each row ends with `(Run in CI: TestInstallationPinned; UNVERIFIED on a real host)`.
9. **machine-identities.md.** In `## Renew a machine certificate`, right after the paragraph that says to run `keyroster init` once without `--user`, add one paragraph: since 03-14c, init also saves the installation ID of the trust bundle it verified, and `keyroster machine renew` refuses a bundle of another installation. A config made before 03-14c on an installation whose bundle names an ID pins none, so every renewal exits 1 with `your saved config pins no installation ID` until it is re-initialised; on an automation host whose config has no user, compare the printed ID with the transcript's Installation ID line and run `keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n>`, with no `--user` (a `--user` there would make the machine's config a user's). Run in CI: TestInstallationPinned (`machine_renew_refused`); UNVERIFIED on a real automation host. The paragraph goes in that section only, never in `## Renewal needs pop.machines`, which TestRootCeremonyPolicyChecks' `machine_identities_pop` window reads. machine-identities.md stays off TestRepinInstructionsKeepIdentity's list: its re-pin form has no `--user` by design.
- **TestRepinInstructionsKeepIdentity** (cmd/keyroster/init_test.go) gains signer-install.md, host-setup.md, revoke.md and enroll-user.md in its runbook list. A paragraph is checked when it contains `keyroster init` and `--force`, with or without `--root-pin`, and must then carry `--user` and `--admin-key`; root-ceremony.md's and server-install.md's existing re-pin paragraphs already do. Each of the four new files must hold at least one checked paragraph (a per-file count), and the existing floor of two stays. If an existing paragraph in a newly listed file trips the rule, it is a re-pin instruction that drops the identity: fix it in the same commit and record it. machine-identities.md is not added to the list (action 9).

The exact phrases verify commands 4 and 5 grep for (normalised whitespace):
- signer-install.md: `--any-installation`, `until this machine's clock reaches the last entry's time minus 300 s`, `recovery_installation_not_pinned` and `recovery_clock_ahead`;
- root-ceremony.md: `Record the installation id line` and `trust verify prints the same installation id line`;
- ceremony-transcript-template.md: `Installation ID (root sign's`;
- server-install.md: `init also saves the installation ID`;
- enroll-user.md: `your saved config pins no installation ID`;
- host-setup.md: `the installation ID your config pins`, `before you run keyroster directory rebind` and `not lowercase ASCII`;
- revoke.md: `another installation's bundle under your roots`;
- machine-identities.md: `on an automation host whose config has no user`.

**The format registry (wire-audit-01).** If `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md` exits 0, edit it in this PR: in `## Installation binding`, add one sentence as a new paragraph of its own after the section's last paragraph (the HostIssue/ProbeIssue/MachineIssue paragraph, which ends with `A new signed format adds a row here in the PR that adds it.` at 3da914f), never inside an existing paragraph, so that the registry check below finds no removed line: `` Since 03-14c, `keyroster audit verify --installation-id` checks the installation ID of the trust bundle in force (and refuses an installation-bound log without that flag or --any-installation), and the CLI checks every served bundle against the installation ID its config pins (serverclient.Trust). `` This plan allocates no leaf kind, message type, domain tag or refusal detail, so no table row changes and TestFormatRegistry is unaffected. If the registry is not on origin/main, record in the SUMMARY that the registry PR must carry that sentence, and that this plan allocates nothing. The registry's `Refusal detail names` section covers signer details only, so recover's `recovery_installation_not_pinned`, `recovery_installation_other` and `recovery_clock_ahead` get no row: they are CLI refusal names, unregistered by design, which the SUMMARY records.

**Pointer sentences.** Each anchor occurs exactly once on origin/main (checked again by this task's precondition). Insert each text exactly once, right after its anchor, inside the same line. Change nothing else in those files.
- **03-12-PLAN.md** and **03-13-PLAN.md.** Anchor: `See 03-14b-PLAN.md.)`. Insert: `` (Since 03-14c: `keyroster audit verify` needs `--installation-id`, or `--any-installation`, where the bundle in force names an installation, which the e2e helpers pass; keep TestVerifyInstallationBinding, TestVerifyLeafTimeBound, TestVerifyBoundValues, TestVerifyForgetKeysOnOtherKinds and TestExportKeysLowercase green, and give any new export key lowercase ASCII; see 03-14c-PLAN.md.)``.
- **03-15-PLAN.md**, three pointers:
  - Anchor `re-initialise the CLIs with the new root pins`. Insert: `` (since 03-14c with `keyroster init --force` and the full flag set, `--user` and `--admin-key` included; init then saves v4's new installation ID, which every later command requires; the v4 transcript records root sign's installation id line in its Installation ID line; see 03-14c-PLAN.md)``.
  - Anchor ``exports the log and runs `keyroster audit verify` with the new pins``. Insert: `` (since 03-14c with `--installation-id` set to v4's installation ID, here and in every automated audit verify command of this plan, because audit verify refuses an installation-bound log without it; see 03-14c-PLAN.md)``.
  - Anchor ``on the laptop the same with `~/.local/bin/keyroster init ...`.``. Insert: `` (Since 03-14c, add `--force`, `--user` and `--admin-key` to both commands: init refuses an existing config without --force, and --force replaces the whole config. Compare the installation id line init prints with the v4 transcript's Installation ID line; see 03-14c-PLAN.md.)``.
- **03-16-PLAN.md.** Anchor `(audit verify with the new pins)`. Insert: `` (since 03-14c with `--installation-id` set to the homelab's installation ID from the v4 transcript, which exercises the binding on the real deployment; see 03-14c-PLAN.md)``.
- **03-08c-SUMMARY.md (Q-C6 A).** Anchor `jq, Python and Go unescape keys and keep the last of repeated ones.` Append: ` (Since 03-14c: Go's encoding/json struct decoding matches keys without regard to case at every depth, not only the top-level key, the Kelvin sign and the long s included; audit verify refuses keys that are not lowercase ASCII; see 03-14c-PLAN.md.)`. Under Q-C6 B this pointer is not made, and verify command 6 runs with `Q6=B`.

03-14 gets no pointer: its Trust calls meet the new signature at compile time, and it adds no audit verify call or export key.

**Publish edits.** Make them in this PR, on top of origin/main. Every wave number is origin/main's value + 1. The totals (edits 2 and 3) are the true counts of the PLAN and SUMMARY files, which is what GSD's tracking update writes (03-14b's R2-1: the tracking update counts the files, and `state.advance-plan` bumps only the Plan line's leading number and keeps the `of M` it is given). Main's totals are consistent at 3da914f, so the true counts happen to equal main's + 1 this time. The values in brackets are what main holds at 3da914f. W12 is the `wave:` of origin/main's 03-12-PLAN.md [30].
0. **Stop guard, first.** Re-run Task 1's first precondition (03-14b's SUMMARY on main, origin/main's 03-12 at `wave: 30` with `depends_on: ["03-14b"]`, 03-14b the only plan at `wave: 29`). If it fails, main moved since the reconcile of 2026-11-11: stop and report for a re-reconcile, and make none of the edits below. This plan never takes over another plan's values silently.
1. Commit this plan as `.planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md`, unchanged: `wave: 30` and `depends_on: ["03-14b"]`.
2. ROADMAP.md, Phase 3:
   - The Plans line ([30/35 plans executed in 34 waves] → 30/36 plans executed in 35 waves). The total is the true count: phase 3 has 35 PLAN files on main, and this plan adds the 36th. The wave count goes up by one. GSD's tracking update at the end of this task rewrites only the counts, from the phase's PLAN and SUMMARY files: 31/36 plans executed in 35 waves. No tool touches the wave count.
   - The Progress table's Phase 3 row ([30/35] → 30/36, and 31/36 after the tracking update).
   - Insert, right before 03-12's wave block, the block `**Wave 30** *(blocked on Wave 29 completion)*` with the unchecked entry `- [ ] 03-14c-PLAN.md — Installation binding (F05, F06, F10): audit verify names and binds the installation, the CLI pins it at init, entries dated past the auditor's clock are refused in audit verify and recover, and export lines bind what JSON readers read`, followed by one blank line. The ROADMAP gate below builds exactly this row, ticked.
   - Renumber every later block one wave later ([30–34] → 31–35), each "blocked on" clause with them.
3. STATE.md, set by hand to the true counts:
   - `total_plans` ([70] → 71): every PLAN file under .planning/phases with this plan (21, 14 and 36).
   - `completed_plans` stays [65]: 65 SUMMARY files until this plan's SUMMARY lands.
   - The Plan line ([Plan: 30 of 35] → Plan: 30 of 36): 30 of phase 3's plans are executed, and the phase has 36 with this one.

   GSD's tracking update then writes, in this order (03-14b's R2-1, checked against the installed GSD tools):
   - `state.advance-plan` bumps only the Plan line's leading number, to `Plan: 31 of 36`, and keeps the `of 36` this edit wrote. Like every STATE write, it also resets `total_plans` and `completed_plans` from the files: 71 and 66.
   - `state.update-progress` writes the same 71 and 66 again.
   - `roadmap.update-plan-progress` writes 31/36 into the Plans line and the Progress row and ticks the 03-14c row.

   So main ends at `total_plans: 71`, `completed_plans: 66` and `Plan: 31 of 36`.
4. 03-12-PLAN.md:
   - `depends_on` becomes `["03-14c"]` [it reads `["03-14b"]`];
   - in its first `<precondition>` (a single line at 3da914f), add the clause `` `MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md` exits 0 `` right before that first `</precondition>`, joined with `; `. Every other clause stays as it is.
5. Every phase-3 plan whose origin/main `wave:` is W12 or above gets `wave:` + 1: 03-12 to 03-16 [30–34] → 31–35. The stop guard ensures no other plan is there.
6. The pointer sentences above.
7. The registry step above.
8. Nothing else in a landed plan or SUMMARY changes.

**After the tracking update** (the end of this task), check that GSD's roadmap update ticked only this plan's row: in Phase 3, every row other than the new 03-14c row is byte-identical to origin/main's, and the 03-12 to 03-16 rows are still `- [ ]`. An earlier tracking update ticked a plan by prefix (03-11b when 03-11 completed); here the prefix hazard is the 03-14 row. If another row was ticked, untick it with a scoped edit, record it in the SUMMARY, and rerun the ROADMAP gate below.

**Gates.** Run the test-time delta gate (Budget, Q-09-3) and the full gate. If this session or WSL boot is not the one that measured the base (after the continuation it never is), re-measure the base on origin/main in a detached worktree first, in place (Budget, "Another session"). `scripts/capslock-check.sh` is expected to report no new pair; a new pair is a deviation to review and record. 03-14b's run already showed keyroster-signer at 91 pairs against a baseline of 92 (`internal/signer CAPABILITY_RUNTIME` gone); unless a baseline-tightening PR has landed first, record that stale pair in the SUMMARY as pre-existing, not as this plan's.

**Push, the PR and the pre-merge review.**
1. Before the publish commit, scan this plan file for private terms: `grep -inE 'find[i]ngs|FIX[-]PLAN|security[-]audit[-]skill|scratch[p]ad|App[D]ata' .planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md` prints nothing (the pattern brackets one character of each term, so the file never holds the terms it looks for; the plain word for review results is covered too, since this plan holds it in no case, and the local pre-push scan, which matches case-sensitively on added lines, finds none either). Then commit by path only, signed and authored as Daniel:
   - the runbooks, the transcript template, the pinned e2e constant, the re-pin test's runbook list and the registry (`docs(runbooks): name and bind the installation in audit verify and the CLI's pin, and the clock bound (F05, F06, F10)`);
   - the publish edits and the pointers (`docs(03-14c): publish the plan, point 03-12, 03-13, 03-15 and 03-16 at it, correct the 03-08c SUMMARY, and shift the later waves`);
   - later, the SUMMARY.
2. Push the branch for the first time.
3. Run `scripts/gh-as-bot.sh pr create --title "fix(trust): bind audit verify and the CLI to one installation (F05, F06, F10)"`. The body is neutral, lists the changes as in the objective, and names the limits that remain:
   - an installation whose bundle names no installation ID has nothing to bind to (the homelab until 03-15);
   - `--any-installation` verifies without binding, by the auditor's choice, and still names the installation;
   - init takes the ID the server serves under the root pins; the user compares it with the record;
   - the clock bound is detective: an auditor with an honest clock detects a forward-dated KRL while the left-out certificate is still valid, and after that it looks like an honest republish;
   - hosts do not bound a KRL's issued_at (deferred).

   Do not enable auto-merge, now or later.
4. Wait for the required checks. Then run the house e2e gate in `MODE=pr` (the script between `# E2E_GATE_BEGIN` and `# E2E_GATE_END` of 03-10b-PLAN.md, with 03-11b's PROBE_PASS list, as 03-14b did): it requires the PR's e2e run to be for HEAD, both main lanes to pass at or under 900 s, and both probe lanes to pass. Confirm that both main lanes passed TestAuditVerifiesIssuance/binds_installation and TestRestoreRunbookChecks, and that cli-windows and cli-macos passed (verify below). Record each main lane's `go test` seconds in the SUMMARY: at 3da914f they ran about 769 s and 804 s, and the new subtest reuses TestAuditVerifiesIssuance's signer, so it adds no bootstrap.
5. The orchestrator then runs the pre-merge review on the green PR, before Task 5.
   - It reviews the diff against T-03-350 to T-03-356 (or the recorded renumbering), and that review is the owner's threat review.
   - A Codex lens may be part of it. Its input is `git diff origin/main...HEAD` and the PR's text only, never a ceremony folder, a passphrase file, `~/.ssh` or a planning file outside the repository.
   - It also checks the diff for host names and private terms, which this plan does not list.
   - Its review results, the fix rounds and their checks are recorded in the SUMMARY.

**The SUMMARY** contains:
- the PR number and the check run IDs;
- R1 to R3 and T1 to T3, with each RED and the cases that passed on R and why;
- the declarations each R commit added;
- every mutant under the mutant rule, with the origin/main results of the ten forget-key mutants;
- the `test-time base:` line (re-measured in place after each new session) and the delta gate's readings of cmd/keyroster, internal/audit and internal/serverclient (the whole-module run is pass or fail only);
- the main e2e lanes' seconds against the 900 s stop;
- the four golden additions, every moved setup and every moved caller's arguments, with why;
- the derived list of kinds that render policy_version (nine expected at 3da914f); the registry's presence and what was recorded there, and that the three recover refusal names are CLI names, unregistered by design;
- the totals after the tracking update: the Plans line `31/36 plans executed in 35 waves`, the Progress row `31/36`, `total_plans: 71`, `completed_plans: 66` and `Plan: 31 of 36`;
- the threat-ID check (and any renumbering);
- what stays UNVERIFIED:
  - every runbook text on a real host, and on the homelab until its bundle names an installation at 03-15;
  - the init-then-rebind sequence end to end;
  - the e2e cases locally (CI only);
  - how Go's struct decoding treats the Kelvin sign, if the control recorded otherwise;
  - the host-side KRL clock bound (deferred, Q-C5);
- capslock (with the pre-existing stale keyroster-signer pair, unless the baseline was tightened first), and the pre-merge review;
- `requirements-completed` left empty: AGENT-01 is complete and REVOKE-01 is 03-11b's (complete); this plan hardens both.

Then run the tracking updates once, commit `docs(03-14c): complete installation-binding plan`, push, and wait.
  </action>
  <verify>
    <automated>git diff --quiet HEAD -- docs/runbooks/ docs/format-registry.md test/e2e/restore_test.go cmd/keyroster/init_test.go .planning/ROADMAP.md .planning/STATE.md .planning/phases/03-linux-agent-and-revocation/ && test -z "$(git ls-files --others --exclude-standard .planning/phases/03-linux-agent-and-revocation/03-14c-*.md)"</automated>
    <fails_when>non-zero exit: an edit to a file this plan publishes is not committed, so the content checks below would read the working tree instead of the commit. This guard runs first. It is path-scoped, because the intentionally dirty .planning files would fail a bare `git status --porcelain`</fails_when>
    <automated>( set -o pipefail; S=.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md; { test "$(grep -c '^test-time base: ' $S)" -eq 1 && T=$(sed -n 's/^test-time base: .* at=\([0-9][0-9]*\)$/\1/p' $S) && test -n "$T" && test $(( $(date +%s) - T )) -le 86400 || { echo 're-measure the base (Budget, test time)'; false; }; } && g() { sed -n "s/^test-time base: \(.* \)\{0,1\}$1=\([0-9.]*\) .*/\2/p" $S; } && CM=$(g cmd) && AU=$(g audit) && SC=$(g serverclient) && test -n "$CM" && test -n "$AU" && test -n "$SC" && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/audit/ ./internal/serverclient/' | awk -v m="$CM" -v a="$AU" -v c="$SC" '{print} $1=="ok" {t=$3; sub(/s$/,"",t); if ($2 ~ /\/cmd\/keyroster$/) {n++; if (t+0 > m+90) bad=1} else if ($2 ~ /\/internal\/audit$/) {n++; if (t+0 > a+90) bad=1} else if ($2 ~ /\/internal\/serverclient$/) {n++; if (t+0 > c+90) bad=1}} END{exit (n!=3||bad)}' )</automated>
    <fails_when>non-zero exit: the SUMMARY's single `test-time base:` line is missing, repeated or more than 24 h old (re-measure it in place, Budget; after a continuation, re-measure it anyway), or the `ok` line of cmd/keyroster, internal/audit or internal/serverclient is missing or more than 90 s above its base (stop and report, after a fresh re-measure confirms it), or "FAIL" or "DATA RACE" in the output (Q-09-3)</fails_when>
    <automated>grep -q -- '--exec' scripts/linux.sh && bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./... && go vet ./... && go vet -tags keyroster_e2e ./internal/agent/... ./cmd/keyroster-agent/ && go vet -tags e2e ./test/e2e/ && go vet -tags "e2e e2eprobe" ./test/e2e/ && go vet -tags "e2e e2emachine" ./test/e2e/ && go vet -tags "e2e e2eprobe e2emachine" ./test/e2e/ && go vet -tags "e2e systemdsmoke" ./test/e2e/ && go vet -tags e2e_pkcs11 ./test/e2e/ && go vet -tags e2e_tpm ./test/e2e/ && go vet -tags e2edistro ./test/distro/ && test -z "$(gofmt -l .)" && $HOME/go/bin/golangci-lint run ./... && bash scripts/capslock-check.sh && bash scripts/dep-firewall.sh && bash scripts/testonly-firewall.sh && bash scripts/check-pinned-actions.sh'</automated>
    <fails_when>non-zero exit (a gate failed; the whole-module test run is pass or fail only, with no per-package time cap, Q-09-3), or "FAIL", "DATA RACE" or a golangci-lint issue line in the output. The vet tag list is the house list at 3da914f (03-14b's full gate) plus `e2e_pkcs11` and `e2e_tpm`, the tags of the required e2e-pkcs11 and e2e-tpm lanes, whose files this plan edits</fails_when>
    <automated>n(){ tr -s '[:space:]' ' ' < "$1"; } && C=$(grep -hE '^[[:space:]]*keyroster audit verify --pin' docs/runbooks/*.md) && test "$(printf '%s\n' "$C" | grep -c .)" -ge 10 && test "$(printf '%s\n' "$C" | grep -vc -- '--installation-id <installation id>')" -eq 0 && ( for f in signer-install host-setup revoke enroll-user server-install; do n docs/runbooks/$f.md | grep -qF 'keyroster init --force --server <URL>' || { echo "no literal re-pin command: $f"; exit 1; }; done ) && test "$(grep -c -- '--installation-id <installation id>' test/e2e/restore_test.go)" -ge 1 && n docs/runbooks/ceremony-transcript-template.md | grep -qF "Installation ID (root sign's" && test "$(n docs/runbooks/host-setup.md | grep -c 'so the parser lists exactly the verified')" -eq 0 && O=$(bash scripts/linux.sh 'go test -count=1 -timeout 15m -v -run "^(TestRootCeremonyPolicyChecks|TestSectionWindowRefusals|TestRepinInstructionsKeepIdentity|TestHostTrustRunbooks|TestProbeAccountRunbook)$" ./cmd/keyroster/ && go test -count=1 -timeout 15m -v -run "^TestProbeHoldReasonsDocumented$" ./internal/agent/apply/') && for t in TestRootCeremonyPolicyChecks TestSectionWindowRefusals TestRepinInstructionsKeepIdentity TestHostTrustRunbooks TestProbeAccountRunbook TestProbeHoldReasonsDocumented; do printf '%s\n' "$O" | grep -qF -- "--- PASS: $t (" || { echo "no PASS: $t"; exit 1; }; done</automated>
    <fails_when>non-zero exit: fewer than ten runbook audit verify command lines were found, or one lacks `--installation-id <installation id>` (prose such as signer-install.md's `The check that holds is` sentence is not a command line and is not counted); a runbook that gains a re-pin remedy lacks the literal command; the pinned e2e line was not updated, the transcript has no Installation ID line, host-setup.md still holds the parser sentence this plan corrects, or one of the runbook tests that read the edited runbooks fails: 03-14b's TestRootCeremonyPolicyChecks and TestSectionWindowRefusals (sectionWindow), the re-pin rule, TestHostTrustRunbooks, TestProbeAccountRunbook or internal/agent/apply's TestProbeHoldReasonsDocumented</fails_when>
    <automated>lab(){ awk -v p="$2" 'BEGIN{RS=""} {s=$0; gsub(/[[:space:]]+/," ",s); if (index(s,p)) {f=1; if (index(s,"Run in CI") && index(s,"UNVERIFIED")) ok=1}} END{exit !(f && ok)}' "$1" || { echo "missing or unlabelled: $1: $2"; return 1; }; } && R=docs/runbooks && lab $R/signer-install.md '--any-installation' && lab $R/signer-install.md "until this machine's clock reaches the last entry's time minus 300 s" && lab $R/signer-install.md 'recovery_installation_not_pinned' && lab $R/signer-install.md 'recovery_clock_ahead' && lab $R/root-ceremony.md 'Record the installation id line' && lab $R/root-ceremony.md 'trust verify prints the same installation id line' && lab $R/server-install.md 'init also saves the installation ID' && lab $R/enroll-user.md 'your saved config pins no installation ID' && lab $R/host-setup.md 'the installation ID your config pins' && lab $R/host-setup.md 'before you run keyroster directory rebind' && lab $R/host-setup.md 'not lowercase ASCII' && lab $R/revoke.md "another installation's bundle under your roots" && lab $R/machine-identities.md 'on an automation host whose config has no user' && tr -s '[:space:]' ' ' < $R/machine-identities.md | grep -qF 'keyroster init --force --server <URL> --tls-pin <pin> --root-pin <fp> [--root-pin ...] --threshold <n>' && ! awk '/^## Renewal needs pop[.]machines/{f=1;next} /^## /{f=0} f' $R/machine-identities.md | tr -s '[:space:]' ' ' | grep -qF 'automation host whose config has no user' && if MSYS_NO_PATHCONV=1 git cat-file -e origin/main:docs/format-registry.md 2>/dev/null; then tr -s '[:space:]' ' ' < docs/format-registry.md | grep -qF 'Since 03-14c, `keyroster audit verify --installation-id` checks' && test "$(git diff --numstat origin/main...HEAD -- docs/format-registry.md | awk '{print $2}')" = "0"; else test -z "$(git diff --name-only origin/main...HEAD -- docs/format-registry.md)"; fi</automated>
    <fails_when>non-zero exit: a new runbook text is missing, or its paragraph lacks a `Run in CI` or an UNVERIFIED label; machine-identities.md lacks the automation-host re-pin command, or holds the new paragraph inside `## Renewal needs pop.machines`; or the registry is on origin/main and lacks the 03-14c sentence or lost a line, or it is not on origin/main and this branch added it</fails_when>
    <automated>Q6=${Q6:-A} && P=.planning/phases/03-linux-agent-and-revocation && ns(){ N=$(git diff --numstat origin/main...HEAD -- "$P/$1") || return 1; printf '%s\n' "$N" | awk 'NF{print $1" "$2}'; } && test "$(ns 03-12-PLAN.md)" = "4 4" && test "$(ns 03-13-PLAN.md)" = "2 2" && test "$(ns 03-14-PLAN.md)" = "1 1" && test "$(ns 03-15-PLAN.md)" = "4 4" && test "$(ns 03-16-PLAN.md)" = "2 2" && test "$(grep -oF 'see 03-14c-PLAN.md.)' $P/03-12-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'see 03-14c-PLAN.md.)' $P/03-13-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'see 03-14c-PLAN.md)' $P/03-15-PLAN.md | wc -l)" -eq 2 && test "$(grep -oF 'see 03-14c-PLAN.md.)' $P/03-15-PLAN.md | wc -l)" -eq 1 && test "$(grep -oF 'see 03-14c-PLAN.md)' $P/03-16-PLAN.md | wc -l)" -eq 1 && grep -qF 'See 03-14b-PLAN.md.) (Since 03-14c:' $P/03-12-PLAN.md && grep -qF 'See 03-14b-PLAN.md.) (Since 03-14c:' $P/03-13-PLAN.md && grep -qF 're-initialise the CLIs with the new root pins (since 03-14c' $P/03-15-PLAN.md && grep -qF 'exports the log and runs `keyroster audit verify` with the new pins (since 03-14c' $P/03-15-PLAN.md && grep -qF 'on the laptop the same with `~/.local/bin/keyroster init ...`. (Since 03-14c' $P/03-15-PLAN.md && grep -qF '(audit verify with the new pins) (since 03-14c' $P/03-16-PLAN.md && if [ "$Q6" = A ]; then test "$(ns 03-08c-SUMMARY.md)" = "1 1" && test "$(grep -oF 'see 03-14c-PLAN.md.)' $P/03-08c-SUMMARY.md | wc -l)" -eq 1 && grep -qF 'keep the last of repeated ones. (Since 03-14c:' $P/03-08c-SUMMARY.md && OK='/03-(08c|14c)-SUMMARY\.md$'; else test -z "$(ns 03-08c-SUMMARY.md)" && OK='/03-14c-SUMMARY\.md$'; fi && test -z "$(git diff --name-only origin/main...HEAD -- $P/ | grep -E 'SUMMARY\.md$' | grep -vE "$OK")"</automated>
    <fails_when>non-zero exit: a later plan or the 03-08c SUMMARY changed beyond its wave line and its pointer lines (expected: 03-12 4 4 for the wave, depends_on, precondition and pointer lines; 03-13 2 2; 03-14 1 1; 03-15 4 4; 03-16 2 2; the 03-08c SUMMARY 1 1 under Q-C6 A, unchanged under B), a pointer is missing, repeated or not right after its anchor, or another landed SUMMARY changed. The stop guard ensures no other plan is shifted</fails_when>
    <automated>P=.planning/phases/03-linux-agent-and-revocation && fw() { awk 'NR>1 && /^---$/{exit} /^wave: /{sub(/^wave: /,""); print}'; } && MSYS_NO_PATHCONV=1 git cat-file -e "origin/main:$P/03-14b-SUMMARY.md" && X12=$(MSYS_NO_PATHCONV=1 git show "origin/main:$P/03-12-PLAN.md") && test "$(printf '%s\n' "$X12" | fw)" = 30 && printf '%s\n' "$X12" | grep -qx 'depends_on: \["03-14b"\]' && W29=$(for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do if [ "$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw)" = 29 ]; then basename "$f"; fi; done) && test "$W29" = 03-14b-PLAN.md && test "$(fw < $P/03-14c-PLAN.md)" = 30 && grep -qx 'depends_on: \["03-14b"\]' $P/03-14c-PLAN.md && grep -qx 'depends_on: \["03-14c"\]' $P/03-12-PLAN.md && grep -n '<precondition>' $P/03-12-PLAN.md | head -1 | grep -qF '`MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md` exits 0</precondition>' && ( for e in 03-12:31 03-13:32 03-14:33 03-15:34 03-16:35; do test "$(fw < "$P/${e%%:*}-PLAN.md")" = "${e#*:}" || exit 1; done ) && ( for f in $(git ls-tree --name-only origin/main -- "$P/" | grep -E '/03-[0-9a-z]+-PLAN\.md$'); do W=$(MSYS_NO_PATHCONV=1 git show "origin/main:$f" | fw) || exit 1; test -n "$W" || exit 1; if [ "$W" -ge 30 ]; then E=$((W+1)); else E=$W; fi; test "$(fw < "$f")" = "$E" || exit 1; done ) && AP='^\.planning/phases/[^/]+/[^/]+-PLAN\.md$' && AS='^\.planning/phases/[^/]+/[^/]+-SUMMARY\.md$' && PP='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-PLAN\.md$' && PS='^\.planning/phases/03-linux-agent-and-revocation/03-[0-9a-z]+-SUMMARY\.md$' && n() { git ls-tree -r --name-only "$1" -- .planning/phases/ | grep -cE "$2"; } && ( for r in "$AP" "$AS" "$PP" "$PS"; do H=$(n HEAD "$r") && M=$(n origin/main "$r") && test "$H" -eq $((M+1)) || exit 1; done ) && ST=$(MSYS_NO_PATHCONV=1 git show origin/main:.planning/STATE.md) && printf '%s\n' "$ST" | grep -qx '  total_plans: 70' && printf '%s\n' "$ST" | grep -qx '  completed_plans: 65' && printf '%s\n' "$ST" | grep -qx 'Plan: 30 of 35' && test "$(grep -c '^  total_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  total_plans: $(n HEAD "$AP")" .planning/STATE.md && test "$(grep -c '^  completed_plans: ' .planning/STATE.md)" -eq 1 && grep -qx "  completed_plans: $(n HEAD "$AS")" .planning/STATE.md && test "$(grep -c '^Plan: ' .planning/STATE.md)" -eq 1 && grep -qx "Plan: $(n HEAD "$PS") of $(n HEAD "$PP")" .planning/STATE.md</automated>
    <fails_when>non-zero exit: the stop guard fails on origin/main (03-14b's SUMMARY missing, 03-12 not at wave 30 with ["03-14b"], or a plan other than 03-14b at wave 29: re-reconcile, publish nothing), or a publish edit is missing or wrong. It passes only on exactly the intended edit:
      - this plan's frontmatter reads `wave: 30` and `depends_on: ["03-14b"]`;
      - 03-12 reads `depends_on: ["03-14c"]`, and its first precondition ends with the new MSYS_NO_PATHCONV=1 clause;
      - 03-12 to 03-16 read waves 31 to 35; every other phase-3 plan on origin/main kept its frontmatter wave (each wave is read from the frontmatter only);
      - HEAD holds exactly one more PLAN file and one more SUMMARY file than origin/main, both in phase 3 (counted in the tree of HEAD, top-level phase directories only);
      - origin/main's STATE held the 3da914f values `total_plans: 70`, `completed_plans: 65` and `Plan: 30 of 35`, and the branch's STATE holds exactly one line of each, with the true counts of HEAD's files: `total_plans: 71`, `completed_plans: 66` and `Plan: 31 of 36` (phase 3's SUMMARY files of its PLAN files).

      The gate counts files in HEAD's tree, and GSD's tracking update counts them on disk. An untracked PLAN or SUMMARY file under .planning/phases therefore shows up as a mismatch, which is right: that number would be wrong on main. Run it after the tracking update; before that update `completed_plans` reads 65 and the Plan line 30 of 36, and the gate fails by design
    </fails_when>
    <automated>ROW="- [x] 03-14c-PLAN.md — Installation binding (F05, F06, F10): audit verify names and binds the installation, the CLI pins it at init, entries dated past the auditor's clock are refused in audit verify and recover, and export lines bind what JSON readers read" && E=$(mktemp) && { MSYS_NO_PATHCONV=1 git show origin/main:.planning/ROADMAP.md | awk -v row="$ROW" '/^### Phase /{p=($0 ~ /^### Phase 3:/)} p && /^\*\*Plans:\*\* 30\/35 plans executed in 34 waves\./ {sub(/30\/35 plans executed in 34 waves/, "31/36 plans executed in 35 waves"); np++} p && /^\*\*Wave [0-9]+\*\* \*\(blocked on Wave [0-9]+ completion\)\*$/ {w=$0; sub(/^\*\*Wave /,"",w); sub(/\*\*.*$/,"",w); w+=0; if (w==30) {print "**Wave 30** *(blocked on Wave 29 completion)*"; print row; print ""; ni++} if (w>=30) {$0="**Wave " (w+1) "** *(blocked on Wave " w " completion)*"; nw++}} /^\| 3\. Linux Agent and Revocation \| 30\/35 \|/ {sub(/\| 30\/35 \|/, "| 31/36 |"); nr++} {print} END{exit (np!=1 || ni!=1 || nw!=5 || nr!=1)}' > "$E"; } && diff "$E" .planning/ROADMAP.md; rc=$?; rm -f "$E"; test "$rc" -eq 0</automated>
    <fails_when>non-zero exit: the ROADMAP differs from the exact intended file. The gate builds it from origin/main's ROADMAP (which must hold the 3da914f base: the Phase 3 Plans line `30/35 plans executed in 34 waves`, Wave blocks 30 to 34, and the Progress row `30/35`), and compares whole files:
      - the Plans line reads `31/36 plans executed in 35 waves`, and the Progress row `| 31/36 |`: the true counts of phase 3's SUMMARY and PLAN files, which the publish gate checks against HEAD's tree, with the wave count 35 that no tool touches;
      - a new `**Wave 30** *(blocked on Wave 29 completion)*` block holds exactly the ticked 03-14c row (publish edit 2's row with `- [x]` for `- [ ]`), followed by one blank line, right before 03-12's block;
      - the former blocks 30 to 34 read 31 to 35, each blocked on the wave before;
      - every other line is byte-identical, so no other row was ticked (the 03-12 to 03-16 rows stay `- [ ]`, the 03-14 row included) and nothing matched by prefix.

      Run it after the tracking update, which ticks the 03-14c row and sets the executed count; before that update the row reads `- [ ]` and the count 30, and the gate fails by design</fails_when>
    <automated>G=$(git log origin/main..HEAD --format='%an <%ae> %cn') && test -n "$G" && test -z "$(printf '%s\n' "$G" | grep -Fvx 'Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot')" && RL=$(git rev-list origin/main..HEAD) && test -n "$RL" && ( for c in $RL; do C=$(git cat-file commit "$c") || exit 1; printf '%s\n' "$C" | grep -q '^gpgsig' || exit 1; done )</automated>
    <fails_when>non-zero exit (the branch has no commits, a commit has another author or a committer other than keyroster-bot, or a commit is unsigned)</fails_when>
    <automated>git fetch origin p03/14c-installation-binding && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md && MSYS_NO_PATHCONV=1 git cat-file -e FETCH_HEAD:.planning/phases/03-linux-agent-and-revocation/03-14c-PLAN.md && test "$(git rev-parse FETCH_HEAD)" = "$(git rev-parse HEAD)" && D=$(git diff --name-only origin/main...HEAD) && ! printf '%s\n' "$D" | grep -qE '^\.planning/(config\.json|milestone\.lock|state\.json)$|\.review-diagnostics|^\.planning/todos/'</automated>
    <fails_when>non-zero exit (the SUMMARY or the plan is not on the pushed branch, local commits are unpushed, a forbidden file was committed, or a todo file was added)</fails_when>
    <automated>D=$(git diff origin/main...HEAD) && L=$(git log origin/main..HEAD --format=%B) && B=$(scripts/gh-as-bot.sh pr view p03/14c-installation-binding --json body,title --jq '.title + "\n" + .body') && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -vE '127\.0\.0\.1' | grep -q . && printf '%s\n%s\n' "$L" "$B" | grep -ciE 'co-authored-by|generated with' | grep -qx 0 && ! printf '%s\n%s\n%s\n' "$D" "$L" "$B" | grep -iqE 'find[i]ngs[.]json|FIND[I]NGS[-]DETAIL|FIX[-]PLAN|security[-]audit[-]skill|scratch[p]ad|App[D]ata' && PR_TITLE="$(scripts/gh-as-bot.sh pr view p03/14c-installation-binding --json title --jq .title)" bash scripts/check-pr-title.sh</automated>
    <fails_when>non-zero exit: an IP address other than loopback is in the diff, a commit message or the PR title or body; an attribution line is present; a private planning artefact or a local temporary path is named; or the PR title is not Conventional Commits within 100 characters</fails_when>
    <automated>B=p03/14c-installation-binding && scripts/gh-as-bot.sh pr checks "$B" --required --watch && test "$(scripts/gh-as-bot.sh pr checks "$B" --json name,bucket --jq '[.[] | select(.name=="cli-windows" or .name=="cli-macos") | .bucket] | sort | join(" ")')" = "pass pass" && G=$(mktemp) && sed -n '/^# E2E_GATE_BEGIN/,/^# E2E_GATE_END/p' .planning/phases/03-linux-agent-and-revocation/03-10b-PLAN.md > "$G" && B="$B" PROBE_PASS='TestProbeSelfTestEndToEnd TestProbePairSpacing TestProbeCertsAgainstSSHD TestProbeSSHDFacts TestMachineIdentityEndToEnd TestMachineIdentityEndToEnd/renew_and_login TestMachineIdentityEndToEnd/collapse_is_generic TestMachineIdentityEndToEnd/if_due_sends_nothing TestMachineIdentityEndToEnd/revoke_machine_refuses_login_and_renewal TestMachineIdentityEndToEnd/keys_revokes_key_for_good TestMachineIdentityEndToEnd/sk_through_agent TestMachineIdentityEndToEnd/sk_key_file_named_error TestMachineIdentityEndToEnd/audit_verify_counts_machine_certificates' MODE=pr bash "$G"; rc=$?; rm -f "$G"; test "$rc" -eq 0 && R=$(scripts/gh-as-bot.sh run list --workflow e2e.yml --branch "$B" --event pull_request --limit 1 --json databaseId --jq '.[0].databaseId // 0') && test "$R" -gt 0 && test "$(scripts/gh-as-bot.sh run view "$R" --json headSha --jq .headSha)" = "$(git rev-parse HEAD)" && JOBS=$(scripts/gh-as-bot.sh run view "$R" --json jobs --jq '.jobs[] | [(.databaseId|tostring), .conclusion, .name] | join("\t")') && for L in 9.5p1 10.5p1; do ID=$(printf '%s\n' "$JOBS" | awk -F'\t' -v n="e2e ($L)" '$3 == n {print $1}'); test -n "$ID" || { echo "no main lane $L"; exit 1; }; LOG=$(scripts/gh-as-bot.sh run view "$R" --job "$ID" --log); for t in TestAuditVerifiesIssuance/binds_installation TestRestoreRunbookChecks; do printf '%s\n' "$LOG" | grep -qF -- "--- PASS: $t (" || { echo "main lane $L: no PASS line of $t"; exit 1; }; done; done</automated>
    <fails_when>non-zero exit: a required check failed or never reported; cli-windows or cli-macos did not pass; the house e2e gate in MODE=pr failed (the PR's pull_request e2e run is not for HEAD, a main lane failed, ran a probe test or took over 900 s, or a probe lane failed, lacks one of 03-11b's PASS lines or took over 420 s); or a main lane (9.5p1 or 10.5p1) lacks the `--- PASS: TestAuditVerifiesIssuance/binds_installation (` or `--- PASS: TestRestoreRunbookChecks (` line. `B` is passed to the gate script as a prefix assignment because the script reads it from its environment</fails_when>
    <automated>test "$(scripts/gh-as-bot.sh pr view p03/14c-installation-binding --json autoMergeRequest --jq '.autoMergeRequest == null')" = true</automated>
    <fails_when>non-zero exit (auto-merge is enabled on the PR)</fails_when>
  </verify>
  <acceptance_criteria>
    - Every new runbook prose text names at least one CI test and an UNVERIFIED label (verify command 5), and every runbook audit verify command passes `--installation-id`.
    - `git log origin/main..HEAD --format='%an <%ae> %cn'` prints at least one line, every line is `Daniel Gustafsson <121555671+Labontese@users.noreply.github.com> keyroster-bot`, and every commit carries a signature.
    - The PR is open without auto-merge, every required check is green, cli-windows and cli-macos passed, the house e2e gate passed in MODE=pr for HEAD with both main lanes at or under 900 s, both main lanes passed TestAuditVerifiesIssuance/binds_installation and TestRestoreRunbookChecks, and 03-14c-SUMMARY.md is on its head.
    - The test-time delta gate passed against a base at most 24 h old, and the publish and ROADMAP gates passed after the tracking update.
    - The pre-merge review's results and fix rounds are in the SUMMARY.
  </acceptance_criteria>
  <done>The PR waits green and reviewed. It carries the plan, the runbook updates, the transcript line, the registry sentence (or its SUMMARY record), the pointers in 03-12, 03-13, 03-15, 03-16 and the 03-08c SUMMARY, and the publish edits: this plan at wave 30 after 03-14b, and 03-12 to 03-16 one wave later (31 to 35).</done>
</task>

<task type="checkpoint:human-action" gate="blocking-human">
  <name>Task 5: Merge gate — the owner reviews PR p03/14c-installation-binding, and Daniel squash-merges it into main</name>
  <read_first>
    - .planning/phases/01-trust-core/01-SKELETON.md "Delivery Protocol" (steps 5-7), read with this plan's Delivery protocol override (merge-gate.sh's plain form only after the merge)
  </read_first>
  <action>After the pre-merge review (Task 4 step 5), the owner reviews, approves and squash-merges the PR in the GitHub web UI (owner, 2026-11-02). Claude never approves or merges, never enables auto-merge and never waits for it.</action>
  <instructions>
    1. Open `gh pr view p03/14c-installation-binding --web`. Read 03-14c-SUMMARY.md, and review:
       - the installation check at the end of audit.Verify, the leaf-time bound in its loop, and the unbound refusal in runAuditVerify;
       - CheckInstallationPin, ErrInstallationNotPinned's re-pin form and Trust's new parameter in internal/serverclient/client.go;
       - recover's step 4 and its two refusals, and its Now;
       - checkLineKeys' two new checks;
       - the four golden additions, the runbook texts and the transcript line.

       Check especially:
       - TrustUnpinned's only caller is init;
       - recover still refuses `recovery_installation_lost` before the pin check;
       - every runbook audit verify command passes `--installation-id`;
       - no trust bundle field, leaf format or root sign output changed.
    2. Approve and squash-merge in the GitHub web UI, with your commit email. No admin bypass, no "Update branch".
    3. Reply "merged". If main moved before you merged, Claude rebases the branch by hand and pushes it. Review the new head, then merge it and reply "merged".
  </instructions>
  <verification>
    - **Before the merge.** Claude runs merge-gate.sh only as `bash scripts/merge-gate.sh --check p03/14c-installation-binding`, which is read-only and exits 1 while the PR is open. It never runs the plain form before the merge.
    - **When main moved.** If `git merge-base --is-ancestor origin/main origin/p03/14c-installation-binding` fails after `git fetch origin`, Claude rebases by hand:
      - On the branch, run `git rebase --gpg-sign origin/main`. The authors stay Daniel's, and keyroster-bot is committer and signer.
      - For `.planning/` tracking files, take origin/main's version and re-apply only this plan's entries, as 01-SKELETON step 5's exit 4 describes. For the runbooks, keep main's text and re-apply this plan's updates.
      - If main added a Trust call site, an audit verify call, an audit leaf kind or an export key, extend this plan's code to it, run Tasks 1 to 3's verify commands again, and record it.
      - If main changed what trust verify prints, regenerate the goldens with `-update-golden`. `diff old new` may then show no removed line except lines that main's change names. Record it.
      - Re-run Task 4's checks against the new origin/main: the anchor check, the runbook and label checks (with the registry), the numstat and pointer check, the publish gate and the ROADMAP gate. Record their readings.
      - If the stop guard (Task 1's precondition 1) or the pinned 3da914f base of the publish and ROADMAP gates (STATE `total_plans: 70`, `completed_plans: 65`, `Plan: 30 of 35`; ROADMAP `30/35 plans executed in 34 waves`) no longer holds on the new origin/main, another plan landed or moved: stop and report for a re-reconcile instead of re-applying the publish edits.
      - Push with lease, as keyroster-bot, and do not enable auto-merge.
      - Wait for the required checks, run Task 4's authorship and signature check again, and ask the owner to review the new head.
    - **After the owner replies "merged".** From the main checkout, Claude runs `bash scripts/merge-gate.sh p03/14c-installation-binding`; the script refuses to run as any copy but origin/main's. For a merged PR it only fast-forwards local main and exits 0. Then Claude runs the `--check` form below.
  </verification>
  <verify>
    <automated>bash scripts/merge-gate.sh --check p03/14c-installation-binding</automated>
    <fails_when>non-zero exit (the PR is not merged, or local main differs from origin/main)</fails_when>
    <automated>MSYS_NO_PATHCONV=1 git cat-file -e origin/main:.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md</automated>
    <fails_when>non-zero exit (the SUMMARY did not reach main, which 03-12's and 03-14d's preconditions check)</fails_when>
  </verify>
  <acceptance_criteria>
    - `scripts/gh-as-bot.sh pr view p03/14c-installation-binding --json state --jq .state` prints `MERGED`.
  </acceptance_criteria>
  <done>On main, audit verify names and binds the installation, the CLI is pinned to one, recover applies the same pin, and entries dated past the auditor's clock are refused. 03-14d may start.</done>
  <resume-signal>Type "merged" after squash-merging the PR in GitHub</resume-signal>
</task>

</tasks>

## Cross-plan notes

- **03-09, 03-09b, 03-10, 03-10b, 03-10c, 03-10d, 03-11 and 03-11b** landed (#88 to #97).
  - They added two Trust call sites: knownhosts.go (03-09b's `keyroster known-hosts sync`) and machinerenew.go (03-11b's `keyroster machine renew`). `revoke host` and `revoke machine` go through openRevocation (revoke.go). Trust's new signature makes the build list each one, Task 2 passes the pin there, and TestInstallationPinned's `known_hosts_sync_refused` and `machine_renew_refused` prove both refuse another installation's bundle before they write or send.
  - They added the leaf kinds host_issue, probe_issue and machine_issue, whose decoders are in internal/audit/export.go (their checks are in hostissue.go, probeissue.go and machineissue.go), and checkForgetFields binds those three kinds' lines byte for byte. Task 3 derives the kinds that render `policy_version` from every decoder in internal/audit at execution, and TestExportKeysLowercase walks every non-test file there, so their honest lines stay verifiable and their keys are checked.
  - cmd/keyroster/audit_test.go exists on main with TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine, unit tests of printVerifyOK and verifyResultOf that run no export and move no arguments; Task 1 extends the file, and the three stay green unchanged. A later test there that runs audit verify on an export passes `--installation-id` (Q-C7), and its export must not be dated more than 300 s ahead (Task 3's clock); a test that needs that sets auditClock.
  - The waves these plans added are on main; the stop guard (Task 1's precondition 1) pins the slot at wave 30.
  - D5 for ProbeIssueRequest and MachineIssueRequest reaches 03-10 and 03-11 only through 03-09's Cross-plan notes. 03-14d's Task 1 precondition is the backstop; raising a D5 pointer in 03-10 and 03-11 belongs to 03-09's or their own plan checks.
- **03-14b** landed right before this plan (#98, 3da914f; Q-C1 A). This plan:
  - adds one line to four of its goldens, by its additions-only rule;
  - extends checkInvariants by one rule;
  - changes no root_sign golden, nothing in rootceremony.Summary, and no policy diff line;
  - keeps TestCeremonyGolden, TestPolicyFieldsCovered, TestSummaryFieldsCovered and TestRootCeremonyPolicyChecks green.

  03-14b's publish guard did not fire, because this plan was not on main when 03-14b was published.
- **03-14d** (F15, Q-C9) lands right after this plan and before 03-12, with its own guard; it moves 03-12's depends_on from this plan to itself. It edits signer-install.md section 8 and the registry's tag table, which this plan does not touch. The placeholder ` --installation-id <installation id>` that this plan adds to signer-install.md's audit verify commands is the same text as 03-14d's ca issue example, so 03-14d's runbook check anchors on the ca issue command line.
- **03-12** (CA rotation) runs after 03-14d. Its pointer sentence names the audit verify flag and the tests to keep green. Its e2e audit verify calls go through the helpers, which pass a flag. Its Bundle reflect gate's InstallationID entry can point at installationLine, which root sign and trust verify both print after the summary since this plan; Summary itself still prints no installation line.
- **03-13** (log and ops key rotation) edits internal/audit/verify.go and revoke.go, and adds e2e log exports. Its pointer sentence names the same duties. Under a log-key rotation the installation ID still carries unchanged, so F05's check is unaffected; its new leaf kinds, if any, follow the 03-09 note above.
- **03-14** (break-glass) edits cmd/keyroster/host.go; its Trust calls pass the pin, which the build enforces. It adds no audit verify call.
- **03-15.** Three pointer sentences:
  - its re-init after the v4 install runs `keyroster init --force` with the full flag set, and init saves v4's new installation ID;
  - its audit verify commands, the automated ones in Tasks 4 and 5 included (03-15-PLAN.md Task 4's and Task 5's export-and-verify commands), pass `--installation-id` with v4's ID;
  - the v4 transcript records root sign's installation id line in the template's new Installation ID line (the first pointer says so).

  A CLI not re-initialised refuses on the new roots as before, and on the pin.
- **03-16** runs audit verify on the homelab after v4; its pointer makes it pass `--installation-id`, which exercises T-03-350 on the real deployment.
- **Later plans:**
  - a plan that adds a decoded export key outside `[a-z0-9_]`, or a data-derived map key, fails TestExportKeysLowercase;
  - a plan that adds an audit.Options literal in cmd/ sets Now, as audit verify and recover do (Q-C4 B), or records why not;
  - a plan that adds a runbook audit verify command passes `--installation-id` (verify command 4 of Task 4 shows the rule).
- **Threat IDs of siblings.** 03-09's note to 03-09b says that if 03-09b needs more IDs than T-03-345 to T-03-349, it continues after 03-14c's last ID. With 03-14d holding T-03-359 to T-03-362, that is after T-03-362. This plan cannot edit 03-09's text; the row-anchored ID checks of this plan and 03-14d keep a mere mention from forcing a renumbering.
- **Phase 4.** Checkpoint witnesses can close F10's residual window (an auditor whose clock is after the forward date); the deferred host-side issued_at bound (Q-C5) is revisited there.

## Edge Coverage (spec-less fallback, this plan)

**Flagged assumption: what binds, and what does not.**
- **An installation without an ID** (pre-D-04; the homelab until 03-15): nothing can be bound. The CLI's pin is empty and passes an ID-less bundle. audit verify needs no flag there and prints `none`; `--installation-id` there is refused.
- **Shared roots.** Not the case (owner). If two installations ever shared a root set: audit verify refuses the other one's log unless the auditor passes `--any-installation`, and names its ID either way; the CLI refuses it once pinned; init, which has no pin yet, takes the ID of the bundle the server serves, so the transcript comparison is the safeguard.
- **The clock bound.** An auditor with an honest clock detects a forward-dated KRL for the whole time the left-out certificate is still valid (the allowance equals krl.PruneMargin). Once the auditor's clock is within 300 s of the forward date, the entry passes and looks like an honest republish. Now 0 (library callers) bounds nothing. A signer whose clock ran ahead gets its log refused until the verifier's clock reaches the last entry's time minus 300 s, whatever its own clock says afterwards; a restore stalls about as long under either answer of Q-C4 (restore step 2's audit verify sets Now under both, and the recovery KRL version is time-derived); B can add up to one republish interval (1 h).
- **Hosts.** A forward-dated issued_at silences a host's krl_stale alert for the forward offset plus 24 h (status.go). Deferred (Q-C5).
- **Hardware.** None. Every test uses software keys.

**Edges:**
- **F05 and Q-C7:**
  - the own export; another installation under a shared root; the library unchecked;
  - an ID-less bundle in force; an ID added after the anchor; a malformed expected ID;
  - the CLI: unbound refused, `--any-installation`, checked, other, both flags, JSON, ID-less without a flag, a malformed flag;
  - the e2e binding against a real signer.
- **F06:**
  - pin equal; pin with another ID; pin with an ID-less bundle; no pin with an ID (Q-C3 A); no pin and no ID; a malformed pin; the unpinned variant;
  - revoke serial, join token and a directory command refusing before any signature; known-hosts sync refusing before it writes a trust file, and machine renew before it sends a request or writes a certificate; the admin-auth diagnosis naming a pin error;
  - init saving and printing; the re-pin rule on the error and the runbooks, with the form without `--user` for an automation host's config (machine-identities.md);
  - recover: lost first, another installation, not pinned, ID-less exports with a pin, nothing to recover without a pin;
  - `directory rebind` across the transition, refused until the re-init;
  - every existing ID-less case kept by re-saving the pin;
  - trust verify in both modes.
- **F10:**
  - forward-dated with --previous; Now 0; exactly at the allowance; one microsecond past it;
  - a KRL within the allowance that leaves out a still-valid certificate; the allowance pinned to PruneMargin;
  - the last entry time; the CLI's clock; recover's clock on an F10-shaped saved export.
- **Export lines:**
  - the version escaped, spaced and with the same value; the replay pair spaced;
  - directory, version, bundle_version and import_krl_versions escaped on kinds that do not render them;
  - policy_version edited, escaped, on another kind, missing, as `V.0`;
  - KIND, Kind, the Kelvin sign, the long s, nested upper case;
  - each forget-only key alone, escaped; the pinned key list;
  - the Go reader premise; the export key gate over internal/audit, data-derived keys included.
- **The controls that must not change:**
  - every existing case row of TestVerifyForgetKeysOnOtherKinds and TestVerifyGrepFields;
  - TestVerifyRevocations;
  - the root_sign goldens and 03-14b's three internal/rootceremony summary goldens (TestSummaryGolden, TestSummaryFieldsCovered);
  - TestEditRevokesLossesBeforeInstall/no_installation_id_warns_and_installs and TestMachineRenew/no_installation_id_refused, with their assertions;
  - cmd/keyroster/audit_test.go's TestVerifyOutput, TestAuditVerifyProbeLine and TestVerifyOutputMachineLine;
  - TestHostTrustRunbooks, TestProbeAccountRunbook and TestProbeHoldReasonsDocumented on the edited runbooks;
  - TestRootCeremonyPolicyChecks;
  - TestDirectoryRebind, TestReadCommandsCheckInstallation, TestHostForget's ID-less case and TestRevokeRecover's nothing-to-recover case, with their assertions;
  - the e2e suite with the helpers' flags, and TestRestoreRunbookChecks with the updated pinned line.

## Source Coverage Audit

| Source | Item | Covered by |
|--------|------|------------|
| GOAL | Access revoked centrally, and the audit of it, belong to one installation | Tasks 1-3 |
| REQ | AGENT-01 (the agent pins the installation ID) | Task 2: the join token's ID comes from the CLI's pin (`join_token_refused`) |
| REQ | REVOKE-01 (CLI revocation) | Task 2: `revoke_serial_refused_before_signing`; recover's pin; Task 3: recover's clock |
| F05 | Options.InstallationID, `--installation-id`, the ID printed in text and JSON, refusal of another installation or none | Task 1 |
| Q-C7 | Refuse an installation-bound log unbound unless `--any-installation`; runbooks pass the flag | Task 1 (CLI, e2e helpers, TestAuditVerifiesIssuance/binds_installation); Task 4 (every runbook command, the pinned e2e line) |
| F06 | init saves the ID; every command refuses another installation's bundle and an ID-less one once pinned; the pre-fix config path; join tokens; recover | Task 2; Q-C3 |
| Q-C3 | Full re-pin form in the error and the runbooks; every user re-inits once, every automation host's config too (without `--user`); 03-15 uses --force | Task 2 (ErrInstallationNotPinned, TestRepinInstructionsKeepIdentity, `machine_renew_refused`); Task 4 (runbooks, machine-identities.md, the re-pin test's list, 03-15 pointers) |
| Owner decision | Q-09-3: `-timeout 15m` on every go test gate, a delta over a quiet base at most 24 h old, stop at +90 s | Budget; Task 1 (base line); Task 4 (delta gate, full gate pass or fail); `-timeout 5m` on every mutant |
| F10 | A clock bound on entry times tied to PruneMargin; the last entry time; recover's clock (Q-C4 B) | Task 3 |
| Q-C5 | Host-side bound deferred, with the corrected facts | Owner decisions; Edge Coverage; T-03-352 |
| Q-C6 | The 03-08c SUMMARY pointer, with a B branch in the verify | Task 4 |
| PR #75 review | Case-folded keys; the escaped or spaced directory_install version; keys forbidden on other kinds; policy_version unbound; each forget-only key tested; the host-setup.md and code-comment claims | Task 3 (code, tests); Task 4 (host-setup.md, 03-08c SUMMARY) |
| Owner decision | Fix home and slot before 03-15; Q-C1 slot with the stop guard (wave 30 after 03-14b at 3da914f) | Frontmatter; Task 1 precondition 1; Task 4 publish edits 0 to 8 and the publish and ROADMAP gates |
| Owner decision | Q-C9: the split; F15 is 03-14d | Owner decisions; Cross-plan notes |
| Owner decision | Roots per installation, so low | Owner decisions; threat severities |
| 03-14b | render-05, additions-only goldens, the green gates | Task 2; Cross-plan notes |
| Owner decision | Delivery: plan in its PR, neutral wording, F-numbers only, signed commits, no auto-merge, outside review on the diff only | Delivery protocol; Tasks 4 and 5 |
| Owner decision | Hardware never required; untested paths UNVERIFIED | Edge Coverage; runbook labels (checked); SUMMARY list |
| CONTEXT | 03-CONTEXT D-04 (installation binding) | Tasks 1-3 |
| CONTEXT | 03-CONTEXT D-20 (runbooks in the same PR, run or UNVERIFIED) | Task 4 (verify command 5) |
| Registry | Record what this plan changes through the format registry, present or absent | Task 4 registry step |
| Deferred | The host-side KRL issued_at bound (Q-C5) | Edge Coverage; T-03-352 |

## Artifacts this phase produces (this plan)

- **internal/audit:** Options.InstallationID and Options.Now; ErrEntryAhead; Report.LastTimeMicros; the bundle-in-force check and the leaf-time bound; checkBoundValues and the key charset rule.
- **cmd/keyroster:**
  - audit verify's `--installation-id` and `--any-installation`, the unbound refusal, its two lines and JSON fields, and auditClock;
  - Config.InstallationID; init's save and line;
  - the pinned Trust at every call site, and the diagnostics that name a pin error;
  - recover's pin check, its two refusals and its clock;
  - trust verify's installation line.
- **internal/serverclient:** Trust(…, installationID), TrustUnpinned, CheckInstallationPin, ErrInstallationNotPinned and ErrInstallationMismatch.
- **Tests:**
  - TestVerifyInstallationBinding (6), TestAuditVerifyInstallation (8), TestAuditVerifiesIssuance/binds_installation (e2e);
  - TestClientTrust (+7), TestInstallationPinned (10), TestInit (+2), TestRevokeRecover (+5), TestRepinInstructionsKeepIdentity (extended), the checkInvariants rule;
  - TestVerifyLeafTimeBound (8), TestAuditVerifyClock (2), TestVerifyBoundValues (13), TestVerifyForgetKeysOnOtherKinds (+17), TestExportKeysLowercase.
- **Docs:** signer-install.md, server-install.md, host-setup.md, revoke.md, root-ceremony.md, ceremony-transcript-template.md, enroll-user.md and machine-identities.md; the registry sentence (the registry is on main).
- **Planning:** the pointers in 03-12, 03-13, 03-15, 03-16 and the 03-08c SUMMARY.

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| a saved export → the auditor | Whoever hands the auditor an export (an insider, a compromised host) chooses which log it is. Before this plan, the root pins were the only binding |
| keyroster-server → the CLI | An untrusted server serves the trust bundle the CLI acts under: the revoke confirmation's ops key and installation, the directory checks, and the join token's installation ID |
| the signer's clock and keys → the log | A signer holding the log key and the ops key writes the entries audit verify and recover judge |
| an export line → its readers | grep, jq, Python and Go read the decoded fields beside the verified leaf |

## STRIDE Threat Register

Threat IDs follow 03-14b (up to T-03-334) and 03-09's revision (T-03-335 to T-03-344), from T-03-350. Task 1's precondition checks that origin/main uses none of T-03-350 to T-03-356, or renumbers.

Mapping from plan check 1's draft (Q-C9 moved F15 to 03-14d, which starts at T-03-359):

| Draft ID | Now |
|---|---|
| T-03-350 (F05) | T-03-350 |
| T-03-351 (F06) | T-03-351 |
| T-03-352 (F15) | 03-14d, T-03-359 |
| T-03-353 (F10) | T-03-352 |
| T-03-354 (export lines) | T-03-353 |
| T-03-355 (a later signed format) | 03-14d, T-03-360 |
| T-03-356 (denial of service by the new refusals) | T-03-354 |
| T-03-357 (accepted residuals) | split: T-03-356 here (ID-less, `--any-installation`, init), 03-14d T-03-361 (login and other exemptions, the audit side of issue requests) |
| T-03-358 (the printed ID) | T-03-355 |

T-03-357 and T-03-358 are left unused.

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-03-350 | Spoofing | audit verify: another installation's export, whose chain has the pinned root set, verifies as OK and anchored, and the output names no installation (F05) | low | mitigate | Options.InstallationID and `--installation-id` compare the bundle in force; the CLI refuses an installation-bound log unbound (Q-C7); the ID is printed on every OK, `none` included; every runbook command passes the flag, and 03-16 exercises it on the homelab. Tests: TestVerifyInstallationBinding, TestAuditVerifyInstallation, TestAuditVerifiesIssuance/binds_installation (e2e), mutants M1-1 to M1-5. Low because roots are per installation (owner). **Residual:** `--any-installation` unbinds by the auditor's choice; the auditor's own record of the ID (the transcript line) is the reference |
| T-03-351 | Spoofing | CLI trust: a hostile server serves a root-sharing installation's bundle, and the revoke confirmation, the directory checks, the join token and recover follow its installation ID (F06) | low | mitigate | init saves the ID; serverclient.Trust takes the pin, enforced by its signature at every call site, and refuses another ID, an ID-less bundle once pinned, and an ID while the config pins none (Q-C3 A); a command that acts on the bundle refuses before it signs a directory, revoke or forget request or mints a join token; admin-API reads before Trust are origin-bound and read-only, and their diagnosis names a pin error; recover compares after its lost check. Tests: TestClientTrust, TestInstallationPinned (no signature, no request), TestInit, TestRevokeRecover, TestRepinInstructionsKeepIdentity, mutants M2-1 to M2-8. **Residual:** init itself takes the served ID under the root pins (T-03-356) |
| T-03-352 | Tampering | a signer holding the log and ops keys appends a krl_publish dated past a still-valid revoked certificate's prune time, so audit verify (with --previous) accepts a KRL without it, and recover would publish without it (F10) | low | mitigate | Options.Now with the allowance equal to krl.PruneMargin, pinned by a test, so an accepted KRL leaves out only certificates expired at the verifier's clock; audit verify and recover both set Now (Q-C4 B); the last entry time is printed. Tests: TestVerifyLeafTimeBound (the clear time named from the last entry), TestAuditVerifyClock, TestRevokeRecover/forward_dated_saved_export_refused, mutants M3-1 to M3-5. **Residual:** detective only: an auditor whose clock is within 300 s of the forward date, or after it, sees an entry that looks like an honest republish; Now 0 for library callers; hosts install such a KRL, since they bound only its version, and its forward issued_at silences their krl_stale alert for the offset plus 24 h (Q-C5, deferred); a compromised signer can push unlogged ops-signed KRLs anyway |
| T-03-353 | Tampering | an export line that verifies reads differently to a JSON reader: case-folded keys (KIND, Kind, the Kelvin sign, the long s) read as a forged host_forget by Go's struct decoding; an escaped or spaced optional key; a key the byte checks forbid on a kind, written escaped; an edited policy_version (PR #75 review follow-ups) | low | mitigate | The key charset rule at every depth; checkBoundValues mirroring every byte check at the parsed level, policy_version included; one case per forget-only key with a real escape and a pinned key list; TestExportKeysLowercase over the decoders' bodies in internal/audit, refusing data-derived keys unrecorded. Tests: TestVerifyForgetKeysOnOtherKinds, TestVerifyBoundValues, `go_reader_folds_case`, mutants M3-6 to M3-20. **Residual:** decoded fields Verify does not bind stay informational, as export.go's doc says; no in-repo reader is affected |
| T-03-354 | Denial of service | the new refusals stop legitimate work: an old config on an installation with an ID (every CLI user re-inits once, and every automation host's config too, whose cron or timer renewals exit 1 until it is re-initialised without `--user`); an unbound audit verify on an installation with an ID; an honest signer clock ahead of the auditor's (a stalled restore); a hand-edited config | low | mitigate | Each refusal names its remedy: the full re-pin form (checked by TestRepinInstructionsKeepIdentity) and, for an automation host, the form without `--user` (in ErrInstallationNotPinned and machine-identities.md), the flag to pass, the time the clock refusal clears and what to check. The e2e helpers and the runbooks pass the flag. recover tells a re-init (`recovery_installation_not_pinned`) from an escalation. On the homelab no pin applies until 03-15, which re-initialises the CLIs with --force anyway (pointer). **Residual:** an auditor whose clock is slow by more than 300 s cannot verify a fresh log until it is corrected; a restore after an honest fast-clock episode waits until the clock passes the forward time |
| T-03-355 | Information disclosure | the installation ID printed by audit verify, init and trust verify | low | accept | The ID is not secret: it is in every bundle, directory, KRL manifest and join token, and root sign already prints it |
| T-03-356 | Spoofing | accepted residuals of this plan's binding: an installation without an ID binds nothing; `--any-installation` unbinds; init pins whatever bundle the server serves under the root pins | low | accept | An ID-less installation gains an ID through `root sign --installation-id new` (03-15 on the homelab). `--any-installation` is explicit and the output still names the installation. init's pin is as strong as its root pins, which are per installation (owner); the runbooks and the init line tell the user to compare the ID with the record |
| T-03-SC | Tampering | dependencies | low | mitigate | No module added; go/parser is stdlib and used in tests only. dep-firewall and testonly-firewall unchanged. The capslock baseline is unchanged; a new pair is a recorded deviation |
</threat_model>

<verification>
- Every verify command passes locally (scripts/linux.sh) or in CI as stated, the full gate passes and the test-time delta gate holds (Q-09-3), the PR's required checks are green with the house e2e gate passing in MODE=pr and TestAuditVerifiesIssuance/binds_installation and TestRestoreRunbookChecks passing and cli-windows and cli-macos green, the pre-merge review is recorded, and the merge gate passes.
</verification>

<success_criteria>
- `keyroster audit verify` shows the installation ID of every log it verifies, refuses another installation's log signed by the same roots with `--installation-id`, and refuses an installation-bound log unless the auditor names the installation or passes `--any-installation`.
- A CLI pinned at init refuses a server that serves another installation's bundle, an ID-less bundle, or a bundle with an ID it does not pin, before any admin signs; recover refuses another installation's exports and tells a re-init from an escalation; trust verify shows the installation ID.
- audit verify and recover refuse an entry dated more than krl.PruneMargin past their clock, and audit verify prints the last entry's time.
- Every export line reads the same to grep, jq and a case-folding Go reader.
- root sign's output, rootceremony.Summary and the trust bundle format and field order are unchanged; 03-14b's goldens changed by four added lines.
</success_criteria>

<output>
Create `.planning/phases/03-linux-agent-and-revocation/03-14c-SUMMARY.md` in Task 4, before the merge gate. Leave `requirements-completed` empty: AGENT-01 is complete and REVOKE-01 is 03-11b's (complete); this plan hardens both. Never record merge facts.
</output>

## Review Dispositions Ledger

### Round 0 — sources (F05, F06, F15 and F10; the PR #75 review follow-ups on audit verify's export lines; 03-14b's Cross-plan notes and render-05; 03-09 owner decisions D2 and D5)

### Round 0b — planner self-review while drafting (2026-11-05), before plan check 1

Recorded in the first draft; its rows that still apply are folded into Round 1 below.

### Round 1 — plan check 1 (2026-11-05, FAIL, fixable: 13 MAJOR, 29 MINOR, 2 refuted) and the owner's answers Q-C1 to Q-C9 (Daniel, 2026-11-05)

Merged as the check's completeness critic directs. "03-14d" marks an item that moved with F15 (Q-C9) and is fixed there.

| Item(s) | Severity | Disposition |
|------------|----------|-------------|
| wire-audit-03 + tests-02 (the lost escapes) | MAJOR | Fixed: every escaped case writes the escape as `\u` plus four hex digits, the delivery protocol says the bytes go into a Go raw string, each case says why it fails on R3, and Task 3's third verify command greps the test files for the escapes |
| tests-04 + ops-04 (ID-less cases under a pinned config) | MAJOR | Fixed: the execution-time grep is authoritative; resignBundle re-saves the pin to the re-signed bundle's ID and noIDBundles cases pin "", so TestDirectoryRebind (four cases), TestReadCommandsCheckInstallation/bundle_without_id, TestHostForget's ID-less case and TestRevokeRecover/no_installation_id_nothing_to_recover keep their assertions; a verify command checks the three assertion strings; rebind_needs_reinit saves through saveConfig, and the runbook labels the init-then-rebind sequence UNVERIFIED |
| ops-01 + critic-qc4-recover-drops-revocation | MAJOR | Resolved by the owner (Q-C4 B): recover sets Now and refuses `recovery_clock_ahead`; the facts are corrected (the forward clamp, the refusal lasts until the last entry's time minus 300 s, the same stall under A and B, recover would drop the revocation without Now); the refusal text names the clear time and what to check; the restore step 2 and recovered-verify sentences; TestRevokeRecover/forward_dated_saved_export_refused and mutant M3-5 |
| closure-F05-flag-never-used | MAJOR (ruled MINOR) | Resolved by the owner (Q-C7): the CLI refuses unbound; every runbook command passes `--installation-id` (verify command 4), the pinned e2e line moves with it; a 03-16 pointer exercises it on the homelab |
| wire-audit-01 (format registry) | MAJOR (ruled MINOR) | Fixed for this plan: a registry step that tolerates the registry being present or absent; this plan allocates nothing and adds one Installation binding sentence; the F15 rows are 03-14d's |
| slot-01 (wave guard) | MAJOR (ruled MINOR) | Fixed: publish edit 1 always takes origin/main's 03-12 values; the guard checks both wave and depends_on, as 03-14b's does; Q-C1's facts name 03-09b and Q-B3 |
| ops-02 (no transcript record) | MAJOR (ruled MINOR) | Fixed: the transcript template's Installation ID line; root-ceremony.md tells custodians to record it and compares trust verify's line with it; the init line and ErrInstallationNotPinned name "the one your admin gives you"; enroll-user.md tells invited users. `user add`'s invite text is not changed (planner decision) |
| ops-03 (re-pin form) | MAJOR (ruled MINOR) | Fixed: ErrInstallationNotPinned and every runbook remedy carry the full re-pin form; TestRepinInstructionsKeepIdentity checks the error and host-setup.md, revoke.md and enroll-user.md |
| tests-03, wire-audit-02 + tests-01, wire-audit-04, wire-audit-05, wire-audit-06 + tests-08, wire-audit-08, wire-audit-09, tests-07, tests-09, closure-QC2-facts-incomplete, closure-F15-stripped-downgrade-untested, critic-mixed-version, critic-pr-body-login-unverified, critic-namespace-doc-drift, critic-adminauth-inventory, wire-audit-10, wire-audit-11, closure-F15-audit-namespace-check | MAJOR, MINOR, INFO | 03-14d (F15 moved there by Q-C9) |
| closure-F10-allowance-vs-prunemargin + wire-audit-07 | MINOR | Fixed (Q-C4 B coupling): maxLeafAheadMicros is krl.PruneMargin × 10⁶, pinned by `allowance_is_prune_margin` and mutant M3-2; `within_allowance_cannot_drop_valid`; the property is in Options.Now's doc and the owner decision |
| closure-export-escaped-key-other-kind | MINOR | Fixed: checkBoundValues refuses parsed version, directory and sigs off directory_install, bundle_version off bundle_install and import_krl_versions off revocation_recovery; four cases and mutant M3-8 |
| tests-05 + ops-08 (recover placement) | MINOR | Fixed: step 4 spelled out in three steps; a pinned config with ID-less exports is refused (`id_less_exports_with_pin_refused`); the nothing-to-recover case pins "" |
| ops-07 (escalate or re-init) | MINOR | Fixed: `recovery_installation_not_pinned` and `recovery_installation_other`, with their texts asserted and mutant M2-6 |
| tests-06 (forget-key survival) | MINOR | Fixed: the origin/main result of all ten mutants is recorded: killed for identity and admin_fingerprints, surviving for the other eight |
| tests-10 (audit_test.go exists) | MINOR | Fixed: Task 1 extends it if 03-09 created it; its existing test passes the flag; Task 3's clock covers it |
| slot-02 (Q-C6 wording) | MINOR | Fixed: the pointer says "at every depth, not only the top-level key"; the decision records the SUMMARY's existing top-level note |
| slot-03 (--force at 03-15) | MINOR | Fixed: a 03-15 pointer at its init step names --force, --user and --admin-key; 03-15's numstat 4 4 |
| slot-04 (anchor uniqueness) | MINOR | Fixed: Task 1's precondition and Task 4's precondition check every anchor exactly once on origin/main |
| slot-05 (Q-C6 B branch) | MINOR | Fixed: verify command 6 takes `Q6=A` or `Q6=B` |
| slot-06 (compile-time claim; 03-13) | MINOR | Fixed: only Trust's signature is a compile-time check (planner decision); 03-13 gets a pointer; numstat 2 2 |
| slot-07 (rebase re-checks) | MINOR | Fixed: Task 5's rebase re-runs Task 4's publish checks against the new origin/main |
| slot-08 (threat-ID collisions) | MINOR | Fixed: Task 1's precondition checks T-03-350 to T-03-356 on origin/main, or renumbers |
| ops-05 (Q-C5 facts) | MINOR | Fixed in the Q-C5 decision: the PR #71 F5 D-R2, the KRLStale fact, option C; the silenced stale alert in T-03-352 |
| ops-06 (every user re-inits) | MINOR | Fixed in the Q-C3 decision and T-03-354; enroll-user.md gains the users' text |
| ops-09 (data-derived keys) | MINOR | Fixed in Round 2: TestExportKeysLowercase fails on any non-literal map key inside the decoders' bodies except the recorded ReasonName site |
| ops-10 (labels) | MINOR | Fixed: verify command 5 requires `Run in CI` and UNVERIFIED in each new paragraph |
| critic-truth88-overclaim | MINOR | Fixed: truth 3 and T-03-351 reworded; the two diagnostic Trust calls return a pin error; `admin_error_names_installation` and mutant M2-7 |
| critic-budget-split | INFO | Resolved by the owner (Q-C9): F15 is 03-14d; this plan's total is about 120k |
| critic-d5-0310-0311-untracked + slot-09 | MINOR, INFO | Recorded in the Cross-plan notes: D5 reaches 03-10 and 03-11 only through 03-09's notes; 03-14d's precondition is the backstop |
| slot-10 | INFO | Fixed: the objective counts the pointers; the publish commit names the 03-08c correction; 03-09b is in the Cross-plan notes |
| tests-12 | INFO | Fixed in Round 2: TestExportKeysLowercase walks every non-test file in internal/audit, inside the decoders' bodies |
| closure-QC3-init-still-tofu, tests-11 | refuted | Not applied |

### Round 2 — plan check 2 of 03-14c (2026-11-05, with 03-14d's plan check 1): closure, three MAJOR, MINORs and INFOs

| Item(s) | Severity | Disposition |
|------------|----------|-------------|
| c-close-wire-tests-01 + c-close-ops-slot-01 (and the not-closed tests-12, ops-09) | MAJOR | Fixed: TestExportKeysLowercase looks only inside the bodies of `Decode`, `decodeLeaf` and every `decode*` function, so it passes at f7eb018, on R3 and on T3; it requires the five decoders to be found (eight at 3da914f, see the Reconcile ledger, D08); the bookkeeping maps are named as out of scope; a map index counts only for an identifier the function declares with a map type, so a slice index cannot trip it; the f7eb018 baseline (one non-literal key, export.go:160) is stated as read; mutant M3-20 (a non-literal key in decodeHostForget) bites |
| c-new-text-01 + c-close-wire-tests-03 + c-close-ops-slot-02 | MAJOR | Fixed: Task 4's verify 4 counts only command lines (`^[[:space:]]*keyroster audit verify --pin`) and requires at least ten, so signer-install.md's prose sentence is not counted and zero hits fail |
| c-new-text-02 + c-new-text-03 + c-close-ops-slot-03 (and the not-closed slot-08) | MAJOR | Fixed: the threat-ID precondition matches only register rows (`^\| T-03-35[0-6] \|`), and its fallback renumbers from the highest ID that starts a register row; the mapping table's rows start with a draft ID and a parenthesis, so neither this plan's nor 03-14d's row-anchored check reads them as definitions |
| c-close-wire-tests-02 | MINOR | Fixed: the escape greps bracket the backslash (`versio[\]u006e`, `[\]u0068ost_gone`), and the delivery protocol adds an `od -c` and `grep -c '[\]u00'` confirmation recorded in the SUMMARY |
| c-close-wire-tests-04 + c-close-ops-slot-05 (and the not-closed ops-03) | MINOR | Fixed: every new remedy writes the literal command; TestRepinInstructionsKeepIdentity lists signer-install.md (the restore path) too, checks every paragraph with `keyroster init` and `--force`, and requires one checked paragraph per new file; verify 4 greps each runbook for the literal command |
| c-close-ops-slot-04 (and the not-closed ops-01) | MINOR | Fixed: the clock check runs once after the loop on the last leaf, and names the last entry's time minus 300 s; `two_ahead_leaves_names_last` pins it |
| c-new-text-04 | MINOR | Fixed: recover's `recovery_clock_ahead` says keep the hold, wait if the journal shows a clock episode, otherwise escalate, matching restore step 2; the test asserts `Keep the hold` |
| c-close-ops-slot-06 | MINOR | Fixed: the first 03-15 pointer carries the transcript duty; the Cross-plan note describes the pointers as written |
| c-new-text-05 | MINOR | Fixed in 03-14d (its check anchors on the ca issue command line); this plan's Cross-plan note says the placeholder is shared |
| c-new-text-06 | MINOR | Fixed: the Cross-plan note names 03-15's Tasks 4 and 5 |
| c-close-ops-slot-07 (and the not-closed slot-05) | INFO | Fixed: ns() skips empty lines, so the Q6=B branch can pass |
| c-close-ops-slot-08 (and the not-closed slot-10) | INFO | Fixed: the objective says six pointer sentences plus the 03-08c SUMMARY pointer |
| c-new-text-07 | INFO | Fixed: the Q-C4 fact and Edge Coverage say "about as long", with B's extra republish interval |
| c-close-wire-tests-05 | INFO | Fixed: root_test.go's idlessGenesis is recorded as reviewed, not moved |
| d-slot-docs-threat-10 | INFO | Recorded in the Cross-plan notes (03-09b's overflow continues after T-03-362); 03-09's text is not this plan's to edit |
| Budget | INFO | Corrected: the plan is about 186 KB, roughly 77k tokens, and the executor's total about 157k; tasks can run in fresh contexts |

## Reconcile ledger (3da914f, 2026-11-11)

The plan was written, checked twice and owner-answered at f7eb018. The reconcile of 2026-11-11 compared it with main at 3da914f (PR #98, 03-14b merged), across the twelve squash commits #87 to #98. Verdict: fix in place, no re-plan. Every code anchor, golden, pointer anchor and the reserved threat-ID gap hold; the design still fits main, and main's binding of the installation ID (bundle, revoke v2, forget, recovery, HostIssue, ProbeIssue, MachineIssue) still binds no log and no CLI to an expected installation, so F05 and F06 stand. No owner question is open: the slot and order (Q-C1 A, Q-B3, Q-C9), the test-time rule (Q-09-3) and the automation hosts' re-pin (Q-C3 A, which D06 extends only in its remedy) are settled. Every reconcile item was re-checked against 3da914f before it was applied; none was rejected.

| id | severity | what changed in this plan |
|----|----------|---------------------------|
| D01 | BLOCKER | Budget's test-time block is Q-09-3 in 03-14b's form: Task 1's first action step writes one `test-time base: cmd=<s> audit=<s> serverclient=<s> at=<epoch>` line on unchanged origin/main over cmd/keyroster, internal/audit and internal/serverclient, with a format check in Task 1's acceptance criteria; Task 1's precondition 8 now says the base is measured and recorded, and never stops the plan by itself. Task 4's delta gate stops at +90 s per package (`n!=3`), requires the base to be at most 24 h old and re-measures it in place in another session or WSL boot. The 400 s and 480 s awk gates and the apply and signer readings are gone; the whole-module run is pass or fail only. Every go test command carries `-timeout 15m` and every mutant command `-timeout 5m`; a timeout is not a kill. The Gates paragraph, the SUMMARY list, the verification block and a Source Coverage row say the same |
| D02 | BLOCKER | The private-term gate spells both artefact names with a bracketed letter, as 03-14b did; under `grep -i` it matches exactly as before. The plain word for review results is reworded at the delivery rule ("the issues"), the pre-merge review step and its acceptance criterion ("review results"), the Round 1 intro ("an item that moved") and both round-table headers ("Item(s)"). Task 4's push step 1 now scans this plan file for the private terms before the publish commit. The plan holds the word in no case |
| D03 | MAJOR | Frontmatter `wave: 30`, `depends_on: ["03-14b"]`. Truth 1 reads "(30 at 3da914f, 03-14b merged as #98)". The Q-C1 record keeps the owner text and adds the OQ-1 and 3da914f sentence. Task 1's precondition 1 is a stop guard (03-14b's SUMMARY on main, origin/main's 03-12 at wave 30 with ["03-14b"], 03-14b the only plan at wave 29, waves read from the frontmatter); the absorb guard (old point 9) and the "+1 from W12" brackets are gone, and publish edit 0 re-runs the stop guard. The brackets are 3da914f's values. The Cross-plan 03-09b bullet and Task 5's rebase step follow: a moved base stops for a re-reconcile |
| D04 | MAJOR | Publish edits 2 and 3 write the true totals (03-14b's R2-1): `30/36 plans executed in 35 waves`, the Progress row `30/36`, `total_plans: 71`, `completed_plans: 65` kept, `Plan: 30 of 36`; the tracking update makes them 31/36, 66 and `Plan: 31 of 36`. The publish gate derives the STATE values from HEAD's PLAN and SUMMARY counts, each exactly one more than origin/main's, and pins main's base (70, 65, `Plan: 30 of 35`). The ROADMAP gate builds the exact intended file from origin/main (`30/35 … 34 waves`, `| 30/35 |`, blocks 30 to 34) and compares whole files, so only the 03-14c row may turn `- [x]`; the action adds the after-tracking prefix-tick check (the hazard is the 03-14 row). Publish edit 2's row carries `- [ ] ` and a blank line, byte for byte the gate's row before the tick |
| D05 | MAJOR | cmd/keyroster/knownhosts.go and cmd/keyroster/machinerenew.go are in files_modified and Task 2's files. The context lists the twelve call sites at 3da914f. TestInstallationPinned gains `known_hosts_sync_refused` (no file under the test HOME's .ssh, no host-trust.json) and `machine_renew_refused` (renewCount 0, no certificate file), on hostEnv/useSSHDir and newRenewEnv/renewAnswer. Both are in the behaviour, the RED list (now twenty-three), the PASS list and M2-2's killers; the artifacts count TestInstallationPinned at 10 |
| D06 | MAJOR | ErrInstallationNotPinned keeps the user form first and adds the automation-host form without `--user` (machine-identities.md); TestClientTrust/unpinned_config_refused also checks that text. Runbook action 9 adds a paragraph to machine-identities.md's `## Renew a machine certificate`, labelled Run in CI (`machine_renew_refused`) and UNVERIFIED on a real automation host, never in `## Renewal needs pop.machines`; verify command 5 checks the phrase, its labels, the literal command and its absence from that section. machine-identities.md is in files_modified and Task 4's files and stays off TestRepinInstructionsKeepIdentity's list. Q-C3's cost facts, truth 3, the Q-C3 coverage row and T-03-354 name every automation host's config |
| D07 | MINOR | The Q-C7 refusal sits after Verify returns and before `verifyResultOf`, so `--json` is covered. InstallationID and LastEntryMicros are set in verifyResultOf, declared after PendingNegativeProbes, without omitempty on `installation_id`. The two text lines are printed by runAuditVerify right after `anchored:`, never by printVerifyOK. Every TestAuditVerifyHostCertificates mention is replaced by the three real unit tests, which move no arguments and stay green. audit.go is 7.3 KB, and Task 4's constant grep leaves cmd/keyroster/audit.go out. Task 1's precondition 7 checks that audit_test.go exists |
| D08 | MINOR | Task 3 records that checkBoundValues and the charset rule are redundant on host_issue, probe_issue and machine_issue (byte-bound by checkForgetFields) but must pass. The policy_version list expects nine kinds at 3da914f. TestExportKeysLowercase requires eight decoders, decodeHostIssue, decodeMachineIssue and decodeProbeIssue included, and its baseline reads "from Decode to the end of decodeProbeIssue, at 3da914f". The Round 2 row is annotated, not rewritten |
| D09 | MINOR | The resignBundle re-pin rule names the new ID-stripping cases (TestEditRevokesLossesBeforeInstall/no_installation_id_warns_and_installs, TestMachineRenew/no_installation_id_refused) and the CA-editing retired_ca_refused. The "assertion moved" check covers their refusal strings in dirpipe_test.go and machinerenew_test.go with the same origin/main-equals-HEAD count, and Task 2's verify runs both tests and TestKnownHostsSync. knownhosts_test.go's two htFix edits are recorded as reviewed, not moved. The keyring grep reads `useCountingKeyring` and `countingAgent` |
| D10 | MINOR | Task 1's verify and the full gate vet `-tags e2e_pkcs11` and `-tags e2e_tpm`; the full gate vets the house tag list. Both files are pure Go, so the vets need no cgo |
| D11 | MINOR | Task 4 runs 03-10b's house e2e gate in MODE=pr with 03-11b's PROBE_PASS list (run for HEAD, main lanes at or under 900 s, probe lanes green) and then requires the PASS lines in both main lanes. Applied with one deviation in name, a planner choice: the binding test is the subtest `binds_installation` of TestAuditVerifiesIssuance, because a top-level TestAuditVerifyBindsInstallation would need a new bootstrapSigner, which the reconcile rules out for lane time, or new shared package state to reuse another test's signer and export. Every mention is renamed; no other plan names the old test. Its unbound case calls runKeyroster directly, because both helpers now inject a flag. The SUMMARY records the main lanes' seconds |
| D12 | MINOR | Estimate raised to 280k raw at low confidence, frontmatter and Budget alike. The reconcile asked for about 200k; recomputed after this pass, the plan itself is about 229 KB (roughly 95k tokens at the plan's measured 2.4 bytes per token) and is read in each of two sessions, so the sum is about 280k. Expected range about 500k to 1.1M (the reconcile gave 400k to 1M); one continuation after Task 1 and an optional one after Task 2, handed over through the SUMMARY draft, each re-measuring the test-time base |
| D13 | MINOR | Both sentences read "AGENT-01 is complete and REVOKE-01 is 03-11b's (complete); this plan hardens both" (the SUMMARY item and `<output>`) |
| D14 | MINOR | The context cites 03-11b-SUMMARY.md, reads "as read on main at f7eb018 and re-read at 3da914f", lists the landed plans and #87, #94, #96, and replaces the call-site list, the audit.go sentence and the checkForgetFields note. The Cross-plan bullet says these plans landed, and names knownhosts.go and machinerenew.go as their call sites (revoke host and revoke machine go through openRevocation) |
| D15 | MINOR | The registry sentence is a new paragraph after the section's last paragraph, never inside one, so the no-line-removed numstat holds. The SUMMARY records the three recover refusal names as CLI names, unregistered by design |
| D16 | MINOR | Runbook action 3 keeps the root-ceremony.md insertions plain prose: no line that starts with a sectionWindow marker, and no `- **` bullet or numbered-step line inside "Change the policy" step 3. Task 4's runbook verify runs TestRootCeremonyPolicyChecks, TestSectionWindowRefusals, TestRepinInstructionsKeepIdentity, TestHostTrustRunbooks and TestProbeAccountRunbook, and TestProbeHoldReasonsDocumented in internal/agent/apply (at account_test.go:538, one line below the reconcile's :537; the plan names it only), each with `-timeout 15m`, and requires each PASS line |
| D17 | MINOR | Task 2's golden check requires `git diff --name-only origin/main...HEAD -- internal/rootceremony/testdata/summary` to be empty, and its verify runs TestSummaryGolden and TestSummaryFieldsCovered |
| D18 | INFO | The mutant rule says the numbering is local, this plan allocates no global M-IDs, and 03-12 starts at M111 |
| D19 | INFO | No change to the expectation "no new pair". The Gates paragraph and the SUMMARY list record keyroster-signer's stale pair (91 against a baseline of 92) as pre-existing, unless the baseline-tightening PR lands first |
| D20 | INFO | No change: render-05's wording is right in both modes, because runTrustVerify's non-`--prev` path accepts only a genesis bundle (trust.VerifyGenesisBundle) |
| D21 | INFO | cmd/keyroster/runbook_test.go is dropped from files_modified: no task edits it, and this plan adds no signing section |

Counts after this pass: files_modified lists 60 files (38 code and test, two of them new; four goldens; eight runbooks; the registry; nine planning files). Task 2's RED list has twenty-three cases, TestInstallationPinned ten. The mutant count is unchanged: 5, 8 and 20, 33 in all.

**For later plans** (not edited here; each plan's own check or re-plan carries it):
- **03-14d (X1).** It depends on this plan in four ways: its Task 1 precondition greps origin/main for `func (c \*Client) TrustUnpinned(` and for this plan's SUMMARY; its runbook text names the installation id line of `keyroster init` and of `keyroster trust verify`, which this plan creates; its ca issue check anchors on the ca issue command line, not on the shared `--installation-id <installation id>` placeholder; and its brackets and gates must follow true totals. This plan keeps TrustUnpinned's exact name and receiver and the init and trust verify lines of its output contract; the machine re-pin form does not touch 03-14d. After this plan, 03-14d is wave 31 with ["03-14c"], 03-12 to 03-16 move to 32 to 36, the ROADMAP reads /37 in 36 waves, and STATE reads `total_plans: 72`, `completed_plans` 66 → 67 and `Plan: 31 of 37` → `Plan: 32 of 37`. Its own reconcile updates its brackets and gates to these true totals and copies this plan's stop guard and whole-file ROADMAP gate.
- **03-12 and its security design note (X2).** After 03-14c and 03-14d it sits at wave 32 with ["03-14d"]. If it is split into 03-12, 03-12b and 03-12c, every sub-plan that touches audit verify, internal/audit's export or trust verify carries this plan's pointer duties: a new decoder's keys are lowercase and the decoder joins TestExportKeysLowercase's required set; its kind joins the derived policy_version list if it renders one; a `CA generations: N` line goes in printVerifyOK, not between `anchored:` and the installation line; a CA-change section placed after the successor header stays before `Bundle SHA-256:`, so the installation-line invariant holds; and any new audit.Options literal in cmd/ sets Now.
- **03-13 and 03-14 (X3).** No change: their anchors hold, and 03-14's host.go Trust calls meet the new signature at compile time.
- **03-15 and 03-16 (X4).** No change required: their anchors hold, and the homelab has no machine config to re-pin before 03-15's v4, which re-initialises every CLI anyway. If 03-15 ever sets up a machine before v4, its first pointer may add "and every automation host's config, without `--user` (machine-identities.md)".
