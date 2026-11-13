---
phase: 03-linux-agent-and-revocation
plan: 14d
subsystem: installation binding (admin issue requests, the signed-request classification)
tags: [wire, signer, cli, installation-id, hardening]
status: complete
requirements-completed: []
decisions:
  - "An admin issue request names its installation: v2 signs the ID, and the signer refuses a missing, another or unexpected ID before the evidence and before any CA key (Q-C2 A)"
  - "ca issue takes the installation ID from --installation-id only, never from the signer or the CLI config (OQ-1 = A)"
  - "LoginIssueRequest, adminauth.Message and the agent-identity rotation stay exempt, with the owner's reasons recorded in the classification table and the registry (Q-C8, Q-D1 = A)"
actuals:
  tokens: 69964
  tasks: 3
  commits: 8
plan_head_before: 62b44073419c047c8c67cfa0a485f6771d471187
plan_head_after: 036c5f000f00caad42fd390c20bbac78b0db3cae
---

# Phase 3 Plan 14d: An admin issue request names its installation (F15)

test-time base: cmd=271.873 signer=396.207 wire=8.610 at=1794545368

## Session 1 (Task 1)

- Branch `p03/14d-issue-installation` from origin/main 62b4407; plan-head ledger `.git/gsd-plan-head-before-03-14d` = 62b44073419c047c8c67cfa0a485f6771d471187.
- The plan file is in the phase directory and untracked; Task 3's publish step commits it.

### Preconditions (Task 1, origin/main 62b4407)

- Stop guard holds: 03-14c's SUMMARY is on main, 03-12 sits at wave 31 with depends_on ["03-14c"], and 03-14c is the only plan at wave 30.
- 03-14c is on main (TrustUnpinned present) and this plan is not (no IssueRequestDomainV2).
- D5 delivered: HostIssueRequest, ProbeIssueRequest and MachineIssueRequest each carry `InstallationID string` (no `git grep -h` prefix stripping was needed).
- All seven code anchors exist; both pointer anchors (03-12, 03-15) occur exactly once.
- Threat IDs T-03-359 to T-03-362 are free as register rows; no renumbering.
- The format registry is present on main (docs/format-registry.md).
- Open owner questions: "None open."

### Test-time base

Measured before any edit, tree equal to origin/main 62b4407, no other heavy job: `bash scripts/linux.sh 'go test -race -count=1 -timeout 15m ./cmd/keyroster/ ./internal/signer/ ./internal/wire/'` started at 1794542952, ended at 1794543399; the `ok` lines read cmd/keyroster 304.504s, internal/signer 427.195s, internal/wire 8.634s.

### R1 (`c7d2741`, test(signer): pin installation binding of admin issue requests (F15))

Declarations R1 added (behaviour unchanged):
- internal/wire/issue.go: `IssueRequest.InstallationID` (first field; Marshal, ParseIssueRequest and SigningBytes do not use it on R1), `IssueRequestDomainV2`, `AdminSSHSIGNamespaceV2`, and `func (r *IssueRequest) Namespace() string` returning AdminSSHSIGNamespace.
- cmd/keyroster/ca.go: `--installation-id` with the output contract's usage, set on the request without validation.
- Test helpers: `v2Body(v1 []byte, id string) []byte` (wire_test.go; marshalUnchecked's doc comment now says it encodes a v1 body and v2Body appends the ID); `issueVector`, `readVector`, `testIssueInstallationID` (wire_test.go); `startFakeSignerOpts(t, fakeSignerOpts)` with `issueErr *wire.ErrorResponse` and `f.lastIssue()`, startFakeSigner keeping its signature and calling it, and `statusWith` moved to file level unchanged (ca_status_test.go); `issueFixture`, `reframe`, `(*logEnv).issuesUnder`, `otherInstallationID` (issue_installation_test.go); the hint constants of the output contract (ca_test.go).
- Fuzz seeds (FuzzParseIssueRequest, all built with v2Body): a valid v2 body, v1 + `0000`, v2 + one byte, a truncated ID (`0020` and 10 bytes), IDs of 31 and 33 characters, an upper-case ID; the body asserts a parsed request with an ID has Namespace() == AdminSSHSIGNamespaceV2 and SigningBytes starting with IssueRequestDomainV2, `0020` and the ID.
- Namespace-overlap lists: AdminSSHSIGNamespaceV2 added to TestForgetRequest/namespace_is_its_own and TestMachineIssueRequest/constants_and_frame.

Moved request builders (pass on R1 and on T1): log_test.go `(*logEnv).request()` sets `req.InstallationID = e.fx.InstallationID`; fixture_test.go `SignRequest` signs under `req.Namespace()`; revoke_test.go TestSubjectResolutionTime/older_longer_cap_found sets `fx.InstallationID`; revoke_host_test.go `issueKR1` sets `e.fx.InstallationID`. Builders found by `git grep -n -E '(^|[^A-Za-z])wire\.IssueRequest\{'` at execution: the six of the plan's context, no others. Reviewed and left unedited: machineissue_test.go admin_refusals_still_logged, evidence_test.go's refusal table, signer_test.go newRequest, ca_test.go TestCAIssueAdminEvidence (it calls adminEvidence with the v1 namespace directly).

### Vectors

- test/vectors/issue_request_signing_v1.hex written by `go test -run '^TestIssueRequestSigningVector$/^v1_bytes$' ./internal/wire/ -update` on the R1 tree, whose SigningBytes is origin/main's (the -update branch writes only the v1 file). SHA-256 `a905f6f3301f646e1c4471c3ee44a154741697b644a686dae93fbab00b5d1963`.
- test/vectors/issue_request_signing_v2.hex derived with this perl script (stdin the v1 file, stdout the v2 file), SHA-256 `b8f8eb1d1875f81b198479a04701f2daa396992874707ac3f299901fbfd276fb`:

```perl
my $id = "00112233445566778899aabbccddeeff";
my $v1d = unpack("H*", "keyroster/issue-request/v1");
my $v2d = unpack("H*", "keyroster/issue-request/v2");
local $/; my $h = <STDIN>; $h =~ s/\s+$//;
substr($h, 0, length $v1d) eq $v1d or die "no v1 domain\n";
print $v2d . "0020" . unpack("H*", $id) . substr($h, length $v1d), "\n";
```

  Output (the v2 file): `6b6579726f737465722f69737375652d726571756573742f7632002030303131323233333434353536363737383839396161626263636464656566660100330000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80007753a616c69636500070005616c69636500000258000102030405060708090a0b0c0d0e0f000000006553f1000000`

### RED (third verify command, from a detached worktree of R1): passed

Twenty-one `--- FAIL:` lines, no `[build failed]`, no timeout:
- `--- FAIL: TestIssueRequestSigningVector/v2_bytes`
- `--- FAIL: TestIssueRequestV2/round_trip_v2`
- `--- FAIL: TestIssueRequestV2/v2_body_helper_parses`
- `--- FAIL: TestIssueRequestV2/trailing_empty_id_refused`
- `--- FAIL: TestIssueRequestV2/trailing_bytes_after_id_refused`
- `--- FAIL: TestIssueRequestV2/malformed_id_refused`
- `--- FAIL: TestIssueRequestV2/domains_differ`
- `--- FAIL: TestIssueInstallation/request_for_other_installation_refused`
- `--- FAIL: TestIssueInstallation/id_rewritten_refused`
- `--- FAIL: TestIssueInstallation/v1_refused_where_bundle_names_one`
- `--- FAIL: TestIssueInstallation/v2_refused_where_bundle_names_none`
- `--- FAIL: TestIssueInstallation/v1_signature_refused_as_v2`
- `--- FAIL: TestIssueInstallation/v2_frame_stripped_to_v1_refused`
- `--- FAIL: TestIssueInstallation/installation_checked_before_evidence`
- `--- FAIL: TestIssueInstallation/classified_unauthorized`
- `--- FAIL: TestCAIssueInstallation/flag_malformed_usage`
- `--- FAIL: TestCAIssueInstallation/request_signed_under_v2`
- `--- FAIL: TestCAIssueInstallation/hint_missing`
- `--- FAIL: TestCAIssueInstallation/hint_mismatch`
- `--- FAIL: TestCAIssueInstallation/hint_unknown`
- `--- FAIL: TestCAIssueInstallation/hint_malformed_with_flag`

Passing on R1, as planned: TestIssueRequestSigningVector/{v1_bytes, v2_derived_from_v1} (the v1 path and the files themselves); TestIssueRequestV2/{v1_body_parses_as_today, truncated_id_refused} (R1 refuses every byte after the evidence); TestIssueInstallation/{v1_issues_where_bundle_names_none, v2_issues_for_own_installation} (the field is ignored on R1); TestCAIssueInstallation/no_hint_malformed_without_flag (no hint exists on R1); TestIssueRequestBytesUnchanged. Each RED case failed for its own reason: the signer cases with `request issued`, except installation_checked_before_evidence (`evidence_not_admin, want issue_installation_mismatch`) and classified_unauthorized (`classified internal`); the CLI cases with exit 1 instead of 2, an ID-less body, or no hint.

### T1 (`75213ed`, fix(signer): name the installation in admin issue requests (F15))

- internal/wire/issue.go: check() refuses a non-empty ID that is not trust.IsInstallationID; `domain()` and `Namespace()` as revoke's; SigningBytes = domain, then (v2) the ID uint16-length-prefixed, then addFields; Marshal appends the ID after the evidence; ParseIssueRequest reads remaining bytes as the ID (readBytes16, limit maxRevokeInstallationID = 64) with plain ErrMalformed for a truncated read, `an empty installation ID field`, `bytes after the installation ID`, then check(). Doc comments of IssueRequestDomain, AdminSSHSIGNamespace and EvidenceAdminSSHSIG name the v1/v2 rule.
- internal/signer/issue.go: the installation switch right after request_time_skew and before verifyAdminEvidence (issue_installation_missing, _mismatch, _unknown; CodeRefused); Issue's doc comment names the rule. evidence.go verifies under req.Namespace(). refusal.go classifies the three details ReasonUnauthorized under `// Issue installation binding (03-14d, F15; the T-03-20 rule).`.
- cmd/keyroster/ca.go: a malformed `--installation-id` is a usage error (exit 2) before warnCustody, the first socket contact; evidence under req.Namespace(); `issueInstallationHint` adds the output contract's hint and `; nothing was issued` to the three details and to malformed_request when the flag was set, keeping the signer's text (`signer refused: issue_installation_missing: <hint>; nothing was issued`).
- T1 changes no test, no vector and no fuzz seed (`git diff --name-only $R1 $T1 -- '*_test.go' 'test/vectors'` empty).

### Task 1 verify

1. First verify command (`-race` named runs, wire and cmd packages, 20 s fuzz, `go vet ./...`, gofmt): exit 0, every required `--- PASS:` line present, no FAIL or DATA RACE. Whole-package reads in it: internal/wire 8.277s, cmd/keyroster 325.675s (pass or fail only).
2. Whole internal/signer under `-race -timeout 15m`: `ok ... 470.319s` (pass or fail only, Q-09-3).
3. RED from a detached worktree of R1: passed (above).
4. Static checks (TestIssueRequestBytesUnchanged byte for byte origin/main's; no `wire.AdminSSHSIGNamespace` in non-test code; per-file v1/v2 naming; EvidenceAdminSSHSIG's doc names AdminSSHSIGNamespaceV2; T1 touches no test or vector): `VERIFY4-OK` on 75213ed.

### Mutants (Task 1)

Each applied to the working tree of T1, run with `bash scripts/linux.sh 'go vet <pkg> && go test -count=1 -timeout 5m -v -run "<RX>" <pkg>'` (RX: wire `^(TestIssueRequestSigningVector|TestIssueRequestV2)$`, signer `^TestIssueInstallation$`, cmd `^TestCAIssueInstallation$`), vet exit 0 every time, no `[build failed]` or `[setup failed]`, no timeout; the file restored with `git checkout --` and its sha256 checked, `git status` clean apart from .planning/config.json. Unmutated: all three commands `ok` on 75213ed.

| Mutant | Change | `--- FAIL:` lines |
|---|---|---|
| M1-1 | drop the mismatch branch | TestIssueInstallation/request_for_other_installation_refused, /installation_checked_before_evidence |
| M1-2 | refuse v1 also where the bundle names none (`case req.InstallationID == ""`) | TestIssueInstallation/v1_issues_where_bundle_names_none, /v2_frame_stripped_to_v1_refused |
| M1-3 | SigningBytes leaves out the ID (domain stays v2) | wire run: TestIssueRequestSigningVector/v2_bytes; signer run: TestIssueInstallation/id_rewritten_refused; table run (Task 2): TestSignedRequestsBindInstallation/types, `IssueRequest: signing bytes do not name the installation` |
| M1-4 | verifyAdminEvidence under wire.AdminSSHSIGNamespace | TestIssueInstallation/request_for_other_installation_refused, /id_rewritten_refused, /v2_issues_for_own_installation, /v1_signature_refused_as_v2 |
| M1-5 | classify drops issue_installation_mismatch | TestIssueInstallation/request_for_other_installation_refused, /installation_checked_before_evidence, /classified_unauthorized |
| M1-6 | Parse accepts an empty trailing ID | TestIssueRequestV2/trailing_empty_id_refused |
| M1-7 | Parse accepts bytes after the ID | TestIssueRequestV2/trailing_bytes_after_id_refused |
| M1-8 | ca issue ignores the flag | TestCAIssueInstallation/request_signed_under_v2 |
| M1-9 | ca issue drops the older-signer hint | TestCAIssueInstallation/hint_malformed_with_flag |
| M1-10 | drop the missing branch | TestIssueInstallation/v1_refused_where_bundle_names_one |
| M1-11 | drop the unknown branch | TestIssueInstallation/v2_refused_where_bundle_names_none |
| M1-12 | the installation switch moved below verifyAdminEvidence | TestIssueInstallation/installation_checked_before_evidence |
| M1-13 | ca issue drops the issue_installation_unknown hint | TestCAIssueInstallation/hint_unknown |

Restored sha256 (= HEAD blobs): internal/wire/issue.go d411347b…6cff62, internal/signer/issue.go cc0a7c27…20e696, evidence.go c8eeb668…6617c6, refusal.go 896ec1c5…c9028d07, cmd/keyroster/ca.go 6275a19e…d2950b7.

### Deviations (Task 1)

- T1 was amended once before any push (bdeb820 → 75213ed): verify 4 found that internal/signer/issue.go's new comment named only `keyroster/issue-request/v1`; the comment now names v2 too. Comment-only; verify 1 and 2 ran on bdeb820's code, gofmt and vet re-ran on 75213ed, and the mutants and their unmutated controls ran on 75213ed.
- None in the plan's scope otherwise; no reviewed-and-unedited site needed an edit (the whole-package signer run passed).

## Session 2 (Task 2, then Task 3)

### Test-time base, re-measured (Q-09-3, another session)

- Session 1's line, `test-time base: cmd=304.504 signer=427.195 wire=8.634 at=1794543399`, was replaced in place by `test-time base: cmd=271.873 signer=396.207 wire=8.610 at=1794545368`.
- Measured in a detached worktree of origin/main 62b4407 outside the repository (removed afterwards), go1.27.4, load average 0.01 at the start: the same command, started at 1794544963, ended at 1794545368 (`at=` is the end, as in session 1).
- Caveat: while it ran, this session wrote internal/wire/installation_test.go and ran `gofmt`, `go vet ./internal/wire/` and one 1 s `go test -run` of internal/wire in the main checkout. Every reading came in at or below session 1's, so the base is not inflated, and it was not re-measured.

### R2 (`79fd250`, test(wire): classify every keyroster/ tag and signed request type by installation binding (F15))

R2 declares nothing. Files: internal/wire/installation_test.go (new) and test/e2e/bootstrap_test.go, negative_test.go, pkcs11_test.go and stall_test.go. Every name in the new file carries a `bind` prefix; `go/token` is imported as `gotoken`, because package wire has a package-level `token` (status.go:26). There is no T2: the test passes on T1's code.

**Signed request types found** (every SigningBytes receiver in internal/wire, pointer receivers all): IssueRequest, RevokeRequest, ForgetRequest, RecoveryRequest, HostIssueRequest, ProbeIssueRequest, MachineIssueRequest (templated, bound) and LoginIssueRequest (exempt, Q-C8, with the plan's reason). The D5 names on origin/main are HostIssueRequest, ProbeIssueRequest and MachineIssueRequest, each with `InstallationID string`. RecoveryRequest's SigningBytes returns `([]byte, error)` and calls Validate; its template passes.

**Tags found: 19 values** (the 18 of 62b4407 plus `keyroster/issue-request/v2`), each classified by value:

| Tag | Class and reason |
|---|---|
| `keyroster/issue-request/v2` | bound, IssueRequest (raw) |
| `keyroster/revoke-request/v2` | bound, RevokeRequest (raw) |
| `keyroster/revoke-recovery/v1` | bound, RecoveryRequest (raw) |
| `keyroster/host-forget-request/v1` | bound, ForgetRequest (raw) |
| `keyroster/host-issue-request/v1` | bound, HostIssueRequest (raw; also its PoP namespace, an alias) |
| `keyroster/probe-issue-request/v1` | bound, ProbeIssueRequest (raw; also its PoP namespace) |
| `keyroster/machine-issue-request/v1` | bound, MachineIssueRequest (raw; also its PoP namespace) |
| `keyroster/issue-request/v1` | bound where the bundle names one: accepted only where the signer's bundle names no installation (Q-C2 A); IssueRequest (raw), checked with InstallationID cleared |
| `keyroster/directory/v1` | bound outside internal/wire, classified, not proven: TestCheckInstallation |
| `keyroster/krl/v1` | bound outside internal/wire, classified, not proven: TestVerifyManifest/other_installation_refused |
| `keyroster/agent-enroll/v1` | bound outside internal/wire, classified, not proven: TestPoP/other_installation_refused |
| `keyroster/trust-bundle/v1` | bound outside internal/wire, classified, not proven: installation_id optional; carried unchanged by VerifySuccessor (TestInstallationIDSuccessor) |
| `keyroster/revoke-request/v1` | refused since 03-03, read by audit |
| `keyroster/policy/v1` | not a request tag: bound through the bundle's policy_sha256 |
| `keyroster/log-leaf/v1` | not a request tag: the log key's own domain |
| `keyroster/log/` | not a request tag: the log key's checkpoint origin (two literals, tlog.OriginPrefix and trust.LogOriginPrefix) |
| `keyroster/login-request/v1` | exempt, owner-recorded (Q-C8) |
| `keyroster/admin-api/v1` | exempt, owner-recorded (Q-D1 = A): an exact origin from the root-verified policy; assumes each installation has its own hostname (reasoned, UNVERIFIED) |
| `keyroster/agent-identity/v1` | exempt, owner-recorded (Q-D1 = A): only over mTLS, from the old identity that signs it, bound to the installation at enrollment (enroll.PoP) |

Every bound wire tag is `raw`, as expected at 62b4407. The walk found no tag beyond these. The four tests named for the tags outside internal/wire exist (`git grep`: hosts_test.go:488, krl_test.go:461 and :482, pop_test.go:72 and :109, trust/installation_test.go:93).

**e2e call sites** (all pass `--installation-id` within four lines of `"ca", "issue"`, except the marked one):
- bootstrap_test.go:343, runIssue, `"--installation-id", e.InstallationID` in the same list (its doc comment names it);
- negative_test.go:403 (ca_issue_without_admin_key, still exit 2 on the missing admin key) and :414 (ca_issue_with_non_admin_key), `env.InstallationID`;
- negative_test.go:443, TestTrustRefuses/issue_names_installation/without_flag_refused: the one no-flag site, marked `// no --installation-id on purpose (03-14d)`;
- negative_test.go:451, .../other_installation_refused, `ffffffffffffffffffffffffffffffff`;
- .../own_installation_issues goes through runIssue (env.issue);
- pkcs11_test.go:630 (e2e_pkcs11), `env.InstallationID`; stall_test.go:208, `env.Signer.InstallationID`.
- The new subtest reuses TestTrustRefuses's second bootstrapSigner env and its own user key `id_installation`; no bootstrapSigner call was added. TestTrustRefuses's doc comment names the installation refusals. `git grep '"issue"' -- test/e2e` finds no other caller, and the only e2e use of `wire.AdminSSHSIGNamespace` is login_refusal_test.go:175's deliberate wrong input (unknown_evidence_type).

### Task 2 verify

1. First command (`-race` named run, whole internal/wire, vet under e2e, e2e_pkcs11 and e2e_tpm, gofmt): exit 0; `--- PASS: TestSignedRequestsBindInstallation/types`, `/tags` and `/diff_logic` present; internal/wire `ok` 9.599s.
2. RED from R2's committed file on a worktree of origin/main: passed (exit 0). Exactly two diagnostic lines:
   - `installation_test.go:127: IssueRequest has no InstallationID string field`
   - `installation_test.go:173: classified tag not found keyroster/issue-request/v2`

   with `--- FAIL: TestSignedRequestsBindInstallation/types`, `--- FAIL: .../tags` and `--- PASS: .../diff_logic`; no `[build failed]`, no timeout.
3. Scope and call sites (`T1=75213ed R2=79fd250`): exit 0. Seven `"ca", "issue"` lines, one marker line.

### Mutants (Task 2)

Run with `bash scripts/linux.sh 'go vet ./internal/wire/ && go test -count=1 -timeout 5m -v -run "<RX>" ./internal/wire/'`, RX `^(TestSignedRequestsBindInstallation|TestForgetRequestSigningVector)$` (M1-3's re-run: `^TestSignedRequestsBindInstallation$`). The unmutated control passes on 79fd250. Each mutant compiled and vetted (exit 0), with no `[build failed]` or `[setup failed]` and no timeout. Each file was restored with `git checkout --`, its sha256 checked against the value before the mutant, and `git status` showed only .planning/config.json.

| Mutant | Change | `--- FAIL:` lines and message |
|---|---|---|
| M2-1 | forget.go addFields leaves out `addBytes16(b, []byte(r.InstallationID))` | TestSignedRequestsBindInstallation/types (`ForgetRequest: signing bytes do not name the installation`), TestForgetRequestSigningVector |
| M2-2 | `const exampleDomain = "keyroster/example/v1"` appended to status.go | TestSignedRequestsBindInstallation/tags (`unclassified tag keyroster/example/v1 (wire, internal/wire/status.go:188:23)`) |
| M2-3 | `type ExampleRequest struct{ InstallationID string }` with a SigningBytes method appended to status.go | TestSignedRequestsBindInstallation/types (`unpinned signed request type ExampleRequest`) |
| M1-3 (re-run against the table) | IssueRequest.SigningBytes leaves out the ID (domain stays v2) | TestSignedRequestsBindInstallation/types (`IssueRequest: signing bytes do not name the installation`) |

`pinned type not found` has no production mutant (removing a SigningBytes method breaks package wire's own tests); `diff_logic` exercises it. Restored sha256: forget.go 98fe0789…fe22980, status.go 45d0c33f…bf62873, issue.go d411347b…6cff62.

### Task 3

**Precondition and stop guard** (after `git fetch origin`, origin/main still 62b4407): both pointer anchors occur exactly once on origin/main; 03-14c's SUMMARY is on main, 03-12 is at wave 31 with ["03-14c"], and 03-14c is the only plan at wave 30.

**Commits:**
- 963a3af `docs(runbooks): name the installation in admin issue requests and record the format (F15)`.
- 1423243 `docs(03-14d): publish the plan, point 03-12 at it, and shift the later waves`. It adds this plan unchanged (blob 75b2a3db, the private plan's bytes).

**Runbook texts** (line numbers at 963a3af; each new text names its CI tests or sits in the paragraph that does, and carries its UNVERIFIED labels):
- signer-install.md:214, a change. Old: `keyroster ca issue --admin-key SHA256:<alice admin key> \`. New: `keyroster ca issue --installation-id <installation id> --admin-key SHA256:<alice admin key> \` (the continuation line is unchanged).
- signer-install.md:218, new paragraph: what `<installation id>` is (the installation id line of the ceremony transcript, its Installation ID line since 03-14c, of `keyroster init` or of `keyroster trust verify`), and never taken from the signer.
- signer-install.md:224, new paragraph: the three refusals before any CA key, the hint and "nothing was issued", a pre-D-04 bundle accepts the request without the flag, and "leave out the flag only after `keyroster trust verify` shows `installation id: none` for the installation you mean to approve".
- signer-install.md:235, new paragraph: "**Upgrade order:** upgrade keyroster-signer and keyroster together before admins pass `--installation-id` ...", the older signer's malformed_request (reasoned from the parser and TestSignerFraming's trailing_byte case), the older CLI without a hint, "Run in CI: TestIssueInstallation, TestCAIssueInstallation and TestTrustRefuses/issue_names_installation (e2e)", and UNVERIFIED on the homelab signer until 03-15 and for an upgrade with a real older signer or CLI.
- test/manual/README.md:69-73, a change. Old: ``for example with `keyroster ca issue --ca user --pubkey test.pub --principal NAME --subject u:windows-check --ttl 12h --admin-key SHA256:...`, and again with ...``. New: ``for example with `keyroster ca issue --installation-id <installation id> --ca user --pubkey test.pub --principal NAME --subject u:windows-check --ttl 12h --admin-key SHA256:...` (the flag is needed where the signer's trust bundle names an installation ID, since 03-14d), and again with ...`` (rewrapped).
- No test pins either example (`git grep 'ca issue' -- test/e2e cmd/keyroster/*_test.go` and the runbook tests: TestRunbookGoToolchain reads signer-install.md for Go versions only).

**Registry** (docs/format-registry.md, on origin/main since 5ec5ff9):
- :134, a change. Old: `| `keyroster/issue-request/v1` | domain and SSHSIG, admin issue request | ...`. New: `... | domain and SSHSIG, admin issue request without an installation ID; accepted only where the signer's bundle names none (03-14d) | ...`.
- :135, new row: `keyroster/issue-request/v2`, `wire.IssueRequestDomainV2`, `wire.AdminSSHSIGNamespaceV2`.
- :199, new last row of the installation-binding table: Issue request v2 (`wire.IssueRequest`, internal/wire/issue.go), `InstallationID`, policy admins (SSHSIG).
- :217, a new paragraph after the "Since 03-14c" paragraph and before `## Reserved names`: the recorded exceptions (v1 issue requests, LoginIssueRequest Q-C8, adminauth.Message and the agent-identity rotation, Q-D1 = A) and the TestSignedRequestsBindInstallation sentence.
- No leaf kind or message type allocated; TestFormatRegistry (internal/tlog) passes.

**Pointers and publish edits:** numstat 03-12 `4 4` (wave 32, depends_on ["03-14d"], the precondition clause, the pointer), 03-13 `1 1` (33), 03-14 `1 1` (34), 03-15 `2 2` (35, the pointer), 03-16 `1 1` (36). ROADMAP: `31/37 plans executed in 36 waves`, the new Wave 31 block with the unchecked 03-14d row, blocks 32 to 36, Progress row `31/37`. STATE: `total_plans: 72`, `completed_plans: 66`, `Plan: 31 of 37`. Verify commands 4 and 5 exit 0.

**Delta gate** (verify command 2, the plan's exact command, at 1423243's tree; this session's base, cmd 271.873 / signer 396.207 / wire 8.610; load average 0.06 at the start, started 1794545956, ended 1794546361): cmd/keyroster 255.616 s (-16.3), internal/signer 400.872 s (+4.7), internal/wire 10.758 s (+2.1). It exits 0.

**Full gate** (verify command 3, at 1423243's tree, started 1794546373, ended 1794547156): exit 0. `go test -race ./...` reported 36 ok (cmd/keyroster 295.410 s, internal/signer 495.104 s, internal/agent/apply 620.584 s, internal/wire 14.773 s, internal/tlog 5.626 s; pass or fail only). Every vet tag passed (e2e, e2e systemdsmoke, e2e_pkcs11, e2e_tpm), and so did gofmt, golangci-lint (`0 issues.`), capslock, dep-firewall, testonly-firewall and check-pinned-actions (51 pinned uses). capslock reports no new pair. keyroster-signer reads 91 against a baseline of 92: `internal/signer CAPABILITY_RUNTIME` is no longer reported. That stale pair predates this plan, as 03-14c recorded.

**PR #101**, https://github.com/Labontese/keyroster/pull/101, opened by keyroster-bot with the plan's title, the limits as one-line bullets, and no auto-merge. The branch was pushed at 1423243 first. The privacy, IP and title gate (verify command 9), the no-auto-merge check and the authorship and signature check all exit 0.

**First CI run at 1423243: two real failures, fixed by two commits (Rule 1 and Rule 3).**
- **lint (GOOS=windows):** `internal/signer/issue_installation_test.go:54:7: undefined: certOf (typecheck)`. R1's `issuesUnder` used recovery_test.go's `certOf`, and recovery_test.go is `//go:build linux`, so internal/signer's tests did not type-check on Windows. The local full gate lints for linux only, so it could not see this. Fix 7c52821, `test(signer): build the installation tests on every GOOS (F15)`: issuesUnder parses the certificate itself. After it: `GOOS=windows` and `GOOS=darwin` go vet of internal/signer, internal/wire and cmd/keyroster, and `GOOS=windows` / `GOOS=darwin` golangci-lint over `./...`, all pass (`0 issues.`), and TestIssueInstallation passes under -race (all ten cases).
- **systemd-sandbox:** test/systemd/smoke.sh issues through `keyroster ca issue` on a genesis bundle that names an installation, and was refused `issue_installation_missing: ... pass --installation-id; nothing was issued`. The plan's inventory listed only the test/e2e callers, so this is a caller it missed (Task 2's grep was scoped to test/e2e). Fix a9a197f, `test(systemd): name the installation in the smoke test's ca issue (F15)`: the script reads `installation_id` from the signed bundle.json, fails if it is empty, and passes `--installation-id` to both of its ca issue calls (kradmin's issue and the outsider's socket-permission refusal). Checked with `bash -n` and the sed extraction on compact and pretty JSON; the run itself is CI only.
- Neither fix touches production code. The delta gate and the full gate above ran at 1423243; after the two fixes, only the vet, lint and named-test runs above were repeated locally.
- A `git grep 'keyroster ca issue' -- docs` finds only prose mentions without a full command (revoke.md, pkcs11.md, custody.md, needs-hardware.md); the plan changes only the two examples, and those stay unchanged.

**CI at HEAD a9a197f (PR #101): every check green.** Run IDs:
- e2e 43375495222: main lanes e2e (9.5p1) and e2e (10.5p1), probe lanes e2e-probe (9.5p1) and (10.5p1);
- ci 43375495176: build-test, lint, fuzz, capslock, govulncheck, dependency-firewall, cli-windows, cli-macos;
- systemd-sandbox 43375495318; e2e-distro 43375495115 (all seven distros); e2e-pkcs11 43375495426 (10.5p1-ed25519, distro-p256); e2e-tpm 43375495127; build-piv 43375495201; CodeQL 43375495137; pinned-actions 43375495129; pr-title 43375495368.

No rerun was needed; no known flake occurred.

The final CI verify passed: required checks; cli-windows and cli-macos both `pass`; the house e2e gate in MODE=pr (03-10b's script with 03-11b's PROBE_PASS list) exits 0 for run 43375495222, whose headSha is HEAD. Readings:
- main lanes' `go test`: 9.5p1 750.187 s, 10.5p1 771.871 s, against the 900 s stop (780.827 s and 803.970 s at e38d6b3);
- probe lanes: 276.524 s and 274.179 s, against the 420 s cap.

Both main lanes print `--- PASS: TestTrustRefuses/issue_names_installation (0.02s)` and its three cases, `/without_flag_refused`, `/other_installation_refused` and `/own_installation_issues` (0.01s each). Auto-merge stays off.

**More ca issue call sites.** Besides the e2e sites listed under R2, a9a197f changed test/systemd/smoke.sh: :227 (kradmin's issue) and :243 (the outsider's socket-permission refusal) now pass `--installation-id "$installation_id"`, read from the signed bundle.json at :205.

**Unchanged v1 controls, green and unedited:**
- TestIssueRequestBytesUnchanged and TestCAIssueAdminEvidence (its request names no ID, so it stays v1);
- the trailing-byte cases of TestParseIssueRequestRefusals and TestSignerFraming;
- the tests that use the v1 tag or namespace as a wrong input: internal/wire/wire_test.go, internal/adminauth/adminauth_test.go, internal/server/admin_test.go, internal/audit/verify_test.go, internal/signer/revoke_test.go and login_test.go, and test/e2e/login_refusal_test.go.

The named ones passed in session 1's first verify. All of them passed in the local full gate at 1423243 and in CI at a9a197f (build-test under -race; both e2e main lanes).

**Threat IDs:** T-03-359 to T-03-362 are free as register rows (session 1's precondition check), so no renumbering was needed.

**requirements-completed:** left empty. REVOKE-01 and AUTH-06 are complete (03-11b), and AGENT-06 is pending, owned by its PoP plans. This plan pins their binding and hardens KEY-02.

**What stays UNVERIFIED:**
- every runbook text on the homelab, until its bundle names an installation at 03-15;
- the e2e cases and the systemd smoke test locally: they ran in CI only;
- the LoginIssueRequest exemption across installations (reasoned, not tested);
- the adminauth and agent-identity exemptions across installations (reasoned, not tested);
- an upgrade with a real older binary: a v2 request to a real pre-03-14d signer (reasoned from TestSignerFraming's trailing_byte case), and an older CLI against an upgraded signer.

**Mutants after 7c52821:** that commit rewrote issuesUnder, the helper behind the cases that killed M1-2 and M1-4, to parse the certificate inline. The behaviour is the same, and TestIssueInstallation passes, so those mutants were not re-run.

**PR body:** it was written before 7c52821 and a9a197f, so it does not mention the smoke-test fix. It was left unedited so that no edit event re-triggers the workflows pinned to HEAD.

## Pre-merge review

**Run and outcome.** The review ran as workflow run wf_7924ba55-26c on PR #101 at a9a197f: four Opus lenses, a Codex lens at high, two Sonnet skeptics per review item and an Opus critic. Outcome: no confirmed defect. One item was refuted, and two items split 1/2 (low, documentation only); the orchestrator checked both against the code, the facts hold, and both were fixed so the docs claim no more than the code does. No code, test or vector changed in the fix round.

**D1 and D2** (one commit, 036c5f0 `docs(runbooks): state what the classification test and the older-CLI refusal cover (F15)`):
- D1, docs/format-registry.md:217 (the recorded-exceptions paragraph). Old: TestSignedRequestsBindInstallation "classifies every keyroster/ string literal in the module and every signed request type in internal/wire". New: "... every keyroster/ string literal in the module's non-test code under internal/ and cmd/, and every signed request type in internal/wire". The `tags` subtest (internal/wire/installation_test.go) walks only the non-test .go files under internal/ and cmd/, as the test's own comments say.
- D2, docs/runbooks/signer-install.md, the upgrade-order paragraph. Old: "A keyroster CLI older than the signer cannot send the flag and is refused `issue_installation_missing` without a hint: upgrade it." New: "A keyroster CLI older than the signer cannot send the flag: where the signer's bundle names an installation ID it is refused `issue_installation_missing` without a hint, so upgrade it." internal/signer/issue.go refuses a flagless v1 request only where the bundle names an ID, and TestIssueInstallation/v1_issues_where_bundle_names_none pins that it still issues elsewhere.
- Strings the tests pin were left intact, in their order (the plan's runbook checks: `upgrade keyroster-signer and keyroster together before admins pass --installation-id`, `Run in CI`, UNVERIFIED, `TestSignedRequestsBindInstallation`, `bound to the installation at enrollment`).
- Run after the edit, through scripts/linux.sh with `-timeout 15m`: cmd/keyroster, internal/tlog and internal/wire (whole packages, which include TestFormatRegistry, TestHostTrustRunbooks, TestRepinInstructionsKeepIdentity, TestRootCeremonyPolicyChecks and TestSignedRequestsBindInstallation) all `ok`; the e2e tests that read signer-install.md (`go test -tags e2e -run TestRestore ./test/e2e/` with KEYROSTER_OPENSSH_PREFIX at the 10.5p1 build: TestRestoreRunbookChecks, TestRestoreReplaysLostDirectory and the restore drills) `ok` in 43 s.

**Refuted.** The classification test accepts a table entry with neither a template nor an exemption reason. Not fixed: a nil-template entry is a reviewed table edit, and the plan's classification relies on review for the labels (the table is the reviewed artifact; the test's job is that no tag or signed type is unclassified and that a templated type's bytes change with its installation ID).

**Commits added after the executor's report:**
- 7c52821 `test(signer): build the installation tests on every GOOS (F15)`;
- a9a197f `test(systemd): name the installation in the smoke test's ca issue (F15)`;
- 036c5f0 `docs(runbooks): state what the classification test and the older-CLI refusal cover (F15)`;
- the complete commit, `docs(03-14d): complete issue-installation plan`, which carries this SUMMARY, STATE.md, ROADMAP.md and the tracking totals. The frontmatter's `commits: 8` and `plan_head_after` count and end at 036c5f0, the head before that commit; the complete commit makes nine.

**Tracking update** (run once, after this section): `state.advance-plan`, `state.update-progress`, `roadmap.update-plan-progress 3`. Totals after it: the Plans line `32/37 plans executed in 36 waves`, the Progress row `32/37`, `total_plans: 72`, `completed_plans: 67` and `Plan: 32 of 37`.

**CI and the house e2e gate.** The readings above are for a9a197f. The commits after it change documentation only (D1, D2, this SUMMARY and the tracking files), so the final head's CI run IDs and the house e2e gate readings for it are in the PR and the hand-over report, not here; this file cannot cite the run of its own commit.

**Deviation (private term, as 03-14c's):** the 03-15 line that carries the pointer anchor names the owner's lab Windows host, as written on main. In that line only, "On <host>:" became "On the owner's Windows PC:", the same substitution 03-14c made in that file's step 2. The numstat stays `2 2`; the commit was amended before its first push (29d3946 became 1423243).

## Hand-over (session 1 stopped after Task 1)

- Session 1 did Task 1 only, as the Budget plans. The continuation starts at Task 2 (R2: internal/wire/installation_test.go and the e2e callers), then Task 3 and Task 4.
- Branch `p03/14d-issue-installation` holds R1 c7d2741 and T1 75213ed on origin/main 62b4407, pushed to origin with upstream set (`env -u GITHUB_TOKEN -u GH_TOKEN git push -u origin p03/14d-issue-installation`). No PR is open; Task 3 opens it.
- The plan file is untracked in the phase directory (never edit it); Task 3's publish step commits it. This SUMMARY draft is untracked too.
- The test-time base above was measured in this session's WSL boot; Task 3's delta gate must re-measure it first on origin/main in a detached worktree outside the repository and replace the line in place (Q-09-3, another session).
- Mutant tooling used here was ad hoc (a perl exact-replace and a runner); nothing of it is in the repository.
- Admin issue callers outside the plan's packages: `git grep -n -E '(^|[^A-Za-z])wire\.IssueRequest\{|ParseIssueRequest\(|wire\.IssueRequestDomain\b' -- '*.go' ':!internal/wire/' ':!internal/signer/' ':!cmd/keyroster/'` finds none, and the only other `Issue(` caller is signerclient itself; test/e2e reaches ca issue through the CLI (Task 2).
- Expected CI state of the pushed branch: e2e fails at T1 until R2 lands, because the e2e genesis always names an installation and runIssue and the direct `"ca", "issue"` calls send no `--installation-id` yet (they are refused issue_installation_missing). Do not read that as a flake or a regression. No workflow run was checked (gh is not authenticated in this shell; scripts/gh-as-bot.sh is the route).
