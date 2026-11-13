# Number and format registry

This file owns every number and tag that keyroster's audit log or wire
protocol reads forever. A leaf kind, a message type or a domain tag, once
merged, keeps its meaning for as long as a log or a peer can hold it, so two
plans must never pick the same one.

`TestFormatRegistry` (internal/tlog/registry_test.go) reads the tables of
leaf kinds and wire message types below and fails when their numbers and
constant names disagree with the code, when a leaf kind's export name is
not `Kind.String`, when a request's "Answered with" is not a response row,
or when a "next free" sentence is stale. It does not check which response
the signer actually sends. The other sections are not checked by a test.
Keep them in step with the code by hand, in the same PR as the change.

## How numbers are allocated

- The next free number goes to the next plan that needs one, in merge order.
- A plan claims its number in its own PR by editing this file: a reserved
  row becomes `in use`, or a new row is added. The test then requires the
  code and this file to agree.
- A reservation names one planned plan. Only the reservations below exist.
  Plans that are drafted but not yet planned (Phases 4 and 5) hold no
  numbers. They take the next free number when they are planned and merged.
- A number is never reused, also after the feature that used it is removed.
  Its row stays, with status `retired`.
- serverdb and signerdb migrations (`internal/serverdb/migrations`,
  `internal/signerdb/migrations`) are not reserved here. A migration takes
  the next number at merge time, in merge order.

## Merkle log leaf kinds

Source: `internal/tlog/leaf.go` (the `Kind` constants, `Kind.String` and
`Kind.valid`). A reader that has no check for a kind refuses it, never
skips it. A kind is in use when it has a constant and `valid` accepts it.

| Kind | Status | Constant | Export name | Plan |
|---:|---|---|---|---|
| 1 | in use | `KindIssue` | `issue` | 01-05 |
| 2 | in use | `KindRefusal` | `refusal` | 01-05 |
| 3 | in use | `KindRefusalSummary` | `refusal_summary` | 01-05 |
| 4 | in use | `KindClockRegression` | `clock_regression` | 01-05 |
| 5 | in use | `KindCAInit` | `ca_init` | 01-05 |
| 6 | in use | `KindBundleInstall` | `bundle_install` | 01-05 |
| 7 | in use | `KindDirectoryInstall` | `directory_install` | 02-01 |
| 8 | in use | `KindLoginIssue` | `login_issue` | 02-01 |
| 9 | in use | `KindRevoke` | `revoke` | 03-01 |
| 10 | in use | `KindKRLPublish` | `krl_publish` | 03-01 |
| 11 | in use | `KindHostIssue` | `host_issue` | 03-09 |
| 12 | in use | `KindProbeIssue` | `probe_issue` | 03-10 |
| 13 | in use | `KindMachineIssue` | `machine_issue` | 03-11 |
| 14 | reserved | | | 03-12 (CA rotation) |
| 15 | in use | `KindRevocationRecovery` | `revocation_recovery` | 03-06b |
| 16 | in use | `KindHostForget` | `host_forget` | 03-08c |

The next free kind is 17.

## Wire message types

Source: `internal/wire/frame.go`. Every wire message type constant is a
byte constant in package wire named `Type` followed by a capital letter;
`TestFormatRegistry` fails on a byte constant there under another name. A
request type is below 0x80; its response type, when it has its own, is the
request type plus 0x80. A request that is answered with another request's
response (for example `TypeLoginIssueRequest`, answered with
`TypeIssueResponse`) leaves its own response number unused, and that
number stays free for it.

### Requests

| Type | Status | Constant | Answered with | Plan |
|---:|---|---|---|---|
| 0x01 | in use | `TypeIssueRequest` | 0x81 | 01-02 |
| 0x02 | in use | `TypeInstallDirectory` | 0x82 | 02-01 |
| 0x03 | in use | `TypeGetDirectory` | 0x83 | 02-03 |
| 0x04 | in use | `TypeStatus` | 0x84 | 02-05 |
| 0x05 | in use | `TypeLoginIssueRequest` | 0x81 | 02-01 |
| 0x06 | in use | `TypeRevokeRequest` | 0x86 | 03-01 |
| 0x07 | in use | `TypeGetKRL` | 0x87 | 03-01 |
| 0x08 | in use | `TypeGetBundle` | 0x88 | 03-07 |
| 0x09 | in use | `TypeGetDirectoryVersion` | 0x89 | 03-07 |
| 0x0A | in use | `TypeHostIssueRequest` | 0x81 | 03-09 |
| 0x0B | in use | `TypeProbeIssueRequest` | 0x81 | 03-10 |
| 0x0C | in use | `TypeMachineIssueRequest` | 0x81 | 03-11 |
| 0x0D | in use | `TypeForgetAgentRequest` | 0x8D | 03-08c |

The next free request type is 0x0E.

### Responses

| Type | Status | Constant | Plan |
|---:|---|---|---|
| 0x81 | in use | `TypeIssueResponse` | 01-02 |
| 0x82 | in use | `TypeInstallDirectoryResponse` | 02-01 |
| 0x83 | in use | `TypeGetDirectoryResponse` | 02-03 |
| 0x84 | in use | `TypeStatusResponse` | 02-05 |
| 0x86 | in use | `TypeRevokeResponse` | 03-01 |
| 0x87 | in use | `TypeGetKRLResponse` | 03-01 |
| 0x88 | in use | `TypeGetBundleResponse` | 03-07 |
| 0x89 | in use | `TypeGetDirectoryVersionResponse` | 03-07 |
| 0x8D | in use | `TypeForgetAgentResponse` | 03-08c |
| 0xFF | in use | `TypeError` | 01-02 |

## Other enumerations read forever

These are small closed sets with one source each. They follow the same
rules (append only, never reuse a number), but they are not checked by a
test. A plan that adds a value lists it here.

| Enumeration | Values today | Source |
|---|---|---|
| Refusal reason classes (refusal leaves) | 1 to 15 | `internal/tlog/leaf.go`, `Reason*` |
| Revoked entry kinds (revoke leaves) | 1 to 3 | `internal/tlog/leaf.go`, `Revoked*` |
| Wire error codes | 1 to 4 | `internal/wire/issue.go`, `Code*` |
| CA roles | 1 to 3 | `internal/wire/issue.go`, `CARole*` |
| Revoke targets | 1 to 4 | `internal/wire/revoke.go`, `Target*` |
| Revoke subject kinds | 1 to 3 | `internal/wire/revoke.go`, `Subject*` |
| Signed-note signature types | 0x01, 0x02 | `internal/tlog/notesig.go`, `SigType*` (C2SP signed-note values, not ours to allocate) |

## Domain-separation tags and SSHSIG namespaces

Every signed format keyroster defines is bound to one tag. A tag is
never shared by two formats, and a format change that verifiers must tell
apart takes a new version (`/v2`), as the revoke request did. Old versions
stay listed while audit still reads them.

"Domain" means the tag is prepended to the signing bytes (with a length
prefix or a zero byte, as the format says). "SSHSIG" means it is the
namespace of an SSHSIG signature. Several formats use the same string as
both.

| Tag | Use | Constant |
|---|---|---|
| `keyroster/issue-request/v1` | domain and SSHSIG, admin issue request | `wire.IssueRequestDomain`, `wire.AdminSSHSIGNamespace` |
| `keyroster/login-request/v1` | domain, login issue request | `wire.LoginRequestDomain` |
| `keyroster/revoke-request/v2` | domain and SSHSIG, revoke request | `wire.RevokeRequestDomain`, `wire.RevokeSSHSIGNamespace` |
| `keyroster/revoke-request/v1` | domain and SSHSIG, 03-01 revoke request; refused since 03-03, still read by audit | `wire.RevokeRequestDomainV1`, `wire.RevokeSSHSIGNamespaceV1` |
| `keyroster/revoke-recovery/v1` | domain and SSHSIG, revocation recovery | `wire.RecoveryRequestDomain`, `wire.RecoverySSHSIGNamespace` |
| `keyroster/host-forget-request/v1` | domain and SSHSIG, host forget | `wire.ForgetRequestDomain`, `wire.ForgetSSHSIGNamespace` |
| `keyroster/host-issue-request/v1` | domain and SSHSIG, host issue request | `wire.HostIssueRequestDomain`, `wire.HostPoPNamespace` |
| `keyroster/probe-issue-request/v1` | domain and SSHSIG, probe issue request | `wire.ProbeIssueRequestDomain`, `wire.ProbePoPNamespace` |
| `keyroster/machine-issue-request/v1` | domain and SSHSIG, machine issue request | `wire.MachineIssueRequestDomain`, `wire.MachinePoPNamespace` |
| `keyroster/log-leaf/v1` | domain, Merkle log leaf | `tlog.LeafDomain` |
| `keyroster/log/` | checkpoint origin prefix (plus 16 hex digits of the log key hash) | `tlog.OriginPrefix`, `trust.LogOriginPrefix` |
| `keyroster/trust-bundle/v1` | SSHSIG, root-signed trust bundle | `trust.NamespaceBundle` |
| `keyroster/policy/v1` | SSHSIG, root-signed policy | `trust.NamespacePolicy` |
| `keyroster/directory/v1` | SSHSIG, admin-signed directory | `directory.Namespace` |
| `keyroster/krl/v1` | SSHSIG, ops-key-signed KRL manifest | `krl.Namespace` |
| `keyroster/admin-api/v1` | SSHSIG, admin API request | `adminauth.Namespace` |
| `keyroster/agent-enroll/v1` | SSHSIG and the PoP `domain` field, host enrollment proof | `enroll.Namespace`, `enroll.Domain` |
| `keyroster/agent-identity/v1` | domain, agent TLS identity rotation | `serverclient.AgentIdentityDomain` |
| `keyroster tpm key probe` | digest signed once at start by a TPM CA key, never stored | `tpm.probeDigest` |

Evidence types and other prefixes:

| Tag | Use | Constant |
|---|---|---|
| `admin-sshsig/v1` | evidence type, an admin's SSHSIG | `wire.EvidenceAdminSSHSIG` |
| `webauthn-assertion/v1` | evidence type, a passkey assertion | `wire.EvidenceWebAuthnAssertion` |
| `host-pop/v1` | evidence type, a host key's SSHSIG over a host issue request; also the first evidence item of a probe issue request, under the probe namespace | `wire.EvidenceHostPoP` |
| `probe-pop/v1` | evidence type, the probe key's SSHSIG over a probe issue request, under the probe namespace | `wire.EvidenceProbePoP` |
| `machine-pop/v1` | evidence type, the machine key's SSHSIG over a machine issue request, under the machine namespace | `wire.EvidenceMachinePoP` |
| `kr-join-v1:` | join string prefix | `join.Prefix` |
| `kr1/`, `kr2/`, `kr3/` | key ID versions (see the key ID budget below) | `cert` (`keyIDPrefix`, `keyIDPrefixKr2`, `keyIDPrefixKr3`) |

## Refusal detail names

The single source is `classify` in `internal/signer/refusal.go`. It maps each
detail string the signer refuses with to its reason class. Every new detail
must be added there. The default branch is `ReasonInternal`, which the
signer answers with `CodeInternal`. On revoke, host forget, directory
install and the machine renew route keyroster-server answers that with 503
("signer unavailable"); on
login redeem it answers 400 "login not redeemable". Either way a detail
that is not classified reads as a signer failure instead of a refusal, to
the client and in the audit log's reason class.

## Installation binding

The rule: every signed request or document that could be replayed against
another installation must carry the installation ID of the trust bundle it
is for, in its signed bytes, and whoever checks the signature must refuse
one that names another installation. The rule applies to every new signed
format. The installation ID is `trust.Bundle.InstallationID` (32 lowercase
hex digits). Formats that carry it today include:

| Format | Field | Signed by |
|---|---|---|
| Revoke request v2 (`wire.RevokeRequest`, internal/wire/revoke.go) | `InstallationID` | a policy admin (SSHSIG) |
| Host forget request (`wire.ForgetRequest`, internal/wire/forget.go) | `InstallationID` | policy admins (SSHSIG) |
| Revocation recovery request (`wire.RecoveryRequest`, internal/wire/recovery.go) | `InstallationID` | a policy admin (SSHSIG) |
| Directory (`directory.Directory`, internal/directory/directory.go) | `installation_id` | policy admins (SSHSIG) |
| KRL manifest (`krl.Manifest`, internal/krl/manifest.go) | `installation_id` | the ops key (SSHSIG) |
| Host enrollment proof (`enroll.PoP`, internal/agent/enroll/pop.go) | `installation_id` | each host key (SSHSIG) |
| Host issue request (`wire.HostIssueRequest`, internal/wire/hostissue.go) | `InstallationID` | the requested host key (SSHSIG) |
| Probe issue request (`wire.ProbeIssueRequest`, internal/wire/probeissue.go) | `InstallationID` | the host key and the probe key (SSHSIG each) |
| Machine issue request (`wire.MachineIssueRequest`, internal/wire/machineissue.go) | `InstallationID` | the machine key (SSHSIG) |

The join token (`join.JoinToken`) also names the installation, but it is
not signed.

`HostIssueRequest` (03-09) carries it in its signing bytes, and the signer
and audit verify refuse a request without one or for another installation
(`host_issue_no_installation_id`, `host_issue_installation_mismatch`).
03-10's `ProbeIssueRequest` and 03-11's `MachineIssueRequest` (both
landed) fall under this rule too: each carries the installation ID in its
signing bytes, and the signer and audit verify refuse one without it or
for another installation (`probe_issue_no_installation_id`,
`probe_issue_installation_mismatch`; `machine_issue_no_installation_id`,
`machine_issue_installation_mismatch`). A new signed format adds a row
here in the PR that adds it.

Since 03-14c, `keyroster audit verify --installation-id` checks the installation ID of the trust bundle in force (and refuses an installation-bound log without that flag or --any-installation), and the CLI checks every served bundle against the installation ID its config pins (serverclient.Trust).

## Reserved names

Names reserved for probe certificates (03-10). They are refused everywhere else:

| Name | Reserved for | Rule |
|---|---|---|
| `keyroster-probe:` | principal prefix of a probe certificate (`keyroster-probe:<host>`) | `cert.Build` and `cert.CheckIssued` refuse it unless the profile is `certprofile.ProbeProfile` (`cert.ReservedPrincipalPrefix`, `ErrReservedPrincipal`). The signer refuses a new directory with a role principal that has it (`principal_reserved`) |
| `keyroster-probe` | the probe account on a host | the signer refuses a new directory that maps it as a host-group account (`account_reserved`; `cert.ReservedAccountName`) |
| `probe.` | key ID subject prefix of a probe certificate under `ca=machine` (`sub=probe.<host>`) | the signer refuses a new directory with a machine of that name and a machine request for one (`machine_name_reserved`, install and issuance); the signer and audit refuse a machine subject revoke of such a name (`subject_reserved`) (03-11) |

A directory already stored with such a name still loads and verifies. A login that would carry the prefix is refused at issuance.

## Key ID budget

sshd writes the certificate's key ID into the line it logs for every
certificate login, at log level INFO:

```
Accepted publickey for <user> from <address> port <port> ssh2: <type> <fingerprint> ID <key ID> (serial <serial>) CA <CA type> <CA fingerprint>
```

That line is built by `auth_log` and `format_method_key` in OpenSSH's
`auth.c`. `do_log` in `log.c` then escapes it with `strnvis`
(`VIS_CSTYLE|VIS_NL|VIS_TAB|VIS_OCTAL`, which can expand one non-printable
byte to up to four) and hands it to syslog as `syslog(pri, "%.500s",
fmtbuf)`. Anything after the first 500 bytes of the escaped line is cut
off. (Checked against openssh-portable `log.c`, `auth.c` and `auth2-pubkey.c`
at `master` commit f78fc73d3162, on 2026-11-05.)

Key IDs keyroster issues contain only printable ASCII (the grammar in
`internal/cert/keyid.go`), so `strnvis` does not expand them.

What the line costs besides the key ID, at most:

| Part | Bytes |
|---|---:|
| Fixed text (`Accepted publickey for `, ` from `, ` port `, ` ssh2: `, ` ID `, ` (serial `, `) CA ` and two spaces) | 62 |
| Certificate type (`ED25519-SK-CERT`, the longest) | 15 |
| Certificate fingerprint (`SHA256:` and 43 base64 characters) | 50 |
| CA type (`ED25519-SK`, the longest) | 10 |
| CA fingerprint | 50 |
| Port | 5 |
| Serial (a uint64 in decimal) | 20 |
| Address (an IPv6 address in text form, without a zone) | 45 |
| User name (32 bytes, the usual Linux login name limit; `auth_log` truncates it to 100 with `%.100s`) | 32 |
| **Total besides the key ID** | **289** |

For a security key (`-SK`) certificate, sshd appends
`, signature count = N` after the CA fingerprint: up to 30 bytes, recorded
by `auth2_record_info` in `auth2-pubkey.c` and added by
`format_method_key`. The budget leaves it out, because cutting it loses no
part of the key ID, the serial or the CA fingerprint.

So the key ID budget is **211 bytes**: 500 minus 289. With a 100-byte user
name, `auth_log`'s cap, it is 143 bytes.

The project's caps today (`internal/cert/keyid.go`):

- The subject is at most 64 bytes (`keyIDSubjectRE`), the request ID exactly
  32 hex digits, and policy, directory and serial at most 20 decimal digits.
  kr3: 64 bytes, and 70 for ca=machine subjects starting `probe.`.
- kr2 carries 1 to 16 role names (`MaxKeyIDRoles`) of at most 32 bytes each
  (`keyIDRoleRE`), joined by `+`.
- `MaxKeyIDLen` is 1024 bytes, the parser's upper bound.

| Key ID | Longest today | Within the 211-byte budget |
|---|---:|---|
| kr1, `ca=user` or `ca=host` | 167 | yes |
| kr1, `ca=machine` | 170 | yes |
| kr2 (`ca=user`), 16 roles of 32 bytes | 726 | no |
| kr3, `ca=host`, 64-byte subject | 192 | yes |
| kr3, `ca=machine`, 70-byte `probe.` subject | 201 | yes |

kr3 (03-09) is the key ID of certificates a host or machine obtains by
proof of possession:
`kr3/ca={ca}/sub={subject}/req={request id}/pol={policy}/dir={directory}/ser={serial}`,
with ca host or machine. Its subject is at most 64 bytes, as kr1's and
kr2's, except a ca=machine subject starting `probe.`, which may be up to 70
bytes (`probe.` and a 64-byte host name, 03-10's probe certificates). Only
those exceed 64 bytes, so every other kr3 subject stays revocable by
subject with wire's 64-byte grammar, and probes are never revoked by
subject (Q-09-8).

Everything in a kr2 key ID but the role names takes at most 199 bytes, so
at the longest subject and 20-digit numbers only 12 bytes of role names
fit; shorter subjects and numbers leave more. A longer key ID leaves sshd's
line without the CA fingerprint, the serial or the end of the key ID
itself. With a 100-byte user name (143 bytes left), a kr1 key ID at its
longest does not fit either.

The rule: the whole key ID, as sshd logs it, must stay within this budget.
Any change that adds a key ID field, lengthens one or adds a key ID version
updates this section in the same PR, with the new longest value.
