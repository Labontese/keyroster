# Runbook: revoke a certificate by serial

This runbook revokes one issued certificate. The admin signs a revocation
request; keyroster-server forwards it unchanged; the signer alone checks
the admin's signature, records the revocation in its audit log and
publishes a new KRL (OpenSSH Key Revocation List). Revocation is CLI only
(D-12): no web page offers it.

> **What a revocation does, and what it does not do yet.** The signer
> records it and publishes the next KRL version at once. A host refuses
> the certificate only once that KRL is in the file its sshd's
> `RevokedKeys` points to. In this version nothing puts it there: the
> keyroster agent that fetches, verifies and installs the KRL arrives
> with 03-05 to 03-07, and no keyroster command fetches and verifies the
> KRL for a hand install yet. Until a host has the KRL, the certificate
> keeps working there until it expires.
>
> This is for user and machine certificates (both are OpenSSH user
> certificates). A **host** certificate (`--ca host`) is different: sshd's
> `RevokedKeys` applies to user authentication only, so no host refuses
> to present its own revoked host certificate. Only an SSH client refuses
> it, once the KRL is in the file its `RevokedHostKeys` (ssh_config)
> points to. Nothing installs it there yet (the known-hosts sync arrives
> with 03-09). **UNVERIFIED**: no test revokes a host certificate and
> checks a client refusing it; the CLI's wording for `--ca host` ran in
> the CLI tests against a stub server (`TestRevokeSerialConfirm`).

> **What is tested and what is not.**
>
> - **Run in CI e2e** (`TestRevokeSerialEndToEnd`, 03-01, on OpenSSH
>   9.5p1 and 10.5p1): `keyroster init`, `keyroster revoke serial`
>   through keyroster-server to the signer, `GET /api/v1/krl`, the
>   manifest check against the root-pinned bundle, `ssh-keygen -Q` on the
>   candidate file, and real sshd refusing the revoked certificate after
>   the KRL file is swapped in, with no reload and no signal, while
>   another certificate keeps logging in.
> - **Run locally in 03-01**: the same test on OpenSSH 10.5p1 and 9.5p1
>   in WSL.
> - **UNVERIFIED until 03-16**: every homelab step. The homelab's trust
>   bundles v1 to v3 carry no installation ID, so the signer there refuses
>   every revocation (`krl_no_installation_id`) until the v4 ceremony
>   (03-15) adds one.

## Before you start

- You are an admin: your SSH key is one of the admins of the root-signed
  policy and is loaded in ssh-agent. `keyroster init` saved it as
  `admin_key`; `--admin-key SHA256:...` uses another key in the agent.
  One admin is enough, whatever the policy's admin quorum: revocation only
  ever removes access.
- The trust bundle in force carries an installation ID (`keyroster root
  sign` gives every genesis bundle one and prints it as
  `installation id: ...`; `keyroster root sign --prev ... --installation-id new`
  adds one to a successor of a bundle without). Without it the signer
  publishes no KRL. **UNVERIFIED**: that upgrade end to end (install
  such a successor with `install-bundle`, restart the signer, revoke). Only
  its parts are tested: `root sign --installation-id new`
  (`TestRootSignInstallationID`) and a successor that adds an ID passing
  the successor checks (`TestInstallationIDSuccessor`). The v4 ceremony
  rehearsal (03-15) installs and starts such a successor, and the homelab
  revocation drill (03-16) revokes under it.
- You know the certificate's serial and the CA that issued it. On a
  certificate file, `ssh-keygen -L -f id_ed25519-cert.pub` prints it as
  `Serial:`; keyroster key IDs end in `/ser=<serial>`, and sshd logs both
  on every login.

## 1. Revoke

```
keyroster revoke serial SERIAL --ca user --reason "laptop lost"
```

`--ca` is `user` (the default), `host` or `machine`. `--reason` is
printable ASCII, at most 256 bytes, and goes into the audit log with the
request. The command verifies the served trust bundle against your root
pins first, then signs the request in ssh-agent under
`keyroster/revoke-request/v2`. The request names the installation ID of
that bundle, so your signature revokes in no other installation: the
signer refuses a request for another installation
(`revoke_installation_mismatch`) and a 03-01 request under
`keyroster/revoke-request/v1`, which names none
(`revoke_installation_missing`). Run in CI (signer, audit and CLI tests,
03-03 pre-merge review).

Expected output:

```
The server reports serial 1792869357962865 (user) revoked: KRL v1792919647 published (log entries 5, 6).
Checked: the server serves KRL v1792919647, signed by the ops key of your root-pinned trust bundle (log entry 6), issued at 2026-10-25T09:14:07Z, at most 300 s before this request.
Not checked: that this KRL lists serial 1792869357962865 (this version cannot read a KRL). A KRL that another revocation published in those 300 s passes the same checks; the signer's "revoked" line (journalctl -u keyroster-signer) is the proof.
Hosts enforce it once their keyroster agent applies this KRL.
```

The two log entries are the `revoke` entry and the `krl_publish` entry,
written in one transaction with the revocation itself. The KRL version is
the publish time in seconds or the previous version plus 1, whichever is
larger, so it always grows and a restored signer with a correct clock
publishes above every version it lost (03-03). Run in CI e2e
(`TestRevokeSerialEndToEnd`, 03-01, versions since 03-03).

With `--ca host` the last line instead says that a host certificate is
checked by SSH clients, through `RevokedHostKeys`, and that nothing
installs the KRL there yet (see the box at the top).

The server's answer is not signed, and a compromised keyroster-server
could drop the request and answer success. So the command reads the
published KRL after the answer and requires its manifest to verify
against your root-pinned trust bundle and its installation ID, with at
least the reported KRL version and `krl_publish` entry, issued no more
than 300 s before the request (the signer refuses a request further than
that from its clock, and the manifest's `issued_at` is that clock
reading). If that fails it prints `the server reports serial N revoked,
but that could not be confirmed: ...` and exits non-zero; nothing tells
you whether the signer revoked, so check the signer host. This catches an
invented version, and an earlier genuine KRL replayed under an invented
answer when it was published more than 300 s before the request. It does
not catch a genuine KRL that another revocation published inside those
300 s: only reading the KRL for the serial would, which 03-03 adds. The
confirmation and each of its refusals ran in the CLI
tests against a stub server (`TestRevokeSerialConfirm`); the confirmed
path also runs in CI e2e.

## 2. Refusals

| What you see | Why | What to do |
|---|---|---|
| `the signer has issued no certificate with this serial` (`unknown_serial`) | The serial is not one this signer issued, or it is mistyped. | Check the serial. Revocation by key, for a certificate this signer did not issue, arrives with 03-03. |
| `... was not issued by that CA` (`ca_role_mismatch`) | `--ca` names another CA than the one that issued it. | Pass the right `--ca`. |
| `.../api/v1/admin/revoke: admin authentication failed` (HTTP 401) | keyroster-server refused the request's admin signature before the signer saw it: the key is not a policy admin, or your clock differs from the server's by more than 2 minutes (the CLI then adds `your clock differs from the server by Ns`). | Use an admin key from the root-signed policy (`--admin-key SHA256:...`), or fix the clock. |
| `the signer refused the revocation; nothing was revoked: ... HTTP 403: [peer text: "REASON"]` | The signer refused it for REASON. The one an operator can hit is `request_time_skew`: the request was created more than 5 minutes before the signer saw it (ssh-agent took that long to sign, say while waiting for a touch, or the clocks differ). | Run the command again; for another REASON, read the signer's log (`journalctl -u keyroster-signer`). |
| `the signer has already accepted a request with this ID` (`duplicate_request`) | The signer saw this request ID before; the CLI picks a fresh random one each run, so only a resent request gets this. | Run the command again. |
| `the server cannot reach its signer (HTTP 503) ... The signer's log names the reason` | The signer could not decide. Its log names `krl_no_installation_id` (the bundle in force has no installation ID), `krl_too_large` or `revocations_not_logged` (both below). | Read the signer's log (`journalctl -u keyroster-signer`). |

The CLI's text in every row ran in the CLI tests against a stub server
(`TestRevokeRefusalText`), the 401 row with a key that is not a policy
admin. Against the real server and signer, end to end, every row is
**UNVERIFIED**: the e2e test runs only a successful revocation. The
signer's own refusals ran in its unit tests (`TestRevoke`, among them
`no_installation_id_refused`, and `TestRevokeKRLTooLarge`); on the
homelab `krl_no_installation_id` is UNVERIFIED until 03-16.

A refusal by the signer is logged in its audit log: individually within
the refusal rate (10 a minute), otherwise only as a count in the next
`refusal_summary` entry, without the request. A request that
keyroster-server refuses itself (malformed, admin authentication, body
too large, rate limit, or 503 because it cannot reach the signer) never
reaches the signer, so the audit log has no entry for it; look in the
server's log instead (`journalctl -u keyroster-server`, which names
every admin authentication failure).

### `krl_too_large`

A KRL is at most 4 MiB, about half a million revoked serials that are not
adjacent to one another. A revocation whose KRL would be larger is refused
and rolled back, so the revocation table never holds an entry that no
published KRL carries. The remedy is an emergency CA replacement (03-13),
which makes every certificate of the old CA useless at once.
**UNVERIFIED**: the replacement procedure does not exist yet. The refusal
and its rollback ran in the signer's unit tests
(`TestRevokeKRLTooLarge`).

### `revocations_not_logged`

Every KRL is rebuilt from the signer's revocation table, which the signed
log does not anchor. Before the ops key signs a new KRL, the signer
requires the table to hold exactly the entries its revoke log entries
record. A row deleted, added or changed outside the signer (another
process writing the state database) is refused: nothing of the
revocation is kept, and the KRL in force stays published and served.
From then on the signer refuses every request that writes to the audit
log (issuance, login, revocation) until it is restarted; the unit test
checks issuance. On restart it refuses to start with the same reason, as
`keyroster-signer doctor` reports. Find and stop whatever
wrote the database. **UNVERIFIED**: no recovery procedure has been
written or run. The refusal ran in the signer's unit tests
(`TestRevocationsChangedWhileRunning`, `TestRevocationsNotLogged`).

## 3. Where the KRL is served

keyroster-server serves the published KRL to any TLS client at
`GET /api/v1/krl`: a JSON document with the KRL bytes, a canonical
manifest and the ops key's detached SSHSIG over it (namespace
`keyroster/krl/v1`). The signer publishes its first KRL, which revokes
nothing, the first time `serve` starts with a trust bundle that carries
an installation ID, before it accepts a request, so a 404 `no_krl` now
means the signer has not published yet: its bundle has no installation
ID, or that first publish failed (its log says why, and it tries again
every minute). From then on the signer publishes the next version by
itself whenever the last one is an hour old, with a fresh `issued_at` and
the same entries, so a reader can tell a KRL that stopped being updated
(D-10). An entry stays in the KRL until its certificate's ValidBefore +
300 s at the KRL's `issued_at`; an explicit key, and a key ID whose
certificate the signer has no record of, stay for good. The KRL keeps the
sections of CA keys the trust bundle no longer trusts until their entries
expire. Run in CI (internal/krl and internal/signer tests, 03-03). The
route needs no login, so keyroster-server keeps the
signer's last answer for up to 5 seconds and asks the signer at most
once for any number of requests in that time; a revocation through it
drops the copy before it answers, so the next read shows the new
version. The bytes are the signer's, unchanged. HTTP clients are told
not to cache it (`Cache-Control: no-store`). The cache ran in the
server's unit tests against a stub signer (`TestKRLCache`).

The server is not trusted for any of it. A reader accepts a KRL only when
the manifest's signature is by the ops key of its root-pinned trust
bundle, the manifest names the installation ID it pinned, its
`krl_version` is above the version it holds, and its `krl_sha256` is the
SHA-256 of the KRL bytes (`krl.VerifyManifest`). Run in CI e2e
(`TestRevokeSerialEndToEnd`, 03-01) through the CLI's pinned TLS client.
`keyroster revoke serial` runs this check after each revocation (step 1);
no command fetches the KRL for a hand install yet.

## 4. The audit log after a revocation

`keyroster audit verify` checks revoke and krl_publish entries since
03-03: each revoke entry against the admin-signed request it logs and the
certificates the log issued, and each published KRL against the one it
re-derives from the logged revocations. An older binary says "not
verifiable by this version" at the first such entry; that is not
tampering, use a current binary. Run in the audit and signer unit tests
(`TestVerifyRevocations`, `TestRevokeSubjectTracer`) and in CI e2e
(`TestRevokeSerialEndToEnd`); on the homelab UNVERIFIED until 03-16.

Always take a saved export after every revocation
(`keyroster-signer export-log`, kept off the signer VM): a signer restore
loses every revocation made after the latest saved export without a
trace, and the restore's check in
[signer-install.md](signer-install.md#a-restore-brings-back-the-older-trust-bundle-policy-and-directory)
cannot see it (T-03-207).

## 5. On the homelab

**UNVERIFIED until 03-16.** The homelab signer runs under trust bundle v3,
which has no installation ID, so every revocation there is refused with
`krl_no_installation_id` until the v4 ceremony (03-15). No homelab host
has `RevokedKeys` configured by keyroster before the agent (03-05 to
03-07).
