# Runbook: revoke certificates, keys and users

This runbook revokes issued certificates: one by its serial (section 1)
or its key ID (section 2), a key with every certificate for it (section
3), or every live certificate of a user, who is then disabled (section 4).
The admin signs a revocation request; keyroster-server forwards it
unchanged; the signer alone checks the admin's signature, records the
revocation in its audit log and publishes a new KRL (OpenSSH Key
Revocation List). Revocation is CLI only (D-12): no web page offers it.

Disabling a user (`keyroster user disable`), revoking a role or unmapping
an account stops only **new** certificates: one already issued stays
valid until its ValidBefore. `keyroster revoke user NAME` (section 4)
ends the issued ones too, on every host that applies the KRL.

> **What a revocation does, and what it does not do yet.** The signer
> records it and publishes the next KRL version at once. A host refuses
> the certificate only once that KRL is in the file its sshd's
> `RevokedKeys` points to. In this version nothing puts it there: the
> keyroster agent that fetches, verifies and installs the KRL arrives
> with 03-05 to 03-07, and no keyroster command fetches and verifies the
> KRL for a hand install yet. Until a host has the KRL, the certificate
> keeps working there until it expires. **UNVERIFIED**: installing a KRL
> on a host by hand; no runbook step or command does it, and only the e2e
> harness swaps a KRL file under a running sshd.
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
> - **Run in CI e2e (03-03b)**, same lanes: `keyroster revoke key-id`,
>   `keyroster revoke key` and `keyroster revoke user` against real sshd
>   (`TestRevokeKeyEndToEnd`, `TestRevokeUserEndToEnd`), sections 2 to 4.
> - **Run locally in 03-01**: the serial test on OpenSSH 10.5p1 and 9.5p1
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

## 1. Revoke by serial: `keyroster revoke serial`

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
Checked: KRL v1792919647 lists serial 1792869357962865 under a user CA key of your trust bundle, so it revokes that certificate.
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
answer when it was published more than 300 s before the request. A
genuine KRL issued after that point passes these checks too (they have no
upper bound, and the signer re-publishes the KRL by itself every hour,
section 6), so a compromised keyroster-server could show a fresh, genuine
KRL without forwarding the request. The command therefore also reads the
KRL it verified (`krl.Parse`, strict) and exits non-zero unless it lists
the serial under one of the trust bundle's CA keys for `--ca`; every
revoke command does the same for its own target (sections 2 to 4). An
absent entry is never reported as revoked: the refusal (`... does not
list serial N ... (not listed)`) names both causes, a revocation that is
not effective or an entry already pruned (an expired certificate leaves
the KRL 300 s after its ValidBefore), and a KRL that does not parse is a
refusal too. The confirmation, the listing check and each of their
refusals ran in the CLI tests against a stub server
(`TestRevokeSerialConfirm`, `TestRevokeKRLCheck`); the confirmed path
also runs in CI e2e.

## 2. Revoke by key ID: `keyroster revoke key-id`

```
keyroster revoke key-id 'kr2/ca=user/sub=alice/req=.../ser=1792991036721938' --ca user --reason "laptop lost"
```

This revokes every certificate with that key ID signed by a CA key of the
`--ca` role (`user`, the default, `host` or `machine`) under which this
signer issued one; sshd logs the key ID (`ID kr2/...`) on every login,
and `ssh-keygen -L -f CERT` prints it as `Key ID:`. The signer refuses a
key ID it never issued (`key_id_not_issued`): such an entry would never
leave the KRL. A certificate this signer did not issue is revoked by its
key (section 3). The entry stays in the KRL until 300 s after the
ValidBefore of the latest such certificate (pruning, section 6), and the
signer re-publishes the KRL every hour (D-10). The command exits 0 only
when the verified KRL lists the key ID under a CA key of the role.

Expected output (from CI):

```
The server reports key ID "kr1/ca=user/sub=u:c/req=f123331cdbc07dde4d7e67345513b6a8/pol=1/ser=1792990664644870" (user) revoked: KRL v1792990666 published (log entries 8, 9).
Checked: the server serves KRL v1792990666, signed by the ops key of your root-pinned trust bundle (log entry 9), issued at 2026-10-26T04:57:45Z, at most 300 s before this request.
Checked: KRL v1792990666 lists key ID "kr1/ca=user/sub=u:c/req=f123331cdbc07dde4d7e67345513b6a8/pol=1/ser=1792990664644870" under a user CA key of your trust bundle, so it revokes every certificate with that key ID that key signed.
Hosts enforce it once their keyroster agent applies this KRL.
```

What is tested: run in CI e2e (03-03b) (`TestRevokeKeyEndToEnd`: sshd
refuses the certificate after the KRL swap); the listing check and its
refusals in the CLI tests (`TestRevokeKRLCheck`). Every homelab step is
UNVERIFIED until 03-16. Check the result with `keyroster audit verify`
(section 7) or a KRL file with `ssh-keygen -Q` (section 6).

## 3. Revoke a key: `keyroster revoke key`

```
keyroster revoke key ~/.ssh/id_ed25519.pub --reason "laptop lost"
```

This revokes the public key itself, as an explicit KRL key: sshd then
refuses it as a plain key from `authorized_keys` and in every
certificate for it, whichever CA signed that certificate. It is the way
to cut off a certificate this signer holds no record of (issued by a
restored older signer state, or by a CA outside this installation) and a
plain key that is still in `authorized_keys` files. FILE is one public
key in `authorized_keys` format; a certificate file revokes the
certificate's key, and the command says so (`Note: ... holds a
certificate`). An explicit key never leaves the KRL, so at most 1000
keys, taking at most 1 MiB, can be revoked this way
([`explicit_key_cap_reached`](#explicit_key_cap_reached)); a key of this
installation's trust bundle (a CA, ops, log or root key) is refused
(`key_is_ca_of_this_installation`). The command exits 0 only when the
verified KRL lists the key.

Expected output (from CI):

```
The server reports key SHA256:HMM+1fMK1KXnOAXKmIVC79cfZiYELMKq+rXy5WAGzIk revoked: KRL v1792990665 published (log entries 6, 7).
Checked: the server serves KRL v1792990665, signed by the ops key of your root-pinned trust bundle (log entry 7), issued at 2026-10-26T04:57:45Z, at most 300 s before this request.
Checked: KRL v1792990665 lists key SHA256:HMM+1fMK1KXnOAXKmIVC79cfZiYELMKq+rXy5WAGzIk as an explicit key, so it revokes that key plain and in every certificate for it.
sshd refuses the key once its host's keyroster agent applies this KRL. As a host key, it is refused only by SSH clients whose RevokedHostKeys file holds this KRL.
```

What is tested: run in CI e2e (03-03b) (`TestRevokeKeyEndToEnd`: sshd
refuses the plain key from `authorized_keys` and a certificate for it,
and accepts another certificate); the certificate-file note and the
listing check in the CLI tests (`TestRevokeKRLCheck`). Revoking a host
key that SSH clients then refuse is UNVERIFIED. Every homelab step is
UNVERIFIED until 03-16.

## 4. Revoke a user: `keyroster revoke user`

```
keyroster revoke user alice --yes --reason "left the team"
```

This cuts a person off: every live certificate of the user, then the
user disabled, then the certificates issued in between. Revocation and
the directory change are separate transactions under separate
authority, so the command runs them in a fixed order:

1. **First revocation.** The signer revokes every certificate of its
   issuance records whose key ID names the user under the user CA and
   that is still live (ValidBefore + 300 s not passed); it prints their
   serials. This is never undone.
2. **Disable.** The user is set `disabled` in a signed directory version
   (the same pipeline as `keyroster user disable`: diff, confirmation or
   `--yes`, signature). At admin quorum 1 it is installed; above it is
   written as a proposal (`--out DIR` names it).
3. **Second revocation.** Once the server reports the install, the
   command revokes the user again. That catches a certificate issued by
   a login that completed between steps 1 and 2. It also runs when the
   directory already shows the user disabled or absent (no directory
   change then): another admin's disable installed after step 1 leaves
   such a certificate too. Its answer re-lists the
   certificates of step 1 next to any new one, because no revocation
   leaves out certificates already revoked; the KRL lists each serial
   once.

Each answer's serials are printed and checked against the verified KRL.
The answer is unsigned, so the check covers exactly the serials it
reports, and the output says so; when it reports more certificates than
it lists (at most 4096), the output says the rest are not checked and
`keyroster audit verify` on an exported log checks them all (section 7).
`--yes` is needed when stdin is not a terminal; without it the command
refuses before it revokes anything.

Expected output at admin quorum 1 (from CI, the SHA-256 values
shortened):

```
First revocation of alice: the server reports 2 certificate(s) revoked: KRL v1792991045 published (log entries 10, 11).
Serials: 1792991036721938 1792991036724417
Checked: the server serves KRL v1792991045, signed by the ops key of your root-pinned trust bundle (log entry 11), issued at 2026-10-26T05:04:05Z, at most 300 s before this request.
Checked: KRL v1792991045 lists each of the 2 serial(s) the server's answer reports, under a user CA key of your trust bundle. The answer is unsigned, so a certificate it does not report is not checked here; keyroster audit verify on an exported log checks every revocation.
Directory version 5, based on version 4 (SHA-256 08ffd469...), the admin-signed version the server serves. Changes:
  ~ user alice active -> disabled
SHA-256 of directory version 5: fab32ef9...
The server reports directory version 5 installed (SHA-256 fab32ef9..., log leaf 12).
That is the server's word: the signer's audit log is the proof (keyroster audit verify on a log exported on the signer host must print "directory installs 5").
Second revocation (after the disable) of alice: the server reports 2 certificate(s) revoked: KRL v1792991046 published (log entries 13, 14).
Serials: 1792991036721938 1792991036724417
Checked: ... (as for the first)
alice is disabled, and the KRL lists every certificate of alice the server reported. Hosts enforce it once their keyroster agent applies this KRL.
```

So the audit log holds two revoke entries for one `revoke user`, the
second repeating the first one's certificates (plus any issued in
between), each followed by its krl_publish entry.

| Status | Meaning | What to do |
|---|---|---|
| exit 0 | Revoked, the user disabled and swept again. Also when the user was already disabled or is not in the installed directory: then there is no directory change, but both revocations run (the second catches a certificate issued before another admin's disable was installed), and the output says so. That the user is already disabled or absent is the server's word, and the output says that too: the CLI checks the admins' signatures on the directory the server serves, not that the signer holds it, so a server can serve an older version; when it serves none, nothing signed backs it. | Nothing. Confirm the install on the signer host ([enroll-user.md](enroll-user.md#confirm-on-the-signer-host)); for a user already disabled or absent, check there that `directory installs` is the version the output names. |
| exit 1 | The first revocation failed or could not be confirmed: nothing is reported revoked. The disable still ran, because it stops new certificates. | Run `keyroster revoke user NAME` again. If the disable failed too, the output names `keyroster user disable NAME` first. |
| exit 3 | Partial. Revoked, but the user is NOT disabled (the directory step failed), or disabled (or already disabled or not in the directory) but the second revocation failed. The user may still obtain certificates, or hold one issued in between. | Run `keyroster revoke user NAME` again: it revokes every live certificate again, those issued since included, then disables and sweeps. A bare `keyroster user disable NAME` would leave the certificates issued in between. |
| exit 4 | Admin quorum above 1: revoked, disable pending. The disable is a proposal, and the user can still obtain certificates until the co-signers install it. | Have it co-signed and installed (`keyroster directory sign`, `keyroster directory install`), then run `keyroster revoke user NAME` again. |

The exits ran in CI (cmd/keyroster revoke tests, 03-03b): `TestRevokeUser`
against a stub server, which also checks the order revoke, install,
revoke. Exit 0 at quorum 1 is run in CI e2e (03-03b)
(`TestRevokeUserEndToEnd`: both of alice's certificates refused by sshd
after the KRL swap, bob's accepted, alice's next login refused
`user_disabled`, `keyroster audit verify` passing with the two revoke
entries). Exits 1, 3 and 4 against a real server are UNVERIFIED (only
the stub server runs them); every homelab step is UNVERIFIED until
03-16.

What it does not cover:

- **Certificates outside the signer's records.** A certificate issued by
  a restored older signer state or by a CA outside this installation is
  not found; with none found the output says `No live certificates of
  NAME in this signer's records; revoke a certificate issued elsewhere
  with keyroster revoke key.` Do that (section 3).
- **Other subject names.** The signer matches the subject in the key ID
  exactly. A certificate issued with `keyroster ca issue --subject u:alice`
  names `u:alice`, not `alice`: revoke it by serial, key ID or key.
- **Admin issuance.** Disabling stops passkey logins only; a policy admin
  can still issue a certificate with `keyroster ca issue`.
- **The window at quorum above 1** stays open until the proposal is
  installed (exit 4), and a compromised keyroster-server that reports an
  install that did not happen moves the second revocation early. Both
  close in Phase 4 (a signer-side issuance barrier and signed install
  receipts). Until then, confirm the install on the signer host and run
  the command again after it.
- Host and machine subjects arrive with 03-09 and 03-11.

## 5. Refusals

| What you see | Why | What to do |
|---|---|---|
| `the signer has issued no certificate with this serial` (`unknown_serial`) | The serial is not one this signer issued, or it is mistyped. | Check the serial. Revoke the certificate by its key ID (`keyroster revoke key-id`, section 2) or, when this signer did not issue it, by its key (`keyroster revoke key`, section 3). |
| `the signer has issued no certificate with this key ID under that CA` (`key_id_not_issued`) | The key ID is mistyped, `--ca` names another role, or this signer did not issue it. | Check the key ID and `--ca`; revoke a certificate this signer did not issue by its key (section 3). |
| `the key is a key of this installation's trust bundle` (`key_is_ca_of_this_installation`) | The key is a CA, ops, log or root key of the bundle in force. An explicit-key entry on a CA key would refuse every certificate it signed. | A compromised CA key is replaced by the emergency CA rotation (03-13); **UNVERIFIED**: that procedure does not exist yet. |
| `the KRL holds as many explicit keys as it may` (`explicit_key_cap_reached`) | See [below](#explicit_key_cap_reached). | See below. |
| `this signer revokes user subjects only` (`subject_kind_unsupported`) | The request named a host or machine subject. | `keyroster revoke user` sends user subjects only; host and machine subjects arrive with 03-09 and 03-11. |
| `... (revoke_installation_missing)` or `... another installation ... (revoke_installation_mismatch)` | The request reached the signer without an installation ID (this CLI always sends one), or for another installation than the signer's. | Check the server URL and root pins `keyroster init` saved; a missing ID means something between the CLI and the signer changed the request. |
| `the server reports ... revoked, but that could not be confirmed: KRL vN, the one the server serves, does not list ... (not listed)` | The verified KRL does not list the target: the revocation is not effective, or the entry was already pruned (section 6). | Treat it as not revoked. Check the signer's `revoked` line (`journalctl -u keyroster-signer`) and run the command again. |
| `the KRL the server serves (vN) is signed but does not parse` | The ops key signed bytes that the strict parser refuses. | Treat it as not revoked; read the signer's log. |
| `... was not issued by that CA` (`ca_role_mismatch`) | `--ca` names another CA than the one that issued it. | Pass the right `--ca`. |
| `.../api/v1/admin/revoke: admin authentication failed` (HTTP 401) | keyroster-server refused the request's admin signature before the signer saw it: the key is not a policy admin, or your clock differs from the server's by more than 2 minutes (the CLI then adds `your clock differs from the server by Ns`). | Use an admin key from the root-signed policy (`--admin-key SHA256:...`), or fix the clock. |
| `the signer refused the revocation; nothing was revoked: ... HTTP 403: [peer text: "REASON"]` | The signer refused it for REASON. The one an operator can hit is `request_time_skew`: the request was created more than 5 minutes before the signer saw it (ssh-agent took that long to sign, say while waiting for a touch, or the clocks differ). | Run the command again; for another REASON, read the signer's log (`journalctl -u keyroster-signer`). |
| `the signer has already accepted a request with this ID` (`duplicate_request`) | The signer saw this request ID before; the CLI picks a fresh random one each run, so only a resent request gets this. | Run the command again. |
| `the server cannot reach its signer (HTTP 503) ... The signer's log names the reason` | The signer could not decide. Its log names `krl_no_installation_id` (the bundle in force has no installation ID), `krl_too_large` or `revocations_not_logged` (both below). | Read the signer's log (`journalctl -u keyroster-signer`). |

The CLI's text in every row ran in the CLI tests against a stub server
(`TestRevokeRefusalText`; the two KRL rows in `TestRevokeKRLCheck`), the
401 row with a key that is not a policy admin. Against the real server
and signer, end to end, every row is **UNVERIFIED**: the e2e tests run
only successful revocations. The
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

### `explicit_key_cap_reached`

An explicit key never leaves the KRL, so the signer revokes at most 1000
distinct keys by key, taking at most 1 MiB of the KRL (an RSA key above
4096 bits or a security-key key with a long application string reaches
the 1 MiB first). Revoking a key that is already revoked always works.
Beyond the cap a key revocation is refused and nothing is recorded, so
the other 3 MiB of the KRL stay for serial and key-ID entries, which
leave it as their certificates expire: one admin cannot fill the KRL for
good. What one admin can still do is use up the cap, after which no
further key can be revoked by key; revocation by serial, key ID and
subject still works, and audit verify shows every key revocation and who
signed it. **There is no remedy in this version**, because revocation
rows are never deleted: remove such a key from every `authorized_keys`
file by hand, and revoke its certificates by serial. The refusal and the
cap ran in the signer's, audit's and krl's unit tests
(`explicit_key_cap_reached`, `explicit_key_cap_refused`,
`TestCheckExplicitKeys`, pre-merge review of PR #61).

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

## 6. Where the KRL is served

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
300 s at the KRL's `issued_at`; an explicit key stays for good. The
signer revokes a key ID only when it issued a certificate with that key
ID under a CA key of the role (otherwise `key_id_not_issued`; revoke a
certificate it did not issue by its key), so every key-ID entry leaves
once its certificate expires. The KRL keeps the
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
Every `keyroster revoke` command runs this check after its revocation and
then parses the KRL for its own target (section 1); no command fetches
the KRL for a hand install yet.

To see what a KRL file revokes, `ssh-keygen -Q -l -f revoked.krl` lists
its CA keys with their serials and key IDs, and its explicit keys;
`ssh-keygen -Q -f revoked.krl CERT_OR_KEY.pub` prints `REVOKED` (exit 1)
or `ok` (exit 0) for one certificate or key. Neither checks the manifest:
only a KRL that passed `krl.VerifyManifest` is the signer's. `-Q -l` ran
locally with OpenSSH 10.5p1 on a KRL our encoder wrote
(`test/vectors/krl_full_v1.hex`, 03-03b); `-Q` on a certificate runs in CI
e2e (`TestRevokeSerialEndToEnd`).

## 7. The audit log after a revocation

`keyroster audit verify` checks revoke and krl_publish entries since
03-03: each revoke entry against the admin-signed request it logs and the
certificates the log issued, and each published KRL against the one it
re-derives from the logged revocations. An older binary says "not
verifiable by this version" at the first such entry; that is not
tampering, use a current binary. `keyroster audit verify --json` counts
the entries by kind (`revoke`, `krl_publish`): each revocation adds one
of each, and a `keyroster revoke user` that disables the user adds two
of each (section 4). Run in the audit and signer unit tests
(`TestVerifyRevocations`, `TestRevokeSubjectTracer`) and in CI e2e
(`TestRevokeSerialEndToEnd`, `TestRevokeUserEndToEnd`); on the homelab
UNVERIFIED until 03-16.

Always take a saved export after every revocation
(`keyroster-signer export-log`, kept off the signer VM): a signer restore
loses every revocation made after the latest saved export without a
trace, and the restore's check in
[signer-install.md](signer-install.md#a-restore-brings-back-the-older-trust-bundle-policy-and-directory)
cannot see it (T-03-207).

## 8. On the homelab

**UNVERIFIED until 03-16.** The homelab signer runs under trust bundle v3,
which has no installation ID, so every revocation there is refused with
`krl_no_installation_id` until the v4 ceremony (03-15). No homelab host
has `RevokedKeys` configured by keyroster before the agent (03-05 to
03-07).
