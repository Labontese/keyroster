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
  publishes no KRL.
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
`keyroster/revoke-request/v1`.

Expected output:

```
The server reports serial 1792869357962865 (user) revoked: KRL v1 published (log entries 4, 5).
Checked: the server serves KRL v1, signed by the ops key of your root-pinned trust bundle (log entry 5).
Not checked: that this KRL lists serial 1792869357962865 (this version cannot read a KRL); the signer's "revoked" line (journalctl -u keyroster-signer) is the proof.
Hosts enforce it once their keyroster agent applies this KRL.
```

The two log entries are the `revoke` entry and the `krl_publish` entry,
written in one transaction with the revocation itself. Run in CI e2e
(`TestRevokeSerialEndToEnd`, 03-01).

With `--ca host` the last line instead says that a host certificate is
checked by SSH clients, through `RevokedHostKeys`, and that nothing
installs the KRL there yet (see the box at the top).

The server's answer is not signed, and a compromised keyroster-server
could drop the request and answer success. So the command reads the
published KRL after the answer and requires its manifest to verify
against your root-pinned trust bundle and its installation ID, with at
least the reported KRL version and `krl_publish` entry. If that fails it
prints `the server reports serial N revoked, but that could not be
confirmed: ...` and exits non-zero; nothing tells you whether the signer
revoked, so check the signer host. This catches an invented version, but
not a server that drops the request and shows an earlier genuine KRL
under an invented answer of that version: only reading the KRL for the
serial would. The confirmation and each of its refusals ran in the CLI
tests against a stub server (`TestRevokeSerialConfirm`); the confirmed
path also runs in CI e2e.

## 2. Refusals

| What you see | Why | What to do |
|---|---|---|
| `the signer has issued no certificate with this serial` (`unknown_serial`) | The serial is not one this signer issued, or it is mistyped. | Check the serial. Revocation by key, for a certificate this signer did not issue, arrives with 03-03. |
| `... was not issued by that CA` (`ca_role_mismatch`) | `--ca` names another CA than the one that issued it. | Pass the right `--ca`. |
| `the signer refused the revocation (is --admin-key a policy admin?)` | The key is not a policy admin, or the signature does not verify. | Use an admin key from the root-signed policy. |
| `signer unavailable ... The signer's log names the reason` | The signer could not decide. Its log names `krl_no_installation_id` (the bundle in force has no installation ID) or `krl_too_large` (see below). | Read the signer's log (`journalctl -u keyroster-signer`). |

Every refusal is also an entry in the signer's audit log. The
`krl_no_installation_id` refusal ran in the signer's unit tests
(`TestRevoke/no_installation_id_refused`); on the homelab it is
UNVERIFIED until 03-16.

### `krl_too_large`

A KRL is at most 4 MiB, about half a million revoked serials that are not
adjacent to one another. A revocation whose KRL would be larger is refused
and rolled back, so the revocation table never holds an entry that no
published KRL carries. The remedy is an emergency CA replacement (03-13),
which makes every certificate of the old CA useless at once.
**UNVERIFIED**: the replacement procedure does not exist yet. The refusal
and its rollback ran in the signer's unit tests
(`TestRevokeKRLTooLarge`).

## 3. Where the KRL is served

keyroster-server serves the published KRL to any TLS client at
`GET /api/v1/krl`: a JSON document with the KRL bytes, a canonical
manifest and the ops key's detached SSHSIG over it (namespace
`keyroster/krl/v1`). Before the first revocation it answers 404
`no_krl`. The answer is never cached (`Cache-Control: no-store`).

The server is not trusted for any of it. A reader accepts a KRL only when
the manifest's signature is by the ops key of its root-pinned trust
bundle, the manifest names the installation ID it pinned, its
`krl_version` is above the version it holds, and its `krl_sha256` is the
SHA-256 of the KRL bytes (`krl.VerifyManifest`). Run in CI e2e
(`TestRevokeSerialEndToEnd`, 03-01) through the CLI's pinned TLS client.
`keyroster revoke serial` runs this check after each revocation (step 1);
no command fetches the KRL for a hand install yet.

## 4. The audit log after a revocation

From the first revocation until 03-03 merges, `keyroster audit verify`
refuses the log at the first `revoke` or `krl_publish` entry with
`audit: entry N (revoke): not verifiable by this version`. That is by
design: a check this version does not have is never skipped. A log
without such entries verifies as before. Run in the audit unit tests
(`TestVerifyKindsWithoutChecks`); on the homelab UNVERIFIED until 03-16.

## 5. On the homelab

**UNVERIFIED until 03-16.** The homelab signer runs under trust bundle v3,
which has no installation ID, so every revocation there is refused with
`krl_no_installation_id` until the v4 ceremony (03-15). No homelab host
has `RevokedKeys` configured by keyroster before the agent (03-05 to
03-07).
