# Runbook: machine identities

A machine identity (D-15) is an automation, such as a CI runner or a
backup job, that needs SSH access without a person and a passkey behind
each login. It is an entry in the admin-signed directory: the automation's
public key, the roles whose principals its certificates carry, and its own
max TTL. Like every directory entry it exists only in a version the admin
quorum signed.

> **What is tested and what is not.** CI runs `keyroster machine add` and
> `remove` through the CLI pipeline against a test server
> (`TestMachineCommands`) and against a real signer in the end-to-end suite
> (`TestDirectoryHostsEndToEnd`, 03-04). It runs `keyroster machine renew`
> and `keyroster revoke machine` against a stub server (`TestMachineRenew`,
> `TestMachineKeyInput`, `TestMachineRenewIfDue`, `TestRevokeMachine`) and,
> on OpenSSH 9.5p1 and 10.5p1 in the e2e-probe job, against real binaries
> and a real sshd (`TestMachineIdentityEndToEnd`, with an sk-dummy key
> through a real ssh-agent, 03-11b). Every step below is UNVERIFIED on the
> homelab until 03-16.

## Add a machine

On the admin workstation, with the automation's public key file (never its
private key; keyroster refuses a file that holds one):

```
keyroster machine add ci --key id_ci.pub --role deploy --max-ttl 24h
```

- `--key`: one Ed25519, ECDSA or security-key (`sk-`) public key, used by
  no other machine and not a host key of any host in the directory.
- `--role`: 1 to 16 existing roles (repeatable).
- `--max-ttl`: the longest certificate the machine gets, at least 1m and at
  most the machine CA cap of the root-signed policy. Without it the machine
  gets that cap.

The diff shows `+ machine ci status=active key=<type> SHA256:... roles=[...]
max_ttl_seconds=...`: compare the fingerprint with
`ssh-keygen -lf id_ci.pub` on the machine before you sign. Like every
directory version, it carries the installation ID of the root-verified
trust bundle (see [host-setup.md](host-setup.md#binding-an-existing-directory-to-the-installation)).

`keyroster machine list` shows the machines of the installed directory, and
`keyroster machine remove ci` removes one (see [below](#remove-a-machine-or-rotate-its-key)
for a machine-only role above the user cap).

## The TTL rule

Each role is checked against the CA profile of every CA it is used under,
so that a group membership change can never switch the cap behind the
admins' backs:

- A role is **user-facing** when its own `users` or `groups` list is
  non-empty, even if those groups have no members today. It keeps the user
  CA cap, also when machines name it.
- A role that no user or group grants and that a machine names is
  **machine-only**: it is checked against the machine CA cap instead, so it
  may be longer than the user cap.
- A role that is both granted and named by a machine (**mixed**) must pass
  both caps, and each of its extensions must be allowed by both profiles.
- A role that nobody grants and no machine names keeps the user CA cap.

A machine's own `--max-ttl` must be at most the machine CA cap. So to give
an automation a role longer than the user cap, create the role within the
user cap (`keyroster role add deploy --max-ttl 1h`), add the machine that
names it, then raise the role (`keyroster role update deploy --max-ttl 20h`).
Granting that role to a user or a group afterwards is refused while it is
above the user cap.

## Renew a machine certificate

On the automation host, as the automation's own OS user, run
`keyroster init` once without `--user` (the server URL, its TLS pin and the
root pins; the config lives in that user's config directory). No admin key
and no passkey are needed. Then:

```
keyroster machine renew ci --key /path/to/id_ci --out /path/to/id_ci-cert.pub
keyroster machine renew ci --agent-key SHA256:... --out /path/to/id_ci-cert.pub
```

The CLI signs the request on the automation host, so the private key is
never sent and never written; `--out` naming the key file is refused. It
checks the answer against the root-verified trust bundle before it writes
anything: the certificate is a user certificate signed by an active or
next machine CA key of the bundle, for this key, for this request and this
policy, with a lifetime and extensions within the machine profile and no
critical option. It writes only the certificate, by temporary file and
rename. The principals are the signer's choice from the machine's roles,
and the CLI does not check them against the directory, which it does not
hold, unless you name them with `--expect-principal P` (repeatable).

The signer issues at most 12 certificates per key per hour. A refused
attempt does not count; an answer that is lost on the way and retried costs
one. Log in with the key and the certificate:
`ssh -i /path/to/id_ci -o CertificateFile=/path/to/id_ci-cert.pub user@host`.

Exit codes: 0 when the certificate was written or is not due, 1 for any
refusal or failure, 2 for a usage error. A timer cannot tell
`machine_disabled` from a server that is down by the exit code alone: read
the text it prints.

### Unattended renewal and passphrases

Keep an unencrypted key file readable only by the automation's user, or
use an encrypted one with `--passphrase-fd N`, fed from a file the unit
opens (for example systemd `LoadCredential=`), never from an argument or
the environment. A stdin that is not a terminal never prompts: the CLI
refuses at once. After signing, the CLI clears the key file buffer, the
passphrase and an Ed25519 key; the big integers of an ECDSA private key
cannot be cleared reliably in Go.

### Security keys

A security key (`sk-`) renews only through ssh-agent with `--agent-key`,
and it asks for a touch at every renewal, so an hourly timer cannot use
one. Unattended jobs need an Ed25519 or ECDSA key: a file, an agent key, or
PIV through the agent. `--key` refuses an sk key file with a named error
that points to `ssh-add` and `--agent-key`. CI runs this with OpenSSH's
sk-dummy provider; a real hardware token is UNVERIFIED.

### An example timer and cron line

UNVERIFIED: no test runs a timer. An hourly line that renews only when the
certificate is missing, for another key, name or CA, or due (from two
thirds of its lifetime, earlier by a fixed amount per certificate of at
most an hour and at most a tenth of the lifetime):

```
0 * * * * keyroster machine renew ci --key /path/to/id_ci --out /path/to/id_ci-cert.pub --if-due
```

If a leaked certificate was revoked by serial and a newer directory version
released the hold, `--if-due` still skips until the old due time: run once
without `--if-due`, or delete the certificate file.

### What a machine certificate does not restrict

keyroster sets no source-address restriction on machine certificates yet: a
certificate and its key work from any address until the certificate
expires or is revoked. Keep the key on the automation host only and keep
its max TTL short. This is revisited before keyroster is used across a
fleet.

## Revoke a machine

`keyroster revoke machine ci` ends a machine's access: see
[revoke.md, section 4c](revoke.md#4c-revoking-a-machine-keyroster-revoke-machine).
Afterwards the signer refuses `ci` new certificates with `machine_disabled`,
with `cert_revoked` while the disable is still a pending proposal, and with
`machine_key_revoked` once `--keys` revoked its key.

## Remove a machine or rotate its key

`keyroster machine remove` revokes nothing: the certificates the machine
already holds stay valid until they expire, and the command says so and
names `keyroster revoke machine`.

Removing the last machine that names a machine-only role leaves the role
granted to nobody, so it falls back to the user CA profile. While the role
does not fit that profile, `keyroster machine remove` is refused, signing
nothing. That is the case when its max TTL is above the user cap, or when it
allows an extension that the machine CA profile allows and the user CA
profile does not. The message names the role and both ways out:

- **Rotate the key.** A machine's key cannot be changed in place
  (`machine add` refuses a name that exists), so add the replacement under
  a new name with the same roles first, then remove the old entry:

  ```
  keyroster machine add ci2 --key id_ci_new.pub --role deploy --max-ttl 20h
  keyroster machine remove ci
  ```

  When the old key may be compromised, end its certificates and block it
  before the entry goes, while `--keys` can still read the key from it
  (OQ-4 of 03-11):

  ```
  keyroster machine add ci2 --key id_ci_new.pub --role deploy --max-ttl 20h
  keyroster revoke machine ci --keys
  keyroster machine remove ci
  ```

  To reuse the name with a new key, run `keyroster revoke machine ci`
  before you remove and re-add it: a subject revoke logged after the
  re-add holds the new key until the next directory version.

- **Remove the machine for good.** Bring the role within the user CA
  profile first, then remove the machine. The message prints the one
  `keyroster role update` command that does it, with every change the
  role needs:
  - `--max-ttl D` when the max TTL is above the user cap (D at most that
    cap; 12h below stands for the user CA cap of your root-signed policy);
  - `--no-extensions` when none of the role's extensions is allowed by the
    user CA profile, or `--extension E` for each one it allows, because a
    given list replaces the role's extensions.

  For a role above the user cap that also allows `permit-port-forwarding`,
  which only the machine profile allows here:

  ```
  keyroster role update deploy --max-ttl 12h --no-extensions
  keyroster machine remove ci
  ```

Both sequences and the refusal run in CI. They are covered by
`TestMachineCommands/machine_remove_machine_only_role_above_user_cap`
(03-04) and, for the extension cases,
`TestMachineCommands/machine_remove_hint_names_the_actual_remedy` (03-05).
Every step is UNVERIFIED on the homelab until 03-16.

## Renewal needs pop.machines

Machine certificates are renewed on proof of possession of the machine key,
which the signer allows only when the root-signed policy has `pop.machines`
true (03-11). When it is off, `keyroster machine renew` refuses before it
sends anything, and keyroster-server answers `machine_pop_not_enabled`
without calling the signer (03-11b). It is set in a root ceremony with
`keyroster root successor-policy --prev policy.json --out policy-next.json
--pop-machines` (run in CI, `TestRootSuccessorPolicyPoP`, 03-04; UNVERIFIED
on the homelab until 03-15). Unlike `pop.hosts`, it can be turned off again
by a later successor policy (turning it off only stops machine renewals),
but this version has no flag that clears it: that needs a hand-written
successor policy.
