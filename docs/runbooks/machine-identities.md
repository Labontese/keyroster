# Runbook: machine identities

A machine identity (D-15) is an automation, such as a CI runner or a
backup job, that needs SSH access without a person and a passkey behind
each login. It is an entry in the admin-signed directory: the automation's
public key, the roles whose principals its certificates carry, and its own
max TTL. Like every directory entry it exists only in a version the admin
quorum signed.

> **What is tested and what is not.** CI runs `keyroster machine add`
> through the CLI pipeline against a test server (`TestMachineCommands`)
> and against a real signer in the end-to-end suite
> (`TestDirectoryHostsEndToEnd`, 03-04). Every step below is UNVERIFIED on
> the homelab until 03-16. In this version a machine entry **issues
> nothing**: certificates for it, and their renewal on proof of possession
> of its key, arrive with 03-11 (the renew section is added there).

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

## Remove a machine or rotate its key

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
true (03-11). It is set in a root ceremony with
`keyroster root successor-policy --prev policy.json --out policy-next.json
--pop-machines` (run in CI, `TestRootSuccessorPolicyPoP`, 03-04; UNVERIFIED
on the homelab until 03-15). Unlike `pop.hosts`, it can be turned off again
by a later successor policy (turning it off only stops machine renewals),
but this version has no flag that clears it: that needs a hand-written
successor policy.
