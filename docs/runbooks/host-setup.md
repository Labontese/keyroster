# Runbook: manual host setup (Phase 2; the Phase 3 agent automates this)

This runbook sets up a host running stock OpenSSH so that it accepts
keyroster user certificates for exactly the accounts and roles the
admin-signed directory maps. Until the Phase 3 host agent exists, an admin
does it by hand: render two files on the admin workstation, copy them to
the host, and point `sshd` at them.

> **What is tested and what is not.** CI's `TestRolesHostPrincipalsEndToEnd`
> feeds a test `sshd` the `keyroster host ca-key` line as its
> `TrustedUserCAKeys` file and the `keyroster host principals` output as
> the account's `AuthorizedPrincipalsFile`, byte for byte. It also feeds it
> the header-only file printed after `keyroster host-group unmap` (step 5).
> It does **not** exercise the copy into `/etc/ssh` on a real host or the
> reload of a real `sshd`. Each step below says which parts are
> UNVERIFIED.

## The principal convention (D-06)

Certificates carry role principals, not account names. The owner confirmed
the convention on 2026-10-22:

- a role grants `role:<name>`: `keyroster role add ops --max-ttl 1h` grants
  `role:ops` unless `--principal` says otherwise;
- a personal account is `u:<username>`: make a role with
  `--principal u:<user>` and grant it to that user only, for example
  `keyroster role add alice-personal --max-ttl 1h --principal u:alice --user alice`.

A host account accepts a certificate only when its principals file lists
one of the certificate's principals. sshd's default (the account name as
principal) is not used.

## Certificates are not host-scoped

A certificate is valid on every host that trusts the user CA. Host groups
only decide what `keyroster host principals` renders: they do not restrict
certificate issuance. A host therefore accepts any certificate carrying a
principal its file lists, whichever host the user had in mind.

## Where rendering runs

Both `keyroster host` commands need the keyroster config of an admin
workstation: `keyroster host ca-key` verifies the served trust bundle
against the saved root pins, and `keyroster host principals` also reads the
admin-signed directory endpoint, so it needs an admin key loaded in
ssh-agent (`--admin-key SHA256:...`, else the config's `admin_key`). Run
both on the admin workstation and copy the output to the host. The host
needs no keyroster binary and no keyroster config.

Before the first directory version is installed, `keyroster host principals`
refuses with "no directory is installed on the server; nothing to render"
and prints nothing. There is nothing to render until an admin has signed a
directory.

## Before you start: roles and host groups (admin workstation)

Every change below is an admin-signed directory version: the CLI verifies
the installed version, shows the diff and asks before it signs (or
`--yes`). With a policy quorum above 1, or `--out DIR`, it writes a
proposal for the other admins instead (see `enroll-user.md`).

```
keyroster role add ops --max-ttl 1h
keyroster group add devs --member alice
keyroster role grant ops --group devs
keyroster host-group add web
keyroster host-group map web deploy ops
```

The last line maps the local account `deploy` of the hosts in host group
`web` to role `ops`. Account names are lowercase.

## 1. Trust the user CA

UNVERIFIED until 02-14 on a real host (CI feeds the same line to a test
sshd).

On the admin workstation:

```
keyroster host ca-key > keyroster_user_ca.pub
```

The line is the active user CA key of the root-verified trust bundle, with
the comment `keyroster user CA (bundle vN)`. Copy `keyroster_user_ca.pub`
to the host as `/etc/ssh/keyroster_user_ca.pub`, owned by root, mode 0644,
and add to `/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub
```

## 2. Point sshd at the principals files

UNVERIFIED until 02-14 on a real host.

Add to `/etc/ssh/sshd_config`:

```
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

and create `/etc/ssh/principals`, owned by root, mode 0755.

## 3. Render and install each account's principals file

UNVERIFIED until 02-14 on a real host (CI feeds the same output to a test
sshd).

On the admin workstation, for each account of the host group:

```
keyroster host principals <group> <account> > principals-<account>
```

Copy `principals-<account>` to the host as `/etc/ssh/principals/<account>`,
owned by root, mode 0644. The file looks like this:

```
# keyroster: generated AuthorizedPrincipalsFile; do not edit
# host group web, account deploy, directory version 7 sha256 <64 hex digits>
role:ops
```

sshd ignores the `#` lines. The second header line names the directory
version and its SHA-256, as `keyroster directory show` prints it. An
account the host group does not map gets the two header lines only: it
accepts no keyroster certificate. An unknown host group is an error, so a
mistyped name never produces a file.

## 4. Check and reload sshd

UNVERIFIED until 02-14 on a real host.

```
sudo sshd -t
sudo systemctl reload ssh    # the unit is sshd on some distributions
```

`sshd -t` must print nothing and exit 0 before you reload.

## 5. Re-render after every change

CI only (`TestRolesHostPrincipalsEndToEnd`); UNVERIFIED on a real host.

Re-render and re-install the files (step 3) after every role, group or
host-group change that touches the host's accounts. Until Phase 3 nothing
does it for you, and a stale file keeps the old access. Compare the second
header line with `keyroster directory show` to recognise a stale file.

After `keyroster host-group unmap <group> <account>`, re-rendering prints a
header-only file. Install it as-is: never keep the old file, and never
delete it by hand. `keyroster host-group remove` refuses while the host
group still maps an account, so the header-only file can always be
rendered first.

## Windows hosts

Account names are lowercase in the directory, and `keyroster host-group map`
refuses an account name with an uppercase letter. Windows host automation
is Phase 5; a manual Windows setup is not covered here and is UNVERIFIED.
