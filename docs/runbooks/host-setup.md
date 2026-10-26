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

## Where the sshd settings go

Run on a homelab host in 02-14 for items 1 and 2: on an Ubuntu host the
item 1 search found no `Match` block and no earlier value, and
`sshd_config` includes `sshd_config.d/*.conf` first, so the settings went
into a drop-in. Removing or commenting out an existing value (item 1) and
item 3 are UNVERIFIED.

Steps 1 and 2 set `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`. For
both, sshd keeps the first value it reads, and a line after a `Match` line
applies only to that `Match` block. A line appended to the end of
`/etc/ssh/sshd_config` can therefore be ignored without any error, and
`sshd -t` does not show it. On the host, before steps 1 and 2:

1. Look for the include line, `Match` blocks and values already set:

   ```
   sudo grep -rniE '^\s*(include|match|trustedusercakeys|authorizedprincipalsfile)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/
   ```

   Remove or comment out every other `TrustedUserCAKeys` and
   `AuthorizedPrincipalsFile` value, including one inside a `Match` block
   that matches a keyroster account: a matching `Match` block overrides
   your value.
2. If `/etc/ssh/sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf`
   above its other settings (Debian and Ubuntu, for example, ship it as
   the first line), put the two settings in a drop-in such as
   `/etc/ssh/sshd_config.d/50-keyroster.conf`, owned by root, mode 0644.
   Drop-ins are read in name order, and a file read earlier would win.
3. Otherwise put them in `/etc/ssh/sshd_config` above the first `Match`
   line.

Step 4 checks the effective values with `sshd -T` before the reload.

## 1. Trust the user CA

Run on a homelab host in 02-14 (CI feeds the same line to a test sshd).

On the admin workstation:

```
keyroster host ca-key > keyroster_user_ca.pub
```

The line is the active user CA key of the root-verified trust bundle, with
the comment `keyroster user CA (bundle vN)`. The bundle version is the
server's word: a compromised server can serve an older root-signed bundle
whose user CA key has since been replaced. Before the first host, and
after every CA change, check that `keyroster audit verify` on the signer
host prints `trust bundle vN` with the same N
([Confirm on the signer host](enroll-user.md#confirm-on-the-signer-host);
step 5).

Copy `keyroster_user_ca.pub` to the host as
`/etc/ssh/keyroster_user_ca.pub`, owned by root, mode 0644, and set it
where sshd reads it first
([Where the sshd settings go](#where-the-sshd-settings-go)):

```
TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub
```

## 2. Point sshd at the principals files

Run on a homelab host in 02-14.

Set, in the same place as step 1
([Where the sshd settings go](#where-the-sshd-settings-go)):

```
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

and create `/etc/ssh/principals`, owned by root, mode 0755.

## 3. Render and install each account's principals file

Run on a homelab host in 02-14, for one account (CI feeds the same output
to a test sshd).

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
version and its SHA-256, as `keyroster directory show` prints it. Both
read the same server, so that version is the server's word (step 5). An
account the host group does not map gets the two header lines only: it
accepts no keyroster certificate. An unknown host group is an error, so a
mistyped name never produces a file.

## 4. Check and reload sshd

Run on two homelab hosts in 02-14: on a test VM with every criterion
below, and on zima-srv without `laddr` and `lport`. Neither host had a
`Match` block, so a `Match` block on the target, the case these criteria
are for, is UNVERIFIED.

```
sudo sshd -t
sudo sshd -T -C user=<account>,host=<host>,addr=<address>,laddr=<server address>,lport=22 | grep -iE '^(trustedusercakeys|authorizedprincipalsfile) '
sudo systemctl reload ssh    # the unit is sshd on some distributions
```

`sshd -t` must print nothing and exit 0. It checks the syntax only, not
which value is in force. `sshd -T -C` prints the effective settings for a
connection to `<account>` from `<address>` (a client address your users
connect from), arriving at `<server address>` on port 22 (use the port
sshd listens on), with any matching `Match` block applied. `<host>` must be
what sshd sees for that client. With `UseDNS no`, the default (check with
`sudo sshd -T | grep -i '^usedns'`), sshd matches `Match Host` against the
client's address, not its name, so pass the address as both `host=` and
`addr=`. Only with `UseDNS yes` is `<host>` the client's resolved name.
Give every one of these criteria: in this test mode sshd treats a
`Match` criterion it was not given (for example `LocalPort` or
`LocalAddress`) as not matching, so leaving `laddr` or `lport` out can hide a
`Match` block that does apply to real connections. If a `Match` block uses
`RDomain`, add `rdomain=<domain>` as well. Run it for each account the host
group maps. It must print exactly:

```
trustedusercakeys /etc/ssh/keyroster_user_ca.pub
authorizedprincipalsfile /etc/ssh/principals/%u
```

Another value, or `none`, means an earlier line or a `Match` block wins:
fix it ([Where the sshd settings go](#where-the-sshd-settings-go)) before
you reload.

## 5. Re-render after every change

CI only (`TestRolesHostPrincipalsEndToEnd`); UNVERIFIED on a real host.

Re-render and re-install the files (step 3) after every role, group or
host-group change that touches the host's accounts. Until Phase 3 nothing
does it for you, and a stale file keeps the old access. Comparing the
second header line with `keyroster directory show` catches a file you
forgot to re-render, but both read the same server: that is the
server's word, not proof.

A re-rendered file only takes effect while sshd still reads
`/etc/ssh/principals/%u`. Re-run step 4's `sshd -T` check after any
change to the sshd configuration, including an OS upgrade that adds a
drop-in or a `Match` block, and when a re-rendered file seems to have no
effect.

**The rendered version is the server's word.** `keyroster host principals`
and `keyroster host ca-key` check the admins' and the roots' signatures,
not that what the server serves is the newest version: the CLI keeps no
high-water mark until Phase 4 (as for `directory show`, see the residual
risk in [enroll-user.md](enroll-user.md#residual-risk)). A compromised
server can therefore serve an older signed directory, for example the one
from before an unmap, or an older trust bundle whose user CA key has since
been replaced, and the rendered file looks valid. After every change that
removes access (unmap, role revoke, group member removal) and every CA
change, and before
you install a rendered file on a new host,
[confirm on the signer host](enroll-user.md#confirm-on-the-signer-host):

- `keyroster audit verify` must print `directory installs N` with the same
  N as the `directory version N` in the file's header (every directory
  version is one install);
- it must print `trust bundle vN` with the same N as the `(bundle vN)`
  comment of the `keyroster host ca-key` line.

If the signer's number is larger, re-render (step 3) and check again. If
the file's number is larger, the signer never installed that version; if
it is still smaller after a re-render, the server serves an older version.
In both cases do not install the file and treat the server as compromised.
The two counters run in the end-to-end tests; the comparison itself is a
manual step and UNVERIFIED.

After `keyroster host-group unmap <group> <account>`, re-rendering prints a
header-only file. Install it as-is: never keep the old file, and never
delete it by hand. `keyroster host-group remove` refuses while the host
group still maps an account, so the header-only file can always be
rendered first.

**These changes stop only new certificates.** Disabling a user, revoking
a role from a user or a group and removing a group member change no
principals file: a certificate already issued keeps the principals it
carries and logs in on every host that lists one of them until its
ValidBefore. An unmap does change the file, but only for that account and
only on the hosts that install the re-rendered file. To end a person's
issued certificates on every host, run `keyroster revoke user NAME`
([revoke.md](revoke.md#4-revoke-a-user-keyroster-revoke-user)): it revokes
every live certificate of NAME in the signer's records, disables NAME and
revokes again. A host refuses those certificates only once its sshd's
`RevokedKeys` file holds the new KRL, and the drop-in in this runbook sets
no `RevokedKeys`. So in this version a host set up with this runbook
enforces no revocation. Until the keyroster agent (03-05 to 03-07) sets
`RevokedKeys` and applies the KRL, such a host refuses a revoked
certificate only if the operator adds a `RevokedKeys` line and installs
the KRL by hand, which is UNVERIFIED ([revoke.md](revoke.md)). Otherwise
`keyroster revoke user` stops only new certificates there, and an issued
one logs in until its ValidBefore.

## Registering a host in the directory

Run in CI e2e (`TestDirectoryHostsEndToEnd`, 03-04); UNVERIFIED on the
homelab until 03-16.

A host entry is the signed host policy of AUTHZ-02: the host's one host
group (D-11), its host public keys and the names its host certificate will
carry (D-16). Only an admin-signed directory version creates one; nothing
about a host comes from the host, the server or an enrollment request. In
this version the entry is read by `keyroster host principals --host`; the
host agent (03-07) and host certificates (03-09) use the same entry later.

1. On the host, print its host public key and its fingerprint, and read the
   fingerprint over a channel you already trust (the console, or an SSH
   session whose host key you verified):

   ```
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Copy the `.pub` file (never the private key file) to the admin
   workstation. Ed25519 and ECDSA host keys are accepted, up to 8 per host;
   RSA is refused.
2. On the admin workstation, register the host in an existing host group:

   ```
   keyroster host add web1 --group web --key ssh_host_ed25519_key.pub \
     --principal web1 --principal web1.lab.example --principal web1.example-tailnet.ts.net
   ```

   The principals are the names clients type: the short name, the FQDN and
   the tailnet name, 1 to 8 of them. Do not add an address the host gets
   from DHCP: the next lease can give it to another host. Each name must be
   in its one canonical spelling, lowercase and without a trailing dot, an
   IPv6 address compressed (`2001:db8::1`, not `2001:DB8:0:0::1`), an IPv4
   address without leading zeros. keyroster refuses any other spelling and
   prints the canonical one; it never rewrites a name. No principal and no
   host key may be on two hosts.

   The diff shows `+ host web1 host_group=web ...` with each key's
   fingerprint: compare it with step 1 before you sign. The first version
   signed after the trust bundle gained an installation ID also shows
   `+ installation_id <id>`; see the next section.
3. Check what the directory holds, and render the file that host's agent
   will write for an account:

   ```
   keyroster host list
   keyroster host principals --host web1 deploy
   ```

   `--host` renders exactly what `keyroster host principals web deploy`
   renders for the host's one host group. An unknown or disabled host is an
   error naming it.

`keyroster host remove web1` removes the entry. `keyroster host-group remove`
refuses while a host names the host group.

**Host agents need `pop.hosts` in the root-signed policy.** Run in CI
(`TestPoPSuccessor`, `TestRootSuccessorPolicyPoP`, `TestInstallBundlePoP`,
`TestVerifyBundlePoP`, 03-04; `trust verify --prev` runs the same
`VerifySuccessor` check, but no test runs that command with such a policy);
UNVERIFIED on the homelab until 03-15. A host
agent gets its certificates on proof of possession of a host key the
directory names, which the signer allows only when the policy in force has
`pop.hosts` true (03-07, 03-09). It is set in a root ceremony
([root-ceremony.md](root-ceremony.md)):

```
keyroster root successor-policy --prev policy.json --out policy-next.json --pop-hosts
```

then `keyroster root sign --prev` with the new policy. Once set, `pop.hosts`
cannot be turned off again (owner decision 2026-10-24): `root
successor-policy` prints `note: pop.hosts cannot be removed once set
(pop_hosts_removed)`, and `root sign --prev`, `trust verify --prev`,
`keyroster-signer install-bundle` and `keyroster audit verify` refuse a
successor that clears it with `pop_hosts_removed`. A host agent that could
not get its probe certificates could not confirm a new KRL, so revocations
would stall.

## Binding an existing directory to the installation

Run in CI (signer and CLI rebind tests: `TestDirectoryInstallationRebind`,
`TestDirectoryRebind`, `TestVerifyDirectoryInstallation`, 03-04);
UNVERIFIED on the homelab until 03-15.

Every directory version names the installation of the trust bundle it was
signed for (D-04), and the signer installs a version only when that
installation is the one of the bundle in force: otherwise it refuses
`directory_installation_missing` (the version names none),
`directory_installation_mismatch` (it names another installation, so it was
signed for another deployment) or `directory_installation_unknown` (it names
one, but the bundle has none). `keyroster audit verify` applies the same
rule to every directory install in the log. Admins never type the ID: every
directory command copies it from the root-verified bundle and the diff shows
it.

A directory installed before the bundle had an installation ID names none.
When the bundle first gains one (the 03-15 ceremony, `root sign --prev ...
--installation-id new`), bind the installed directory once:

```
keyroster directory rebind
```

It writes the next version with every user, group, role, host group, host
and machine unchanged and only `installation_id` set, shows the diff
(`+ installation_id <id>`), asks and signs, and installs it (or writes a
proposal when the policy's admin quorum is above 1). It refuses, signing
nothing:

- when the root-verified bundle has no installation ID: there is nothing to
  bind to;
- when the installed directory already names that installation;
- when the installed directory names another installation; the message names
  both IDs. The signer never installs such a directory, so the server serves
  one from another deployment.

Any other directory edit binds the directory too, because it copies the ID.

Until the bound version installs, logins under the unbound directory keep
working on the signer: the owner's lenient answer to D-04 (03-01). The
signer logs a warning at start (`installed directory names no installation,
but the trust bundle in force does`). Host agents (03-07) never accept a
directory without the installation ID, so bind it before the first agent
enrolls.

## Windows hosts

Account names are lowercase in the directory, and `keyroster host-group map`
refuses an account name with an uppercase letter. Windows host automation
is Phase 5; a manual Windows setup is not covered here and is UNVERIFIED.
