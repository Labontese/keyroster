# Runbook: manual host setup (Phase 2; the Phase 3 agent automates this)

This runbook sets up a host running stock OpenSSH so that it accepts
keyroster user certificates for exactly the accounts and roles the
admin-signed directory maps. Until the Phase 3 host agent exists, an admin
does it by hand: render two files on the admin workstation, copy them to
the host, and point `sshd` at them.

For the agent's side: [Supported platforms](#supported-platforms),
[Not supported](#not-supported),
[Before the agent: preflight](#before-the-agent-preflight),
[Moving a Phase 2 host to the agent](#moving-a-phase-2-host-to-the-agent)
and [Drift](#drift).

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
no `RevokedKeys`. So a host set up with this runbook enforces no
revocation. Until it is enrolled with the keyroster agent ([Enrolling a
host](#enrolling-a-host), 03-07), which sets `RevokedKeys` and applies
every KRL, such a host refuses a revoked
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
   address as four decimal octets without leading zeros. keyroster refuses
   any other spelling and prints the canonical one where there is one; it
   never rewrites a name. A name whose labels are all numbers, such as the
   hex `0x7f000001` or `127.0.0.0x1`, is refused too: a resolver reads it
   as an IPv4 address. No principal and no host key may be on two hosts.

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

The CLI applies the signer's rule to the directory it reads: `directory
show`, `directory sign`, `directory install`, `user list`, `host list`,
`machine list`, `host principals` and every edit refuse a served directory
that names another installation than the root-verified bundle, or names
one while the bundle has none, and print nothing from it. An unbound
directory is still read (`TestReadCommandsCheckInstallation`).

Until the bound version installs, logins under the unbound directory keep
working on the signer: the owner's lenient answer to D-04 (03-01). The
signer logs a warning at start (`installed directory names no installation,
but the trust bundle in force does`). Host agents (03-07) never accept a
directory without the installation ID, so bind it before the first agent
enrolls.

## Supported platforms

The keyroster agent (`keyroster-agent`, Phase 3) manages stock OpenSSH on
(D-17):

- Debian 12 and later, Ubuntu 24.04 and later;
- RHEL, AlmaLinux and Rocky Linux 9 and later;
- current Alpine and current Arch Linux;
- Proxmox VE 8 and later (Debian-based).

**What is tested.** Run in CI (`e2e-distro`, 03-06): each image below, as
root in a container, installs its own `openssh-server` and runs its
packaged `sshd_config` with StrictModes yes. The agent passes its preflight,
applies with the `signal` reload, accepts a certificate login through the
`current` symlink, reports a later `Match` block as drift, and takes over the
Phase 2 layout. `TestDistroRefusals` provokes these preflight cases on each
image's own sshd, with their exit status: `foreign_trust_setting` (another
drop-in, `sshd_config`, a file included from outside `sshd_config.d` with a
`Match` block, a nested glob include, `AuthorizedPrincipalsCommand` in
`sshd_config` and in an included `Match` block), `no_dropin_dir`,
`account_excluded` (report only), `login_grace_unbounded` (preflight and
apply), `ssh_keygen_missing`, `host_pop_not_enabled`,
`no_loopback_listener`, and exit 2 for an sshd that cannot run, an apply
that holds the lock and an `Include` cycle (the distribution's `sshd -T`
refuses it). `TestDistroDetectRefusesSSHDArgs` provokes
`sshd_command_unknown` through `/etc/conf.d/sshd`. The other codes are
unit-tested only, UNVERIFIED on a distribution's sshd:
`login_grace_unknown` (a real `sshd -T` always prints seconds),
`rhel8_unsupported`, `fips_unsupported`, `dropin_drift`,
`sshd_config_unsafe`, `sshd_command_unknown` from a systemd unit, and the
apply-only `phase2_adoption_pending`. The facts each image ships:

| Image | OpenSSH | `Include sshd_config.d/*.conf` at line | Ed25519 CAs accepted (`casignaturealgorithms`) | LoginGraceTime | `ssh-keygen` | Notes |
|---|---|---|---|---|---|---|
| debian:12 | 9.2 | 12 | yes, listed first | 120 | comes with `openssh-server` | |
| debian:13 | 10.0p2 | 12 | yes, listed first | 120 | comes with `openssh-server` | |
| ubuntu:24.04 | 9.6p1 | 12 | yes, listed first | 120 | comes with `openssh-server` | |
| ubuntu:26.04 | 10.2p1 | 24 | yes, listed first | 120 | comes with `openssh-server` | |
| almalinux:9 | 9.9p1 | 15 | yes, after the ECDSA types (crypto-policies) | 120 | comes with `openssh-server` | `sshd_config.d` is mode 0700 and ships `50-redhat.conf` |
| alpine (latest) | 10.3p1 | 15 | yes, listed first | 120 | separate package `openssh-keygen` | no PAM; `sshd -T` prints no `revokedkeys` line while it is unset |
| archlinux (latest) | 10.6p1 | 2 | yes, listed first | 120 | comes with `openssh` | an ML-DSA-44+Ed25519 host key the agent skips (it reads the Ed25519 one); no `revokedkeys` line while unset |

The two-step swap waits the LoginGraceTime bound plus 30 s, measured on
CLOCK_MONOTONIC, before an addition takes effect after a removal: 150 s with
the packaged 120 s.

**What is not tested.** The containers run no service manager, so systemd
and OpenRC reloads, `systemctl try-reload-or-restart` on Ubuntu's socket
activation on a booted host, SELinux on an enforcing EL9 host and Proxmox VE
are UNVERIFIED until the dogfood hosts (03-16). Older EL9 minor releases are
covered only by the current AlmaLinux 9 image. Detection (below) is
unit-tested on constructed `systemctl show` output, and
`TestDistroDetectStock` runs it on each image's real file system with
`systemctl show` output built from the image's own unit file (Alpine: its
own `/etc/conf.d/sshd`); the output of a real `systemctl show` is UNVERIFIED
until 03-16.

### How the agent finds and reloads sshd

Without `--sshd`, `--sshd-config` and `--reload`, the agent reads the service
that runs sshd (03-06; PR #68 review, owner decisions D-R1 and D-R4):

- **systemd:** `systemctl show` of `ssh.socket`, `ssh.service` and
  `sshd.service` gives the binary and the command line (`ExecStart`). The
  agent runs `sshd -t` and `sshd -T` with `-f <config>` only, so it accepts
  only the arguments every stock unit uses: `-D`, `-e` and one `-f <file>`
  (Debian and Ubuntu `-D $SSHD_OPTS`, EL9 `-D $OPTIONS`, Arch `-D`). A
  `$NAME` or `${NAME}` is resolved from the unit's `Environment` and
  `EnvironmentFile`s (`/etc/default/ssh`, `/etc/sysconfig/sshd`; empty on
  every stock image), so `SSHD_OPTS="-f /etc/ssh/sshd_config.prod"` makes the
  agent check that file. Anything else, such as `-o RevokedKeys=none`,
  `-p 2222` or a value it cannot unquote, is refused as
  `sshd_command_unknown`, and so is an `EnvironmentFile` it cannot read
  safely (owned by root, writable by no one else, no symlink another user
  controls, at most 64 KiB) or cannot be sure how systemd splits into
  lines: a backslash anywhere (also a comment that ends in one, which
  systemd continues on the next line), a quoted value that is not exactly
  one quoted string (systemd's quoted values span lines), or a line that is
  not `NAME=VALUE` (such as `export NAME=...`). A missing optional file
  (`EnvironmentFile=-...`) is empty. The agent does not read systemd's
  manager environment (`DefaultEnvironment=` in `system.conf`,
  `systemctl set-environment`), which a unit's `$NAME` also sees: a variable
  set only there is read as empty. UNVERIFIED: an `OPTIONS` or `SSHD_OPTS`
  set that way is not detected (PR #68 review fix round 2, P8, deferred).
- **OpenRC:** `/etc/conf.d/sshd` (at most 64 KiB, owned by root, writable
  by no one else). The agent reads the variables Alpine's stock init script
  uses: `cfgfile`, else `SSHD_CONFIG`, else `$SSHD_CONFDIR/sshd_config`;
  `SSHD_BINARY`; `command_args`, else `SSHD_OPTS`, which may hold only `-D`
  and `-e` (set the file with `cfgfile`). `openrc-run` sources the file with
  `sh`, so every line must be a comment, a blank line or one plain
  `NAME=VALUE` assignment (an unquoted value without shell characters, or
  one single- or double-quoted string without `$`, a backtick or a
  backslash); anything else (`export`, a command, `;`, a trailing comment)
  refuses the file as `sshd_command_unknown`. The agent does not read the
  init script's own command line (Alpine's stock script adds only
  `-o PidFile=` and `-f <cfgfile>` when they differ from the defaults),
  `/etc/rc.conf`, or the environment `openrc-run` inherits. UNVERIFIED: a
  modified init script, or `command_args`/`SSHD_OPTS` set in `/etc/rc.conf`
  or the inherited environment, is not detected.
- **Socket activation (Ubuntu's `ssh.socket`):** whenever `ssh.socket` is
  active, the reload strategy is `systemd-socket:<unit>`, whatever the
  service's own state. Every reload, the apply's and every rollback's, runs
  `systemctl try-reload-or-restart <unit>`: a running sshd, also one a
  connection started since the agent looked, re-reads its configuration,
  and a stopped one reads the files on disk when the next connection starts
  it. The report's `reload_actions` names each command that ran. A unit
  caught in a transitional state (`activating`, `reloading`,
  `deactivating`) is refused: run again. The strategy `none`, which reloaded
  nothing, no longer exists.

`--sshd`, `--sshd-config` and `--reload` override detection; a host started
with other arguments is then the operator's to vouch for.

## Not supported

The agent's preflight names these hosts and refuses them (D-18):

- **RHEL 8** and its rebuilds (`rhel8_unsupported`). Its OpenSSH 8.0 reads
  no `sshd_config.d`, so the agent's settings could take effect only by
  editing `sshd_config`, which the agent never does. Move the host to RHEL 9
  or later (or Alma or Rocky 9 or later).
- **RHEL in FIPS mode** (`fips_unsupported`, from
  `/proc/sys/crypto/fips_enabled`). FIPS mode's OpenSSH rejects the Ed25519
  CA keys keyroster signs with. Run the host without FIPS mode.

Run in CI as unit tests (`TestPreflight`); no RHEL 8 or FIPS host ran.

## Before the agent: preflight

Run in CI (`e2e-distro`, 03-06) on every image above for the codes
[What is tested](#supported-platforms) lists; the others are unit-tested
only. UNVERIFIED on a real host until 03-16.

```
sudo keyroster-agent preflight
```

It prints its findings as JSON and changes nothing on the host, except a
trial copy of the agent's drop-in. It writes that copy only while no
drop-in exists on a host where the agent has installed nothing (no
`/etc/ssh/keyroster/current` or `last-good`), removes it before it exits,
and never reloads sshd. With the trial in place, `sshd -T` shows whether
`sshd_config.d` is read before every other trust setting. On an installed
host it writes no trial: the trial names `current`'s CA keys without a
`RevokedKeys` line, so an sshd that loaded it would accept revoked
certificates. There a missing, trial or edited drop-in is `dropin_drift`
instead. Without `--sshd` and `--sshd-config` it detects the service that
runs sshd ([How the agent finds and reloads
sshd](#how-the-agent-finds-and-reloads-sshd)). Its exit status is:

- 0 when no finding refuses the host;
- 3 when one does (`sshd_command_unknown` included);
- 2 for a usage or tool error, such as an sshd that cannot run, or an apply
  that holds the agent's lock.

`account_excluded` and `phase2_adoptable` are report only and leave the exit
status at 0.

The first apply, and every change of the drop-in, runs the same checks
before anything is written (without the trial) and refuses on any refusal.
Every apply also refuses `login_grace_unbounded` at its start (03-05). On a
first install a file the agent did not write at `00-keyroster.conf` is
`foreign_trust_setting`; once a generation is installed the file is the
agent's own, and an edited one is repaired, never refused, so a KRL still
installs.

| Code | What it means | Fix |
|---|---|---|
| `ssh_keygen_missing` | No `ssh-keygen` at the path given (default `/usr/bin/ssh-keygen` or `/bin/ssh-keygen`); the agent checks every CA line and KRL with the host's own tools | Install it (`openssh-client`, `openssh-clients`, or `openssh-keygen` on Alpine), or pass `--ssh-keygen` |
| `no_dropin_dir` | `/etc/ssh/sshd_config.d` is missing, or `sshd -T` with the trial drop-in still shows the setting unset: sshd does not read `sshd_config.d/*.conf` before its other settings | Add `Include /etc/ssh/sshd_config.d/*.conf` as the first line of `sshd_config` (every image above ships it near the top) |
| `foreign_trust_setting` | A line sets `TrustedUserCAKeys`, `RevokedKeys`, `AuthorizedPrincipalsFile`, or an `AuthorizedPrincipalsCommand` other than `none` (then every `AuthorizedPrincipalsCommandUser` line too) in any file sshd reads but the agent's drop-in, inside `Match` blocks too; the finding names the file and line. The agent follows every `Include` from `sshd_config` (or the service's `-f` file), recursively, with relative paths under `/etc/ssh`, `Include` lines inside `Match` blocks, and a `*` in the last path component (owner decision D-R3, extending D-07). Every line is split as sshd splits it (a port of OpenSSH 9.2p1's and 10.2p1's tokeniser: quoted keywords and arguments, `keyword=value`, backslash escapes, a trailing `#` comment), so a quoted `"Include"` or `"AuthorizedPrincipalsFile"` is seen; quoted and partly quoted keywords, single- and double-quoted paths, `include=` and a trailing comment were checked against a real sshd 9.2p1, the other escapes only against its source. Also raised when `sshd -T`, or `sshd -T -C` for a managed account, reports one of these set where the agent did not read it. A principals command matters because sshd consults its output when the principals file matches none, which widens which certificates an account accepts | Remove or comment out that line. The agent never merges with or overrides another trust setting. The Phase 2 runbook's exact layout is taken over instead (below) |
| `sshd_config_unsafe` | A file sshd reads, or the directory an `Include` names, could be changed by another user (not owned by root, writable by group or others, or behind a symlink another user owns), or the `Include` graph cannot be followed: a cycle, more than sshd's 16 levels, a `~` path, more than 512 files, a file larger than 1 MiB, a line with an unbalanced quote (or a keyword in single quotes), or an `Include` path with another glob character than `*` (`?`, `[...]`, a backslash) or a `*` in a directory component. The agent matches only `*` because sshd's glob(3) and Go's differ on the others: `[!x]` is a negation in glob(3), and `[^x]` is a literal `^` in sshd 9.2p1's. A trust setting there cannot be ruled out. On an installed host the agent's own drop-in is evaluated as the apply writes it, so an edited `00-keyroster.conf` is repaired, not refused; an unsafe `sshd_config.d` directory is still refused, because rewriting the file cannot fix it | Make those files and directories root-owned and writable only by root, and simplify the `Include` lines (a plain path, or one `*` in the file name) |
| `sshd_command_unknown` | The detected service starts sshd with an argument other than `-D`, `-e` and `-f <file>` (after resolving `$SSHD_OPTS`, `$OPTIONS`, OpenRC's `command_args`), or its settings file cannot be read safely ([How the agent finds and reloads sshd](#how-the-agent-finds-and-reloads-sshd)) | Move the option into `sshd_config`, where the agent checks it, and leave the variable empty |
| `dropin_drift` | Only on an installed host: `00-keyroster.conf` is missing, holds a preflight trial, or differs from what the agent writes (owner decision D-R2, "repair and report"). The apply never refuses on it | A trial: `sudo keyroster-agent apply --once` replaces it with the agent's drop-in and reloads sshd, even with nothing new to install. Missing or edited: the next apply that installs a new signed state rewrites it (the old file is kept as `dropin.prev` until that apply commits). Keep other sshd settings in another file |
| `no_loopback_listener` | sshd listens on no loopback address. The agent self-tests sshd over loopback only (the owner's D-05 answer, loopback-only) | Add `ListenAddress 127.0.0.1` to `sshd_config` beside the existing `ListenAddress` lines; the agent never edits `sshd_config` |
| `login_grace_unbounded` | `sshd -T` reports `logingracetime 0`. The agent's two-step swap waits LoginGraceTime plus 30 s before an addition takes effect, so it needs a bound | Set a bounded `LoginGraceTime` in `sshd_config`, for example the default 120 |
| `login_grace_unknown` | `sshd -T` reports a LoginGraceTime that is not a number of seconds | As above |
| `host_pop_not_enabled` | The verified, pinned policy has no `pop.hosts`; host agents require it (not raised before any policy was received) | A root-signed successor policy with `pop.hosts` ([Host agents need pop.hosts](#registering-a-host-in-the-directory)): `keyroster root successor-policy --pop-hosts` in a root ceremony. It can never be turned off again |
| `rhel8_unsupported`, `fips_unsupported` | See [Not supported](#not-supported) | |
| `account_excluded` (report only) | `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups` refuse a managed account, evaluated per account with `sshd -T -C` and sshd's pattern rules. A `user@host` entry "may" exclude, depending on the client's address | Change them by hand if the account should log in with certificates; the agent never edits them |
| `phase2_adoptable` (report only) | The host holds the Phase 2 runbook's exact layout | Follow [Moving a Phase 2 host to the agent](#moving-a-phase-2-host-to-the-agent) |

Only `keyroster-agent apply` reports these two:

| Code | What it means | Fix |
|---|---|---|
| `phase2_adoption_pending` | The exact Phase 2 layout, matching the signed state, found by a run that may not take it over (the applier unit's run loop; its sandbox cannot remove files in `/etc/ssh`). Nothing is written or removed | Run `sudo keyroster-agent apply --once` once from a root shell |
| `phase2_layout_differs` | A Phase 2 style layout that is not exactly the runbook's, or does not match the signed state. Every difference is listed | Fix each difference (below) |

## Enrolling a host

Run in CI e2e (`TestAgentEnrollEndToEnd`, 03-07): a join token minted with
`keyroster host join-token`, `keyroster-agent install`, the fetcher's
enrollment over the agent listener, `keyroster host pending` compared with
`keyroster-agent identity`, `keyroster host approve`, the first apply, a
certificate login, and a revocation refused a few seconds later, against a
real sshd on OpenSSH 9.5p1 and 10.5p1. Every step on the homelab is
UNVERIFIED until 03-16. Join-token minting and `host approve` are
owner-run on the homelab: they are admin-signed acts, which the permission
classifier refuses for agents.

**Before you start.**

- The root-signed policy must set `pop.hosts`. Without it, minting a join
  token, the enrollment and the pending list are refused
  `host_pop_not_enabled`, by the server and, for `host join-token` and
  `host approve`, by the CLI itself on the policy it verified. The fix is a
  root ceremony with `keyroster root successor-policy --pop-hosts`
  ([Registering a host in the directory](#registering-a-host-in-the-directory)),
  which can never be turned off again.
- keyroster-server must run an agent listener (`--agent-listen`, see
  [server-install.md](server-install.md#the-agent-listener-host-agents-03-07)).
- The host passes `sudo keyroster-agent preflight` ([Before the agent:
  preflight](#before-the-agent-preflight)).
- Root on an enrolled host can read the whole signed directory the agent
  receives: every user name, role, host group and credential ID (D-03, a
  single-tenant deployment). Enroll only hosts whose root you would show
  that to.

**1. Mint a join token (admin workstation).**

```
keyroster host join-token <name> --ttl 30m --out <name>.join
```

`<name>` is the host name the directory will give the host. The token is
32 random bytes, valid for one enrollment and at most 1 h (30 min by
default); the server keeps only its SHA-256. The command writes the join
string (`kr-join-v1:...`) to the file with mode 0600 and never prints it:
the file is a secret until the token is used or expires. On a Windows
workstation the file gets no mode 0600: it inherits the ACL of its
directory, and the command says so and warns. Write it to a directory only
you can read, for example under your user profile, and delete it once it
is on the host (an owner-only ACL is a pending todo). It carries the
agent listener's URL, the TLS roots and pins and the trust-root pins and
threshold of your `keyroster init` config, and the installation ID of the
trust bundle it verified.

**2. Install the agent (on the host, as root).**

Create the fetcher's system user first, with a group of its own:

```
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin keyroster-agent
```

On Alpine:

```
addgroup -S keyroster-agent && adduser -S -D -H -G keyroster-agent -s /sbin/nologin keyroster-agent
```

(UNVERIFIED: neither command has run on a real host; the e2e run uses the
test user through `--fetch-user`.) Copy the join file to the host with mode
0600 (for example `install -m 0600 <name>.join /root/<name>.join` after
`scp`), then:

```
keyroster-agent install --join-file /root/<name>.join
rm /root/<name>.join
```

Install refuses before it writes anything when the join string does not
parse, the user `keyroster-agent` does not exist, a path below already
exists as a symlink, as the wrong type, with another owner or a wider mode
(`install_path_unsafe`), or `pins.json` pins another installation
(`install_pins_differ`). It lays out these paths, each created relative to
its parent opened without following links:

| Path | Owner | Mode | Holds |
|---|---|---|---|
| `/var/lib/keyroster-agent` | root:root | 0755 | the applier's state |
| `/var/lib/keyroster-agent/accepted` | root:root | 0700 | the signed documents the applier accepted |
| `/var/lib/keyroster-agent/pins.json` | root | 0600 | trust-root pins, threshold, installation ID |
| `/var/lib/keyroster-agent/spool` | keyroster-agent:root | 0750 | the signed documents the fetcher received |
| `/var/lib/keyroster-agent/outbox` | root:keyroster-agent | 2750 | the applier's answers to the fetcher (`enroll-pop.json`; `accepted.json`, the versions it accepted, which the fetcher's state requests start from) |
| `/etc/keyroster-agent` | root:root | 0755 | |
| `/etc/keyroster-agent/fetch.json` | root:keyroster-agent | 0640 | the agent server's URL, TLS roots and pins |
| `/var/lib/keyroster-agent-fetch` | keyroster-agent | 0700 | the fetcher's identity key |
| `/var/lib/keyroster-agent-fetch/join-token` | keyroster-agent | 0600 | the token, until the server accepts the enrollment |
| `/etc/ssh/keyroster` | root:root | 0755 | the agent's generations (created now so the applier's unit can start) |
| the two units or OpenRC scripts | root:root | 0644 / 0755 | [Running the agent](#running-the-agent) |

The fetcher can write only its own directory and the spool. Everything it
writes there is data the root applier verifies against its own pins; it
reads nothing from the fetcher but through a no-follow, non-blocking,
size-capped open. The ownership of these paths as root, with the real
users, is run in CI in `agent-smoke.sh` (03-08); the e2e run creates them
as the test user.

**3. Start the fetcher and the applier**:
`systemctl daemon-reload && systemctl enable --now keyroster-agent
keyroster-agent-fetch` ([Running the agent](#running-the-agent)).

The fetcher generates its identity (a self-signed Ed25519 TLS client
certificate) on its first start and writes `identity.pub` into the spool.
It asks the applier for the proof of possession (`enroll-request.json` in
the spool); `keyroster-agent run` signs it with every Ed25519 and ECDSA host
key `sshd -T` names and answers in the outbox; the fetcher posts it. Both
then wait quietly for the approval. (Run in CI under systemd in
`agent-smoke.sh`; the e2e run uses the same binaries with `--poll 1s` and
`--interval 1s`.)

**4. Approve the host (admin workstation, then the host).**

```
keyroster host pending
```

lists each host waiting for approval with its agent identity and host key
fingerprints and the facts it reported (its own word only). On the host,
as root:

```
keyroster-agent identity
```

prints the same `agent identity:` and `host key:` lines. Compare every one
of them out of band; then:

```
keyroster host approve <name> --group <host group> --principal <name> [--principal <fqdn> ...] \
  --host-key SHA256:<host key 1> [--host-key SHA256:<host key 2> ...]
```

Give `--host-key` once for every `host key:` line `keyroster-agent
identity` printed on the host. `host approve` fetches the pending host again
and refuses, signing nothing, unless its host keys are exactly the ones you
gave: none missing, none extra (owner decision D-R4, PR #71). That binds the
signature to the keys you compared, not to whatever the server answers at
approve time. `--host-key` is required with `--yes`; without `--yes`, `host
approve` prints the fingerprints and asks before it signs, and then compare
them in that output, not in an earlier `host pending`. (Run in CI:
`TestHostApproveHostKeys` and `TestAgentEnrollEndToEnd`.)

`host approve` shows the fingerprints again and signs a directory version
with a host entry `<name>`, the enrolled host keys, the host group and the
principals you typed: nothing in it comes from the host but its keys,
which it proved it holds. The server serves the agent signed state once
the installed directory holds an active entry with exactly those keys, and
from its first state answer on it records the agent as approved: after
that the agent keeps receiving signed state even when its entry is
disabled or removed, so the removal itself and every later revocation
reach the host ([Removing a host](#removing-a-host)). The next poll pulls
the signed state and `keyroster-agent run` applies it ([How fast changes
arrive](#how-fast-changes-arrive)).

**Refusals.**

| Code | Where | What it means | Fix |
|---|---|---|---|
| `host_pop_not_enabled` | CLI, server | The policy in force lacks `pop.hosts` | A root ceremony with `--pop-hosts` (above) |
| `no_agent_listener` | `host join-token` | The server runs no agent listener | `--agent-listen` (server-install.md) |
| `token_used`, `token_expired`, `token_unknown` | fetcher log | The token enrolled another agent, expired (enforced to the second), or was never minted | A new join token, then `keyroster-agent install` again |
| `host_keys_in_use` | fetcher log | A host key is already on a directory host entry, or on an agent this server enrolled before | A directory entry only (a host registered with `keyroster host add`): `keyroster host remove <name>`. The refusal left the token unused, so the fetcher's next attempt enrolls while the token is valid (after it expired, a new join token and `install`); then approve under the same name. An agent enrolled before, for example a host whose agent state was reinstalled with the same host keys: remove its entry if it has one, then forget the old agent by its identity, `keyroster host forget --identity <identity>` ([Removing a host](#removing-a-host)), then a new join token and `install` |
| `identity_in_use` | fetcher log | This fetcher identity is enrolled already | None needed: the host is enrolled |
| `enroll_pop_invalid` | fetcher log | A host key's signature does not verify | Re-run the applier (`keyroster-agent run`); escalate if it repeats |
| `host_key_unreadable` | applier log | A host key is held by an agent (`HostKeyAgent`), encrypted, or does not match its `.pub` | Use unencrypted host key files |
| `enroll_request_invalid`, `enroll_pop_mismatch` | applier, fetcher log | The hand-over files do not check out | Let the fetcher write a fresh request (restart it) |
| `not_approved` | fetcher log | Enrolled, not approved yet | Step 4 |
| `unknown_agent` | fetcher log | The server has no agent with this identity: never enrolled, or forgotten (`keyroster host forget`) | A new join token, then `keyroster-agent install` again |
| `rate limited` (429) | fetcher log | The server's limiter refused a state request; the fetcher keeps what it spooled and goes on at the next poll | None; escalate if every poll says it |
| `host_in_directory`, `host_not_enrolled` | `host forget` | A directory entry still holds the agent's host keys; no agent has that identity (forgotten already, or its identity rotated) | Remove the host first and wait for its removal confirmation; check the identity with `keyroster host pending` |
| `host_removal_not_applied` | `host forget` (CLI) | The agent was approved once and the server has no recorded removal confirmation for it: the host's heartbeat never showed a served directory that removes it (`removal confirmed at directory v<N>` is missing in `keyroster host pending`) | Wait for its next heartbeat; `keyroster host forget --identity <identity> --host-gone` for a host that is gone for good ([Removing a host](#removing-a-host)) |
| `host_swap_pending` | `host forget` (CLI and server) | The agent's removal is confirmed, but its host's newest heartbeat shows a swap it has not finished (`swap pending` in `keyroster host pending`), so the confirmation does not yet speak for what it enforces (03-08c); nothing was forgotten | Wait for its next heartbeat and run the command again; `--host-gone` for a host that is gone for good |
| `forget_name_ambiguous` | `host forget` (CLI) | More than one agent has the name (a re-enrolled host); nothing was sent | Run one of the `keyroster host forget --identity <identity>` commands the refusal lists ([Removing a host](#removing-a-host)) |
| `forget_state_changed` | `host forget` | The agent changed since `keyroster host pending` was read (its approval, removal version, confirmation or enrollment time, or its identity rotated); nothing was forgotten | Run the command again |
| `admin_quorum_not_met` | `host forget` (CLI and signer) | Too few distinct admin signatures: one for an agent never approved, the policy's admin quorum for every other (03-08c, owner decision Q3); nothing was signed, or the signer forgot nothing | Give one `--admin-key` per admin, each key in the one ssh-agent ([Removing a host](#removing-a-host), step 3) |
| `request_time_skew` | `host forget` (CLI and signer) | Signing took more than 240 s, or the request's time is more than 300 s from the signer's clock; nothing was forgotten | Run the command again and confirm each key promptly; check the clocks |
| `forget_facts_mismatch` | `host forget` (signer) | The admins signed that the agent was never approved, but the server's row says it was (or the reverse); nothing was forgotten | Run `keyroster host pending` again; if it repeats, the server and the signed request disagree: escalate |
| `forget_host_in_directory` | `host forget` (signer) | The signer's directory still has an entry, active or disabled, with one of the agent's host keys; nothing was forgotten | Remove the host first and wait for its removal confirmation |
| `forget_confirmation_invalid` | `host forget` (signer) | The confirmation names a directory version the signer never installed, or another document's SHA-256; nothing was forgotten | Run `keyroster host pending` again; if it repeats, escalate |
| `forget_logged_not_deleted` | `host forget` (server) | The signer logged the forget as audit entry `<N>`, but the agent changed before the server could delete it; the agent is still served | Run `keyroster host pending` and forget it again, which logs a second entry |
| `stale_heartbeat` | server | The heartbeat's seq is not above the stored one: the usual answer between the applier's status writes. A seq below the stored one is also logged by the server as `heartbeat_seq_regressed` (at most once an hour) and flagged `seq_regressed` | None: the fetcher logs nothing for it |
| `heartbeat_seq_future` | fetcher log, server log | The heartbeat's seq is more than an hour beyond the server's clock: the host's clock runs ahead. Nothing but its clock offset is stored, so `clock_skew` shows it (D-R2) | Fix the host's clock; the applier restarts its seq from its clock once the clock is back |
| `heartbeat_field_invalid` | fetcher log, server log | A status field broke its rule; the answer names the field | Escalate: the agent wrote, or something changed, a status the server refuses |
| `fetch_dir_not_owned` | fetcher | The fetcher runs as another user than its directory's owner (root running `--rotate-identity`) | `sudo -u keyroster-agent keyroster-agent-fetch ...` |
| `identity_rotation_too_soon` (429) | `--rotate-identity` | The agent rotated its identity less than an hour ago; one agent rotates at most once an hour, and its rate limit is the agent's, whatever its identity (PR #72 review) | Wait for `Retry-After`; an unplanned earlier rotation is [An unexpected identity rotation](#running-the-agent) |
| `install_no_service_manager`, `install_no_sshd_config_d` | install | Neither systemd nor OpenRC found; no `/etc/ssh/sshd_config.d` on a systemd host | [Running the agent](#running-the-agent) |
| `install_path_unsafe`, `install_pins_differ` | install | See step 2 | Fix the path; for other pins, remove the agent's state first |

The `host forget` refusals above run in CI (03-08b, 03-08c). The server's: `host_in_directory`
and `host_not_enrolled` in `TestAgentRemoval`, `forget_state_changed`
in `TestForgetHost`, `host_swap_pending` in `TestRemovalConfirmation` and `forget_logged_not_deleted` in `TestForgetHost` (03-08c). The signer's (03-08c):
`admin_quorum_not_met`, `request_time_skew`, `forget_facts_mismatch`, `forget_host_in_directory` and `forget_confirmation_invalid` in
`TestForgetAgent`. The CLI's: `forget_name_ambiguous`, `forget_state_changed`,
`host_in_directory` and `host_not_enrolled` in `TestHostForget`, and
`host_removal_not_applied` in `TestHostForget` and `TestHostForgetHostGone`, and
`host_swap_pending`, `admin_quorum_not_met`, `request_time_skew` and `forget_logged_not_deleted` in `TestHostForget` (03-08c). On the
homelab they are UNVERIFIED until 03-16.

## Running the agent

Run in CI: systemd on Ubuntu 24.04, in the `systemd-sandbox` job
(`test/systemd/agent-smoke.sh` and `TestAgentSystemdSmoke`, 03-08): both
units under real systemd against the runner's own `ssh.service`, the first
apply through `systemctl`, a certificate login, the heartbeat in `keyroster
host status`, an identity rotation as the real `keyroster-agent` user, the
cross-user writes below, and `systemd-analyze security` for both units.
OpenRC and the other distributions' service managers are UNVERIFIED until
03-16; so is every step on the homelab.

`keyroster-agent install` writes the agent's two services (root:root): on
a systemd host (`/run/systemd/system` exists) the units
`/etc/systemd/system/keyroster-agent.service` and
`keyroster-agent-fetch.service` (0644); on an OpenRC host
(`/sbin/openrc-run` exists) the scripts `/etc/init.d/keyroster-agent` and
`/etc/init.d/keyroster-agent-fetch` (0755). With neither it refuses
`install_no_service_manager`, and on a systemd host without
`/etc/ssh/sshd_config.d` it refuses `install_no_sshd_config_d`, both before
it writes anything. It creates `/etc/ssh/keyroster` (root:root 0755) before
the units, because systemd refuses to start a unit whose `ReadWritePaths`
path does not exist. It neither enables nor starts them. Edit them only
through drop-ins (`systemctl edit`): a later `install` writes them again.

| Unit | Runs as | May write (`ReadWritePaths`, everything else read-only) | Network |
|---|---|---|---|
| `keyroster-agent-fetch.service` | `keyroster-agent`, no capabilities, `NoNewPrivileges` | `/var/lib/keyroster-agent-fetch /var/lib/keyroster-agent/spool`; it reads `/etc/keyroster-agent/fetch.json` and the outbox | IPv4 and IPv6 sockets only (`RestrictAddressFamilies=AF_INET AF_INET6`: no Unix, netlink or packet sockets). The unit does not restrict destinations: the server's address is not known when `install` writes it; a host firewall can restrict them |
| `keyroster-agent.service` | root, no capabilities, `NoNewPrivileges` | `/etc/ssh/keyroster /etc/ssh/sshd_config.d /var/lib/keyroster-agent` (the spool and the outbox are inside the state directory) | loopback only: `IPAddressDeny=any`, `IPAddressAllow=localhost` (its self-test; the owner's D-05 answer `loopback-only`) |

`/etc/ssh` itself stays read-only to the applier's unit. That is why taking
over a Phase 2 host is a hand-run step (below), and why the unit's applier
reports `phase2_adoption_pending` instead of doing it.

`sshd -t` and `sshd -T` refuse to run without sshd's privilege separation
directory (`Missing privilege separation directory: /run/sshd`). A
socket-activated `ssh.service`, Ubuntu 24.04's default, creates it only
once a connection started sshd, so after a boot the applier could neither
apply nor check, and the first connection would start sshd with the trust
files from before the boot. The applier's unit therefore creates
`/run/sshd` (root:root 0755) before it starts (`ExecStartPre=+`, outside its
sandbox). A hand-run `keyroster-agent apply --once` on such a host before
the unit ever ran needs `sudo install -d -m 0755 /run/sshd` first. (Found
and run in CI by `agent-smoke.sh` on the runner's socket-activated sshd.)

**Start them** (as root):

```
systemctl daemon-reload
systemctl enable --now keyroster-agent keyroster-agent-fetch
```

or on OpenRC (UNVERIFIED until 03-16):

```
rc-update add keyroster-agent default && rc-update add keyroster-agent-fetch default
rc-service keyroster-agent start && rc-service keyroster-agent-fetch start
```

The OpenRC scripts have no sandbox: the applier runs as root and the
fetcher as `keyroster-agent` (`command_user`), and that user is the only
separation. The fetcher's script creates its log,
`/var/log/keyroster-agent-fetch.log`, as `keyroster-agent` 0640 before
the start (`checkpath` in `start_pre`), because `start-stop-daemon` opens
the log only after it dropped to that user (PR #72 review; UNVERIFIED
until 03-16 like the rest of OpenRC).

**On a Phase 2 host** ([Moving a Phase 2 host to the agent](#moving-a-phase-2-host-to-the-agent)):
the units run as usual and the applier reports `phase2_adoption_pending`
(`keyroster host status` shows it as the last apply's error). After
approving the host and re-rendering its principals files, run once, from a
root shell:

```
sudo keyroster-agent apply --once
```

The applier's unit cannot remove files in `/etc/ssh`; the hand run can. The
apply lock serialises it with the unit.

**What the units do.** `keyroster-agent run` looks at the spool every 5 s
and applies new signed state. It runs the drift check
([Drift](#drift)) after every apply and every 15 min, with a random 60 s
either way. After every apply and every check it writes its status to
`/var/lib/keyroster-agent/outbox/status.json` (root:keyroster-agent 0640,
written atomically without following links; its own copy is
`/var/lib/keyroster-agent/heartbeat.json`, 0600). `keyroster-agent-fetch`
polls every 60 s, with a random 10 s either way. After every poll the
server answered, it posts that status as a heartbeat, with its clock offset
(`clock_offset_s`, below). Between the applier's writes the server already
holds that status and answers `stale_heartbeat`; the fetcher logs nothing
for it.

The fetcher, as the real `keyroster-agent` user, cannot create a file in
`/var/lib/keyroster-agent` (where `pending.json` lives), in `accepted/` or
in the outbox, nor overwrite `pins.json`, `outbox/status.json` or
`outbox/accepted.json`. It can read the outbox and write the spool. The
applier never reads the outbox. (Run in CI: `agent-smoke.sh`, with the real
users.)

**Revocations keep applying** (owner decision D-R2, at every stage of the
apply; 03-08d). When the applier cannot apply the bundle or directory a
capture holds, the capture's KRL still lands. The cases:

- the bundle or directory step is refused by verification (a chain gap,
  or a version a signer restore re-made);
- the directory renders a generation above the agent's caps: a principals
  file above 64 KiB, more than 4096 principals files, or an intermediate
  above them (the swap's intermediate holds the accounts of the generation
  in force and of the new one);
- a verified bundle carries a CA line the host's `ssh-keygen` refuses
  (`ca_line_rejected`);
- no directory is accepted, after `keyroster-agent reset-directory` and
  before the fetcher spools one.

The applier then installs the capture's KRL alone, verified again against
the bundle it accepted (during a widening wait, against the pending
target's), with the CA keys and principals in force. `last_apply.result`
is `refused`, and its error names the refusal (`generation_too_large`,
`ca_line_rejected`, `directory_not_verified` or `host_not_in_directory`,
for example); `keyroster host status` shows the error as a
`last apply error` note. After `reset-directory` a verified successor bundle's
CA keys apply as well, with last-good's principals. A KRL that only the
refused bundle's ops key signed waits with that bundle, and before the
first install the refusal stands and nothing is installed. The host keeps
the directory and principals it had until the server publishes a
directory it can apply: split the oversize host group or roles and
publish again.

That does not help a host that is far behind. An apply reads at most 64
versions of each kind past the ones the host accepted, so when the
refused version is the newest of those, a fixed version published after
it never enters a capture. Such a host's report keeps `"spool_more": true`
under the same `generation_too_large` or `ca_line_rejected` refusal, apply
after apply (the report is one JSON line per apply in the applier unit's
journal, or the output of `sudo keyroster-agent apply --once`). Publishing
again does not move it:

- For a directory, run `keyroster-agent reset-directory` on the host as
  root. The next poll then takes the server's current directory the way a
  first install does (signer-install.md, "Re-bootstrap each such host").
- For a bundle, escalate: `reset-directory` re-bootstraps the directory
  only.

Revocations keep applying meanwhile. UNVERIFIED on a real host: no test
or drill runs this case.

Failed applies no longer pile up generations under `gen/`:
every rollback, and every undone first install, ends with the retention
cleanup a commit runs. Run in CI (03-08d):
`TestKRLAlone` (`oversize_principals_file_krl_applied`,
`too_many_accounts_krl_applied`, `intermediate_union_too_large_krl_applied`,
`ca_line_rejected_krl_applied`, `superseded_during_wait_krl_applied`,
`ops_key_changed_krl_waits`, `failed_runs_do_not_grow_gen`,
`failed_first_installs_do_not_grow_gen`,
`recovered_first_installs_do_not_grow_gen`) and
`TestResetDirectory` (`reset_then_newer_krl_before_directory_arrives`,
`reset_then_new_bundle_before_directory`). UNVERIFIED on a real host: no
03-16 drill provokes these refusals.

**Watch the hosts** (admin workstation):

```
keyroster host status [--json]
```

```
bundle v3 on 2/3 hosts
directory v7 on 2/3 hosts
KRL v1793196839 on 3/3 hosts

HOST  DIRECTORY ENTRY               LAST SEEN  STATUS   BUNDLE  DIRECTORY  KRL           GENERATION  DRIFT  LAST APPLY  ALERTS
web1  active                        12s ago    4m ago   v3      v7         v1793196839   12          no     ok          -
web2  active                        40s ago    40s ago  v3      v7         v1793196839   9           no     ok          pending: intermediate
web3  removed, served until forget  5m ago     12m ago  v2*     v6*        v1793196839   4           no     ok          silent
```

Each row is a host the directory approved once: when it was last seen (any
request), how old its stored status is (`STATUS`: when the server last
stored a newer one), the bundle, directory and KRL versions it applied (`*` where they differ from
the server's current ones, by number or SHA-256), the generation, drift,
the last apply's result (`ok`, `refused`, `rolled_back` or `error`, with
its `detail` and `host_status`), and its alerts. A host counts on a version
in the header only when it applied exactly that version, SHA-256 included,
and no swap is pending. During 03-05's two-step
swap the row shows `pending: intermediate` (or `final`, `commit`), which is
not a failure: the versions are still the last committed ones until the
final step and its self-test. The applier writes that status each time it
writes the pending marker, so the row shows the swap during its widening
wait too, which can last LoginGraceTime (PR #72 review). A host removed, disabled or re-keyed in the
directory that is still served shows that on its own row (`removed, served
until forget`), never as waiting for approval; so does `keyroster host
pending`. An agent that `keyroster host approve` approved but that has
not polled since shows `approved, not yet polled` (`not_yet_polled` in
`--json`; owner decision D-R2, 03-08b; run in CI:
`TestServedHostsNeverPending/approved_not_yet_polled_in_status`,
`TestHostStatus/approved_not_yet_polled`). A re-keyed host is one whose active entry under its name now
holds other host keys than the agent enrolled with, whether the host's keys
were changed or another agent was enrolled and approved under the name: it
shows `host_keys_changed, served until forget`, and the server records no
removal for it. What the host then installs depends on its current sshd
host keys, not on the keys the agent enrolled with:

- when an active entry, under any name, holds the host's current keys
  (the host was re-keyed and its entry re-added with the new keys), its
  applier renders that entry normally, with that entry's principals;
- when no entry holds its current keys and its last entry's name is still
  active (another agent was approved under the name), its applier keeps
  the last good principals files (`host_keys_rotated`): none after an
  applied removal, the old ones otherwise.

A removal the host confirmed before the name was used again stays
confirmed until the host's own heartbeat shows principals again (owner
decision D-R1, 03-08b; see [Removing a host](#removing-a-host), step 2).
Convergence is the server's report of what each host said: run
`keyroster-agent check` on a host to see it there. The CLI refuses an
answer whose fields do not check out, and prints nothing outside printable
ASCII. (Run in CI: `TestHostStatus`, `TestHeartbeat`,
`TestAgentStatusEndToEnd`, `TestServedLine`.)

**Re-enrolling a host.** Enrollment refuses an identity or a host key that
another agents row still holds (`identity_in_use`, `host_keys_in_use`), so
the order depends on what the new agent keeps:

- **Same machine, keeping its fetcher identity (`identity.key`) or its host
  keys:**
  1. remove the entry (`keyroster host remove <name>`);
  2. wait until `keyroster host pending` shows the old agent's `removal
     confirmed at directory v<N>` ([Removing a host](#removing-a-host),
     step 2);
  3. forget the old agent (`keyroster host forget --identity <identity>`,
     the command host pending prints for it);
  4. mint a new join token and run `keyroster-agent install` again
     ([Enrolling a host](#enrolling-a-host));
  5. approve it (`keyroster host approve <name> ...`).

  UNVERIFIED until 03-16, whose forget drill runs exactly this order on
  the homelab (owner decision Q4); its server checks run in CI
  (`TestRemovalConfirmation`, `TestForgetHost`, `TestAgentRemoval`).
- **A new identity and new host keys** (another machine, or a reinstalled
  fetcher on a re-keyed host):
  1. remove the entry;
  2. wait for the old agent's removal confirmation in `keyroster host
     pending`;
  3. enroll and approve the new agent under the name;
  4. forget the old agent by its identity: `keyroster host forget
     --identity <identity>`.

  The name alone is then refused as `forget_name_ambiguous`, since two
  agents have it, also while the new agent is approved but has not polled
  yet (owner decision D-R2). Run in CI e2e (`TestAgentReenrollEndToEnd`,
  03-08b, both before and after the new agent's first poll); on the
  homelab UNVERIFIED until 03-16.

In both orders the forget needs no `--host-gone` when the old agent
confirmed its removal before the name was used again, and does need it
when the old agent never applied the removal (a host that reached the
re-added name without the removal keeps its last good principals and
never confirms it; `TestRemovalConfirmation`). A confirmed old agent whose
host shows principals again loses its confirmation, and its forget then
needs `--host-gone` unless it reports the removal again (owner decision
D-R1). While its host reports a swap in progress, its forget waits
(`host_swap_pending`) and the confirmation stays (03-08c; [Removing a
host](#removing-a-host), step 2).

**What host status rests on** (owner decision D-R4, PR #72 review). Each
row is the host's own report, and the unprivileged fetcher posts it: it
reads the root applier's `outbox/status.json` but composes the heartbeat
itself, and nothing in the body proves that the applier wrote it. A
compromised fetcher can therefore withhold a new KRL or directory version
from the spool and report it applied, and `keyroster host status` then
shows the host as converged. The host still logs `krl_stale` at error
level in its own journal (journald priority 3) once the KRL in force is
24 h old, and `keyroster-agent check` on the host shows what is installed
there. A status signed by the applier is a possible later plan (threat row
T-03-284, pending todo `signed-applier-status`).

**Alerts.**

- `silent`: the host's last request is more than 180 s old on the server's
  clock (D-10); one exactly 180 s old is not silent. A stopped fetcher, a
  network break or a host that is down. (Run in CI:
  `TestHeartbeat/silent_boundary_180_not_181` and, with real time,
  `TestAgentStatusEndToEnd`.)
- `status_stale`: the host is still seen, but its stored status is more
  than 32 min old (two drift-check periods of 15 min with up to 60 s of
  jitter; one exactly 32 min old is not flagged). The applier writes a
  status after every apply and every check, so its unit
  (`keyroster-agent.service`) has stopped or cannot write while the
  fetcher keeps polling: nothing checks drift or applies revocations
  there. (Run in CI: `TestStatusStale`, `TestHostStatusAge`; PR #72
  review.)
- `check_failed`: the last drift check could not run, for example because
  `sshd -T` refuses an `sshd_config` with a syntax error; `DRIFT` shows
  `failed`, and the error follows the table. The applier writes that
  status instead of keeping the last healthy one. Fix the configuration
  on the host; until then neither checks nor applies succeed there. (Run
  in CI: `TestRunPublishesFailedCheck`, `TestHostStatusCheckFailed`; PR
  #72 review.)
- `krl_stale`: the KRL in force was issued 24 h ago or more (its manifest's
  `issued_at`). The applier logs an error line on every check (journald
  priority 3), and nothing else changes: the KRL stays installed and no
  login is refused because of its age. The server re-publishes the KRL every
  hour (03-03), so this means the host gets no new KRL: a frozen or
  unreachable server, or a host that cannot apply it. A signer clock
  stepped back by more than 24 h, or a host clock that far ahead, raises a
  false `krl_stale`; it only alerts.
- `clock_skew`: the host's clock is more than 300 s off the server's
  (|`clock_offset_s`| > 300). `clock_offset_s` is the server's `Date` header
  minus the host's clock when the poll's answer arrived, in whole seconds
  (the header's resolution is one second, so the true skew can be up to 1 s
  more than shown); the fetcher logs it at error level too. The server
  keeps the offset of every heartbeat that parses, also one it refuses as
  stale or as `heartbeat_seq_future`, so the flag follows the fetcher's
  latest measurement (owner decision D-R2, PR #72). Fix the host's
  clock: the agent's swap timing (03-05's KRL_M = KRL_B) and certificate
  expiry both rely on it, and a lagging host accepts expired certificates.
- `seq_regressed`: the host is seen, but its heartbeats since the stored
  one carry a lower seq: its state was reset (`heartbeat.json` lost) after
  its clock had run ahead. The status shown is the stored one until the
  host's seq passes it, at most an hour later, because the server refuses
  a seq more than an hour beyond its own clock (`heartbeat_seq_future`).
  The server logs it as `heartbeat_seq_regressed` at most once an hour per
  agent; an equal seq is the usual quiet `stale_heartbeat`. (Run in CI:
  `TestHeartbeatSeq`; D-R2.)
- `identity rotated <age>`: the agent's identity rotated in the last 7
  days. Expected after `--rotate-identity`; otherwise see [An unexpected
  identity rotation](#running-the-agent) (D-R1).
- `stuck: pending_state_unknown`: see [Manual recovery](#manual-recovery).
- `diverged`: the host reports a bundle, directory or KRL above the
  server's current version, or the current number with other bytes. That
  is the sign of a host that accepted a version a signer restore lost
  (signer-install.md): check its `accepted.json` and reset its directory
  as that runbook says. It never counts as converged. (Run in CI:
  `TestHostStatusDiverged`, `TestCommittedAndDiverged`.)

**Rotating the agent's identity.** On the host:

```
sudo -u keyroster-agent keyroster-agent-fetch --rotate-identity
```

It makes a new key, writes it to `/var/lib/keyroster-agent-fetch/identity.next`
(0600) before it asks the server, and asks over mTLS with the current
identity, signed by the current key. On the server's answer the new key
becomes `identity.key`; from then on the old certificate gets
`unknown_agent`. When the answer is lost, the fetcher's next poll gets
`unknown_agent` with the old key, tries `identity.next`, and keeps it when
the server accepts it; when the request never reached the server, the old
key keeps working. Running `--rotate-identity` again after a failed one is
safe: it never replaces an `identity.next` it finds, because that may be
the only key the server knows. It tries that key first and finishes the
earlier rotation when the server takes it, asks again for that same key
when the server answers `unknown_agent` for it, and stops with an error,
keeping the file, when it cannot reach the server (PR #72 review). The
server allows one rotation per agent an hour
(`identity_rotation_too_soon`). The rotation and the
polls hold one lock, and the running service picks the new key up at its
next poll. Run it as `keyroster-agent`: as root it is refused
`fetch_dir_not_owned`, because the keys must stay the service user's.
Compare the new identity with `keyroster host status --json`
(`identity_spki_sha256`) or `keyroster-agent identity`. (Run in CI:
`TestIdentityRotation`, and with the real users under systemd in
`agent-smoke.sh`.)

**An unexpected identity rotation.** keyroster-server logs every rotation
at warning level (`agent identity rotated`, with the host, the old and the
new identity and the client's address) and records it on the agent's row.
`keyroster host status` shows `identity rotated <age>` for 7 days, and
`--json` carries `identity_rotated_at` and `identity_rotations` (owner
decision D-R1, PR #72). A rotation nobody ran on the host means its
identity key (`/var/lib/keyroster-agent-fetch/identity.key`) may be
stolen: whoever holds it can rotate the row to a key of their own, from
anywhere. The real host then gets `unknown_agent`, which its fetcher logs
at error level (`ERROR unknown_agent`, journald priority 3), and it gets no
revocations from then on. Treat the row as lost, and re-enroll the host:

1. On the admin workstation, remove its entry (`keyroster host remove
   <name>`), then forget the lost row by its identity, the rotated one
   `keyroster host pending` shows: `keyroster host forget --identity
   <identity> --host-gone`. Do not wait for its heartbeat: the key's holder
   can report anything. (The forget's checks run in CI, `TestForgetHost`
   and `TestHostForgetHostGone`; this step on a real host is UNVERIFIED
   until 03-16.)
2. On the host, as root, find out how the key left it. Stop both units,
   delete `/var/lib/keyroster-agent-fetch/identity.key` (and
   `identity.next`, if present), so the fetcher makes a new identity at its
   next start, and enroll the host again with a new join token
   ([Enrolling a host](#enrolling-a-host)).

(The log line, the row's fields, the `host status` line and the fetcher's
error line are run in CI: `TestIdentityRotationRecorded`, `TestHostStatus`,
`TestUnknownAgentLoggedAtError`. The re-enrollment itself is UNVERIFIED: no
test runs it, on CI or on a real host.)

## Manual recovery

When `keyroster host status` shows `stuck: pending_state_unknown`,
something other than the agent changed `/etc/ssh/keyroster`: `current` or
`last-good` is not a link to one of the agent's generations, or one is
missing. Until it is resolved, the host applies nothing, revocations
included, which is why the alert exists. On the host, as root:

1. Inspect `/etc/ssh/keyroster/current` and `/etc/ssh/keyroster/last-good`
   (`ls -l /etc/ssh/keyroster`), and find out what changed them.
2. Run

   ```
   sudo keyroster-agent apply --once --recover-to-last-good
   ```

   It waits the LoginGraceTime bound and points `current` at `last-good`
   again. The next apply goes on from there.

(UNVERIFIED on a real host until 03-16; the recovery itself is 03-05's,
run in CI there.)

## Removing a host

Run in CI: `TestAgentRemoval` (server unit tests: the removed host gets the
removal version and later KRLs, a never-approved agent is still refused,
forget is refused while the directory holds the host's keys, and the host
keys enroll again after it), `TestHostForgetWaitsForRemoval` and
`TestRemovalConfirmation` (the confirmation is recorded only from a
heartbeat that shows a served directory removing the host, and stays when
the name is used again), `TestForgetHost` and `TestHostForget` (forget by
identity, `forget_name_ambiguous`, `forget_state_changed`, `--host-gone`),
`TestAgentEnrollEndToEnd` (e2e: the removal reaches the enrolled host and
its certificate logins are refused, a later revocation still reaches it,
the server records the confirmation from the real agent's heartbeat, and
forget goes through on it) and `TestAgentReenrollEndToEnd` (e2e: the
re-enroll flow under one name, 03-08b). Every step on the homelab is
UNVERIFIED until 03-16, whose forget drill proves them (owner decision Q4).

An enrolled agent that the directory approved once keeps receiving signed
state (directory, bundle and policy, KRL) after its host entry is disabled
or removed (owner decision D-R1, PR #71). That is what makes the removal
reach the host: the applier installs the version that removes the entry,
and the host then has no principals files (its certificate logins are
refused; `authorized_keys` and the console are unaffected), while later
revocations keep arriving. Until the agent is forgotten, root on a removed
host can still read every later directory version, as root on any
enrolled host can (D-03); that is the leak this order accepts.

1. **Remove the entry (admin workstation).** `keyroster host remove <name>`.
2. **Wait until the host has confirmed that version.** `keyroster host
   pending` lists the host as `removed, served until forget`, then the line
   `removal confirmed at directory v<N>` once the server recorded the
   confirmation, and the `keyroster host forget --identity <identity>`
   command for it. `keyroster host status` shows the directory version the
   host applied and `host_removed` in its last apply; on the host, as root,
   `/var/lib/keyroster-agent/status.json` names the same
   (`last_apply.directory_version`, `host_status`).

   The server records the removal version when it first serves the agent a
   directory in which no entry holds its keys and no active entry carries
   its name. It records the confirmation from the host's own heartbeat,
   and only when both of these hold (03-08b, owner decision D-R1):
   - the host reports that the apply which committed its directory
     emptied its principals: `last_apply` is `ok` with `host_status`
     `host_removed` or `host_disabled`, no swap is pending, and its
     generation lists no `principals/` file. `host_status` is that of
     the generation the host has in force, not only of the apply that
     rendered it, so a no-op apply (the first one after the agent
     restarts) reports it again (PR #74 pre-merge review fix round 2;
     run in CI: `TestStatusHostStatus`, `TestAgentReenrollEndToEnd`);
   - the directory it reports committing is one the server served and
     that removes the host: at or above the removal version, not above
     the current version, with the SHA-256 of the server's directory
     document under that number, and naming the host nowhere.

   A heartbeat that the server stored while the signer could not answer
   for an older version is checked again by `keyroster host pending`. The
   confirmation stays recorded when the name is used again (a re-keyed
   entry, or another agent approved under it) as long as the host shows no
   principals. It is cleared, and the forget needs `--host-gone` again,
   when a later heartbeat of the same agent shows principals again: a
   `principals/` file, or an apply that rendered an active entry
   (`host_status` empty), for example after the host was re-keyed and
   re-added under an entry with its new keys. It is also cleared by a
   heartbeat that cannot tell, a truncated file list. A later heartbeat
   that reports the removal again (`host_removed` or `host_disabled`)
   confirms it again; one that reports `host_keys_rotated` does not (run
   in CI: `TestRemovalConfirmation`). The server logs `agent removal
   confirmation cleared` at warning level. An entry that holds
   the agent's keys again clears both the confirmation and the removal.

   A swap in progress (`pending`) neither records nor clears a
   confirmation: its file list is the generation the swap started from,
   while the target's principals may already be live (03-08c, owner
   decision 2026-10-29, in place of PR #74 pre-merge review fix round 2's
   clear). While the stored heartbeat shows it, `keyroster host pending`
   prints `swap pending` next to the confirmation, and forget is refused
   `host_swap_pending`: by the CLI before it signs, by the server before
   it asks the signer, and again in the delete's own transaction, so a
   swap the host starts meanwhile still stops it. Wait for the next
   heartbeat, which shows the swap committed, and run forget again; an old
   agent of the re-enroll flow that goes through a swap (a KRL update)
   then needs no `--host-gone`. For a host that is gone for good,
   `--host-gone` overrides the wait. Run in CI: `TestRemovalConfirmation`
   (`pending_swap_*`, 03-08c), `TestHostForget` (`swap_pending_*`);
   UNVERIFIED on the homelab until 03-16.

   The confirmation is the host's word: the unprivileged fetcher composes
   the heartbeat, so a fetcher that lies about what was applied gets a
   confirmation recorded (accepted residual, threat row T-03-284; see
   [What host status rests on](#running-the-agent)).

   A row whose removal an older server (03-08) cleared, or whose latest
   stored heartbeat reports a directory that names it again, is not
   confirmed retroactively: its forget needs `--host-gone`. A host you
   cannot reach any more never confirms; go on only if it is
   decommissioned.
3. **Forget the agent (admin workstation).** Forget names one agent, and
   the admins sign it:

   ```
   keyroster host forget --identity <identity> --admin-key <admin 1> --admin-key <admin 2>
   ```

   with the identity `keyroster host pending` printed, or `keyroster host
   forget <name>` when only one agent has that name. When more than one
   agent has it (a re-enrolled host, see [Re-enrolling a
   host](#running-the-agent)), the name is refused `forget_name_ambiguous`:
   the CLI lists each agent with its state and its `--identity` command and
   sends nothing. The CLI reads `keyroster host pending` (and `keyroster
   host status`, for agents the directory approves now, an agent approved
   but not yet polled included) and builds the forget request from the row
   it read: the agent's identity, name, enrollment time and host keys,
   whether it was approved once, its removal version and its recorded
   confirmation, or `--host-gone`. The request names the installation of
   the root-pinned trust bundle.

   The enrollment time is stored in whole seconds. A forget read before a
   re-enrollment of the same identity in the same second as the original
   enrollment cannot be told apart from one for the new row: that needs
   the `host pending` read, the whole forget and the re-enrollment inside
   that one second (accepted residual, owner decision D-3 of PR #75's
   review, threat row T-03-286; not tested, by construction).

   **Who signs** (owner decisions Q2 and Q3, 2026-10-29). An agent that was
   never approved, and so never received state, is forgotten with one
   admin signature: one `--admin-key`, or the `admin_key` of `keyroster
   init`. Every other agent needs the policy's `admin_quorum` of distinct
   admins, each key given with its own `--admin-key`, all in the one
   ssh-agent the CLI uses; the first one also signs the request to the
   server. Too few distinct keys are refused before anything is signed
   (`admin_quorum_not_met`, with the number needed). The CLI prints what
   is signed (the identity, name and enrollment time, the host key
   fingerprints, approved once, the removal version, the confirmation or
   `host_gone`, and the signing keys), sets the request's time, asks each
   key to sign, and refuses `request_time_skew`, sending nothing, when
   signing took more than 240 s (slow touch confirmations): run the command
   again and confirm promptly.

   **What happens.** The server checks the request against its row and
   asks keyroster-signer, stating on its own whether its row was approved
   once. The signer checks the signatures under the rule above and refuses
   too few (`admin_quorum_not_met`), a signed approved-once that differs
   from the server's statement (`forget_facts_mismatch`), a host key that
   any directory entry still holds (`forget_host_in_directory`), and a
   confirmation that is not a directory it installed
   (`forget_confirmation_invalid`). It then logs the forget as a
   `host_forget` audit entry in the same transaction as its decision. The
   server deletes the agent only after that, by a statement that re-checks
   every fact, and prints its identity, its host keys and `Forget logged
   as audit entry <N>`. From then on that identity gets `unknown_agent`
   and receives nothing, and its host keys can enroll again with a new
   join token. While the signer cannot be reached or cannot decide, the
   server answers 503 and forgets nothing; so does a signer whose stored
   directory changed while it decided (`directory_changed`, PR #75
   review): run the command again.

   The refusals, each forgetting nothing:

   - `forget_state_changed` when the agent changed since `host pending`
     was read (its approval, removal version, confirmation or enrollment
     time, or its identity rotated), or when its host's stored heartbeat
     shows principals again (the host resumed service) before the server
     cleared the confirmation (PR #75 review; `TestRemovalConfirmation`,
     `resumed_*`): run the command again, which reads `host pending`
     anew. The server answers the same when no heartbeat is stored for an
     agent with a recorded confirmation. keyroster-server records a
     confirmation only from a stored heartbeat, so only an edit of its
     database outside it leads there, and running the command again gets
     the same answer until the host sends a heartbeat: the CLI drops
     `--host-gone` for an agent whose removal is confirmed. UNVERIFIED: no
     test runs that case;
   - `host_in_directory` while any directory entry, active or disabled,
     still holds one of the agent's host keys: forgetting an agent whose
     host is still in the directory would stop the revocations that host
     needs;
   - `host_removal_not_applied` for an agent approved once that has no
     recorded confirmation (owner decision 2026-10-28). The CLI refuses it
     before it signs, naming the `--host-gone` command;
   - `host_swap_pending` while the host reports a swap it has not finished
     (step 2);
   - the signer's refusals above, answered 403 with the signer's reason.

   `forget_logged_not_deleted` means the signer logged the forget (audit
   entry `<N>`, which the CLI names), but the agent changed before the
   server could delete it (a fact, its identity, a swap it started, or
   principals its host shows again; the delete re-checks the stored
   heartbeat in its own transaction), so
   the server deleted nothing and keeps serving it: `keyroster host
   pending` still lists it. Run `keyroster host pending` and forget it
   again, which logs a second entry; the first one records an
   authorization the server did not carry out.

   For a host that will never report again (decommissioned, disk wiped):

   ```
   keyroster host forget --identity <identity> --host-gone --admin-key <admin 1> --admin-key <admin 2>
   ```

   It overrides the confirmation, or the wait for a pending swap, only;
   the admins still sign it, and the entry records `host_gone`. The CLI
   prints that it does, and the server and the signer log it at warning
   level. Over a pending swap on a confirmed agent, the request also
   carries the confirmation: the CLI prints `host_gone: overrides the
   host's unfinished swap`, and the server logs `agent forgotten with
   --host-gone over a pending swap` with the confirmed version. If the
   host is still running, it gets no more signed state from
   then on, revocations included, and keeps enforcing what it applied
   last. For a never-approved agent, or a confirmed one with no swap
   pending, the CLI drops `--host-gone` with a note.

   Run in CI (03-08c): `TestForgetAgent` (the signer's rule, both sides of
   Q3, every refusal), `TestVerifyHostForget` (audit verify's rule),
   `TestForgetHost` (the server relays, deletes only after the signer's
   answer, and answers 503 or `forget_logged_not_deleted` deleting
   nothing), `TestHostForget` (the signatures, the local refusals),
   `TestAgentEnrollEndToEnd` and `TestAgentReenrollEndToEnd` (e2e: the
   forget is logged as audit entry `<N>` and audit verify accepts it). CI's
   e2e policy has an admin quorum of 1, so the quorum-2 path runs in the
   unit tests only, and end to end it is UNVERIFIED (owner decision D-4
   of PR #75's review: no quorum-2 e2e lane in CI). 03-16's forget drill
   records the policy's `admin_quorum` and the number of admins who signed
   its forget; quorum 2 stays UNVERIFIED end to end until a drill has run
   under an `admin_quorum` of at least 2 with at least that many signers.
   The other homelab steps are UNVERIFIED until 03-16, whose forget drill
   proves them (owner decision Q4).

   **Checking that a forget was authorized.** Export the signer's log and
   run `keyroster audit verify` (signer-install.md): every forget is a
   `host_forget` entry, which audit verify re-checks with the signer's rule
   (the installation, the number of distinct admin signatures under the
   policy in force, the request ID used once, no host key in the directory
   in force, the confirmation's directory logged). Audit verify also
   refuses the export unless each `host_forget` line is exactly the line
   the signer's export writes for its verified entry (owner decision D-1
   of PR #75's review), so every field on it is the entry's own: the
   agent's `identity`, `expected_name`, `enrolled_at_us` and
   `host_key_fingerprints`, `approved_once`, `host_gone`,
   `removal_version`, `confirmed_version` and `confirmed_sha256`,
   `request_id`, `created_at`, `resolved_at`, the policy and directory
   versions, `evidence_types`, and `admin_fingerprints`, the fingerprints
   of the keys whose signatures it checked (each evidence item must be a
   valid signature by an admin of the policy in force; an admin who signs
   twice counts once). Read these fields only from an export that audit
   verify accepted. Audit verify prints counts, not the entries: to find
   the forgets, read the accepted export with a JSON parser, for example
   `jq -c 'select(.decoded.kind == "host_forget") | .decoded' export.jsonl`
   (UNVERIFIED: jq was not run; the same selection with Python's `json`
   module was run once against a test export, not in CI), and look for
   the host's identity in `identity`. Audit verify parses
   every line with its keys unescaped, as such a parser does, and refuses
   the export if a key occurs twice in one object, a line's decoded `kind`
   is not its entry's kind, or a line of another kind carries a field only
   a `host_forget` line has (`identity`, `expected_name`, `enrolled_at_us`,
   `host_key_fingerprints`, `approved_once`, `host_gone`,
   `removal_version`, `confirmed_version`, `confirmed_sha256`,
   `admin_fingerprints`); so the parser lists exactly the verified
   `host_forget` entries (PR #75 review, fix round 2). The fields say what
   the admins signed, not that it was true: audit verify checks that the
   number of signatures fits the signed `approved_once`; it cannot tell a false one, because the log records no approvals: one
   admin together with a compromised keyroster-server could forget an
   approved host with one signature, but that server could drop the row
   without the signer anyway (T-03-293, T-03-285). A host whose fetcher
   logs `unknown_agent` (at error level, in its journal) while the log has
   no `host_forget` entry for its identity was dropped by keyroster-server
   without a forget: treat the server as compromised. This check is
   detection only, because a server can always stop serving a host. Run in
   CI: the entry and the fetcher's line in `TestAgentEnrollEndToEnd`, and
   the refusals in `TestVerifyForgetKeysOnOtherKinds`; as an operator
   check UNVERIFIED until 03-16.

## How fast changes arrive

Run in CI e2e (`TestAgentApplyEndToEnd`, 03-05, and
`TestAgentEnrollEndToEnd`, 03-07); the homelab measurement is 03-16
(UNVERIFIED until then).

- **Revocations and removals** (a revoked certificate, a removed principal,
  a removed CA key) are live within one poll of the fetcher (60 s, with a
  random 10 s either way), plus at most 5 s for keyroster-server's KRL cache
  and 5 s for the applier's round. They never wait: they only narrow what
  sshd accepts, so they are swapped in at once.
- **Additions** (a new principal, a new CA key) are live at most
  LoginGraceTime + 30 s after the applier's previous swap of the trust
  files: 150 s with the default LoginGraceTime of 120. That previous swap
  may be the first step of the same apply, which installs an intermediate
  generation that allows only what both versions allow, or an earlier
  apply. With no swap in that interval, additions are live at once. The
  wait is measured on CLOCK_MONOTONIC (owner decision 2026-10-26, PR #67;
  the plan's earlier + 5 s, 125 s, is superseded).
- **A failed self-test** rolls the CA keys, principals and drop-in back to
  the last generation that passed one; the newer KRL stays in force (the
  KRL never rolls back), so `current` can differ from `last-good` at rest.
- **A host the directory disables or removes** gets no principals files
  (its certificate logins are refused; `authorized_keys` and the console
  are unaffected); it keeps receiving every KRL and CA key. A host whose
  keys match no entry while its last entry is still active, or match two
  entries, keeps its last principals. The applier's report names the case
  (`host_status`: `host_disabled`, `host_removed`, `host_keys_rotated`,
  `host_keys_disagree`).

## Moving a Phase 2 host to the agent

Run in CI (`e2e-distro`, `TestDistroAdoptPhase2`, 03-06, on every image
above, and `TestAdopt`). The units of step 1 run in CI on Ubuntu 24.04
([Running the agent](#running-the-agent)); the order below on a Phase 2
host is UNVERIFIED until 03-16.

The agent takes over a host set up with this runbook only when its layout
is exactly the runbook's (D-08):

- `/etc/ssh/sshd_config.d/50-keyroster.conf` holds exactly the two lines
  `TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub` and
  `AuthorizedPrincipalsFile /etc/ssh/principals/%u`, and nothing else;
- `/etc/ssh/keyroster_user_ca.pub` holds one line with the trust bundle's
  active user CA key (its comment is ignored);
- `/etc/ssh/principals/` is a root-owned directory, and every
  `/etc/ssh/principals/<account>` in it is byte-equal to what
  `keyroster host principals <group> <account>` renders from the directory
  the agent has verified;
- no other file sets one of these settings, `sshd_config` included, and
  `sshd -T` shows exactly those two values.

The order:

1. Install the agent and enable both units (03-07, 03-08). The fetcher
   enrolls, and once the signed state arrives the unit's applier reports
   `phase2_adoption_pending` and writes nothing. Before enrollment,
   `sudo keyroster-agent preflight` already reports `phase2_adoptable` and
   exits 0.
2. Approve the host (`keyroster host approve`, 03-07).
3. Re-render every principals file with
   `keyroster host principals <group> <account>` and copy it to
   `/etc/ssh/principals/<account>`. The approval installs a new directory
   version, and each file's second header line names the version it was
   rendered from, so files rendered before the approval no longer match.
4. Run `sudo keyroster-agent apply --once` once, from a root shell. The
   apply lock serialises it with the unit. Unlike the hardened applier
   unit, the hand run can remove files in `/etc/ssh`.

Step 4 writes the agent's generation and `00-keyroster.conf`, which sshd
reads before `50-keyroster.conf`. It proves with `sshd -T`, and with
`sshd -T -C` for every managed account, that its values win, then reloads
sshd and self-tests. Only once its generation is last-good does it remove
the three Phase 2 paths: `50-keyroster.conf`, `keyroster_user_ca.pub`, each
principals file it compared, and then the empty principals directory. They
are copied to `/var/lib/keyroster-agent/phase2/` first and kept there until
the removal and an `sshd -t` have succeeded. A crash during the removal is
resumed by the next `apply --once`. A resume that finds `00-keyroster.conf`
edited, or missing, first writes the agent's drop-in again, checks it with
`sshd -t` and `sshd -T`, reloads sshd and self-tests, and only then removes
anything. If the self-test fails, the agent's
files are removed again and the Phase 2 layout was never touched.

When it refuses with `phase2_layout_differs`, the report lists every
difference:

- **"only the header differs"**: the file's principal lines match, but it
  was rendered from another directory version (the report names both).
  Re-render it with `keyroster host principals <group> <account>`.
- **The principal lines differ**: the report lists both sets. Re-render the
  file, or run `sudo keyroster-agent apply --once --dry-run` to see what the
  agent would install.
- **A line to remove**: an extra line in `50-keyroster.conf`, or one of the
  settings in `sshd_config` or another drop-in, named by file and line.
- **Another CA key**: `keyroster_user_ca.pub` does not hold the bundle's
  active user CA key. Run `keyroster host ca-key` again.

Any other layout is never taken over: remove it by hand first, and the
agent then installs its own files as on a new host.

## Drift

Run in CI (`e2e-distro`, `TestDistroDrift`, 03-06); UNVERIFIED on a real
host until 03-16.

```
sudo keyroster-agent check
```

It reports, as JSON, every way sshd or the installed files differ from
what the agent installed, and fixes nothing (AGENT-05):

- `sshd -T` must show the drop-in's three paths and no
  `AuthorizedPrincipalsCommand`, and so must
  `sshd -T -C user=<account>,host=127.0.0.1,addr=127.0.0.1,laddr=<l>,lport=<p>`
  for every account the generation has a principals file for. A later
  `Match` block or an earlier file is reported with the keyword, and the
  account when it applies only to that account;
- every file sshd reads, the whole `Include` graph as preflight follows it,
  is searched for a trust setting outside the agent's drop-in; each is
  listed under `foreign` by file and line, and so is a file the agent
  cannot read safely (`sshd_config_unsafe`);
- `00-keyroster.conf` must hold exactly what the agent writes; a missing,
  trial or edited drop-in is listed under `files`. The next apply that
  installs a new signed state repairs it (a trial, any apply);
- the generation `current` names is re-hashed against its record in
  `/var/lib/keyroster-agent/generations/<N>.json`. It resolves `current`
  once, so an apply that swaps it during the check cannot mix two
  generations;
- accounts that `AllowUsers`, `AllowGroups`, `DenyUsers` or `DenyGroups`
  exclude are listed, report only.

Exit status 0 when nothing drifted, 3 on drift, 2 for a tool error (no
generation installed). The check runs `sshd -T -C` with loopback client
addresses only. A `Match Address` block that applies only to some remote
client ranges (for example a tailnet's shared address space, RFC 6598) is
therefore not checked, and an override there can go unreported.
`keyroster-agent run` (the applier's unit) runs the same check after every
apply and every 15 min, with a random 60 s either way, and reports its
result in the heartbeat (`keyroster host status`, DRIFT; AGENT-05, 03-08;
run in CI: `TestRunChecks`).

## Windows hosts

Account names are lowercase in the directory, and `keyroster host-group map`
refuses an account name with an uppercase letter. Windows host automation
is Phase 5; a manual Windows setup is not covered here and is UNVERIFIED.
