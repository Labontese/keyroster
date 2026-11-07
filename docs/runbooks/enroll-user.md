# Runbook: enroll a user (and the first admin)

This runbook takes a new user from nothing to a passkey that the signer
accepts. An account grants nothing until an admin binds the user's passkey
in an **admin-signed directory version**, the only thing the signer treats
as authority (D-01, D-03). The server only proposes: it keeps the pending
account and the registered passkey, and forwards the signed version to the
signer.

> **What is tested and what is not.** The end-to-end tests
> (`TestEnrollApproveEndToEnd`, `TestApproveConflictNoLostUpdate`,
> `TestApproveQuorumTwo`, `TestApproveProposalAfterReinvite`) run these
> commands against a real signer and server, with soft authenticators
> standing in for the browser: `user add` (also `--reinvite`),
> `user pending`, `user approve` (without `--fingerprint`, and with
> `--fingerprint ... --yes`, also with `--out`), `user list`,
> `directory sign` (with `--yes`, and its refusal without a terminal),
> `directory install`, and on the signer side `keyroster-signer export-log`
> with `keyroster audit verify`. **UNVERIFIED end to end**, tested only
> against a fake server in the CLI's unit tests: `user disable`,
> `user enable`, and the interactive `Sign directory version N? [y/N]`
> prompt.
>
> **Run on the homelab in 02-13**, for the first admin (D-04): the
> Windows `keyroster.exe` against keyroster-server and the vTPM signer
> under trust bundle v3.
>
> - The owner ran `user add`, `user approve`, `role add`, `role grant`,
>   `host-group add` and `host-group map` in his own terminal. Their
>   printed output (the invite URL, the diff) was not recorded. What they
>   did was checked afterwards with `user pending`, `user list`,
>   `directory show` and `host principals`.
> - The registration page ran in Chrome on Windows, with a passkey in
>   Chrome's own synced passkey store. `user pending` showed it as ES256
>   and synced.
> - `directory show` ran against the real server.
> - The signer-host check below ran (see there).
>
> The interactive prompt's output was not seen. Another browser, a
> hardware authenticator, and `user disable` and `user enable` on a real
> server remain **UNVERIFIED**.

## Before you start

- You are an admin: your SSH key is one of the admins of the root-signed
  policy and is loaded in ssh-agent. `keyroster init` saved it as
  `admin_key`; any command also takes `--admin-key SHA256:...` to use
  another key in the agent.
- Your `--server` is one of the policy's webauthn origins. The server
  accepts admin requests only there and answers any other with the same
  "admin authentication failed".
- Every command that talks to the server prints the evaluation-only banner
  when a CA key has software custody (KEY-06).

## 1. Invite the user (admin)

```
keyroster user add NAME
```

It prints the invite URL, a `keyroster init` line for the user and the
pinned TLS root PEM. Send all three to the user **through a channel you
trust**. The user saves the PEM as `keyroster-tls-root.pem`, the file name
the init line reads. The PEM is public; the `--tls-pin` in the line is
what protects it.

## 2. Register the passkey (user)

The user opens the invite on the computer that holds the passkey and
registers. The page then shows the passkey's fingerprint
(`SHA256:...`). The user reads that fingerprint to the admin **by voice or
in person**, not through the server.

**The page closed before the fingerprint showed, or the fingerprint is
lost:** the admin runs

```
keyroster user add NAME --reinvite
```

The old invite stops working, and so does any passkey registered with it
that no directory binds yet. The user registers again with the new invite.

## 3. Approve the passkey (admin)

```
keyroster user pending NAME
keyroster user approve NAME --fingerprint SHA256:...
```

`user pending` shows the fingerprint the server holds. Compare it with the
one the user read to you. Then run `user approve` with **the fingerprint
as the user read it**, not as the server showed it. Without
`--fingerprint`, `user approve` lists the pending fingerprints and exits 2;
with a fingerprint that matches no pending passkey it refuses and signs
nothing.

`user approve` then:

1. verifies the server's trust bundle against your root pins, and the
   installed directory's signatures against the policy's admins (it never
   builds on a version it did not verify);
2. builds the next version with the passkey bound to NAME, checks it, and
   prints the diff and the new version's SHA-256;
3. asks `Sign directory version N? [y/N]` (in a script with no terminal it
   refuses unless you pass `--yes`);
4. signs the version with your SSH key under `keyroster/directory/v1`;
5. installs it through the server (policy quorum 1), or writes a proposal
   for co-signing (quorum above 1, or `--out DIR`).

Check the diff before you answer `y`: your signature is the authority.

On success it prints `The server reports directory version N installed
(SHA-256 ..., log leaf L)`. That is the server's report, not something the
CLI can check: nothing the signer signed comes back to it (see
[Confirm on the signer host](#confirm-on-the-signer-host)).

`keyroster user list` then shows NAME as active, and
`keyroster directory show` prints the admin-signed directory the server
serves, with every passkey's fingerprint. Both verify the admins'
signatures over what the server serves; neither can tell whether the
signer has installed it.

## The first admin (D-04)

There is no special first-user path. The first admin runs steps 1 to 3
for themself: `user add`, register their own passkey, `user approve` with
their own SSH admin key. That installs directory version 1.

**Run on the homelab in 02-13.** The owner enrolled this way. The
fingerprint he read from the page was the one `user pending` listed.
After his `user approve`, `user list` showed him active with exactly that
passkey.

## Quorum above 1

When the policy needs more than one admin signature, `user approve` (or
`--out DIR`) writes a proposal directory: `directory.json`,
`directory.json.sigs` and `base.sha256` (a note of the version it was
built on). Then:

```
keyroster directory sign DIR --admin-key SHA256:<your key>
keyroster directory install DIR
```

`directory sign` re-checks the proposal: it must follow the installed
verified version, name the installation of the root-verified trust bundle
(a proposal for another installation, or for none while the bundle has
one, is refused: the signer would never install it), and every signature
already in it must verify and be by a policy admin. It shows the diff and asks before it signs; in a script
with no terminal it refuses unless it is given `--yes`. A co-signer whose
key is not the `admin_key` in their config names it with `--admin-key`.
An admin who already signed is refused: a second signature by one admin
counts once. `directory install` signs nothing and asks nothing; the
signer decides whether the signatures meet the quorum.

**Stale proposal.** If `directory sign` or `directory install` says the
directory changed since it was read, another version was installed after
the proposal was built. Discard the proposal directory and
re-run the command that produced it, for example
`keyroster user approve NAME --fingerprint ...`; the passkey is still
pending. Running
`directory install` again on the same proposal fails again.

**Proposal already served.** If `directory install` says the server
already serves the proposal as directory version N ("nothing to do"), the
proposal itself was installed, for example by an earlier attempt whose
answer was lost, or by another admin at the same moment. Do not rebuild
it; `directory sign` of it refuses with "there is nothing to sign". After a
change that removes access (a disable, a role revoke, an unmap), confirm
on the signer host as below.

## After a reinvite, discard any proposal for that user

A proposal written before the reinvite (`user approve --out`, or one
waiting for a co-signer) still names the discarded passkey. Once the
reinvite command has returned, the server refuses to install such a
proposal and says the passkey is **no longer pending**; co-signing it is
wasted work. Delete the directory, and after the user has registered again
run `user approve` with the new fingerprint.

Deleting matters: the refusal is the server's. A fully signed proposal is
still a valid directory version to the signer, which cannot know what is
pending, so do not leave such files around.

## A reinvite does not undo an approval

The server handles a reinvite and an install of the same user one after
the other, never at once. If another admin's install of that user's
approval reached the server first, it wins: the passkey is bound, and your
reinvite produced an invite for one additional passkey. Check with
`keyroster user list` after a reinvite: a user shown as active was
approved before it, and that passkey stays bound to the account.
`keyroster user disable NAME` stops the account from obtaining new
certificates if it must not be used; `keyroster revoke user NAME` also
ends the ones already issued ([Disabling a user](#disabling-a-user)).

## After "the server cannot reach its signer": look before you retry

When `user approve` or `directory install` fails with "the server cannot
reach its signer", the server may have lost the signer's answer, and
cannot tell whether the version was installed. Run `keyroster user list`,
and `keyroster directory show` for the fingerprints:

- If NAME is active with the fingerprint you approved, the approval went
  through: do not approve again. `keyroster user pending NAME` can still
  list that passkey until the next directory change, and a second
  `user approve` of it is refused because the passkey is already bound.
- If the fingerprint is not in the directory, nothing was installed, and
  you run the command again.

Both views are what the server serves. If you suspect the server itself is
compromised, they prove nothing about the signer: decide on the signer
host instead ([Confirm on the signer host](#confirm-on-the-signer-host)).

The views can also lag the signer. An install waiting behind a slow
signature (a hardware key waiting for a touch, say) is still installed
once that signature ends, after the CLI has reported the error. Since
03-08i the server keeps answering during such a signature, so it can
serve the version it read before for up to 5 s (statusTTL) after the
signer commits the new one. Wait until any touch prompt on the signer
host is answered, then 5 s more, before you read the views. Running the
command again meanwhile installs nothing twice: the signer installs each
version only after the one it holds, so a rerun built on the older
version is refused with `directory_version_chain` once the first install
committed. `user approve` then says `the directory changed since it was
read (another admin installed a version); re-run this command`: read the
views again first. A rerun of `directory install` with the same proposal
reads the directory again and says `The server already serves proposal
DIR as directory version N (SHA-256 ...); nothing to do.` That answer
runs in the CLI tests against a stub server, after an install whose
answer was lost (`TestDirectoryPipeline/proposal_already_served`). The
rest is reasoned from the code; no test loses an install's answer while
a signature is held. **UNVERIFIED**, in CI and on a real host.

## A directory hosts cannot render is refused at install

Every command that installs a directory version can be refused with
`directory_unrenderable`: `keyroster directory install`, `user approve`,
and the other user, role, host and machine commands that sign a new
version. The CLI's error names that code. That is reasoned from
serverclient's error text; no test runs the CLI against this refusal
(UNVERIFIED). The signer refuses the version when:

- a host group maps more than 2048 accounts. While a host moves between
  two versions it holds both versions' accounts, so the limit is half of
  the host agent's 4096;
- or one account's principals file, as the host agent writes it, would be
  larger than 64 KiB.

Nothing is installed, and the directory keeps its version. Split the host
group, or map fewer roles to the account, then sign again.

**A directory installed before this release** whose host group maps more
accounts than that, or whose principals file is larger, stays in force, and
hosts keep rendering what they rendered.

- A later version that only disables or removes users, roles or accounts
  installs as usual. That includes `user disable` and the disable step of
  `keyroster revoke user`.
- A version that adds an account to that host group, swaps one of its
  accounts for a new name, or makes a file that is already too large any
  larger is refused until the group is split.
- A new host group must meet the limits.

**The 64 KiB limit is measured as if the version number had its largest
possible length**, so a file accepted once stays within the limit at every
later version. In practice the limit is up to about 19 bytes below 64 KiB.

**When you split, keep the account names.** A host that moves to the split
version holds the accounts of both versions for a moment. New, disjoint
account names can push that set above the agent's 4096, and the host then
refuses the move (`generation_too_large`). Its KRLs still land
(host-setup.md, "Revocations keep applying"), but it keeps its old
principals.

**Moving a host to another host group.** While a host moves, it holds the
accounts of its old host group and of its new one. A version that moves a
host is refused with `directory_unrenderable` when those accounts together
are more than 4096, or when a principals file of the new group is larger
than 64 KiB. Split the old host group first. With both groups at most 2048
accounts this never happens.

The signer recognises a moved host by a host key that both versions list.
It also goes by the host's name, but only when the new version gives the
host a key that no active host had before (a possible rekey). A version
that replaces all of a host's keys and moves it is therefore checked the
same way. Hosts that only swap or take over names, with keys that were
already listed, are judged by their keys alone.

**Limitation (UNVERIFIED):** a host that is renamed *and* given new keys
in the same version is not recognised as moved, so the signer does not
check the move. Its agent may then refuse the move
(`generation_too_large`) and keep its old principals. Rename a host and
replace its keys in separate versions.

Run in CI (TestDirectoryUnrenderable, TestRenderable, TestMoveByName and
TestSizerMatchesRender, 03-08h); UNVERIFIED on a real host.

## Disabling a user

```
keyroster user disable NAME
keyroster user enable NAME
```

Both go through the same pipeline (verify, diff, confirm, sign, install or
propose). A disabled user keeps its passkeys in the directory and cannot
sign in. Enabling needs at least one bound passkey.

**Disabling stops only new certificates.** The signer issues a disabled
user nothing new, but every certificate already issued stays valid until
its ValidBefore (up to the user CA's 12 h cap): a stolen laptop with a
fresh certificate keeps logging in to every host that lists its
principal. The same holds for revoking a role from the user or a group,
removing the user from a group and unmapping an account. To end the
issued certificates too, run `keyroster revoke user NAME` instead of
`user disable`: it revokes every live certificate of NAME in the signer's
records, disables NAME and revokes again
([revoke.md](revoke.md#4-revoke-a-user-keyroster-revoke-user)). A host
refuses those certificates only once its sshd's `RevokedKeys` file holds
the new KRL, and the drop-in in [host-setup.md](host-setup.md) sets no
`RevokedKeys`. So a host set up by hand enforces no revocation. Until it
is enrolled with the keyroster agent ([host-setup.md, "Enrolling a
host"](host-setup.md#enrolling-a-host), 03-07), which sets `RevokedKeys`
and applies every KRL, such a host refuses a revoked certificate only if
the operator adds a `RevokedKeys` line and installs the KRL by hand,
which is UNVERIFIED (revoke.md). Otherwise `revoke user` stops only new
certificates there.

**After every disable**, confirm it on the signer host
as below. A compromised server can answer the install without forwarding
it, and from then on serve the version you signed as if it were installed,
while the signer keeps issuing certificates under the old one.

## Confirm on the signer host

On the signer host, export the signer's log and verify it against the root
pins you hold on paper:

```
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/log.jsonl
keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 /tmp/log.jsonl
```

Its `OK:` line must say `directory installs N`, where N is the version
the CLI reported. Every directory version is one install, so a smaller N
means the signer never installed the version you signed: treat the server
as compromised, and know that the user can still get certificates until
that version is installed on the signer. The export and the `directory installs` count run in the
end-to-end test `TestEnrollApproveEndToEnd`
(`audit_verify_counts_installs`), without the `runuser` wrapper that
[signer-install.md](signer-install.md) uses on a real host.

**Run on the homelab in 02-13.**

- `export-log` ran on the signer host with the `runuser` wrapper above,
  writing to standard output instead of `--out`.
- `audit verify` ran on the admin's Windows computer, on a copy of that
  export.
- With the pins of TEST roots C and D, the root set of bundles v2 and v3,
  the `OK:` line said `directory installs 5`.
- `directory show` reported version 5. The five admin-signed versions
  were approve, role add, role grant, host-group add and host-group map.

## Logging in

Once the user's passkey is bound and an admin has granted the user a role,
the user gets a certificate with one command:

```
keyroster login
keyroster login --role ops --ttl 30m
```

After the certificate is in the agent, `keyroster login` also refreshes
the host trust files in `~/.ssh` (`--no-known-hosts` skips that): see
[Trusting hosts without TOFU](#trusting-hosts-without-tofu).

- `keyroster login` makes a new key in memory and prints
  `Key fingerprint: SHA256:...`, the principals and the lifetime. It opens
  the approval page in your browser (`--no-browser` only prints the URL).
- **Approve only if the page shows exactly the fingerprint your terminal
  printed.** If you did not just run `keyroster login`, close the page:
  someone may have started a login and sent you the link, hoping you
  approve it for them (consent phishing). Approving it would give them a
  certificate for your principals. A browser extension with access to the
  keyroster site can defeat this comparison, so approve in a browser
  profile without one (see [Residual risk](#residual-risk)).
- After the passkey prompt the browser hands the result to
  `keyroster login` on `127.0.0.1`. The CLI checks the certificate against
  the user CA of your root-signed trust bundle (its own key, exactly the
  principals, roles and extensions it asked for, no critical options, at
  least 60 s left) and adds it to the agent
  with a lifetime of its remaining validity, counted on the server's clock
  (your clock plus the measured difference, plus one second), so the agent
  never keeps it past its expiry. It never writes the key
  to a file. It prints the certificate's `Serial:` and `Key ID:`, which
  match the signer's log.
- `--role` picks some of your roles (default: all of them). `--ttl` may
  only shorten the lifetime: the default and maximum is the smallest cap
  of the selected roles, never above the user CA's. It must be at least
  2 minutes.
- Your computer's clock must be within 60 s of the server's; the CLI
  refuses otherwise.
- **Linux and macOS:** the certificate goes into the ssh-agent at
  `SSH_AUTH_SOCK`. If none is running, start one first with
  `eval $(ssh-agent)`. GNOME's gcr-ssh-agent, as shipped in Ubuntu 26.04,
  passed the lifetime and certificate probe (A3) in 02-14 and works as that
  agent. Other gcr versions are UNVERIFIED.
- **ssh may log you in with another key.** If the host also has one of
  your plain keys in `authorized_keys`, ssh may offer that key first, and
  then the certificate is not what logged you in. To offer only
  certificates, add `-o PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com`.
  The run on Linux in 02-14 used it together with
  `-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no`, so a
  refused certificate ends the login instead of falling back to a password
  prompt. The same settings in a `Host` block, and any of them with the
  Windows inbox client, are UNVERIFIED.
- **Windows:** the certificate goes into keyroster's own agent, never the
  Windows OpenSSH agent service. `keyroster login` starts it when needed
  and prints a `Host <your keyroster hosts>` block with an `IdentityAgent`
  line for `~/.ssh/config`. Keep that block host-scoped (see
  `keyroster agent -h`).
- **"login not completed ...; run keyroster login again":** do exactly
  that. The CLI never retries. If the server's answer was lost after the
  signer issued, the log holds one certificate for a key that only the
  exited `keyroster login` process had, so nobody can use it.
- **Remote machines:** there is no headless login yet (D-12). Log in on
  your own computer and forward your agent (`ssh -A`) only to hosts you
  trust.

What is tested: `TestLoginEndToEnd` runs `keyroster login` on Linux
against a real signer, server, OpenSSH `ssh-agent` and `sshd`, with a soft
authenticator standing in for the browser and the passkey: the approval
page shows the CLI's fingerprint, the certificate logs in through the
agent, a `--ttl 2m` certificate leaves the agent at expiry, two concurrent
logins stay apart, an unapproved login issues nothing, and a role revoked
between approval and hand-off gets the signer's refusal. The CLI flow also
runs against a fake server on Linux, macOS and Windows in CI.

**Run on the homelab in 02-14, on Windows:** the owner ran
`keyroster login` and `keyroster login --ttl 5m` on Windows 11 in Chrome,
approving with a synced Chrome passkey unlocked by Windows Hello. The owner
saw the fingerprint on the page before any passkey prompt, and the prompt
appeared only after Approve. The certificate logged in to a stock OpenSSH host
through keyroster agent, and the 5 m certificate was gone from the agent
at a later listing while the other stayed (the listing times were not
recorded, so removal at expiry itself is not shown). The signer's log records both logins, and the
host's sshd journal records the SSH login with the 8 h certificate.

**Run on the homelab in 02-14, on Linux:** on the laptop (Ubuntu 26.04,
GNOME) the owner ran `keyroster login` and `keyroster login --ttl 5m`,
approving in Chrome with the same synced passkey, unlocked through Google
Password Manager. Both certificates went into gcr-ssh-agent. The owner saw
the fingerprint on the page before any passkey prompt, and the prompt
appeared only after Approve. The 8 h certificate logged in to a stock
OpenSSH host. The first `ssh` used the laptop's own plain key instead (see
"ssh may log you in with another key"), and a run that offered only
certificates logged in with the certificate. The 5 m certificate was still
in the agent before its expiry, and gone 57 s after it while the other
stayed. The signer's log records both logins, and the host's sshd journal
records the certificate login.

**Still UNVERIFIED:** Edge and every browser other than Chrome, a
hardware or device-bound authenticator (both runs used one synced
passkey), web sign-in on Linux, macOS, OpenSSH `ssh-agent` outside CI, the
browser opener, and the Windows path in which `keyroster login` itself
starts keyroster agent.

## Trusting hosts without TOFU

Clients reach enrolled hosts with no "authenticity of host" prompt:
keyroster writes the trust files ssh reads, from the admin-signed
directory and the KRL, which the CLI verifies itself (03-09b, REVOKE-04).
Run in CI e2e (03-09b) on OpenSSH 9.5p1 and 10.5p1: `TestHostCertNoTOFU`
(an admin's sync and a user's login write the files, and real ssh reaches
the host by `HostKeyAlias` with no prompt) and `TestHostTrustLongLines`
(the line shapes at their bounds). UNVERIFIED until 03-16 on a real
client. The Windows client's use of these files is UNVERIFIED.

**1. The files.** Three in `~/.ssh` and a state file in the CLI's config
directory:

- `~/.ssh/keyroster_known_hosts`: one `@cert-authority` line per trusted
  host CA, over the principals of the active host entries;
- `~/.ssh/keyroster_revoked_hosts.krl`: the verified KRL;
- `~/.ssh/keyroster_ssh_config`: one strict `Host` block over every name
  the client ever saw (active, disabled, removed), which trusts only
  `keyroster_known_hosts` (`UserKnownHostsFile` and
  `GlobalKnownHostsFile`), sets `KnownHostsCommand none` (so a
  `KnownHostsCommand` later in your configuration adds no host key for a
  managed name; run in CI e2e (03-09b), `TestHostTrustLongLines` part
  `c_d7_block_after_include`), sets `StrictHostKeyChecking yes` and always
  names the KRL as `RevokedHostKeys`;
- `host-trust.json` in the keyroster config directory (next to
  `config.json`): the floors and the names.

Include the managed config from `~/.ssh/config` **at top level, before the
first Host or Match line** and outside any Host or Match block: ssh keeps
the first value it obtains, and an Include inside a Host block is
conditional on that block. The CLI prints the line when it is missing and
warns when it is misplaced:

```
Include ~/.ssh/keyroster_ssh_config
```

The managed config's first directive, at top level before its Host block,
is `IgnoreUnknown KnownHostsCommand` (owner decision D-R4). ssh below
OpenSSH 8.5 does not know `KnownHostsCommand` and refuses an unknown
keyword even inside a Host block that does not match, so without that line
every ssh would fail once the Include is added. `IgnoreUnknown` acts only
where its line is active, which is why the Include must sit at top level.
ssh also keeps the first `IgnoreUnknown` it obtains: if your own
`~/.ssh/config` sets `IgnoreUnknown` before the Include, add
`KnownHostsCommand` to your own list. Run in CI e2e (03-09b) on OpenSSH
9.5p1 and 10.5p1: `TestHostTrustLongLines` part `c_d7_block_after_include`
(the line parses, and changes nothing else `ssh -G` prints for a managed
name). Clients below OpenSSH 8.5 are UNVERIFIED: no CI lane runs one.

The block never falls back to `~/.ssh/known_hosts`. A name outside it
keeps your own configuration. Run in CI (03-09b):
`TestKnownHosts/include_missing_prints_line_once`,
`TestKnownHosts/include_after_host_warned_with_both_line_numbers`.

**2. Refreshing.** Admins run `keyroster known-hosts sync`; every
`keyroster login` refreshes the files too (`--no-known-hosts` skips that,
the KRL fetch included). The outcome is one line:

- `Host trust refreshed (directory vN, KRL vK, M names).`
- `Host trust partly refreshed: revocations only (<reason>).` (or the
  bound, item 8)
- `Host trust not refreshed: <reason>.`

`keyroster known-hosts sync` exits 0 when refreshed or unchanged, 3 when
partly refreshed, and 1 when nothing was written. `keyroster login`
always exits 0 for its certificate, whatever the host trust outcome. Run
in CI (03-09b): `TestKnownHostsSync`, `TestLoginFlowFakeServer`.

Two refreshes of one user at the same time (a `keyroster login` while a
`known-hosts sync` runs) take no lock. Right before each file it renames,
a run reads the state again (and, before the KRL, the KRL on disk), and
when the other run has recorded newer files it stops without writing
anything older: `Host trust not refreshed: a concurrent refresh won: ...`.
A residual remains (owner decision D-R1): a rename right after that check
can still land behind the other run's, so an older KRL, older CA lines or
an older Host block can stay in place, and a revocation the newer KRL
holds is then not enforced, until the next refresh re-verifies and
rewrites every file. The state file has no such check before its rename
(the run read it again just before), so two runs can also swap their
state writes: the state then keeps the slower run's floors, never below
the ones that run began with, and until a refresh from an honest server
raises them again a compromised server could serve a directory version
between the two runs' versions (T-03-347). The swap can also drop the
names the faster run added from the state and the Host block. They come
back when a directory that lists them is served again; a name removed
from the directory in between does not come back, so it leaves the
strict block and falls to your own ssh configuration (T-03-346, under
this race). Run in CI (03-09b):
`TestKnownHosts/concurrent_state_after_state_step_stops_krl`,
`TestKnownHosts/concurrent_newer_krl_on_disk_stops_krl`; the window
itself is UNVERIFIED (no test can time it).

**3. What every signed-in user receives (T-03-100).** Every user who
completes a passkey login receives the whole admin-signed directory with
the login answer: users, roles, groups and memberships; hosts with their
principals and keys; machines and their keys; public credential data. It
holds no secrets. The owner accepted this while one installation serves
one organisation. Run in CI (03-09b): `TestLoginRedeem` (the server sends
it only from the mirror for the status it read before the login, and the
certificate is always returned).

**4. The refresh lag (T-03-240).** Changes reach a client at its next
login or sync. After that, a disabled or removed name has no CA line
while it stays in the block, so it is refused (never prompted), and a
revoked certificate is refused through the KRL. Run in CI e2e (03-09b):
`TestHostCertNoTOFU/refused_through_krl_alone` and
`TestHostCertNoTOFU/refused_through_missing_ca_line_alone`.

**5. The costs.** A managed name is unreachable until its host has a host
certificate. Disabled and removed names stay refused. Names removed
before the client's first verified refresh are not covered. Explicit
host-key entries appear in the KRL only after `keyroster revoke host
--keys` (revoke.md, section 4b).

**6. Ports (D7).** The managed block covers port 22 by name. For another
port, add after the Include a block for the exact managed name with `Port
<n>` and `HostKeyAlias <that same name>`, and nothing else:

```
Include ~/.ssh/keyroster_ssh_config

Host web1
	Port 2222
	HostKeyAlias web1
```

Placed after the Include, every other managed name stays strict; placed
above it, the Include becomes conditional on that block (OpenSSH reads it
with NEVERMATCH) and the other names lose the strict settings (QB-6).
Run in CI e2e (03-09b): `TestHostTrustLongLines` (its part
`c_d7_block_after_include`, with the negative control above the Include).

**7. Freshness and rollback.** A KRL manifest older than 24 hours prints a
warning; the files are still written. An older directory or KRL than the
client already wrote is refused (an equal one is accepted), and an equal
directory version with another SHA-256 is refused. After a signer restore,
older directory versions are refused until the admins re-install up to
the last version the client wrote, while revocations keep flowing. An
older trust bundle (a restore brings one back) freezes the CA lines and
the Host block, with a warning, until its version is back at the one the
client saw; the KRL, checked with the stored ops key, keeps flowing. Run
in CI (03-09b): `TestKnownHosts/older_bundle_freezes_ca_lines_krl_still_written`,
`TestKnownHosts/older_krl_refused_equal_accepted`,
`TestKnownHosts/stale_manifest_warned_still_written`.

**8. Starting over.** When the CLI refuses because the state file is
missing (while a managed file exists), damaged or for another
installation, or when it warns that the names reached their bound (4 MiB
of names: the Host block is frozen, no name is dropped, and `sync` exits
3), delete the three files and the state file, then refresh:

```
rm ~/.ssh/keyroster_known_hosts ~/.ssh/keyroster_revoked_hosts.krl ~/.ssh/keyroster_ssh_config
rm ~/.config/keyroster/host-trust.json   # Linux; the refusal prints the path
```

Run in CI (03-09b): `TestKnownHosts/missing_state_with_managed_files_refuses_all_writes`,
`TestKnownHosts/bound_freezes_config_keeps_krl_and_known_hosts`.

**Which names every client pins.** The Host block and the CA lines hold
exactly the principals of the host entries in the admin-signed
directory; the CLI checks their form, not whose names they are. So the
admins who sign the directory choose which names every user's ssh trusts
only the organisation's host CA for. An external name (a public service
such as `git.example.com`) or a wrong one (a mistyped name, an address)
affects every user at their next refresh: ssh then refuses that service's
own host key. Names only grow, so a wrong name stays in the block, refused,
after its entry is fixed or removed. To drop it on one client, start over
(item 8). A root-signed scope of the names clients pin is planned for
Phase 4 (owner decision D-R3).

**9. The home ssh reads.** ssh expands `~` from the account's home in the
account database, never from `$HOME`. So the CLI refuses every write when
`$HOME` is not the account's home, and says so (QB-5). When the lookup
fails it only warns and writes. The CGO_ENABLED=0 Linux release's os/user
reads only `/etc/passwd`, so every account known only through NSS or LDAP
gets that warning and no home check. Run in CI (03-09b):
`TestKnownHostsUnix/home_differs_from_account_refuses`,
`TestKnownHostsUnix/home_lookup_failure_warns_and_continues`.

## Residual risk

**A browser extension can defeat the fingerprint comparison.** An
extension that can read and change the keyroster site can swap the
approval page's challenge and the address the assertion goes to while your
own fingerprint stays on screen: `app.js` reads the challenge from
`data-options` when you click Approve and posts the result to the URL in
`data-assertion`. It can also read the loopback redirect to
`keyroster login`. The page's Content-Security-Policy does not restrict
extensions. Approve in a browser profile without extensions that have
access to the keyroster host, or withhold their site access. This is
outside the Phase 2 threat model (a compromised WebAuthn client); Phase 4
revisits browser integrity.

**The fingerprint comparison does not hold against a compromised
server.** The passkey signs only the WebAuthn challenge, never the
fingerprint the page shows. A compromised server can show the fingerprint
your terminal printed while the challenge covers a request for a key of
its own; the signer then issues a certificate for that key, with your
principals and at most your TTL cap. `keyroster login` refuses any
certificate that is not for its own key, so you get none that time, but
the server holds one. The issuance is in the signer's log, with the
fingerprint of the server's key (`key_fingerprint` in the export), which
no terminal printed. A compromised server can collect such an assertion
from any passkey ceremony at its origin. The comparison protects you on
an honest server against a login someone else started and sent you
(T-02-56, T-02-60).

With attestation none, a **compromised server** can show both sides the
fingerprint of an attacker's credential: the user sees it on the page, and
the admin sees it in `user pending`. The out-of-band comparison stops a
stolen invite on an honest server, not a compromised server. The sign of
it is that the user's own first `keyroster login` fails. Every binding is
an admin signature in the audit log (`keyroster audit verify` counts the
directory installs), so such a binding cannot be hidden afterwards
(RESEARCH Pitfall 13).

A **compromised server** can also withhold or delay any install,
including a `user disable`, and still answer it as installed: the CLI
checks the answer only against the version and SHA-256 of what it sent,
which the server knows too. It can then serve the version you signed, so
`directory show` and `user list` show the change while the signer still
holds the older version. It cannot make you sign anything you did not see,
and every later edit builds on the version you signed, so none of them can
be installed before it. Until the CLI verifies a receipt signed by the
signer (Phase 4), the signer's own log is the only proof:
[Confirm on the signer host](#confirm-on-the-signer-host).

The CLI also keeps no record of the newest trust bundle and policy it has
seen: it accepts any bundle and policy your root pins signed, the oldest
included. So a **compromised server** can serve an older policy, and an
admin key that policy names but a newer one removed (a lost or stolen
admin key) can then sign a directory that `directory show` and
`user list` print as verified. The signer is not fooled: it checks against
the policy in force. When you remove an admin, treat what the CLI shows as
the server's word until you have checked the signer's log on the signer
host; `keyroster audit verify` prints the trust bundle and policy versions
it ends at (`trust bundle vN, policy vN`). The CLI keeps no high-water mark
until Phase 4.

**Enrolled hosts check their directory against the policy in force too**
(03-08f). After a policy that changes the admins is installed, a host
checks its stored directory again under that policy on every run. While
the new policy's admins have not signed it, the host renders no
certificate principals: certificate logins to it are refused, as the
signer refuses issuance in the same state, while `authorized_keys` and the
console are not affected. The host reports `directory_not_authorized`, and
`last_apply` shows it as `refused`. So **install the new admins' directory
right after the bundle.** The host takes, standalone, the newest
directory the new admins sign that names this installation and fits the
policy, at its stored directory version or higher (at the stored version
only with other bytes). A host
whose stored directory version is above anything the new admins have
signed stays without principals until you run
`sudo keyroster-agent reset-directory` on it. Installing the new admins'
directory is the signer and CLI recovery that todo 2026-10-21 (recover the
directory after an admin-set change) tracks for Phase 4. Run in CI
(`TestDirectoryUnderPolicyInForce`: `lagging_host_admin_removed_principals_dropped`,
`new_admins_next_version_accepted_standalone`,
`stored_version_above_new_admins_needs_reset`, 03-08f); UNVERIFIED on the
homelab, where Phase 3 runs no admin-set change of enrolled hosts.

A host whose sshd host keys match no entry of the directory it takes
(`host_keys_rotated`), or two (`host_keys_disagree`), normally keeps its
last good principals. It keeps them only while the policy in force
authorizes the directory they were rendered from. A host that already
kept them (its last status was `host_keys_rotated` or
`host_keys_disagree`) keeps them only while the new policy has the same
admin quorum and CA profiles and keeps every admin of the accepted policy,
as after `reset-directory`. So when the new admins'
directory lists the host under other keys, the host gets the bundle's CA
keys and the KRL with no principals, reports the host status, and stays
so until a directory lists its current keys. The same holds after
`reset-directory`, before a directory is accepted, when the new policy
drops an admin or changes the admin quorum or the CA profiles (PR #82
review). Run in CI
(`TestLastGoodPrincipalsUnderPolicyInForce`, with
`kept_principals_then_admin_removed_keeps_none` for an already-kept host);
UNVERIFIED on the homelab.

A host that already rendered such a directory before this change removes
its principals at its first run that ends without a verification or KRL
error (`persisted_unauthorized_state_dropped_on_noop_capture`). A run that
is refused in verification or for its KRL (`krl_not_verified`, or
`krl_signer_retired`) installs nothing, so the principals stay until a run
succeeds. UNVERIFIED: no test builds the state from before this change
together with a refused KRL.
