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
verified version, and every signature already in it must verify and be by
a policy admin. It shows the diff and asks before it signs; in a script
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
revocation, confirm on the signer host as below.

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
`keyroster user disable NAME` stops the account if it must not be used.

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

## Disabling a user

```
keyroster user disable NAME
keyroster user enable NAME
```

Both go through the same pipeline (verify, diff, confirm, sign, install or
propose). A disabled user keeps its passkeys in the directory and cannot
sign in. Enabling needs at least one bound passkey.

**After every revocation** (`user disable`), confirm it on the signer host
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
