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
> `user enable`, `directory show`, and the interactive
> `Sign directory version N? [y/N]` prompt. The registration page in a real
> browser with a real authenticator is **UNVERIFIED** until plan 02-13.

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

## Residual risk

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
