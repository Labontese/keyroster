# CA rotation: prepare, two ceremonies, the switch and the drain

This runbook rotates a CA key of a role (here `user`) through two root
ceremonies (D-14, KEY-08). Ceremony 1 adds a prepared key as `next`, so
that every host trusts it beside the active key; an abort withdraws it
again. Ceremony 2 switches: the `next` key becomes active and the old
key drains, trusted by the hosts until its `trusted_until`, after which
every agent drops it.

> **UNVERIFIED on the homelab hosts and signer.** Each step that CI runs
> names its test; "Run in CI" at the end lists them. The end-to-end proof
> runs against real sshd on OpenSSH 9.5p1 and 10.5p1 in the
> `e2e-rotation` job: `TestCANextAndAbort` for ceremony 1 and the abort,
> `TestCARotationNoFailedLogin` for the whole rotation, and
> `TestHostCARotation` for what the host CA's gate prevents.

## Scope

This runbook covers a complete rotation of one role: the prepare step,
ceremony 1 and its install, the wait for the hosts, ceremony 2 (the
switch) and its install, the removal of the old key from the signer, the
drain on the hosts, and the abort of a `next` key before the switch.
Between the two ceremonies a `next` key is trusted by every host and used
by nobody, because the signer signs only with the active key. After the
switch the signer signs with the new key, and the hosts keep trusting
the old one until its `trusted_until`, so that no certificate it signed
is cut off early. Neither ceremony changes a root or the installation
ID, so no CLI pin changes.

Every CA entry stays in every later bundle: an aborted key stays listed
as `retired`, a drained key as `draining` with its end, its generation
number is never used again, and the next prepare makes the next
generation. Roles switch one at a time: switch the user CA, wait for
its drain, then the next role.

## What you need

- The roots and the threshold of the bundle in force, as for any successor
  in [root-ceremony.md](root-ceremony.md) "Change the policy".
- The `bundle.json` and `policy.json` in force with their `.sigs` files,
  and the bundle's SHA-256 as recorded at its install (`--prev-sha256`).
- A second person who did not run the prepare step. They read the new
  key's fingerprint from the signer console and write it in the transcript
  ([ceremony-transcript-template.md](ceremony-transcript-template.md)).
- The transfer medium.
- A clean `keyroster-signer doctor` (no FAIL, no restore marker), a
  `signer.db` backup and an export of the audit log taken before you start.

## 1. Prepare the next key

Run [signer-install.md](signer-install.md) "Prepare a CA key generation"
for the role (here `user`). It prints
`role user generation 2 <fingerprint> <alg> <custody>` on the signer
console. Read the fingerprint aloud to the second person, who writes it
in the transcript as "next CA fingerprint as read from the signer console
by <name>". Nobody copies it from a file.

What prepare creates depends on the signer's backend:

With the software backend, prepare writes `software/user-g2.age` in the
state directory (generation 1 keeps `software/user.age`). With the agent
backend it creates nothing: `--key` names a key the agent already holds.

With the tpm backend, prepare creates the key inside the TPM with noDA and
writes `tpm/user-g2.tpmkey` and `tpm/user-g2.auth` in the state directory
(generation 1 keeps `tpm/user.tpmkey` and `tpm/user.auth`). It runs on
swtpm only, and no YubiKey or physical TPM has run it.

With the piv backend, prepare generates the key on the card in the first
slot in 0x87 to 0x95 that no generation row records, and prints that slot
on the console after `prepare file:`, as `location: 87` for the first
rotation. There are 15 slots in all, shared by every role's later
generations and, from 03-13, by the ops and log keys. A slot is never
reused, even after retire-key emptied or overwrote it, and prepare refuses
`piv_no_free_slot` when none is left: a rotation never changes custody,
so a card with no free slot rotates no further. The person who reads the
console writes the `location:` line into the transcript beside the
fingerprint, because the slot is recorded nowhere else outside
`signer.db`. It runs on the fake card only, and no YubiKey or physical
TPM has run it.

A key in the slot that is next, which no generation row records (a lost
prepare, a `signer.db` restored from before a prepare, or a key put there
by hand), makes prepare refuse `ErrSlotOccupied` (the console prints
`slot already holds a key`, naming the slot) on every later run, for
every role, until the slot is emptied. Overwriting it by hand does not
clear it. On firmware 5.7 and later `ykman piv keys delete <slot>` empties
it, and only when the rule of piv.md "Generation slots" allows it: never
on a restored database before the restore section of signer-install.md
has run to its end; never while a signed bundle waits to be installed,
because a bundle that `install-bundle` refuses with `no stored generation`
names a generation the database lost, and the slot's key may be that
generation's key; and never a key you keep in the slot for another use.
The signer holds the card while it runs, so it is stopped for the delete
(piv.md "Generation slots"). Below 5.7 nothing empties it short of
`ykman piv reset`, which destroys every CA key on the card. Each `ykman`
command here is UNVERIFIED. The refusal runs on the fake card only, and
no YubiKey or physical TPM has run it.

Prepare on piv needs the management key on the signer host for the run,
placed and shredded by the block of piv.md step 5
([piv.md](../backends/piv.md)): its last line runs this step's prepare
and starts the signer only when prepare exited 0. So on a PIV signer that
block replaces the stop, prepare and start of signer-install.md; after a
refused prepare the key is already shredded and the signer is still
stopped, so run `sudo systemctl start keyroster-signer.service` by hand
(the refusal wrote nothing the signer serves), fix the cause, and run the
block again. Prepare on piv refuses `--key`. It runs on the fake card
only, and no YubiKey or physical TPM has run it.

The prepare file lies in the signer's `incoming` directory, which the
signer's user owns. Read it onto the medium as that user, so that root
opens nothing below that directory:

```
S=/var/lib/keyroster-signer
runuser -u keyroster-signer -- cat "$S/incoming/user-g2.json" >/media/transfer/user-g2.json
```

## Ceremony 1: add the next CA key

On the offline ceremony machine, every root that signs runs the same
command and flags, with the fingerprint the second person wrote down:

```
keyroster root sign --prev /media/transfer/prev --prev-sha256 <recorded sha256> \
  --roots roots.pub --threshold <N> --policy /media/transfer/prev/policy.json \
  --out-dir /media/transfer/succ --agent-key SHA256:<root> \
  --ca-next user=/media/transfer/user-g2.json \
  --ca-next-fingerprint user=SHA256:<read aloud>
```

`--ca-next-fingerprint` is mandatory. `root sign` compares it with the
prepare file's key before anything is written or signed, and refuses a
different one with `ca_next_fingerprint_mismatch`: then stop, the file on
the medium is not the key that was prepared. Each further root passes the
same command and flags; `root sign` rebuilds the successor from them and
refuses to sign a different one.

Run it first without `--confirm` and read the whole output. Check, and
answer no to the prompt if anything differs:

- **The CA-change section** comes right after `Successor of trust bundle`,
  `Previous root keys` and `signatures needed:`. It holds exactly one line,
  `CA user gen 2 SHA256:...: none -> next`, and its fingerprint is the one
  the second person wrote down as the next CA fingerprint as read from the
  signer console. No other `CA <role> gen` line, and no
  `CA entries: unchanged`.
- **The root set.** `Root set: unchanged`. The `Root keys (threshold` line
  of the summary lists the roots of the bundle in force at the agreed
  threshold.
- **The summary's CA keys** list the user CA `gen 1 active` and `gen 2
  next` with the same fingerprint, and the host and machine CAs unchanged.
- **The policy block**: `Policy in force:` names the policy version and
  SHA-256 you pinned with `--prev-sha256`, and the next line reads
  `Successor policy: unchanged, every field carried over`, with no
  `WARNING: this successor changes` line. Ceremony 1 changes no policy.
- **The PoP and WebAuthn lines** read as in force: `pop hosts=` or
  `pop: none (`, and `webauthn rp_id ` with the origins in force.

A confirmation given with `--confirm` skips this read point, so the first
run of a ceremony never carries `--confirm`. The checks describe the output of
this tool version; if `root sign` prints something these checks do not
name, do not apply there: stop and answer no.

Then verify the signed successor against the pins:

```
keyroster trust verify --prev /media/transfer/prev --prev-sha256 <recorded sha256> \
  --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> \
  --bundle /media/transfer/succ/bundle.json --policy /media/transfer/succ/policy.json
```

It prints the same CA-change section and `Root set: unchanged` after its
`Successor of trust bundle` line.

## Install the successor

On the signer, with the signer stopped. Root runs nothing below the
signer's state directory: keyroster-signer owns it and its `incoming`
directory and could replace either by a link, so the successor files are
written as the signer's user from the medium. The copy under `set -C`
refuses to overwrite, so every file it writes is first removed as that
user, and the removal, each copy and the install are chained with `&&`:
a failed removal or copy stops the chain before the install, which never
runs against a stale or half-copied file.

First move `/media/transfer/export.jsonl` aside under another name and
keep it, if it is there (the first rotation may find none), as
signer-install.md asks you to keep every export: the block writes the new
export under the same name.

```
systemctl stop keyroster-signer.service
S=/var/lib/keyroster-signer
runuser -u keyroster-signer -- rm -f "$S/incoming/bundle.json" "$S/incoming/bundle.json.sigs" \
  "$S/incoming/policy.json" "$S/incoming/policy.json.sigs" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/bundle.json" <"/media/transfer/succ/bundle.json" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/bundle.json.sigs" <"/media/transfer/succ/bundle.json.sigs" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/policy.json" <"/media/transfer/succ/policy.json" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/policy.json.sigs" <"/media/transfer/succ/policy.json.sigs" &&
runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer install-bundle --state-dir "$S" \
  --bundle "$S/incoming/bundle.json" --policy "$S/incoming/policy.json"
systemctl start keyroster-signer.service
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir "$S"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer export-log --state-dir "$S" --out /tmp/ca-rotation.jsonl &&
runuser -u keyroster-signer -- cat /tmp/ca-rotation.jsonl >/media/transfer/export.jsonl &&
runuser -u keyroster-signer -- rm -f /tmp/ca-rotation.jsonl
keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> --installation-id <installation id> /media/transfer/export.jsonl
```

`install-bundle` prints `installed bundle version <N>` and refuses a next
entry that is not a stored generation. doctor's `OK generations` line
lists the user CA `next g2` with the new fingerprint. The signer still
signs with generation 1. The export is copied onto the transfer medium
at once, as the signer's user, and its copy under `/tmp` is removed; the
audit verify reads the copy on the medium. That copy stays off the signer
box for good: it is the `--previous` of ceremony 2's install, unless you
take a newer one the same way. It is the anchor with which the signer
refuses a database rolled back after this install, so it is never
rebuilt from files on the signer box later.

## Wait for the hosts

Each agent adds the new line to its `user_ca_keys` after the widening
wait: about the sshd `LoginGraceTime` bound plus 30 s, 150 s at the
default of 120 s. On a host, the live `user_ca_keys` then holds both user
CA lines, and `keyroster-agent check` passes. `keyroster host status`
shows `user CA keys of bundle v<N> live on <X>/<M> hosts`, and the gate is
M/M.

The count is published by the CLI from the hash each host reports for its
own `user_ca_keys` file, through the fetcher, in the host's heartbeat: a
host counts only when that hash is the one the bundle in force gives and
its own last check is clean ([host-setup.md](host-setup.md), "Running the
agent"). A host that holds the new line back never counts. Running
`keyroster-agent check` by hand on a host shows that host's own report but
writes no status, so it does not change the count; a held or stuck host
counts only after root has recovered it with
`keyroster-agent apply --once --recover-to-last-good`, as host-setup.md
says, and the agent's next clean check has reached the server. A host you
removed from the directory stays in M, and keeps the count below M/M,
until you run `keyroster host forget` for it. Hosts that keyroster-agent
does not manage are not counted: check the current
`keyroster host ca-key` output on each of them by hand before ceremony 2
([host-setup.md](host-setup.md#1-trust-the-user-ca)).

## Abort: withdraw the next CA key

Abort when the `next` key is wrong, its fingerprint was not the one read
aloud after all, or it may be compromised. Run the same ceremony on the
bundle in force as `--prev`: the successor ceremony 1 signed and
installed, in `/media/transfer/succ` with its policy and `.sigs` files,
with the SHA-256 recorded for it, not ceremony 1's own `--prev` directory.
Pass the abort flag instead of the two next flags:

```
keyroster root sign --prev /media/transfer/succ --prev-sha256 <recorded sha256 of succ/bundle.json> \
  --roots roots.pub --threshold <N> --policy /media/transfer/succ/policy.json \
  --out-dir /media/transfer/abort --agent-key SHA256:<root> \
  --ca-retire user:2
```

Run it first without `--confirm` and check as in ceremony 1, except:

- the CA-change section holds exactly one line,
  `CA user gen 2 SHA256:...: next -> retired`, with the fingerprint of the
  key you withdraw, and no other `CA <role> gen` line and no
  `CA entries: unchanged`;
- `Root set: unchanged`, and the `Root keys (threshold` line as in force;
- `Policy in force:` and `Successor policy: unchanged, every field carried
  over`, with no `WARNING: this successor changes` line, and the
  `Previous root keys` of the bundle in force;
- the PoP and WebAuthn lines as in force: `pop hosts=` or `pop: none (`,
  and `webauthn rp_id `.

A confirmation given with `--confirm` skips this read point, so run
without `--confirm` first; if the output shows something these checks do
not name, do not apply there. Verify it with `keyroster trust verify
--prev` and install it as in "Install the successor", with the abort
directory in place of `succ`.

Every host drops the line on its next run, at once (a narrowing change
needs no wait), and the agents' host-certificate and probe answer checks
refuse the key. Then destroy the aborted key by hand, because retire-key
removes draining keys only, never an aborted one: delete
`software/user-g2.age` in the state directory as the signer's user for
the software backend (`runuser -u keyroster-signer -- rm -f /var/lib/keyroster-signer/software/user-g2.age`);
remove it from the ssh-agent with `ssh-add -d` for the agent backend; for
the tpm backend delete `tpm/user-g2.tpmkey` and `tpm/user-g2.auth` as the
signer's user (`runuser -u keyroster-signer -- rm -f /var/lib/keyroster-signer/tpm/user-g2.tpmkey /var/lib/keyroster-signer/tpm/user-g2.auth`),
which removes the wrapped key and destroys nothing inside the TPM. With
the piv backend the key stays in its slot, which the bundle in force no
longer trusts: the slot is the `location:` line the transcript recorded
at prepare, and it stays recorded and is never reused; overwriting it by
hand with `ykman` is UNVERIFIED. The generation row stays, and doctor
does not warn. The generation number is never reused: the next prepare
makes generation 3.

## Before ceremony 2

**The upgrade gate.** Every component must understand a `draining`
entry and its `trusted_until` before a switch bundle exists. Upgrade in
this order: the signer and the server first; then every agent, each
applier together with its fetcher from one release; then the CLIs.
Older builds refuse `draining` and `trusted_until`: an old agent fails
closed and keeps the bundle it has (on that host the old key stays
active and logins keep working until it is upgraded), and an old CLI
cannot log in until it is upgraded. `keyroster host status` shows each
agent's version in its AGENT column; do not go on while one is older.

**The hosts.** The live count of "Wait for the hosts" reads M/M for the
bundle in force, and every host that keyroster-agent does not manage
holds every line of `keyroster host ca-key`.

**The clients, for the host role.** Install ceremony 2 of the host role
no earlier than the gate of "The host CA" allows: at least the user
profile's max TTL after ceremony 1's install, once the managed
`keyroster_known_hosts` of every account whose ssh reads the managed
files holds the new host CA's line (a user who always passes
`--no-known-hosts` included; an account that cannot refresh itself
gets the line from an admin who runs `keyroster known-hosts sync` as
that account), and once `keyroster host status` reads
`bundle v<N> on <M>/<M> hosts` for the server's current bundle N,
ceremony 1's or a later one that still lists the new host CA.

### Pre-switch check

On the signer, as the signer's user:

```
S=/var/lib/keyroster-signer
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir "$S"
```

Its line `OK switch_floor: user generation 1: the certificate that sets
the earliest trusted_until a switch could carry is serial <s> (key ID
<k>, valid until <v>); the earliest is <e>` (or `... the log records no
certificate of this key; the earliest is the floor`) names the
certificate the switch must outlast. Write `<e>` in the transcript: the
switch's `trusted_until` must be at or after it, or the install refuses
`drain_window_too_short`. A host certificate that an admin issues with
`keyroster ca issue --ca host` lives as long as its `--ttl`, up to the
host profile's `max_ttl_seconds`, which the floor of "Ceremony 2" covers
(for the host role that floor counts the host cap, "The host CA"). The
`<e>` read here lies past a role's floor only when a certificate was
issued under an earlier policy whose cap for its role was larger. Then
wait until it expires, or switch the other roles first. A revoked
certificate still counts, because the hosts drop the old key on time
only if every certificate it signed is dead by then: revoking does not
help, waiting does.

## Ceremony 2: switch to the next CA key

Hold it while the signer still serves; plan the install right after it.
On the offline ceremony machine, on the bundle in force (ceremony 1's
successor, with its SHA-256 as recorded at its install), every root that
signs runs the same command and flags. `--policy` is the policy in
force: ceremony 2 changes no policy.

```
keyroster root sign --prev /media/transfer/succ --prev-sha256 <recorded sha256 of succ/bundle.json> \
  --roots roots.pub --threshold <N> --policy /media/transfer/succ/policy.json \
  --out-dir /media/transfer/switch --agent-key SHA256:<root> \
  --ca-switch user --drain-allowance 24h
```

`--drain-allowance` (default 24h, whole seconds from 0 to 168h) is what
the switch adds to its floor: the old key is trusted until the ceremony's
issued_at plus the larger user `max_ttl_seconds` of the two policies,
plus 300 s, plus the allowance. Each further root passes the same command
and flags, the same `--drain-allowance` included; `root sign` refuses a
different bundle, naming `--ca-switch` and `--drain-allowance` among its
inputs.

Run it first without `--confirm` and read the whole output. Check, and
answer no to the prompt if anything differs:

- **The CA-change section** comes right after `Successor of trust
  bundle`, `Previous root keys` and `signatures needed:`. It holds
  exactly two lines, as the tool prints them:
  `CA user gen 1 SHA256:...: active -> draining, trusted until <t>; install by <i> (advice)`
  and `CA user gen 2 SHA256:...: next -> active`. The first fingerprint is
  the active key's; the second is the one the transcript holds as the next
  CA fingerprint as read from the signer console at ceremony 1. No other
  `CA <role> gen` line, and no `CA entries: unchanged`.
- **The end.** The printed `trusted until <t>` is at or after the earliest
  on the pre-switch doctor line for the same key. Write both in the
  transcript.
- **The advice.** `install by <i>` is the ceremony's issued_at plus the
  allowance: the time by which the signer must stop issuing with the old
  key, by the signer's clock, and so the latest time to install the
  switch. `install by` is advice and never a refusal; the signer's install
  binding decides. An allowance near 0 needs the signer stopped before
  the ceremony. `install by unknown (advice)` means the tool could not
  derive it: a policy without a profile for the role, or a `trusted until`
  that does not parse or lies below the floor. `root sign` refuses a
  `--drain-allowance` above 168h itself, before it signs, with
  `root sign: --drain-allowance <d> is above the cap of 168h0m0s`. Only a
  successor built by other means can carry a larger allowance; for it the
  advice reads
  `install by unknown (advice: the allowance <a> is above the cap of 168h0m0s, which root sign never builds; do not install or distribute this bundle)`.
  Host agents enforce no upper bound on `trusted_until`, and the signer's
  install refusal `drain_window_too_long` (see "Install the switch")
  depends on the signer's install clock, so it may still accept such a
  bundle: the cap is the root holders' check, and a bundle that prints
  this line is not installed or distributed.
- **The root set.** `Root set: unchanged`. The `Root keys (threshold` line
  of the summary lists the roots of the bundle in force at the agreed
  threshold.
- **The summary's CA keys** list the user CA `gen 1 draining` with its
  `trusted until <t>` and `gen 2 active`, with the same fingerprints, and
  the host and machine CAs unchanged.
- **The policy block**: `Policy in force:` names the policy version and
  SHA-256 you pinned with `--prev-sha256`, and the next line reads
  `Successor policy: unchanged, every field carried over`, with no
  `WARNING: this successor changes` line.
- **The PoP and WebAuthn lines** read as in force: `pop hosts=` or
  `pop: none (`, and `webauthn rp_id ` with the origins in force.

A confirmation given with `--confirm` skips this read point, so the first
run of a ceremony never carries `--confirm`. The checks describe the
output of this tool version; if `root sign` prints something these checks
do not name, do not apply there: stop and answer no.

Then verify the signed successor against the pins:

```
keyroster trust verify --prev /media/transfer/succ --prev-sha256 <recorded sha256 of succ/bundle.json> \
  --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> \
  --bundle /media/transfer/switch/bundle.json --policy /media/transfer/switch/policy.json
```

It prints the same two CA-change lines and `Root set: unchanged`.

## Install the switch

**The export first.** The install needs `--previous`: an export-log file
of this log kept off the box, `/media/transfer/export.jsonl`, the copy
that ceremony 1's install block put on the medium or a newer one taken
the same way right after the last install. The signer reads its last
line, from at most its last 1 MiB, and requires that this log extends
that checkpoint. Take no export now: one made from files on the signer
box would come from the very database the install is meant to check, so
it would always extend itself and the check could not fire. If the copy
on the medium is missing or empty, do not rebuild it from the box: stop
and escalate, because the signer then has no anchor outside itself.

**The install**, on the signer, as the signer's user, before the
`install by` time. The copy under `set -C` refuses to overwrite, so the
export of an earlier switch and the files of an earlier successor are
removed first, and the chain keeps the install from running against a
stale or half-copied file. The export is read from the medium, never from
`/tmp` or any other path on the signer box. The signer is not started
here: the old key must leave the backend first (next section).

```
S=/var/lib/keyroster-signer
systemctl stop keyroster-signer.service
runuser -u keyroster-signer -- rm -f "$S/incoming/bundle.json" "$S/incoming/bundle.json.sigs" \
  "$S/incoming/policy.json" "$S/incoming/policy.json.sigs" "$S/incoming/previous.jsonl" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/bundle.json" <"/media/transfer/switch/bundle.json" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/bundle.json.sigs" <"/media/transfer/switch/bundle.json.sigs" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/policy.json" <"/media/transfer/switch/policy.json" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/policy.json.sigs" <"/media/transfer/switch/policy.json.sigs" &&
runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/previous.jsonl" <"/media/transfer/export.jsonl" &&
runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer install-bundle --state-dir "$S" \
  --bundle "$S/incoming/bundle.json" --policy "$S/incoming/policy.json" \
  --previous "$S/incoming/previous.jsonl"
```

After its CA lines, `install-bundle` prints, per key the switch starts to
drain, `drain user generation 1 until <t>; the last certificate the log
records for it is valid until <v>` (`none recorded` when the log records
none). Write it in the operations log. The install binds the switch to the
log: `<t>` must be at least 300 s after the largest ValidBefore among the
old key's logged certificates. Its refusals, as
[signer-install.md](signer-install.md) "Install a CA switch: `--previous`"
states them, each of which writes nothing:

- `install_previous_required`: no `--previous`; run it again with the
  newest saved export.
- `install_previous_invalid`: the file's last line is not a checkpoint of
  this log; use the export-log file itself, the copy that ceremony 1's
  install block put on the medium. Never take a fresh export from the
  signer box to get past this: it would extend itself, and the check
  would prove nothing.
- `install_previous_not_extended`: this log does not extend the export;
  the database was restored or changed after it. Stop and follow
  signer-install.md "Restore from before the last switch".
- `drain_window_too_short`: a logged certificate of the old key outlives
  `trusted_until` minus 300 s; the refusal names it and the earliest
  acceptable end. Repeat ceremony 2 with a larger allowance.
- `drain_window_too_long`: `trusted_until` is above the latest acceptable
  end; check the ceremony machine's clock and the allowance, and repeat
  ceremony 2.
- `drain_scan_missing`: an internal fence, the install ran without the
  log scan the binding reads; stop and report it, never work around it.

**A refused switch bundle is burned.** It never leaves the signer host,
and every copy of a refused bundle is destroyed before the ceremony is
repeated in a fresh output directory: the `--out-dir` on the ceremony
machine, the copy on the transfer medium, and the five files in
`incoming`, removed as `runuser -u keyroster-signer -- rm -f` of their
names. Hosts accept any root-signed successor, and refuse a re-made
bundle of the same version until root clears it, so a refused bundle that
reached a host would split that host from the signer. `root sign` in the
same `--out-dir` would only rebuild the refused bundle with its stored
issued_at; the repeat uses a fresh directory. The export on the medium is
not part of the refused bundle: it stays.

On any refusal except `install_previous_not_extended`, which goes to the
restore section, destroy the refused files as stated above and then start
the signer again, so that issuance is not left down:

```
systemctl start keyroster-signer.service
```

The signer serves the bundle in force, whose old key is still active, and
a refusal wrote nothing. Repeat ceremony 2 later, from a fresh output
directory.

## Remove the old key and restart

With the signer still stopped, the old key leaves the backend. Until it
has, `serve` refuses `draining_key_still_usable` and doctor reports
`FAIL draining_key_still_usable`. On the piv backend doctor does not read
the card: it reports `WARN draining_key_unchecked` for the draining entry
whether or not the key is still in its slot. There retire-key and serve's
start check read the recorded slot by its key, so retire-key's report and
serve's refusal, not doctor, show whether the key is still held. Run
retire-key as the signer's user, in the same pinned form as the install:

```
S=/var/lib/keyroster-signer
D=$(mktemp -d)
runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer ca-rotate retire-key --state-dir "$S" --role user
```

Per backend, as [signer-install.md](signer-install.md) "Remove the old
key after a switch" states it:

- **software:** retire-key deletes the old key's file and exits 0 with
  `retire-key: no draining key of role user is held`.
- **agent:** retire-key cannot remove a key from an agent. For the key
  the agent still lists it prints `... still held by the agent; write
  this public key line into retire-user-g1 and run:
  SSH_AUTH_SOCK=<socket> ssh-add -d retire-user-g1`, then that line, and
  for each certificate identity of the same key one more command and
  line for `retire-user-g1-cert.pub`, and exits 1 with
  `retire_key_incomplete`. `<socket>` is the signer's own agent socket.
  Root writes those files never relative to the shell's directory, only
  in the root-owned directory `D=$(mktemp -d)` made above, under absolute
  paths, runs each printed command on that path (root only connects to
  the signer's agent socket), runs retire-key again and removes `$D`
  once it exits 0:

  ```
  printf '%s\n' '<the public key line retire-key printed>' >"$D/retire-user-g1"
  SSH_AUTH_SOCK=<socket> ssh-add -d "$D/retire-user-g1"
  printf '%s\n' '<the certificate line retire-key printed, if any>' >"$D/retire-user-g1-cert.pub"
  SSH_AUTH_SOCK=<socket> ssh-add -d "$D/retire-user-g1-cert.pub"
  runuser -u keyroster-signer -g keyroster-signer -G tss -- keyroster-signer ca-rotate retire-key --state-dir "$S" --role user && rm -rf -- "$D"
  ```

  With a PKCS#11 provider behind the agent (custody `pkcs11-agent`), the
  old key object must also be deleted from the token, or the next
  provider load adds it to the agent again and `serve` refuses again
  (UNVERIFIED: no PKCS#11 token has been rotated).
- **tpm:** retire-key checks that a regular `tpm/user.tpmkey` holds the
  draining key, deletes it and `tpm/user.auth`, syncs the directory, and
  exits 0 as for software. A link, another entry or a lone auth file at a
  generation's name is removed unchecked, because no key at that name can
  be opened. A key file that holds another key, one that does not read as
  a TPM key, or a directory that is not empty stays, counts as held and is
  reported `not removed:`: inspect it, and delete both files as the
  signer's user
  (`runuser -u keyroster-signer -- rm -f "$S/tpm/user.tpmkey" "$S/tpm/user.auth"`)
  only once you know what it is, then run retire-key again, and start the
  signer only after exit 0. After a crash between the two deletions, run
  retire-key again, which finishes the removal. The deletion removes the
  key's wrapped blobs and destroys nothing inside the TPM: an earlier copy
  of both files still signs on the same TPM. It runs on swtpm only, and no
  YubiKey or physical TPM has run it.
- **piv:** retire-key checks that the recorded slot holds the draining
  key, overwrites it with a throwaway key (PIN once, touch never) on every
  firmware, and exits 0. It needs the management key, placed and shredded
  by the block of piv.md step 5, whose last line runs this retire-key.
  Run without the key at the stored path (outside the block, or with no
  key pasted), it reports `not removed:` naming `mgmt-key-file` (the one
  form of this refusal: the signer reads the key only when it writes to
  the card) and exits 1, and the signer stays stopped: run the block with
  the key, which starts the signer only after exit 0. The slot stays
  recorded and is never reused. That the overwrite destroys the old key
  is UNVERIFIED on a real card.

Start the signer only after retire-key exits 0. Then doctor, a fresh
export, and the audit with both roots pinned. First move
`/media/transfer/export.jsonl` aside under another name and keep it, as
signer-install.md asks you to keep every export: the block writes the
new export under the same name.

```
S=/var/lib/keyroster-signer
systemctl start keyroster-signer.service
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir "$S"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer export-log --state-dir "$S" --out /tmp/ca-switch.jsonl &&
runuser -u keyroster-signer -- cat /tmp/ca-switch.jsonl >/media/transfer/export.jsonl &&
runuser -u keyroster-signer -- rm -f /tmp/ca-switch.jsonl
keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> --installation-id <installation id> /media/transfer/export.jsonl
```

doctor prints no `draining_key_still_usable` line (on the piv backend the
`WARN draining_key_unchecked` line is still printed after retire-key,
because doctor does not read the card), and its `OK switch_floor` line
now names generation 2. The export is copied onto the medium at once, as
the signer's user, and its copy under `/tmp` is removed, as after
ceremony 1's install. This copy stays off the signer box: it is the
`--previous` of the next switch. From now on every certificate the
signer issues is signed by generation 2.

## The drain

The hosts trust both user CA keys until the old key's `trusted_until`.
Each agent drops the old key at that time by itself, on its own clock,
with no new bundle ([host-setup.md](host-setup.md), "CA rotation: what
the agent does"). A host that keyroster-agent does not manage needs its
`/etc/ssh/keyroster_user_ca.pub` replaced by hand with the output of
`keyroster host ca-key` after that time.

**The host-side proof**, after `trusted_until`: on a host, as root,
`keyroster-agent check` shows no `trust_expired` and no `bundle_behind`,
and the live `user_ca_keys` holds the generation-2 line without the old
key. Across the fleet, each heartbeat's `user_ca_keys` hash equals the
SHA-256 of `trust.UserCAKeysFile(B, now)` for B the switch bundle as the
verified audit export carries it, not the server's copy. This is
detection, not enforcement: a host that did not drop the key still
trusts it until its agent runs again.

## The host CA

The same steps switch the host role, with one more gate: ceremony 2 for
the host role waits until clients have refreshed. What differs for the
host role is below.

**Which clients.** The gate concerns every account whose ssh reads
keyroster's managed trust files for the enrolled hosts. `keyroster login`
and `keyroster known-hosts sync` write them into the `~/.ssh` of the
account they run as, and ssh reads them through the
`Include ~/.ssh/keyroster_ssh_config` line at top level of
`~/.ssh/config`, before its first Host or Match line
([enroll-user.md](enroll-user.md#trusting-hosts-without-tofu), item 1).
Such an account gains a host CA line only when it refreshes: a refresh
writes one `@cert-authority` line for each host CA the trust bundle
trusts at the client's clock, and narrowing never adds one. An account
that never had these files keeps its own configuration: keyroster
writes nothing that its ssh reads.

**The gate.** Install ceremony 2 for the host role no earlier than
ceremony 1's install plus the user profile's max TTL: the largest user
`max_ttl_seconds` of the policy in force at ceremony 1's install and of
every policy installed since (`--user-max-ttl` at genesis, 12 h by
default). By the end of the wait every user certificate issued before
ceremony 1's install under the policy then in force has expired; one
issued before the install under an earlier policy with a larger user
cap may still be valid; so a user whose only certificates were issued
before that install under the policy then in force needs a new one,
from a login or from an admin. The wait does not show that a login
refreshed. Before ceremony 2's install, every account whose ssh reads
the managed files has refreshed, a user who always passes
`--no-known-hosts` included. An account has refreshed when its managed
`~/.ssh/keyroster_known_hosts` holds the new host CA's line: the
`@cert-authority` line that ends `keyroster host CA generation <g>`, g
being the host generation that ceremony 1 added (its CA-change line
`CA host gen <g> SHA256:...: none -> next`). An account that runs ssh
from several computers has refreshed when the file on each of them
holds the line. The ways to refresh:

- A user refreshes with a `keyroster login` without
  `--no-known-hosts`, run as the account ssh runs as and on the computer
  it runs from. The file shows whether it wrote the line: the login
  succeeds whatever its host trust outcome, and one that ran with
  `--no-known-hosts` adds no host CA line: it only narrows the file
  (enroll-user.md, "Narrowing"). A user who always passes
  `--no-known-hosts` runs one `keyroster login` without it.
- An admin refreshes with `keyroster known-hosts sync`, which exits 0
  when it refreshed; the file, not the exit, shows the new line. It
  needs an admin key from the root-signed policy, loaded in ssh-agent.
- An account that has the managed files and neither a login of its own
  nor an admin key (an automation account, or a host that ssh connects
  onward from) is refreshed only by an admin who runs
  `keyroster known-hosts sync` as that account after ceremony 1's
  install and before ceremony 2's install, and who then checks that
  account's file for the line. If nobody does, it is a client that
  never refreshes. That sync signs with the admin key through the
  ssh-agent the account reaches (its fingerprint given with
  `--admin-key`), so for as long as the account reaches that agent
  every one of its processes can ask it to sign as the admin: run the
  sync while nothing else runs as that account, and end the agent's
  reach right after. (UNVERIFIED: no test runs sync for another
  account.)

Whichever way, the line is the check. A login or a sync writes the
host CAs of the trust bundle the server gave it when it started, and
for a short time after ceremony 1's install the server can still give
the earlier bundle, so a refresh that wrote only the old line is
repeated until the file holds the new one.

No tool counts the clients that have refreshed, and none holds the
switch of the host role back: `root sign` and the install check a host
switch as they check any other, so the gate is the operator's.

**The hosts before the switch.** "Wait for the hosts" counts each
host's `user_ca_keys` file, which a bundle that changes only the host
role leaves as it is. For the host role read instead the line
`bundle v<N> on <X>/<M> hosts` of `keyroster host status`: before
ceremony 2 it reads M/M, with N the server's current bundle, ceremony
1's or a later one that still lists the new host CA (a bundle installed
in between still lists it when its ceremony printed no `CA host` line
in the CA-change section, as `root sign` and `keyroster trust verify`
print it), and a host removed from the directory stays in M until
`keyroster host forget`. A host that has not taken a bundle that
names the new host CA refuses the certificate the signer issues it
after the switch (`answer_unpinned_ca`; Run in CI: `TestVerifyAnswer`,
its `unpinned_ca` case, and
`TestHostCertStep/hostcert_answer_drained_ca_refused`, an answer by a
host CA outside the agent's trusted set; UNVERIFIED end to end) and
asks again after a back-off of 60 s up to an hour (Run in CI:
`TestDecide/backoff_schedule`). It keeps the certificate it has
(UNVERIFIED: no test shows a kept certificate surviving that refusal).
So it stays on its old certificate until it takes that bundle or the
old certificate runs out, after which clients refuse it.

**The switch.** For the host role the floor of "Ceremony 2" uses the
host profile's `max_ttl_seconds` (720 h by default), not the user one:
the old host CA is trusted until the ceremony's issued_at plus the
larger host `max_ttl_seconds` of the two policies, plus 300 s, plus the
allowance.

**What the hosts do.** After the switch each host whose certificate
keyroster-agent renews keeps serving its certificate by the old host CA
and moves to the new host CA when that certificate is next replaced:
normally at its own next renewal, at two thirds of its certificate's
lifetime, up to an hour early, unless the agent replaces it earlier
because it is missing or near its end, the host's principals in the
directory changed, its CA is no longer trusted, or the KRL revokes it.
A certificate the agent obtains lives the smaller of 30 days and the
host cap, so at the default cap of 720 h such a host renews about 20
days after its own last certificate, host by host: at most about 20
days after the switch, and for many hosts sooner. A host that
keyroster-agent does not manage, whose certificate an admin issued with
`keyroster ca issue --ca host`, keeps that certificate for as long as
its `--ttl`, up to the host cap, and moves to the new host CA only when
an admin issues it a new one after the switch (UNVERIFIED: no test
issues a host certificate by hand across a host-CA switch).

**What a client meets.** A client whose managed file holds the new host
CA's line holds both host CA lines and accepts either certificate,
before and after each host's move. A client whose managed file has not
been refreshed since before ceremony 1's install holds only the old host
CA's line: it reaches each host until that host moves, and refuses it
with `Host key verification failed` from then on, possibly weeks after
the switch, until it refreshes. Watching for failures right after the
switch shows little, because most hosts move only at their renewals. A
client whose managed `keyroster_known_hosts` is never rewritten by a
full refresh cannot be rotated safely.

**The drain.** No file that sshd reads lists a host CA key. The old host
CA drains in the agents and on the clients: each agent stops accepting
answers signed by it at its `trusted_until` (an agent's answer set is
the host CAs the bundle trusts at the agent's clock), and every
keyroster command that verifies the trust bundle removes its line from
`keyroster_known_hosts` once its `trusted_until` has passed on the
client's clock (enroll-user.md, "Narrowing"). For the host role the
guarantee of "What this guarantees and what it does not" reads against
the clients: every certificate the signer issued with the old host CA
key and the verified log records expires at least 300 s before that
key's `trusted_until`, the earliest moment a client stops trusting it.

Run in CI: `TestHostCARotation` (the `e2e-rotation` job, OpenSSH 9.5p1
and 10.5p1, one host at a host cap of 90 s and two clients on
loopback). The test waits for the host's heartbeat to report ceremony
1's bundle before the switch. A client whose managed file holds both
host CA lines after a sync the test checks line by line reaches the
host by the old host CA's certificate right after the
switch and by the new one's after the host's renewal; in between the
host asks for no certificate, installs no other and its agent refuses
no answer; a client that did not refresh reaches it
right after the switch, is refused with `Host key verification failed`
after the renewal, and reaches it again once its known_hosts file holds
the lines a fresh refresh writes. The test does not wait the gate's
time and does not wait for the host drain. UNVERIFIED: the host drain's
end on a real host and client (unit-tested only), a real fleet, a
client on Windows, clients older than OpenSSH 8.5, real clients that
never refresh, and a sync run for another account.

## What this guarantees and what it does not

The guarantee, scoped: every certificate the signer issued with the old
key and the verified log records, revoked or not, expires at least 300 s
before the hosts stop trusting that key, and once retire-key has exited 0
the signer can no longer issue with it. The root holders read, before
they sign, which key stops being active, when its trust ends and the
advised install time.

The residuals, which the signer and audit do not cover:

- a certificate signed with the old key outside the signer;
- a certificate issued after the export that `--previous` names, in a
  log that was then rolled back to that export's point: the rolled-back
  log still extends the export, and the install's binding reads only the
  certificates the verified log records, so it never sees that
  certificate;
- a later recovery that carries a long-lived certificate;
- consumers that do not re-evaluate a certificate after its CA drains;
- KRL entries with no ValidBefore;
- a revoked certificate that still sets the maximum (the remedy is to
  wait);
- copies of the state directory and of a key file taken before
  retire-key, and the bytes of a deleted key file on an SSD or a
  copy-on-write filesystem;
- an earlier copy of a TPM generation's `.tpmkey` and `.auth` files (a VM
  snapshot, a hypervisor backup that holds the vTPM state, a hand copy of
  the state directory), which still signs on the same TPM after
  retire-key deleted the files, because the deletion destroys nothing
  inside the TPM;
- the old private key in a PIV slot that retire-key overwrote with a
  throwaway key: that the overwrite destroys it is Yubico's documented
  behaviour, UNVERIFIED on a card;
- a restored pre-switch database that is served while its backend holds
  the old key again, and a `--previous` that is an export of the restored
  log itself; both are covered by signer-install.md "Restore from before
  the last switch", by the runbook and not by the signer.

An emergency retire, the only early end of a draining key, is 03-13's.

## Run in CI

`TestSwitchTracer`, `TestDrainBinding`, `TestRetireKey`,
`TestRootSignSwitchFlags` and `TestCARotationNoFailedLogin` (the
`e2e-rotation` job, OpenSSH 9.5p1 and 10.5p1: a certificate login every
second through prepare, ceremony 1, the switch, the removal of the old
key, the drain and the host's drop), `TestHostCARotation` (the same
job: what the host CA's gate prevents, a client that refreshed and one
that did not across the host's renewal), with `TestCANextAndAbort`,
`TestRootSignSuccessor`, `TestCeremonyGolden` and
`TestRootCeremonyPolicyChecks`. The TPM and PIV backends: the `tpm` leg of
`TestSignerRestartMixedBundle` and `TestTPMCARotation` (the `e2e-tpm`
job, on swtpm), the `piv` leg of `TestSignerRestartMixedBundle` (the
`build-piv` job, on the fake card), and the backends' unit tests
(`TestTPMGenerationFiles`, `TestTPMKeyAtExact`, `TestTPMHolds` and
`TestTPMRemoveGeneration` in `e2e-tpm`; `TestPIVGenerationAllocator`,
`TestPIVHolds`, `TestPIVRemoveGeneration` and
`TestPIVManagementKeyAtUse` in `build-piv`). UNVERIFIED: the drain on
real hosts of a fleet, the machine CA, the host drain's end on a real
host and client (unit-tested only), every physical TPM, the homelab
vTPM signer, every YubiKey, and every homelab signer; a real client run
is 03-16's.

CI runs the TPM path on swtpm over a Unix socket (custody `vtpm`) and the
PIV path on an in-memory fake card. Real hardware is not exercised. In
particular:

- **TPM:** `/dev/tpmrm0` and a physical TPM (custody `tpm`), their key
  creation, noDA against a physical TPM's dictionary-attack counter, and
  that the kernel's resource manager leaves no handle loaded
  (go-tpm-keyfiles' `FlushHandle` ignores errors). The homelab's vTPM
  signer has not rotated: the homelab signer's first rotation runs its
  first prepare and its first retire-key. Removing a generation's
  `.tpmkey` and `.auth` files deletes the key's wrapped blobs; it
  destroys nothing inside the TPM. Any earlier copy of both files still
  signs on the same TPM until its owner hierarchy is cleared: a VM
  snapshot, a hypervisor backup that holds the vTPM state, a hand copy of
  the state directory, and unerased blocks on an SSD or a copy-on-write
  filesystem.
- **PIV, on every YubiKey:** generating into 0x87 to 0x95; reading a
  slot's metadata when it is empty, overwritten or never used; that an
  overwrite is atomic and destroys the old private key (Yubico's
  documented behaviour, not observed here); signing from a generation
  slot after a reopen in a separate process; the algorithm per firmware
  for generations; PIN once across processes; the card's answer to a
  wrong management key; every `ykman` command this runbook names,
  `ykman piv keys delete <slot>` and `ykman piv reset` included; and the
  15-slot exhaustion on a real card, which CI checks on the fake card
  only. Deletion on firmware 5.7 and later is not implemented: the pinned
  piv-go v2.6.0 has no delete command, so retire-key overwrites on every
  firmware.
- **A key in a generation slot that no generation row records stops PIV
  rotation**, as "1. Prepare the next key" says, until the slot is
  emptied when the rule of piv.md "Generation slots" allows it.
- **The management key file is shredded, not proven erased.** `shred`
  does not reliably erase a file on an SSD or a copy-on-write
  filesystem.
- **The location column is not logged.** A database edit of a PIV
  generation's location is stopped by the fingerprint checks before any
  card write, but an edit that points at any slot that does not hold the
  draining key makes the signer's check answer "not held", and audit
  cannot show which slot a generation used.

## What changes for nobody

Neither ceremony changes a root or the installation ID, so no CLI pin
changes, and the clients keep their configuration as it is. A user's
next login fetches a certificate signed by the new key; a certificate
issued before the switch keeps working until it expires, because the
hosts trust the old key until its end. A switch of the host role needs
no configuration change either, but a client must have refreshed
first, as "The host CA" says.
