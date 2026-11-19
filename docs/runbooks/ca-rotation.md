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
> `TestCARotationNoFailedLogin` for the whole rotation.

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
  keyroster-signer export-log --state-dir "$S" --out /tmp/ca-rotation.jsonl
keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> --installation-id <installation id> /tmp/ca-rotation.jsonl
```

`install-bundle` prints `installed bundle version <N>` and refuses a next
entry that is not a stored generation. doctor's `OK generations` line
lists the user CA `next g2` with the new fingerprint. The signer still
signs with generation 1. Keep the export off the box: it is the
`--previous` of ceremony 2's install, unless you take a newer one.

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
the software backend (`runuser -u keyroster-signer -- rm -f "$S/software/user-g2.age"`), or
remove it from the ssh-agent with `ssh-add -d` for the agent backend. The
generation row stays, and doctor does not warn. The generation number is
never reused: the next prepare makes generation 3.

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
`drain_window_too_short`. A host certificate that an admin issues has no
cap on its validity, so a long one can make the switch of the host role
wait. Then wait until it expires, or switch the other roles first. A revoked
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
  `install by unknown (advice: the allowance <a> is above the cap of 168h0m0s, so the signer refuses this switch)`.
  The signer's own upper bound on `trusted_until` is its install refusal
  `drain_window_too_long` (see "Install the switch").
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
of this log kept off the box, the export that ceremony 1's install block
took or a newer one taken right after the last install. The signer reads
its last line, from at most its last 1 MiB, and requires that this log
extends that checkpoint. Copy it to the medium as the signer's user, so
that root opens nothing the signer's account could have replaced by a
link:

```
runuser -u keyroster-signer -- cat /tmp/ca-rotation.jsonl >/media/transfer/export.jsonl
```

**The install**, on the signer, as the signer's user, before the
`install by` time. The copy under `set -C` refuses to overwrite, so the
export of an earlier switch and the files of an earlier successor are
removed first, and the chain keeps the install from running against a
stale or half-copied file. The signer is not started here: the old key
must leave the backend first (next section).

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
  this log; use the export-log file itself.
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
issued_at; the repeat uses a fresh directory.

## Remove the old key and restart

With the signer still stopped, the old key leaves the backend. Until it
has, `serve` refuses `draining_key_still_usable` and doctor reports
`FAIL draining_key_still_usable`. Run retire-key as the signer's user, in
the same pinned form as the install:

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
- **tpm and piv:** refused `rotation_not_supported_on_backend` until
  03-12f.

Start the signer only after retire-key exits 0. Then doctor, a fresh
export, and the audit with both roots pinned:

```
S=/var/lib/keyroster-signer
systemctl start keyroster-signer.service
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir "$S"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer export-log --state-dir "$S" --out /tmp/ca-switch.jsonl
keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold <N> --installation-id <installation id> /tmp/ca-switch.jsonl
```

doctor prints no `draining_key_still_usable` line, and its
`OK switch_floor` line now names generation 2. Keep the export off the
box: it is the `--previous` of the next switch. From now on every
certificate the signer issues is signed by generation 2.

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
the host role waits until clients have refreshed. A client gains a host
CA line only from `keyroster login` or `keyroster known-hosts sync`, so a
client that has not run either since ceremony 1 knows only the old host
CA and refuses the hosts' new host certificates after the switch
(UNVERIFIED until 03-12f's host-CA test).

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
key, the drain and the host's drop), with `TestCANextAndAbort`,
`TestRootSignSuccessor`, `TestCeremonyGolden` and
`TestRootCeremonyPolicyChecks`. UNVERIFIED: the drain on real hosts of a
fleet, the machine CA, the host CA end to end (03-12f), and every
homelab signer; a real client run is 03-16's.

## What changes for nobody

Neither ceremony changes a root or the installation ID, so no CLI pin
changes, and the clients keep their configuration as it is. A user's
next login fetches a certificate signed by the new key; a certificate
issued before the switch keeps working until it expires, because the
hosts trust the old key until its end.
