# CA rotation: ceremony 1 and abort

This runbook adds a prepared CA key as `next` through a root ceremony, so
that every host trusts it beside the active key, and withdraws it again by
an abort (D-14, KEY-08, 03-12b).

> **UNVERIFIED on the homelab hosts and signer.** Each step that CI runs
> names its test. Run in CI: `TestCANextAndAbort` (the `e2e-rotation`
> job, against real sshd on OpenSSH 9.5p1 and 10.5p1), `TestRootSignSuccessor`,
> `TestCeremonyGolden` and `TestRootCeremonyPolicyChecks`.

## Scope

This runbook covers ceremony 1 and abort only, and there is no switch
yet: a `next` key is trusted by every host and used by nobody, because the
signer signs only with the active key, until it is aborted. This is not a
complete rotation until 03-12e adds the switch. Ceremony 1 changes no root
and no installation ID, so no CLI pin changes.

Every CA entry stays in every later bundle: an aborted key stays listed
as `retired`, its generation number is never used again, and the next
prepare makes the next generation.

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
directory and could replace either by a link, so a stale file there is
removed as the signer's user, and the successor files are written as the
signer's user from the medium:

```
systemctl stop keyroster-signer.service
S=/var/lib/keyroster-signer
runuser -u keyroster-signer -- rm -f "$S/incoming/bundle.json" "$S/incoming/bundle.json.sigs" \
  "$S/incoming/policy.json" "$S/incoming/policy.json.sigs"
for f in bundle.json bundle.json.sigs policy.json policy.json.sigs; do
  runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$S/incoming/$f" <"/media/transfer/succ/$f"
done
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer install-bundle --state-dir "$S" \
  --bundle "$S/incoming/bundle.json" --policy "$S/incoming/policy.json"
systemctl start keyroster-signer.service
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir "$S"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer export-log --state-dir "$S" --out /tmp/ca-rotation.jsonl
keyroster audit verify --installation-id <installation id> --threshold <N> \
  --pin SHA256:<A from paper> --pin SHA256:<B from paper> /tmp/ca-rotation.jsonl
```

`install-bundle` prints `installed bundle version <N>` and refuses a next
entry that is not a stored generation. doctor's `OK generations` line
lists the user CA `next g2` with the new fingerprint. The signer still
signs with generation 1.

## Wait for the hosts

Each agent adds the new line to its `user_ca_keys` after the widening
wait: about the sshd `LoginGraceTime` bound plus 30 s, 150 s at the
default of 120 s. On a host, the live `user_ca_keys` then holds both user
CA lines, and `keyroster-agent check` passes. The live count of hosts that
trust the key in `host status` arrives in 03-12d.

## Abort: withdraw the next CA key

Abort when the `next` key is wrong, its fingerprint was not the one read
aloud after all, or it may be compromised. Run the same ceremony on the
bundle in force (the one ceremony 1 installed) as `--prev`, with its
recorded SHA-256, and the abort flag instead of the two next flags:

```
keyroster root sign --prev /media/transfer/prev --prev-sha256 <recorded sha256> \
  --roots roots.pub --threshold <N> --policy /media/transfer/prev/policy.json \
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
refuse the key. Then destroy the aborted key by hand, because there is no
retire-key command yet (03-12e): delete `software/user-g2.age` in the
state directory as the signer's user for the software backend
(`runuser -u keyroster-signer -- rm -f "$S/software/user-g2.age"`), or
remove it from the ssh-agent with `ssh-add -d` for the agent backend. The
generation row stays, and doctor does not warn. The generation number is
never reused: the next prepare makes generation 3.

## What changes for nobody

No root and no installation ID changes, so no CLI pin changes, and the
clients keep their configuration as it is. `known_hosts` and logins behave
as before until 03-12d.
