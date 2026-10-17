# Runbook: offline root ceremony

This runbook creates keyroster's trust root and signs the genesis trust
bundle and policy. One admin can run it alone. Every host and signer trusts
the CA keys only because the root keys signed them, so the root keys never
touch a networked machine.

There are two variants:

- **Software roots (homelab, D-10).** Two independent Ed25519 root keys,
  each in an age-encrypted file on its own USB stick, each with its own
  passphrase. Root threshold 1-of-2: a bundle signed by either root is
  accepted.
- **Hardware roots (product path, D-11).** FIDO2 (`ed25519-sk`) or PIV keys
  that never leave their tokens, reached through an offline `ssh-agent`. See
  [Hardware-root variant](#hardware-root-variant).

> **The software root is a deliberate homelab deviation.** Success criterion 2
> asks for M-of-N *hardware* root keys. The homelab uses two software keys
> with a 1-of-2 threshold instead (D-10). This is the same M-of-N model as
> the hardware path (independent keys plus a threshold), so moving to
> YubiKeys later means a new ceremony and a re-signed bundle, not a format
> change. The deviation is visible everywhere: `keyroster root init` and
> `keyroster root sign` print a `SOFTWARE ROOT:` banner, the `.pub` file,
> `roots.pub`, the bundle and every ceremony summary label the key
> `custody=software`, and `keyroster-signer doctor` prints `WARN software_root` for a
> software-held root (D-11).

## What you need

- A **ceremony machine**: any x86-64 computer you can boot from USB. Its
  disk is not used.
- A **live USB** with a Debian or Ubuntu live image, without persistence.
- **USB A** and **USB B**: two sticks for the two root keys (software
  variant). Label them.
- A **transfer USB** for public documents only: `ca-pubkeys.json`,
  `policy.json`, `roots.pub`, the bundle, the policy and their signatures.
- A **second machine** with Go to cross-check the `keyroster` binary.
- Paper and pen for fingerprints, and the transcript template
  ([ceremony-transcript-template.md](ceremony-transcript-template.md)).
- Two passphrases of at least 20 characters (for example six or more
  diceware words), one per root. `keyroster root init` refuses shorter
  ones.

Never type a passphrase on the command line or put it in an environment
variable. keyroster reads it only from the terminal (with echo off) or from
an inherited file descriptor (`--passphrase-fd`, meant for automation and
tests).

## 1. Prepare the binary and the ceremony machine

1. On your normal machine, check out the `main` commit you will use and
   record its hash in the transcript. Build the CLI with a clean tree:

   ```
   git rev-parse HEAD
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o keyroster ./cmd/keyroster
   sha256sum keyroster
   ```

2. On the **second machine**, check out the same commit, run the same build
   and compare the SHA-256. Go builds are reproducible, so the two hashes
   must be identical. If they differ, stop and find out why. Record the hash
   in the transcript.
3. Copy `keyroster` to the transfer USB.
4. Boot the ceremony machine from the live USB. Unplug the network cable.
   Disable wireless before doing anything else:

   ```
   sudo rfkill block all
   sudo nmcli networking off    # if NetworkManager runs
   ip -br link
   ip -br addr
   ```

   `ip -br link` must show **only `lo`** as up (state `UNKNOWN` or `UP`);
   every other interface must be `DOWN`. `ip -br addr` must show only
   `127.0.0.1/8` and `::1/128`. If any other interface is up, stop: find
   the cause, or use a different machine.
5. Mount the transfer USB, copy `keyroster` to `/tmp` (RAM on a live
   system), and check its hash against the transcript:

   ```
   cp /media/transfer/keyroster /tmp/keyroster && chmod +x /tmp/keyroster
   sha256sum /tmp/keyroster
   ```

   `/media/transfer`, `/media/usbA` and `/media/usbB` in this runbook stand
   for wherever the sticks are mounted. A live desktop session usually
   mounts them under `/media/<user>/<LABEL>`;
   `lsblk -o NAME,LABEL,MOUNTPOINT` shows the actual mount points.

## 2. Prepare the CA public keys and the genesis policy (signer host)

On the signer host, which has a network but no root key (the
`keyroster-signer ca-init` and `install-bundle` commands arrive with plan
01-07):

1. Initialise the CA keys. `ca-init` creates (or selects) the user, host,
   machine, ops and log keys in the signer's keystore and writes their
   public keys, algorithms and custody to `ca-pubkeys.json`:

   ```
   keyroster-signer ca-init --state-dir /var/lib/keyroster-signer --backend <backend> --out /media/transfer/ca-pubkeys.json
   ```

2. Write the genesis policy. Each `--admin` names an admin's SSH public key
   whose signature may authorize issuance. An admin key must not be a root
   key: a root only signs bundles and policies, so `root sign`,
   `trust verify` and `install-bundle` refuse a policy that lists a root as
   an admin.

   ```
   keyroster root genesis-policy --admin alice=alice.pub --out /media/transfer/policy.json
   ```

3. Record the SHA-256 of `ca-pubkeys.json` and `policy.json` in the
   transcript, then move the transfer USB to the ceremony machine.

## 3. Generate the two software roots (offline)

On the ceremony machine, with only USB A and the transfer USB inserted:

```
/tmp/keyroster root init --out /media/usbA/root-a.age
```

`root init` asks for passphrase A twice, refuses passphrases shorter than 20
characters, and refuses to overwrite an existing `root-a.age` or
`root-a.age.pub`. It writes:

- `root-a.age`: the Ed25519 private key in OpenSSH format, encrypted with
  age (scrypt passphrase recipient, work factor 2^18), armored, mode 0600.
- `root-a.age.pub`: the public key with the comment `custody=software`.

It prints the `SOFTWARE ROOT:` banner and the key's `SHA256:` fingerprint.
**Write the fingerprint on paper** next to "root A".

Unmount and remove USB A. Insert USB B and repeat with a **different**
passphrase:

```
/tmp/keyroster root init --out /media/usbB/root-b.age
```

Write fingerprint B on paper. Then build `roots.pub` from the two public key
files:

```
cat /media/usbA/root-a.age.pub /media/usbB/root-b.age.pub > /media/transfer/roots.pub
```

(Insert USB A again for this, or copy `root-a.age.pub` to the transfer USB
before removing USB A. The `.pub` files are public.)

## 4. Sign with root A, then with root B (offline)

Insert USB A. Sign the bundle and the policy with threshold 1:

```
/tmp/keyroster root sign \
  --ca-pubkeys /media/transfer/ca-pubkeys.json \
  --policy /media/transfer/policy.json \
  --roots /media/transfer/roots.pub \
  --threshold 1 \
  --out-dir /media/transfer/ceremony \
  --key /media/usbA/root-a.age
```

`root sign`:

1. asks for passphrase A and decrypts the key in memory only;
2. refuses if `roots.pub` does not declare this root `custody=software`;
3. prints a summary of what the signature vouches for: every root, CA, ops
   and log key with fingerprint, role, algorithm and custody, the
   threshold, the admins and CA profiles, and the bundle SHA-256;
4. asks you to type the first 8 hex digits of the bundle SHA-256.

Before typing, compare **both root fingerprints in the summary with the
paper**, and the CA fingerprints with `ca-init`'s output. Then type the hash
prefix. `root sign` prints the `SOFTWARE ROOT:` banner and appends the
signatures to `bundle.json.sigs` and `policy.json.sigs`. If it stops after
writing only one of them, run the same command again: it signs only the
document this root has not signed yet. Do not edit `.sigs` files by hand.

Remove USB A, insert USB B and run the same command with
`--key /media/usbB/root-b.age` and the same `--out-dir`. `root sign` refuses
if the bundle in `--out-dir` does not match the inputs, so both roots sign
exactly the same bundle. One signature is enough for threshold 1, but
signing with root B now proves that USB B and passphrase B work, before an
emergency depends on them.

## 5. Verify offline and copy the results

```
/tmp/keyroster trust verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
  --bundle /media/transfer/ceremony/bundle.json --policy /media/transfer/ceremony/policy.json
```

It lists each root that signed both documents as `signed by root ...`, and
any root that signed only one as `root ... signed the bundle only` or
`... the policy only`. It must end with

```
OK: 2 of 2 pinned roots signed both documents (bundle 2, policy 2, threshold 1)
```

Record that line and the SHA-256 of `bundle.json` and `policy.json` in the
transcript.

The transfer USB now holds `roots.pub`, `ceremony/bundle.json`,
`ceremony/bundle.json.sigs`, `ceremony/policy.json` and
`ceremony/policy.json.sigs`: public documents only. Check that no `.age`
file is on it:

```
find /media/transfer -name '*.age'
```

must print nothing.

## 6. Install the bundle on the signer host

Move the transfer USB to the signer host and install the bundle, pinning the
root fingerprints **from the paper**, not from a file on the USB:

```
keyroster-signer install-bundle --state-dir /var/lib/keyroster-signer \
  --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
  --bundle /media/transfer/ceremony/bundle.json --policy /media/transfer/ceremony/policy.json
```

The signer verifies the bundle and policy against the pins and logs the
install as its first audit entry. Record the install time in the transcript.

## 7. Store and shut down

- Store USB A and USB B in **two different places**.
- Store passphrase A and passphrase B **separately from the sticks** and
  from each other (for example in two sealed envelopes or two password
  managers). Never write a passphrase on a stick.
- Shut down the ceremony machine. The live system has no persistence, so
  the decrypted keys and `/tmp/keyroster` are gone. **Never connect the
  ceremony machine to a network** during the ceremony, and do not reuse its
  live session afterwards.
- Keep the filled-in transcript with your own records, away from the
  sticks. Do not commit it: it says where the root media and passphrases
  are kept. The public results (root fingerprints, bundle and policy
  SHA-256) are in the signed bundle and the signer's audit log anyway.

## Rotate the roots (successor bundle)

A rotation replaces the root set with a **successor bundle**: version N+1
of the bundle in force, naming the new roots. Rotate when you:

- replace TEST roots, or any roots that may be exposed, with roots from an
  offline ceremony;
- retire a lost or compromised root;
- move from software roots to hardware roots.

**The rule.** The signer, `trust verify --prev` and `audit verify` all
apply the same rule (`trust.VerifySuccessor`):

- the successor is version N+1, and its `prev` is the SHA-256 of the bundle
  in force;
- a threshold of the **current** roots AND a threshold of the **new** roots
  must sign both the bundle and the policy. The two are counted
  independently, and a root in both sets counts toward both. A freshly
  listed new root cannot rotate trust without the current roots'
  threshold. **At threshold 1, though, any single current root can:** one
  stolen current root and a key the thief creates meet both thresholds.
  `root sign --prev` prints a warning when the bundle in force has root
  threshold 1;
- the CA, ops and log keys are carried over unchanged (CA rotation comes in
  Phase 3);
- the policy is carried over unchanged, or advanced by exactly one version
  chained to the policy in force;
- no policy admin is a root, new or retired. `root sign --prev` and
  `trust verify --prev` hold only the bundle in force, so they check the
  new roots and the current ones. `install-bundle`, `serve`, `doctor` and
  `audit verify` hold every earlier bundle and also refuse a root that an
  earlier rotation retired. Never list a retired root key as an admin.

### What you need

- Everything from [What you need](#what-you-need), with one USB stick per
  new root.
- The `bundle.json` and `policy.json` in force **and their `.sigs` files**,
  copied to `/media/transfer/prev`. The ceremony directory they came from
  holds all four: `ceremony/` for the genesis bundle (step 5), `rotation/`
  for an earlier rotation.
- The SHA-256 of that `bundle.json` **from the transcript**, as recorded in
  [step 5](#5-verify-offline-and-copy-the-results) or in step 5 of the
  previous rotation. Never take it from `sha256sum` of the copy in
  `/media/transfer/prev`: that only checks the copy against itself.
  `root sign --prev` and `trust verify --prev` take it as `--prev-sha256`
  and refuse a `bundle.json` with any other hash before anything is
  written or reported. They also refuse a `bundle.json` or `policy.json`
  that its own roots' threshold has not signed. That second check cannot
  tell a forged root set from the real one; only the recorded hash can.
- The current roots, or enough of them to meet the current threshold.

### Steps

1. **Prepare.** Do [step 1](#1-prepare-the-binary-and-the-ceremony-machine),
   then run `date -u`. If the clock is earlier than the `issued_at` of the
   bundle in force, or clearly wrong, set it before signing:
   `root sign --prev` refuses a clock earlier than the previous bundle's.
2. **Generate the new roots offline**, as in
   [step 3](#3-generate-the-two-software-roots-offline), one stick per root
   and **each fingerprint on paper**:

   ```
   /tmp/keyroster root init --out /media/usbC/root-c.age
   /tmp/keyroster root init --out /media/usbD/root-d.age
   cat /media/usbC/root-c.age.pub /media/usbD/root-d.age.pub > /media/transfer/new-roots.pub
   ```

3. **Build the successor and sign it with a new root:**

   ```
   /tmp/keyroster root sign --prev /media/transfer/prev \
     --prev-sha256 <SHA-256 of the bundle in force, from the transcript> \
     --roots /media/transfer/new-roots.pub --threshold 1 \
     --policy /media/transfer/prev/policy.json \
     --out-dir /media/transfer/rotation \
     --key /media/usbC/root-c.age
   ```

   It refuses, and writes nothing, if `prev/bundle.json` does not have
   exactly that SHA-256. Before you type the hash prefix, compare:
   - the `Successor of trust bundle vN, sha256 ...` line with the
     transcript once more;
   - the new root fingerprints with the paper;
   - the CA, ops and log fingerprints with the previous ceremony;
   - the policy hash.

   The summary also prints `signatures needed: t1 of the n previous roots
   AND t2 of the m new roots, on both documents`. Then repeat the command
   with `--key /media/usbD/root-d.age` and the same `--out-dir`.
4. **Sign with a current root.** Run the same command with the current
   root's key and the same `--out-dir`. Use `--key` for a software root, or
   `--agent-key SHA256:<fingerprint>` for a root in an `ssh-agent`.
   - A current root that is still offline signs offline, in the same way.
   - A current root that is already treated as exposed signs where it is
     kept, and is never brought to the ceremony machine. An example is the
     homelab TEST roots of plan 01-14, which were created on a networked
     machine. Its signature only authorizes the hand-over, so it adds
     nothing an attacker does not already have. The trust rests on the new
     roots' signatures, on the paper check in step 5, and on the recorded
     SHA-256 in `--prev-sha256`: the holder of an exposed root can sign a
     forged bundle in force as easily as the real one, so only that hash
     shows that the new roots sign a successor of the real one.
5. **Verify against the paper:**

   ```
   /tmp/keyroster trust verify --prev /media/transfer/prev \
     --prev-sha256 <SHA-256 of the bundle in force, from the transcript> \
     --pin SHA256:<new root C from paper> --pin SHA256:<new root D from paper> --threshold 1 \
     --bundle /media/transfer/rotation/bundle.json --policy /media/transfer/rotation/policy.json
   ```

   It lists the signers as `signed by previous root ...` and
   `signed by new root ...`. It refuses unless `prev/bundle.json` has the
   recorded SHA-256 and its own roots' signatures, both thresholds are met,
   and the new root set is exactly the pinned fingerprints. It must end with an
   `OK: successor of trust bundle v1: ...` line. In the homelab shape (two
   current roots at threshold 1, one of which signed, and both new roots
   signed) that line reads:

   ```
   OK: successor of trust bundle v1: previous roots 1 of 2 signed both documents (threshold 1); new roots 2 of 2 signed both documents (threshold 1, pinned)
   ```

   Record that line and the SHA-256 of `rotation/bundle.json`.
6. **Install** with the signer stopped, as in
   [signer-install.md, "Install a successor bundle"](signer-install.md#install-a-successor-bundle-stop-install-start).
   A successor takes no `--pin`: `install-bundle` checks it against the
   installed bundle. Compare the SHA-256 that `install-bundle` prints with
   the one you recorded in step 5.
7. **Audit.** Export the log and verify it pinned to the **new** roots from
   the paper:

   ```
   keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/log.jsonl
   keyroster audit verify --pin SHA256:<new root C from paper> --pin SHA256:<new root D from paper> --threshold 1 /tmp/log.jsonl
   ```

   It must print `anchored: the pinned roots are the root set of trust
   bundle v2`. The pins name the root set of one bundle in the log (the
   anchor). Every bundle before the anchor is authenticated by the prev-hash
   chain, and every bundle after it by the successor rule.

   **After a rotation away from exposed roots, auditors pin the NEW roots.**
   Pins of the old roots still verify the real log (anchored on v1). But
   they would also verify any forked log that the old roots could sign,
   because the old roots are the anchor of such a fork. Pins of the new
   roots refuse that fork with "not anchored in the pinned roots": no
   bundle in it has the new root set.
8. **Retire the old roots.** Once steps 6 and 7 pass, destroy every copy of
   the old root keys and their passphrases. The signer then accepts a
   further successor only with the new roots' signatures. The old roots'
   public fingerprints stay usable as audit pins.

Steps 1 to 8 use only commands that `TestRootRotationLiveSigner` (e2e, real
binaries, real sshd) and the unit tests run: `root init`, `root sign --prev`
with `--key` and `--agent-key`, `trust verify --prev`, `install-bundle`
without `--pin`, `export-log`, and `audit verify` pinned to the new roots,
to the old root, and to a set that matches no bundle. The refusals and the
audit anchoring are covered there too. The tests pass passphrases with
`--passphrase-fd` and the hash prefix with `--confirm`; at a ceremony,
type them at the prompts.

> **Steps 6 and 8 run on the homelab, with TEST roots; the offline steps are UNVERIFIED.**
> Plan 01-20 ran step 6 (stop, `install-bundle` without `--pin`, start) on
> the homelab vTPM signer. This was a rehearsal rotation from the 01-14 TEST
> roots onto two new TEST roots, C and D. In that rehearsal, steps 1 to 5
> ran in WSL on a networked workstation, each `keyroster` command under
> `unshare -r -n`. Directories stood in for the USB sticks, and the
> fingerprints printed by `root init` stood in for paper. The live USB, the
> separate physical sticks, the paper fingerprints and an offline machine
> therefore remain **UNVERIFIED**, and so does step 7 as written (pins from
> paper). The owner's real offline ceremony runs them in a later rotation.
> `--prev-sha256` was added after that rehearsal, which checked the bundle
> in force by comparing hashes by hand. The flag is exercised only by
> tests: `TestRootRotationLiveSigner` (real binaries) runs the accepted
> path and the wrong-hash refusal of both commands; the in-process unit
> tests also cover a foreign prev, a missing flag and a prev without its
> own roots' signatures.
>
> Plan 01-21 ran step 8 for TEST roots A and B only, which were held on a
> networked workstation: their WSL copies were removed with `shred -u` and
> checked, and the owner attested that no other copy exists. This is not a
> guaranteed erase, so A and B stay treated as exposed. Destroying roots
> held on offline media, like the offline steps, remains **UNVERIFIED** until
> the owner's real offline ceremony.

## Change the policy: successor policy (for example, add the WebAuthn RP)

The policy is root-signed, so changing it means a **successor bundle**
with the same roots, CAs, ops key and log key, and a successor policy:
version N+1 whose `prev` is the SHA-256 of the policy in force. The
signer, `trust verify --prev` and `audit verify` apply the same rule as
for a rotation (`trust.VerifySuccessor`).

In Phase 2 the only field you can change this way is the **WebAuthn
relying party** (`rp_id` and its origins), which passkey logins need.
`keyroster root successor-policy` carries every other field over
unchanged: admins, admin quorum, CA profiles and timelock. A quorum-gated
policy change for those fields comes in Phase 4 (AUTHZ-03).

> **`rp_id` is a one-way setting.** Every passkey enrolled under it works
> only for that exact hostname. Renaming the host or changing `rp_id`
> later makes every enrolled passkey unusable, and every user must enrol
> again. Choose the hostname users will reach keyroster under for good,
> not an IP address or a tailnet domain (both are refused).

You need everything from [What you need](#what-you-need), plus:

- the `bundle.json` and `policy.json` in force and their `.sigs` files,
  copied to `/media/transfer/prev` (as for a rotation);
- the SHA-256 of that `bundle.json` from the transcript;
- the `roots.pub` of the bundle in force (the roots do not change), and
  enough of those roots to meet its threshold.

0. **Prepare.** Do [step 1](#1-prepare-the-binary-and-the-ceremony-machine)
   first: build the binary and compare its SHA-256 with a second machine's
   build, boot the live USB offline, and check that only `lo` is up. Then
   run `date -u`. If the clock is earlier than the `issued_at` of the
   bundle in force, or clearly wrong, set it before signing:
   `root sign --prev` refuses a clock earlier than the previous bundle's.
   Step 3 decrypts a root; never do that on a networked machine or with a
   binary whose hash you have not compared.
1. **Take the policy in force.** It is `/media/transfer/prev/policy.json`.
2. **Write the successor policy:**

   ```
   /tmp/keyroster root successor-policy --prev /media/transfer/prev/policy.json \
     --webauthn-rp-id keyroster.example.org --out /media/transfer/policy-next.json
   ```

   Add `--webauthn-origin https://keyroster.example.org:8443` (repeatable)
   when the login page is served on another port; the default origin is
   `https://<rp-id>`. It prints the old and the new `rp_id` and origins,
   the new policy's SHA-256 and, on stderr:

   ```
   WARNING: rp_id is a one-way setting. Every passkey enrolled under it works only for that exact hostname; renaming the host or changing rp_id makes every enrolled passkey unusable.
   ```

   It refuses, and writes nothing, when `--out` exists, when `--prev` is
   not a canonical policy, when the RP would not change, and when the RP
   is not valid (an IP address, a tailnet domain, an origin with a path).
   The output is not signed; nothing trusts it until step 3.
3. **Sign the successor bundle** with the roots in force, as in
   [Rotate the roots](#rotate-the-roots-successor-bundle) step 3, but with
   the **same** roots file and threshold and the new policy:

   ```
   /tmp/keyroster root sign --prev /media/transfer/prev \
     --prev-sha256 <SHA-256 of the bundle in force, from the transcript> \
     --roots /media/transfer/roots.pub --threshold 1 \
     --policy /media/transfer/policy-next.json \
     --out-dir /media/transfer/policy-change \
     --key /media/usbA/root-a.age
   ```

   Before you confirm, check two lines of the summary:

   - `webauthn rp_id <hostname>  origins [...]` must name exactly the
     hostname and origins you chose. `rp_id` is one-way, and this is the
     only place `root sign` shows it. Every root custodian who signs
     checks it, including one who did not see step 2's output.
   - `policy sha256:` must equal the **last** `sha256:` line of step 2's
     output, which is the new policy's hash. The first line of that output
     (`successor of policy vN, sha256 ...`) is the hash of the previous
     policy.

   A root in both the previous and the new root set counts toward both
   thresholds, so the roots' threshold of signatures is enough.
4. **Verify against the paper:**

   ```
   /tmp/keyroster trust verify --prev /media/transfer/prev \
     --prev-sha256 <SHA-256 of the bundle in force, from the transcript> \
     --pin SHA256:<root A from paper> --pin SHA256:<root B from paper> --threshold 1 \
     --bundle /media/transfer/policy-change/bundle.json \
     --policy /media/transfer/policy-change/policy.json
   ```

   It must end with `OK: successor of trust bundle vN: ...`, and its
   summary must show the same `webauthn rp_id ... origins [...]` line you
   checked in step 3.
5. **Install** with the signer stopped:
   [signer-install.md, "Install a successor bundle"](signer-install.md#install-a-successor-bundle-stop-install-start).
6. **Audit.** Export the log and run `keyroster audit verify` pinned to the
   roots in force (from paper), with the commands of
   [Rotate the roots](#rotate-the-roots-successor-bundle) step 7. The
   expected output differs from that step's:

   - The `OK:` line names the new trust bundle and policy versions
     (`trust bundle vN+1, policy vN+1`) and counts
     `login certificates N, directory installs N`.
   - The `anchored:` line names the bundle where the current roots
     **first** appeared, not the new bundle: a policy change keeps the
     roots. On an installation whose roots were never rotated it prints
     `anchored: the pinned roots are the root set of trust bundle v1`;
     after one rotation, the rotation's bundle version.

**The trust bundle version goes up by one.** A policy change is a new
trust bundle, so record its version and SHA-256 in the transcript like a
rotation's (KEY-07 bookkeeping): the next rotation or policy change chains
to it with `--prev-sha256`.

**A directory installed before the change stays in force** if the new
policy still authorizes it (its admins signed it and its roles fit the
user CA profile). Adding the RP changes neither, so logins work under the
existing directory right after the restart, and `audit verify` accepts
logins under it (`pol=N+1`, `dir` unchanged). The unit tests
`TestDirectoryRestart/restart_under_rp_only_policy` (signer) and
`TestVerifyLoginTampering/login_directory_survives_rp_policy_change`
(audit) run exactly that; the e2e test below installs its directory after
the change.

> **Compatibility: update every `audit verify` binary.** From this change
> on, the log can hold `directory_install` and `login_issue` entries, and
> an `audit verify` binary older than plan 02-04 refuses every log that
> holds one. A Phase 1 binary stops at the first `bundle_install` whose
> policy names the WebAuthn RP, which is this procedure's successor
> bundle, before it reaches any login:
>
> ```
> audit: entry N: bundle_install is not a valid successor of trust bundle vN-1: policy: trust: document is not canonical JSON: json: unknown field "webauthn"
> ```
>
> This error does not mean the bundle was tampered with: a Phase 1
> binary does not know the policy's `webauthn` field. Update the binary.
> Only a log whose `directory_install` comes before any policy with the RP
> gives `tlog: malformed leaf: unknown kind 7` from a Phase 1 binary. A
> binary built between plans 02-01 and 02-04 reports
> `audit: entry N (directory_install): not verifiable by this version`.
> None of them ever reports such a log as verified, so auditors must
> update before they can verify it. These three messages come from
> Phase 1 (`c526edf`) and 02-03 (`d6f53b3`) builds run on exports from
> the audit test fixture, in this procedure's order and with the
> directory first; they were not run on a real signer's export.

> **What has run.** `TestAuditLoginAcrossPolicyChange` (e2e, real
> binaries, real sshd, in CI) runs steps 2 to 6 on the agent backend, with
> a root in an `ssh-agent` (`--agent-key`) instead of `--key`, the hash
> prefix passed with `--confirm`, and directories instead of USB sticks:
> successor-policy adds the RP to a signer whose genesis policy has none,
> `root sign --prev` and `trust verify --prev` accept the successor, the
> signer is stopped, the bundle installed and the signer restarted, a
> directory is installed and a login certificate is issued under policy
> v2 that sshd accepts, and the exported log verifies with
> `login certificates 1, directory installs 1`. The successor-policy
> refusals are unit-tested (`TestRootSuccessorPolicy`). Running this
> procedure on the homelab signer, offline, from paper fingerprints, is
> **UNVERIFIED**; plan 02-13 does it.

## Hardware-root variant

For the product path (D-11), replace steps 3 and 4 with hardware keys. The
rest of the ceremony is unchanged.

**FIDO2 (`ed25519-sk`, custody `fido`).** On the ceremony machine, with
`libfido2` available, create one key per token:

```
ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:keyroster-root-a -f /tmp/root-a
```

The key is resident on the token, so a later ceremony recovers its handle
with `ssh-keygen -K` instead of keeping a handle file.

**PIV (custody `piv`).** Generate the key on the token (for example
`ykman piv keys generate` for slot 9c, Ed25519 on YubiKey firmware 5.7 or
later, otherwise P-256) and use the vendor's PKCS#11 module.

Then start an **offline** `ssh-agent` and load the keys:

```
eval "$(ssh-agent -s)"
ssh-add /tmp/root-a                          # FIDO2 key handle
ssh-add -s /usr/lib/x86_64-linux-gnu/libykcs11.so   # PIV through PKCS#11
ssh-add -l                                   # note the SHA256 fingerprints
```

Write `roots.pub` by hand with the matching custody:

```
sk-ssh-ed25519@openssh.com AAAA... custody=fido
ssh-ed25519 AAAA... custody=piv
```

and sign with each root through the agent instead of `--key`:

```
/tmp/keyroster root sign ... --threshold <M> --agent-key SHA256:<fingerprint>
```

Touch the token when it blinks. `custody=fido` is accepted only for `sk-*`
keys, and `sk-*` keys only as `custody=fido`. `root sign --agent-key`
reaches the agent through `SSH_AUTH_SOCK` (a Unix socket), so this variant
runs on Linux. No `SOFTWARE ROOT:` banner appears unless `roots.pub`
declares a root `custody=software`.
