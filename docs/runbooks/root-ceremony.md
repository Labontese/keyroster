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
   whose signature may authorize issuance:

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
signatures to `bundle.json.sigs` and `policy.json.sigs`.

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

It must end with `OK: signed by 2 of 2 pinned roots (threshold 1)`. Record
the SHA-256 of `bundle.json` and `policy.json` in the transcript.

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
