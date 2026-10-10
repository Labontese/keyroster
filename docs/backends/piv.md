# YubiKey PIV backend

keyroster can keep its online keys (the user, host and machine CAs, the ops
key and the log key) in the PIV application of a YubiKey 5. The keys are
generated on the card and cannot be exported (KEY-05). The keystore backend
is `piv`, and its keys are recorded with custody `piv` in the signer's
state, in `ca-pubkeys.json`, in the root-signed trust bundle and in the
audit log's `ca_init` entry.

> **Not yet validated on a real YubiKey.** CI runs the backend against an
> in-memory fake card (see "What CI verifies" below). The code that talks to
> a real card, and every `ykman`, `pcscd` and polkit step on this page, has
> not been run on hardware yet. That validation is tracked in
> [docs/security/needs-hardware.md](../security/needs-hardware.md) for the
> Phase 6 review (D-12). Until then, treat this page as the intended
> procedure, not a tested one.

## Default binaries do not include PIV

The backend uses [piv-go](https://github.com/go-piv/piv-go) (v2.6.0), which
on Linux links the PC/SC library `libpcsclite` through cgo. keyroster's
default and release binaries are static and cgo-free (`CGO_ENABLED=0`), so
they do not contain the backend or piv-go. Build the signer yourself with
the `piv` build tag:

```
sudo apt-get install libpcsclite-dev     # Debian/Ubuntu: pcsc-lite headers
CGO_ENABLED=1 go build -tags piv -o keyroster-signer ./cmd/keyroster-signer
go version -m keyroster-signer | grep -E 'piv-go|CGO_ENABLED|-tags'
```

The last line should list `github.com/go-piv/piv-go/v2 v2.6.0`,
`-tags=piv` and `CGO_ENABLED=1`. `keyroster-signer ca-init --backend piv`
on a default binary fails with `unknown backend "piv"`.

## Requirements

- **A YubiKey 5 with firmware 5.3.0 or newer.** The backend reads each
  slot's public key and origin through the GET METADATA command, which
  firmware 5.3.0 introduced; older firmware is refused. `ykman info` shows
  the firmware version.
- **The algorithm follows the firmware (D-09).** Firmware 5.7.0 or newer gets
  Ed25519 keys; 5.3.0 to 5.6.x get ECDSA P-256 keys. `ca-init` prints the
  firmware and the algorithm.
- **`pcscd` running** on the signer host (`sudo apt-get install pcscd`).
- **Card access for the signer user only** (see step 2).
- One YubiKey per signer. If more than one is attached, name the one to use
  with `--backend-opt serial=NNNNNNN` (the serial printed by `ykman info`).

## Slots

The five keys use retired key-management slots, so the standard slots 9a,
9c, 9d and 9e stay free for other uses:

| Role | Slot |
|---|---|
| user | 0x82 |
| host | 0x83 |
| machine | 0x84 |
| ops | 0x85 |
| log | 0x86 |

`ca-init` refuses, and generates nothing, if any of these slots already
holds a key. It never overwrites a key.

## PIN policy once, touch policy never

The keys are generated with **PIN policy once** and **touch policy never**.
The signer is unattended: it signs whenever a request carries valid admin
evidence (D-13), and nobody is there to touch the card. The backend verifies
the PIN once, when it opens the card at signer start (and in `ca-init` and
`install-bundle`). With PIN policy once, the card then signs without the PIN
until the card is removed or the signer restarts.

**A wrong PIN stops the signer at start and uses up one PIN retry.** The
YubiKey blocks the PIN after three wrong attempts in a row (the default),
and only the PUK unblocks it; with the PUK blocked too, only a PIV reset
helps, and that destroys the CA keys. Verifying the PIN at start, rather
than at the first signature, means a wrong PIN never costs a retry per
signing request. Three guards keep a restart loop from blocking the PIN:

- Before it sends the PIN, the backend reads the card's PIN retry counter
  and refuses, without trying the PIN, when fewer than **2** retries are
  left. Automatic starts therefore never spend the last retry. An
  unreadable counter is a refusal too.
- A refused PIN, and the refusal to try one, end `keyroster-signer` with
  exit status **78**. The shipped unit sets `RestartPreventExitStatus=78`,
  so systemd does not restart it.
- For every other failure the unit waits `RestartSec=5s` between restarts
  and gives up after 5 starts in 10 minutes (`StartLimitBurst=`,
  `StartLimitIntervalSec=`).

After exit status 78: fix the PIN file and check the counter by hand
(`ykman piv info` shows the PIN tries left). With fewer than 2 left the
signer will not start even with the right PIN: enter the correct PIN once
by hand, with any `ykman piv` command that asks for it, to reset the counter
(which command is convenient for this has not been checked on a card yet;
needs-hardware item 2). Then start the service again. If the signer refused
because of the counter, it never sent the PIN, so the counter is still where
you found it. A card whose PIN retry limit was set below 2 (`ykman piv
access set-retries`) can therefore never start the signer.

What runs where: the counter check and the exit status are tested in CI
(fake card, `TestPIVPINRetriesGuard`; `TestCredentialRefusedExitStatus`),
and systemd's handling of the restart settings was checked with a transient
unit (exit 78 is not restarted, exit 1 is). **UNVERIFIED on a card:** that
piv-go's `Retries()` reads the counter of a real YubiKey in a fresh session
and that one wrong PIN lowers it by exactly one (needs-hardware item 2).

The trade-off: while the signer runs, any code that can talk to the card in
that session can sign without knowing the PIN. Two things limit that. piv-go
keeps a PC/SC transaction open on the card for as long as the signer has it
open, so other processes cannot use the card meanwhile (this follows from
piv-go's source and is not yet checked on hardware). And the signer refuses
to sign without evidence, and logs everything it signs. The card stops the
key from being copied; it does not stop a signer host that an attacker
controls from signing (see [custody.md](../security/custody.md)).

## Setup

### 1. Prepare the YubiKey: no default credentials

A new YubiKey has the default PIN `123456`, PUK `12345678` and a default
management key. The backend refuses the default PIN and the default
management key. On an administrator's machine (not the signer host if you
can avoid it), with [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/):

```
ykman info                                   # firmware version and serial
ykman piv info                               # PIV state
ykman piv access change-pin                  # prompts; 6-8 characters
ykman piv access change-puk                  # prompts
```

Create the new management key in a file that only you can read, then set it
on the card. AES-256 works on firmware 5.4 and newer; use `--algorithm TDES`
on older firmware:

```
umask 077
openssl rand -hex 32 > mgmt-key              # 32 bytes, hex
ykman piv access change-management-key --algorithm AES256
# ykman prompts for the current key (press Enter for the default)
# and for the new key: paste the contents of mgmt-key
```

Do not use `--protect`: it stores a random management key on the card
behind the PIN, and the signer needs the key in a file to generate keys.
Keep the PIN, PUK and management key in your password manager.

### 2. Give the signer user, and only it, access to the card

`pcscd` asks polkit before it lets a process use a reader or card. A system
service user has no active login session, so it needs a rule. Create
`/etc/polkit-1/rules.d/50-keyroster-pcscd.rules`, with `keyroster-signer`
being the OS user that runs the signer:

```
polkit.addRule(function(action, subject) {
    if ((action.id == "org.debian.pcsc-lite.access_pcsc" ||
         action.id == "org.debian.pcsc-lite.access_card") &&
        subject.user == "keyroster-signer") {
        return polkit.Result.YES;
    }
});
```

Then `sudo systemctl restart polkit pcscd`. Check that no other rule grants
these actions to other users, and do not add the signer user to groups that
are granted them.

### 3. Store the PIN and management key for the signer

The signer reads the PIN and the management key only from files, never from
the command line. Both files must be regular files (not symlinks) with mode
0600 or stricter, owned by the signer user; the backend refuses anything
wider:

```
sudo install -d -o keyroster-signer -g keyroster-signer -m 0700 /etc/keyroster-signer/piv
sudo install -o keyroster-signer -g keyroster-signer -m 0600 /dev/null /etc/keyroster-signer/piv/pin
sudo install -o keyroster-signer -g keyroster-signer -m 0600 mgmt-key /etc/keyroster-signer/piv/mgmt-key
sudoedit /etc/keyroster-signer/piv/pin       # write the PIN, one line
shred -u mgmt-key
```

The PIN file holds the PIN on one line. The management key file holds the
key in hex (16, 24 or 32 bytes).

### 4. Initialise the CA

```
keyroster-signer ca-init --state-dir /var/lib/keyroster-signer \
  --backend piv \
  --backend-opt pin-file=/etc/keyroster-signer/piv/pin \
  --backend-opt mgmt-key-file=/etc/keyroster-signer/piv/mgmt-key
```

Without `--key` flags, `ca-init` generates the five keys on the card. It
prints a line such as `YubiKey PIV firmware 5.7.1 → ssh-ed25519 keys,
custody piv`, then one line per key with its fingerprint, algorithm and
custody. Then continue with the root ceremony (`keyroster root sign`) and
`keyroster-signer install-bundle` as for any backend.

`ca-init` runs once per state directory; a second run is refused and
changes nothing. It also refuses when any of the five slots already holds a
key. If key generation fails part-way (for example the card is pulled), the
slots already filled stay occupied and a retry is refused. To start over,
reset the card's PIV application with `ykman piv reset`, which deletes
**every** PIV key and restores the default PIN, PUK and management key; then
repeat from step 1.

### 5. Remove the management key from the signer host

Signing needs only the PIN. The management key is needed again only to
generate keys, so move it off the host after `ca-init`:

```
sudo shred -u /etc/keyroster-signer/piv/mgmt-key
```

`ca-init` stored the backend options, including the `mgmt-key-file` path.
Override that option with an empty value whenever you run `install-bundle`
or `serve`, so the signer does not look for the file:

```
keyroster-signer serve ... --backend-opt mgmt-key-file=
```

## Options

| Option | Required | Meaning |
|---|---|---|
| `pin-file` | yes | File with the PIV PIN (mode 0600 or stricter). The default PIN is refused. |
| `mgmt-key-file` | for `ca-init` only | File with the management key in hex (mode 0600 or stricter). The default management key is refused. |
| `serial` | no | Serial number of the YubiKey to use. Without it, exactly one YubiKey must be attached. |

The backend also refuses a key that was imported into a slot rather than
generated on the card, and any key whose fingerprint differs from the one
pinned in the trust bundle.

**Custody `piv` is what the card reports, not what it proves (D-WR-04).**
The backend picks any PC/SC reader whose name contains "yubikey" (or the one
with the `serial` you set), and "generated on the card" is the card's own
answer to GET METADATA. A virtual smart card (for example vsmartcard/vpcd
under a "Yubico YubiKey" reader name) or an applet that answers the Yubico
extensions would pass both checks with a key held in software, and be
recorded as custody `piv`. A real YubiKey can prove origin with a per-slot
attestation certificate that chains to Yubico's PIV CA (piv-go `Attest` and
`Verify`); the backend does not check it yet. That is deferred to the phase
1 gap plan, because it needs decisions that cannot be tested here: which
Yubico roots to trust (newer firmware uses a different attestation
hierarchy), whether Ed25519 slots on firmware 5.7 attest, and whether a
failed attestation refuses the key or only lowers its custody. Until then,
whoever signs the bundle should check on the card itself that the five
public keys in `ca-pubkeys.json` are the slot keys (`ykman piv keys info`)
and, for full assurance, verify each slot's attestation by hand
(`ykman piv keys attest`).

`keyroster-signer doctor` therefore never prints the OK hardware-custody
line for `piv` keys. It does not read the card either: it reports them as
`INFO piv_custody_reported`, the custody the card reported at ca-init.

## What CI verifies, and what needs hardware

The `PIV` workflow (`.github/workflows/piv.yml`, check `build-piv`):

- vets and lints the tagged package and runs its unit tests under `-race`
  against an in-memory fake card that holds real Ed25519 and P-256 keys;
- builds `keyroster-signer` with `-tags piv` and checks that it links piv-go
  with `CGO_ENABLED=1`;
- checks that the default `keyroster` and `keyroster-signer` builds link
  neither piv-go nor cgo.

The unit tests run the backend's own code: option and secret-file checks,
the slot map, the algorithm choice by firmware, the PIN verification at
open (a wrong PIN refuses the card after exactly one attempt; a correct one
is sent once, not per signature), the PIN retry guard (no PIN is sent with
fewer than 2 retries left or an unreadable counter, so ten starts with a
wrong PIN leave one retry), provisioning and its refusals (occupied or
unreadable slot, default PIN or management key, firmware below 5.3.0), the
fingerprint pin, the imported-key refusal, signing without the management
key, and eight concurrent signers through one card. The fake card behaves
like piv-go as far as the backend can tell (a key signs only after the
session is logged in with the PIN), but it is not a YubiKey. A certificate signed through the backend verifies with
`cert.Build` and x/crypto's `CertChecker`.

**needs-hardware:** CI has no YubiKey. Not yet run on hardware:

- `internal/keystore/piv/yubikey.go`: finding the card through `pcscd`,
  selection by serial, and the piv-go calls, including the PIN retry
  counter read (`Retries()`);
- piv-go's own code on a real card: GET METADATA on an empty slot (expected
  to return "not found"), key generation, Ed25519 and ECDSA signatures, and
  that a session logged in once with the PIN keeps signing PIN-once keys;
- every `ykman`, `pcscd` and polkit step on this page.

These are tracked in [needs-hardware.md](../security/needs-hardware.md) for
the Phase 6 review (D-12).
