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
sudo apt-get install gcc libpcsclite-dev pkg-config     # Debian/Ubuntu: a C compiler for cgo, the pcsc-lite headers, and pkg-config to find them
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
| generations 2 and later, every role | 0x87 to 0x95 |

The generation slots 0x87 to 0x95, 15 in all, are shared by every role's
later generations: `ca-rotate prepare` takes the first that no generation
row records, and a slot is never reused, even after retire-key overwrote
it (see "Generation slots").

`ca-init` refuses, and generates nothing, if any of the five genesis slots
0x82 to 0x86 already holds a key. It never overwrites a key, and neither
does prepare, with one exception: retire-key overwrites the draining
generation's own slot with a throwaway key, after checking that it holds
that key. The first retire-key of a role overwrites a genesis slot, 0x82
for the user CA.

## Generation slots

A key in a generation slot that no generation row records is a key the
signer's database does not know. It arises from a lost prepare (the card
generated the key and the row was not committed), from a `signer.db`
restored from before a prepare, or from a key put there by hand.
`ca-rotate prepare` then refuses `ErrSlotOccupied`, printed as
`slot already holds a key` and naming that slot, on every later run, for
every role, because the allocator takes the first slot that no row
records and never writes over an occupied one. Overwriting the slot by
hand does not clear it, because the slot stays occupied.

On firmware 5.7 and later the way out is `ykman piv keys delete <slot>`,
run only when this rule allows it:

- Never on a restored database before the restore section of
  [signer-install.md](../runbooks/signer-install.md) has run to its end.
- Never while a signed bundle waits to be installed: first every trust
  bundle that a ceremony has signed is installed on this signer. Where
  `install-bundle` refuses a bundle with `no stored generation`, the
  database lacks a generation that a bundle names (the lost generation
  that signer-install.md "Restore from before the last switch" stops on),
  the slot's key may be that generation's key, and it is not deleted.
  With every signed bundle installed, no bundle names a key in a slot that
  no generation row records, so no host trusts that key and no signer
  needs it, because the signer installs no bundle that names a key that
  is no stored generation.
- Never a key you keep in a generation slot for another use. keyroster
  uses 0x87 to 0x95 for generations, so a key of another use there stops
  PIV rotation.

A prepare's own report of the key is no reason to keep it: the error of a
prepare that created the key and could not record it says
`the backend created the key` and gives its fingerprint and slot, and a
successful prepare's fingerprint and `location:` line stand in the
transcript from before a restore. The refusal itself names the slot and
not the key.

The signer holds the card while it runs, so it is stopped for the
delete, as the first line of step 5's block stops it. `ykman` asks for
the management key: give it at the prompt from the password manager,
never write it to a file and never pass it on the command line. The
block of step 5, run again for the prepare, starts the signer.

Below firmware 5.7 nothing empties a slot short of `ykman piv reset`,
which destroys every PIV key on the card, the working CA keys included,
and firmware cannot be upgraded on a YubiKey. Every `ykman` command of
this section is UNVERIFIED.

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
generate keys, so move it off the host after `ca-init`.
`/etc/keyroster-signer/piv` belongs to the signer's user (step 3), so
every command of this step that names it runs as that user, never as
root below that directory:

```
sudo runuser -u keyroster-signer -- shred -u /etc/keyroster-signer/piv/mgmt-key
```

Step 3's root `sudo install` form is for the first setup only, while root
has just created the directory, and is never used again.

`ca-init` stored the backend options, including the `mgmt-key-file` path.
The signer reads the management key only when it writes to the card
(ca-init, prepare and retire-key), so `install-bundle`, `serve`, `doctor`
and every other command run with the file absent and need no override;
an empty override (`--backend-opt mgmt-key-file=`) is still accepted. The
shipped unit's `serve` carries no override, and the signer's PIV leg
opens the backend as serve does, with the stored options and no
override; no test starts the systemd unit on a PIV signer, which stays
UNVERIFIED.

`ca-rotate prepare` and `ca-rotate retire-key` write to the card, so a
CA rotation brings the key back for the one command and takes it out
again, in one block run on the signer host:

```
sudo systemctl stop keyroster-signer.service
K=/etc/keyroster-signer/piv/mgmt-key
sudo runuser -u keyroster-signer -- rm -f "$K"
sudo runuser -u keyroster-signer -- sh -c 'umask 077 && set -C && cat >"$1"' sh "$K"
sudo runuser -u keyroster-signer -- keyroster-signer ca-rotate <arguments> --state-dir /var/lib/keyroster-signer; rc=$?; sudo runuser -u keyroster-signer -- shred -u "$K"; test "$rc" -eq 0 && sudo systemctl start keyroster-signer.service
```

`<arguments>` is `prepare --role <role> --out <file>` or
`retire-key --role <role>`, as the runbook step names them. Paste the key
from the password manager into the `cat` of the fourth line and end it
with Ctrl-D. The path is the one ca-init stored, so no `--backend-opt` is
needed. The shred runs on every exit status of the command, so the key
leaves the host whatever prepare or retire-key returned. The signer is
started only after the shred, and only when the command exited 0:

- after a refused prepare the key is already shredded and the signer is
  still stopped, so run `sudo systemctl start keyroster-signer.service`
  by hand (the refusal wrote nothing the signer serves), fix the cause,
  and run the block again;
- after a refused retire-key the signer stays stopped until the block
  runs again with the key and retire-key exits 0;
- if the last line did not run to its end (an interrupt such as Ctrl-C,
  which skips the rest of that line, a lost session, or a failed shred),
  or you stopped after placing the key, run
  `sudo runuser -u keyroster-signer -- shred -u /etc/keyroster-signer/piv/mgmt-key`
  by hand before anything else (the full path, because a new shell has
  no `K`).

`shred` does not reliably erase a file on an SSD or a copy-on-write
filesystem, so the key's old blocks may survive on such storage. While
the key is on the host, whoever reads it can overwrite or replace any
slot.

## Options

| Option | Required | Meaning |
|---|---|---|
| `pin-file` | yes | File with the PIV PIN (mode 0600 or stricter). The default PIN is refused. |
| `mgmt-key-file` | for `ca-init`, `ca-rotate prepare` and `ca-rotate retire-key` | File with the management key in hex (mode 0600 or stricter), read only when one of them writes to the card. The default management key is refused. |
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
  the fake card (`internal/keystore/piv/fake.go`) is compiled only with
  `-tags piv,pivfake`;
- runs the signer's PIV rotation leg (`TestSignerRestartMixedBundle/piv`)
  at command level on the fake card, under `-race`, with the
  management-key file absent except for prepare and retire-key;
- builds `keyroster-signer` with `-tags piv` and checks that it links piv-go
  with `CGO_ENABLED=1`, and proves that this release binary holds no fake
  card by its file list, its build info (exactly `-tags=piv`) and its
  symbols (on a stripped `-s -w` build only the first two checks work);
- checks that the default `keyroster` and `keyroster-signer` builds link
  neither piv-go nor cgo.

govulncheck in this workflow and CodeQL build `-tags piv` only, so they
never see `fake.go`. The management key's block of step 5 is pinned for
its form by `TestCARotationBackendSteps` and is never run in CI
(UNVERIFIED).

The unit tests run the backend's own code: option and secret-file checks,
the slot map, the algorithm choice by firmware, the PIN verification at
open (a wrong PIN refuses the card after exactly one attempt; a correct one
is sent once, not per signature), the PIN retry guard (no PIN is sent with
fewer than 2 retries left or an unreadable counter, so ten starts with a
wrong PIN leave one retry), provisioning and its refusals (occupied or
unreadable slot, default PIN or management key, firmware below 5.3.0), the
fingerprint pin, the imported-key refusal, signing without the management
key, and eight concurrent signers through one card; and the generation
slots: the allocator (the first slot of 0x87 to 0x95 that no generation
row records, never reused, `piv_no_free_slot` with all 15 recorded, an
occupied unrecorded slot refused `ErrSlotOccupied` with no card write),
the location of each generation, Holds by fingerprint, the overwrite of
the draining slot with a throwaway key, and the management key read only
at a card write (`TestPIVGenerationAllocator`,
`TestGenerationKeyAfterReopen`, `TestPIVGenerationSlots`,
`TestPIVHolds`, `TestPIVRemoveGeneration`,
`TestPIVManagementKeyAtUse`). The fake card behaves
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
- every `ykman`, `pcscd` and polkit step on this page;
- the generation slots on every YubiKey: generating into 0x87 to 0x95;
  reading a slot's metadata when it is empty, overwritten or never used;
  that an overwrite is atomic and destroys the old private key (Yubico's
  documented behaviour, not observed here); signing from a generation
  slot after a reopen in a separate process; the algorithm per firmware
  for generations; PIN once across processes; the card's answer to a
  wrong management key; `ykman piv keys delete <slot>` and
  `ykman piv reset`; and the 15-slot exhaustion on a real card, which CI
  checks on the fake card only. Deletion on firmware 5.7 and later is not
  implemented: the pinned piv-go v2.6.0 has no delete command, so
  retire-key overwrites on every firmware;
- a key in a generation slot that no generation row records stops PIV
  rotation, for every role, until the slot is emptied ("Generation
  slots"); overwriting the slot by hand does not clear it;
- the management key file is shredded, not proven erased: `shred` does
  not reliably erase a file on an SSD or a copy-on-write filesystem;
- the location column is not logged: a database edit of a PIV generation's
  location is stopped by the fingerprint checks before any card write, but
  for generation 2 or later an edit that points at another generation slot,
  one that does not hold the draining key, makes Holds answer "not held",
  and audit cannot show which slot a generation used.

These are tracked in [needs-hardware.md](../security/needs-hardware.md) for
the Phase 6 review (D-12).
