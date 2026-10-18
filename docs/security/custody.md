# Key custody

Every online key of `keyroster-signer` (the user, host and machine CAs, the
ops key and the log key) records a **custody**: where the private key lives.
ca-init writes the custody into `ca-pubkeys.json`, the offline root signs it
into the trust bundle, and the `ca_init` audit log entry records it. A
weaker custody is therefore visible to anyone who reads the bundle or the
log. It cannot be hidden by the online CA host.

## Custody levels, strongest first

| Custody | Where the key lives | Backend | Notes |
|---|---|---|---|
| `pkcs11-agent` | A hardware security module (YubiHSM 2, Nitrokey HSM 2, SmartCard-HSM) reached through OpenSSH `ssh-agent` and `ssh-pkcs11-helper` | `agent` with `custody=pkcs11-agent` | See [docs/backends/pkcs11.md](../backends/pkcs11.md). The key cannot be exported. **Declared by the operator, not verified:** the agent cannot show where a key lives, so a SoftHSM token or a plain `ssh-add` key would be recorded the same way. `doctor` prints `INFO pkcs11_custody_declared`, never the OK hardware-custody line. |
| `piv` | A YubiKey PIV slot | `piv` (build tag `piv`, not in default binaries) | See [docs/backends/piv.md](../backends/piv.md). The key cannot be exported. Touch and PIN policies are per slot. **Card-reported, not attested:** the backend takes the card's word that it is a YubiKey and that the key was generated on it; slot attestation is not checked yet ([piv.md](../backends/piv.md)). `doctor` does not read the card and prints `INFO piv_custody_reported`, never the OK hardware-custody line. Not yet validated on a real YubiKey ([needs-hardware.md](needs-hardware.md)). |
| `tpm` | A physical TPM 2.0 chip or firmware TPM (Intel PTT, AMD fTPM, Infineon, Nuvoton, STMicroelectronics) | `tpm` | The key is created inside the TPM and is wrapped by its storage root key. It cannot be used without that TPM and the key's auth value. |
| `vtpm` | A virtual or software TPM: swtpm/libtpms (QEMU, Proxmox VE), Hyper-V, Google Cloud, or any TPM whose manufacturer is not on the allowlist below | `tpm` | Weaker than a physical TPM, stronger than a software key. See below. |
| `agent` | A plain private key loaded into `ssh-agent` | `agent` | **Test and development only.** The key exists as a file somewhere. `doctor` flags it. |
| `software` | A key file, age-encrypted with a passphrase (for roots: on offline media) | `software` (online keys) | **Evaluation only.** For online keys see [Software CA keys (KEY-06)](#software-ca-keys-key-06); for roots see [Software root](#software-root-d-10-d-11). `doctor` flags it. |

Hardware custody guarantees one thing: **the key cannot be copied**. It does
not stop an attacker who controls the signer host from asking the device to
sign while they are present.

## TPM and vTPM (KEY-04, D-07, D-08, D-09)

`keyroster-signer ca-init --backend tpm` creates the five online keys as
**ECDSA P-256** keys inside the TPM (TPMs practically never implement
Ed25519). For each role the signer keeps two files in
`{state-dir}/tpm/`, mode 0600 in a 0700 directory:

- `{role}.tpmkey`: the TSS2 PEM key file. It holds the key wrapped by the
  TPM's storage root key, and is useless without that TPM.
- `{role}.auth`: a random 32-byte auth value that the TPM requires for every
  signature. Anyone who can open the TPM device but cannot read the signer's
  state directory (for example another member of group `tss`) cannot use the
  key.

The keys are created with **`noDA`**: a wrong auth value does not count
against the TPM's dictionary-attack counter. That counter is TPM-wide, so
without `noDA` a corrupt auth file could lock the TPM out for every other
user of it (for example TPM+PIN disk unlocking); the auth value is 32 random
bytes, so dictionary-attack protection adds nothing. At start the backend
proves each key's auth value with one test signature: a wrong one stops the
signer with exit status 78, which the systemd unit does not restart on
(D-WR-01). Keys created before `noDA` was set (signer installs from before
this change) stay dictionary-attack protected; for them the start-up check
limits a bad auth file to one failed authorisation per manual start.

The backend loads only keys that were **generated inside the TPM** and
cannot leave it: the key's public area must have `fixedTPM`, `fixedParent`
and `sensitiveDataOrigin` set (D-CR-02). A key made in software and
imported with `TPM2_Import` (for example `tpm2_import` + `tpm2_encodeobject`)
is still a working TPM key file, but whoever made it may keep a copy, so
`ca-init` and `serve` refuse it instead of recording custody `tpm`. CI tests
this over swtpm: such an imported key signs in the TPM, and the backend
refuses it (`TestImportedKeyRefused`).

The backend reads the TPM's manufacturer ID (`TPM2_GetCapability`,
`TPM_PT_MANUFACTURER`) and derives the custody from it. ca-init prints it,
for example `TPM manufacturer: IBM → custody vtpm`.

| Manufacturer ID | Meaning | Custody |
|---|---|---|
| `INTC`, `AMD`, `IFX`, `NTC`, `STM` | Intel PTT, AMD fTPM, Infineon, Nuvoton, STMicroelectronics | `tpm` |
| `IBM` | swtpm/libtpms, used by QEMU and Proxmox VE vTPMs | `vtpm` |
| `MSFT` | Hyper-V vTPM, Microsoft's reference simulator | `vtpm` |
| `GOOG` | Google Cloud vTPM | `vtpm` |
| any other | unknown: not assumed to be hardware | `vtpm` |

The mapping is an **allowlist and fails closed** (D-WR-02): a manufacturer
that is not known to make physical or firmware TPMs is custody `vtpm`. A TPM
reached through the test-only `swtpm-socket` option is always `vtpm`,
whatever manufacturer the process behind the socket reports. The `custody`
backend option can only make this weaker: `--backend-opt custody=vtpm`
labels any TPM as virtual, and `custody=tpm` is refused unless the custody
already is `tpm`. `doctor` applies the same rule when it compares the live
TPM with the recorded custody.

**The manufacturer ID is self-reported.** It is whatever the TPM, or the
hypervisor that emulates it, answers to `TPM2_GetCapability`; nothing
authenticates it, so a hypervisor that claims `INTC` is recorded as `tpm`.
Verifying the TPM's endorsement-key certificate against the manufacturer's
CA would close that gap; it is not implemented (deferred to the phase 1 gap
plan).

**Upgrade note:** a signer whose keys were recorded as custody `tpm` on a
TPM whose manufacturer is not on the allowlist now derives `vtpm`. `serve`
refuses the custody mismatch and `doctor` prints `WARN custody_mismatch`.
Such a signer must be re-initialised (new keys and bundle) with its custody
recorded as `vtpm`, or the vendor added to the allowlist through a reviewed
change with evidence that its ID belongs to hardware TPMs.

**A vTPM is only as safe as its hypervisor host.** The homelab runs the
signer in a Proxmox VM with a vTPM (D-08). That vTPM is swtpm on the Proxmox
host, and its state, including the storage root key that wraps the CA keys,
is a file on that host. Whoever controls the Proxmox host (root, backups,
snapshot exports) controls the keys. This is **weaker than a physical TPM**,
where the storage root key never leaves the chip, and **stronger than a
software key**: the guest VM alone cannot export the keys, so a compromise of
the signer VM gives an attacker a signing oracle only while they are present,
not a copy of the keys. `doctor` reports custody `vtpm` as a warning (plan
01-13), and the bundle shows it to every verifier.

## Software CA keys (KEY-06)

keyroster runs without any hardware. `keyroster-signer ca-init --backend
software --backend-opt passphrase-file=FILE` creates the five online keys
(user, host and machine CA, ops key, log key) as **Ed25519** keys. Each is
stored as an armored age file encrypted to the passphrase, with one scrypt
recipient at age's default work factor: `{state-dir}/software/{role}.age`,
mode 0600 in a 0700 directory. The bundle, `ca-pubkeys.json` and the
`ca_init` log entry record custody `software` for every key.

**This custody is for evaluation only.** It does not protect against:

- **A compromised signer host.** `serve` decrypts the keys into memory at
  start and keeps them there. Whoever controls the signer host can read
  them, copy them and issue certificates, even after leaving.
- **A passphrase stored on the same host.** `serve` must read the
  passphrase at every start, so it is normally on the signer host, in a
  file or a systemd credential. A passphrase stored next to the key files
  makes the keys equivalent to plaintext for anyone who can read both.
- **Offline guessing of leaked key files.** If the `.age` files leak on
  their own, for example from a backup or a copied state directory, they
  can be attacked offline. The only protection left is the passphrase's
  entropy at age's default scrypt work factor. keyroster requires at least
  20 characters, but that is a length floor, not a strength check. Use a
  randomly generated passphrase, for example `openssl rand -base64 32`,
  never a memorable phrase.

The passphrase comes only from a file, never from argv or the environment,
and keyroster never logs or prints it:

- `--backend-opt passphrase-file=FILE`: a regular file with no group or
  other permissions (mode 0600 or 0400). Exactly one trailing newline is
  ignored. ca-init stores the option (the path, not the passphrase), so
  `install-bundle` and `serve` read the same file.
- Without that option, `$CREDENTIALS_DIRECTORY/keyroster-software-passphrase`,
  as systemd provides it with `LoadCredential=keyroster-software-passphrase:PATH`
  or `LoadCredentialEncrypted=`. This path is tested with
  `CREDENTIALS_DIRECTORY` set by a unit test; it has **not been run under a
  real systemd unit (UNVERIFIED)**.

A passphrase shorter than 20 characters, a passphrase file readable by
group or others, a key file or key directory that is not private or is a
symlink, and a key file that does not decrypt to the recorded key are all
refused.

`doctor` reports `WARN software_key`. The signer reports the custody of
every key itself, over its `Status` message, and nothing else is trusted
for it: no flag, environment variable or configuration of the CLI or the
server can hide or soften the warning. Every `keyroster ca issue` asks the
signer for its status before it issues and, while any key has custody
`software`, prints this banner to stderr, framed by lines of `!`. The
server's web UI (plan 02-06) will show the same text on every page:

```
EVALUATION ONLY - SOFTWARE CA KEY: the user, host, machine, ops, log keys
of this keyroster signer are software keys (custody software). Anyone who
copies the key files and their passphrase, or controls the signer host,
can issue certificates. Do not use this instance for real access
(docs/security/custody.md).
```

The text is one constant in `internal/custodytext`. A test requires this
document to quote it verbatim.

## Software root (D-10, D-11)

The homelab's offline trust root is a **software root**: two independent
Ed25519 root keys, each age-encrypted with its own passphrase on its own USB
stick, threshold 1-of-2. This is a deliberate deviation for the homelab
only; the tooling supports hardware roots (ed25519-sk and PIV) and CI tests
them with software stand-ins. The deviation stays visible: the bundle
records root custody `software`, and every ceremony that signs with such a
root prints a **SOFTWARE ROOT** banner (see
[docs/runbooks/root-ceremony.md](../runbooks/root-ceremony.md)). `doctor`
flags it too (plan 01-13).

## No backend survives a live server compromise as a signing oracle

Every backend above protects the key from being copied. None of them stops
an attacker who has taken over the signer host from asking for signatures
while they are there. What keyroster adds is that the signer itself refuses
to sign without evidence: in Phase 1, an admin SSHSIG over the exact request
digest by a key in the root-signed genesis policy (D-13). The signer appends
an audit log entry before any certificate leaves it. A compromised API or
CLI host therefore cannot mint certificates on its own, and whatever a
compromised signer host signs is recorded in a log that verifiers check
against the root.

## Test setup for the TPM backend (CI and local)

CI cannot use a physical TPM, so the `e2e-tpm` workflow runs swtpm from the
Ubuntu archive. Because swtpm reports manufacturer `IBM` and is reached
through `swtpm-socket`, every key in that run is custody `vtpm`; the tests assert that, in `ca-pubkeys.json` and in the
verified bundle. `scripts/swtpm-setup.sh DIR` starts it on a Unix socket
carrying raw TPM commands (`unixio`). The backend reaches that socket with
the test-only option `swtpm-socket=PATH` (go-tpm `linuxudstpm`). No root is
needed, so local runs (WSL2) use the same setup.

Over swtpm, CI checks that a wrong auth value on a provisioned key returns
`TPM_RC_BAD_AUTH` and leaves `TPM_PT_LOCKOUT_COUNTER` unchanged, while the
same mistake on a key without `noDA` returns `TPM_RC_AUTH_FAIL` and raises it
(`TestProvisionNoDA`), and that `serve` then exits 78
(`TestTPMWrongAuthNotRestartable`). **UNVERIFIED on a physical TPM** (the
TPM 2.0 specification says it behaves the same; [needs-hardware.md](needs-hardware.md)
item 4).

**CI exercises the swtpm `unixio` transport only.** The unit tests under
`-race` and the full e2e suite run over it. The production device path
(`device=/dev/tpmrm0`, go-tpm `linuxtpm.Open`) is not exercised in CI. It is
first exercised in plan 01-14, the homelab dogfood on the Proxmox VM's own
vTPM. Everything above the transport (key creation, key files, signing,
custody) is the same code in both cases; only the transport differs.

A `vtpm-proxy` mode was attempted and dropped. In that mode swtpm sits behind
the kernel's `tpm_vtpm_proxy`, and the kernel creates a new `/dev/tpmrmN`,
which would have put the production transport in CI. On the `ubuntu-24.04`
runner it never got past loading the module: the runner's kernel
(`6.17.0-1022-azure`) has no `tpm_vtpm_proxy`, not even in
`linux-modules-extra-6.17.0-1022-azure` (spike on PR #12). WSL2 kernels lack
the module too. The mode was removed from the script rather than kept
untested.

go-tpm's `tpm2/transport/simulator` package is never used: it links a cgo
TPM simulator that production never runs. depguard denies it, and
`go list -deps ./...` must not contain it or `go-tpm-tools`.

A TCP transport (option `swtpm-tcp`, go-tpm `transport/tcp`) was planned as a
third fallback. A local spike showed that it works with swtpm's TCP server,
but it is not built: the Unix-socket mode works without root, and a TCP
client in the signer would add network code to a process that is
network-less by design (KEY-01).
