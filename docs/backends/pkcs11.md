# PKCS#11 HSM backend (YubiHSM 2 and other tokens)

keyroster can keep its online keys (the user, host and machine CAs, the ops
key and the log key) inside a PKCS#11 hardware security module. The keys are
generated on the token and never leave it. keyroster itself never loads the
vendor's PKCS#11 module: the signer talks to an OpenSSH `ssh-agent`, and the
agent runs the module in OpenSSH's separate `ssh-pkcs11-helper` process
(KEY-03). Vendor C code therefore never runs inside `keyroster-signer`, and
the keyroster binaries stay pure Go.

The keystore backend is `agent` with the custody label `pkcs11-agent`. The
custody is recorded in the signer's state, in `ca-pubkeys.json`, in the
root-signed trust bundle and in the audit log's `ca_init` entry, so anyone
who verifies the bundle or the log sees that the keys are declared
HSM-held.

**The custody is declared by the operator, not verified (D-WR-03).** The
ssh-agent protocol does not say where a key lives: a key from the HSM, a
key from a SoftHSM token and a plain key added with `ssh-add` look the
same, and an entry's comment is whatever the loader set. The signer
therefore records `pkcs11-agent` because `ca-init` was told so. `ca-init`
prints "custody pkcs11-agent declared by the operator, not verified", and
`doctor` prints `INFO pkcs11_custody_declared` instead of the OK
hardware-custody line. Whoever signs the bundle should check, on the HSM
itself, that the five public keys in `ca-pubkeys.json` are HSM keys (for
example `yubihsm-shell` or `pkcs11-tool --list-objects`) before signing.

## When to use it

Use this backend when the CA host has, or can reach locally, a PKCS#11 token:

- **YubiHSM 2** (module `yubihsm_pkcs11.so`, talking to `yubihsm-connector`
  on localhost)
- **Nitrokey HSM 2** or **SmartCard-HSM** (OpenSC's `opensc-pkcs11.so`)
- any other token with a PKCS#11 module that supports EC key pairs

A TPM is the other hardware option (`--backend tpm`, custody `tpm`), and its
CA keys are always P-256. With a PKCS#11 token the algorithm is whatever the
token holds (D-09): Ed25519 when the token and the agent support it,
otherwise P-256.

## Requirements

- **OpenSSH 10.5 or newer for the signer's agent where possible.** 10.5
  fixed a bug where a locked agent that was forwarded could be made to add
  PKCS#11 providers remotely. The signer's agent is never forwarded (see
  below), but run a fixed agent anyway.
- **Ed25519 keys need `ssh-agent` 10.1 or newer.** OpenSSH added Ed25519 keys
  on PKCS#11 tokens in 10.1. An older agent (for example Ubuntu 24.04's
  9.6p1) refuses to load them (`agent refused operation`). With an older
  agent, generate P-256 keys instead.
- The keys must be key pairs with a public-key object and a private-key
  object that share a `CKA_ID`, as `ssh-pkcs11-helper` expects. Give each key
  a unique `CKA_ID` and a label.

## Setup

The steps below use placeholders: `MODULE` is the absolute, symlink-resolved
path of the vendor module and `signer` is the OS user that runs
`keyroster-signer`.

### 1. Prepare the token

Create one key pair per role on the token, with the vendor's tool or with
OpenSC's `pkcs11-tool`, for example:

```
pkcs11-tool --module MODULE --login --pin env:TOKEN_PIN \
  --keypairgen --key-type EC:prime256v1 --id 01 --label user-ca
```

and likewise `host-ca` (id 02), `machine-ca` (03), `ops` (04) and `log` (05).
Use `EC:edwards25519` for Ed25519 keys. `--pin env:NAME` reads the PIN from
an environment variable instead of the command line, where every local user
could read it with `ps`.

For a **YubiHSM 2**:

- install `yubihsm-connector` and run it bound to `127.0.0.1` only;
- point the module at it with a `yubihsm_pkcs11.conf` containing
  `connector = http://127.0.0.1:12345`, and set `YUBIHSM_PKCS11_CONF` to
  that file in the agent's environment;
- create a dedicated authentication key for the signer with only the signing
  capabilities it needs (`sign-ecdsa` for P-256, `sign-eddsa` for Ed25519)
  and delete or disable the factory default authentication key;
- the PKCS#11 PIN is the authentication key ID followed by its password (for
  example `0002` + password).

List the public keys and their labels without logging in:

```
ssh-keygen -D MODULE
```

### 2. Store the PIN for ssh-add

Write the token PIN to a file that only the signer user can read, and an
askpass script that prints it:

```
install -d -m 0700 -o signer -g signer /etc/keyroster-signer
install -m 0600 -o signer -g signer /dev/null /etc/keyroster-signer/token-pin
# write the PIN into token-pin with an editor, not with echo on the shell

cat >/etc/keyroster-signer/askpass.sh <<'EOF'
#!/bin/sh
exec cat /etc/keyroster-signer/token-pin
EOF
chown signer:signer /etc/keyroster-signer/askpass.sh
chmod 0700 /etc/keyroster-signer/askpass.sh
```

The PIN then reaches `ssh-add` only through `SSH_ASKPASS`: it never appears
in a command line, a shell history or a log.

### 3. Run a dedicated agent for the signer

Run one `ssh-agent` for the signer, as the signer user, on its own socket,
allowing only the vendor module with `-P`:

```
ssh-agent -D -a /run/keyroster-signer-agent/agent.sock -P MODULE
```

- `-P` is an allowlist of provider paths (comma-separated patterns). The
  agent compares it with the resolved path of the module, so list the real
  file, not a symlink. List several modules only if the token really needs
  them.
- The socket directory `/run/keyroster-signer-agent` is owned by the signer
  user with mode 0700.
- **Never forward this agent and never share it with interactive users.**
  Do not point any login session's `SSH_AUTH_SOCK` at it and never use it
  with `ssh -A`: anyone who can talk to the agent can ask it to sign with
  the CA keys. Root keys never go into this agent either; they live in a
  separate offline agent during a ceremony (see the
  [root ceremony runbook](../runbooks/root-ceremony.md)).

Plan 01-13 ships the systemd units for the signer and its agent. Until then
run the agent under the signer user with your service manager.

### 4. Load the token

```
SSH_AUTH_SOCK=/run/keyroster-signer-agent/agent.sock \
SSH_ASKPASS=/etc/keyroster-signer/askpass.sh SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
  ssh-add -s MODULE </dev/null
SSH_AUTH_SOCK=/run/keyroster-signer-agent/agent.sock ssh-add -l -E sha256
```

The second command prints the SHA256 fingerprints of the five keys. The
agent keeps the token session open; after the agent or the token restarts,
load the token again before the signer can sign.

### 5. Initialise the CA

Pin every role to its key by fingerprint. The signer never picks "the first
key" in the agent:

```
keyroster-signer ca-init --state-dir /var/lib/keyroster-signer \
  --backend agent \
  --backend-opt socket=/run/keyroster-signer-agent/agent.sock \
  --backend-opt custody=pkcs11-agent \
  --key user=SHA256:... --key host=SHA256:... --key machine=SHA256:... \
  --key ops=SHA256:... --key log=SHA256:...
```

`ca-init` runs once per state directory. A second run is refused and changes
nothing. Then continue with the root ceremony (`keyroster root sign`) and
`keyroster-signer install-bundle` as for any backend; the bundle records
custody `pkcs11-agent` for all five keys (declared, see above).

## A root key on a PKCS#11 token

A root key can also live on a PKCS#11 token, reached through its own offline
`ssh-agent` during the ceremony: declare it `custody=pkcs11` in `roots.pub`
(a YubiKey PIV root is declared `custody=piv`, see the runbook) and sign with
`keyroster root sign --agent-key SHA256:...`. Keep root and CA keys on
different tokens and in different agents.

## What CI verifies, and what needs hardware

The `E2E PKCS#11` workflow (`.github/workflows/e2e-pkcs11.yml`) uses SoftHSM2
as the stand-in for a YubiHSM 2 (D-12). `scripts/softhsm-setup.sh` creates a
CA token with the five role keys and a separate root token, and
`test/e2e/pkcs11_test.go` runs, in two lanes:

- `e2e-pkcs11 (distro-p256)`: P-256 keys in Ubuntu's own ssh-agent (9.6p1),
  which also must refuse Ed25519 token keys;
- `e2e-pkcs11 (10.5p1-ed25519)`: Ed25519 keys in an OpenSSH 10.5p1 agent.

Each lane runs `ca-init`, a root-signed bundle with the root in its own
token, `install-bundle`, an admin-signed `keyroster ca issue`, a login on a
real sshd and `keyroster audit verify --pin`; it also checks that a second
`ca-init` is refused, that eight concurrent issuances get distinct valid
certificates, and that the PIN appears in no output and no process command
line.

**needs-hardware:** no real YubiHSM 2 (or other hardware HSM) has been
tested yet. Validation on real hardware, including the connector setup and
the authentication-key capabilities above, is tracked as a needs-hardware
item for the Phase 6 review (D-12); see
[docs/security/needs-hardware.md](../security/needs-hardware.md).
