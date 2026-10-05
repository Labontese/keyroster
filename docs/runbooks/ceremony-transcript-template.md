# Root ceremony transcript

Copy this file to `docs/ceremonies/<date>-<purpose>.md`, fill it in during
the ceremony ([root-ceremony.md](root-ceremony.md)) and commit it through a
pull request.

**Passphrases, key files and network details are never recorded here.**
Do not write a passphrase, a hint to a passphrase, the contents of an
`.age` file, a private key, an IP address or a hostname into this
transcript. Everything below is public.

## Ceremony

| Field | Value |
|---|---|
| Date (UTC) | |
| Operator | |
| Purpose | genesis / root rotation / re-sign |
| Variant | software roots (D-10) / hardware roots (D-11) |

## Software

| Field | Value |
|---|---|
| keyroster commit (`main`) | |
| `keyroster` binary SHA-256 (build 1) | |
| `keyroster` binary SHA-256 (build 2, second machine) | |
| Live USB image name | |
| Live USB image SHA-256 | |
| `ip -br link` showed only `lo` up | yes / no |

## Roots

| Root | SHA256 fingerprint | Key type | Custody | Medium label |
|---|---|---|---|---|
| A | | | | |
| B | | | | |

Root threshold: ___ of ___

## Documents

| File | SHA-256 |
|---|---|
| `ca-pubkeys.json` | |
| `policy.json` | |
| `roots.pub` | |
| `bundle.json` | |
| `bundle.json.sigs` | |
| `policy.json.sigs` | |

Bundle SHA-256 prefix typed at each signing: `________`

## Signatures

| Root | Signed bundle and policy | Time (UTC) |
|---|---|---|
| A | yes / no | |
| B | yes / no | |

`keyroster trust verify` result (last line): ______________________

## Install

| Field | Value |
|---|---|
| `keyroster-signer install-bundle` time (UTC) | |
| Pins used (from paper) | |
| Signer audit entry for the install | |

## Storage

| Item | Location (described, not an address) |
|---|---|
| USB A | |
| USB B | |
| Passphrase A | stored separately from USB A: yes / no |
| Passphrase B | stored separately from USB B: yes / no |

Ceremony machine shut down without a network connection: yes / no

Signed off by: ____________________
