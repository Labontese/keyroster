# Root ceremony transcript

Copy this file, fill it in during the ceremony
([root-ceremony.md](root-ceremony.md)) and keep it with your own records.
Do not commit it: the storage section says where the root media and
passphrases are kept.

**Passphrases, key files and network details are never recorded here.**
Do not write a passphrase, a hint to a passphrase, the contents of an
`.age` file, a private key, an IP address or a hostname into this
transcript. Nothing below is secret, but the storage section is private.

## Ceremony

| Field | Value |
|---|---|
| Date (UTC) | |
| Operator | |
| Purpose | genesis / root rotation / policy change / re-sign |
| Variant | software roots (D-10) / hardware roots (D-11) |
| Agreed policy change (the changed field names, and a reference to the record that holds the agreed values; no hostname or other value is written here; agreed before the successor policy is written, and recorded by someone other than its proposer, or by the owner on a single-owner installation) | |

For a policy change, every custodian takes the changed field names from the
`Agreed policy change` row and checks every value in the policy block of `root sign --prev`
against the record that row refers to (root-ceremony.md, "Change the policy", step 3). The row and that
check run in CI (TestCeremonyGolden, TestSummaryGolden and TestRootCeremonyPolicyChecks, 03-14b;
TestAuditLoginAcrossPolicyChange, e2e, real binaries) and are UNVERIFIED in a real ceremony.

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

Installation ID (root sign's `installation id:` line): `________________________________`

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
