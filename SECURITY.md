# Security Policy

keyroster is security software: it issues SSH certificates, holds certificate
authority keys and records who was granted access. We take reports about it
seriously, and we would much rather hear about a problem from you than from an
attacker.

## Scope

This policy covers the keyroster code in this repository: the `keyroster` CLI,
the `keyroster-signer` process, their wire formats, trust bundles and audit
log, the build and release scripts, and the GitHub workflows. Bugs in
OpenSSH, Go or a dependency belong with that project; if keyroster uses one
in a way that makes it exploitable, that part is in scope here.

## How to report

Report vulnerabilities **only** through GitHub private vulnerability
reporting:

https://github.com/Labontese/keyroster/security/advisories/new

**Never report a vulnerability in a public issue, pull request, discussion or
commit.** Public reports put every user at risk before a fix exists. If you are
unsure whether something is a security problem, report it privately anyway.

## What to include

- What you found, and the component and commit or version it affects.
- Steps or a proof of concept that reproduce it.
- The impact you expect: what an attacker gains (for example, a certificate
  they should not get, access that survives revocation, an audit entry that
  can be hidden or rewritten, a CA key that leaves its custody).
- Any conditions it needs (configuration, privileges, network position).

Leave out real secrets, private keys and production hostnames.

## What to expect

keyroster is pre-alpha and maintained by one person, so responses are best
effort:

- We acknowledge your report within **7 days**.
- We keep you updated while we investigate and fix it, and agree the
  disclosure date with you.

## Supported versions

There are no releases yet, so no version is supported. Fixes land on the
`main` branch only. Once releases exist, this section will say which ones get
security fixes.

## Disclosure

We follow coordinated disclosure: the fix and a GitHub security advisory are
published together, after the date agreed with you. We credit reporters in the
advisory unless you prefer to stay anonymous.

## Threat model

The threats keyroster is designed against (a compromised CA server, stolen
client keys, a malicious insider or administrator, and supply-chain attacks)
are described in the project constraints in
[`.claude/CLAUDE.md`](.claude/CLAUDE.md). How the CA keys are held, and what
each custody option does and does not protect against, will be documented in
`docs/` as the trust core lands during the current development phase.
