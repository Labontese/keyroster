# keyroster

[![CI](https://github.com/Labontese/keyroster/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Labontese/keyroster/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Labontese/keyroster/badge)](https://scorecard.dev/viewer/?uri=github.com/Labontese/keyroster)

keyroster is a self-hosted SSH certificate authority and access roster for teams. It issues, tracks, renews and revokes OpenSSH certificates, finds the plain SSH keys that still grant access outside the CA, and keeps a tamper-evident audit log, so that at any moment you know exactly who has access to what and can revoke it immediately. It works with stock OpenSSH and is fully open source, with no security features held back for an enterprise tier.

> **Warning: keyroster is pre-alpha software. It is incomplete, its formats and interfaces will change without notice, and it has not had a security review. Do not use it in production or to protect anything that matters.**

## Status

Development happens in public. The current work is the trust core: an offline trust root, a separate signer process that holds the CA keys (preferably in hardware), and a Merkle audit log. Nothing here is ready for real use yet.

## License

keyroster is licensed under the [Apache License, Version 2.0](LICENSE).

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open public issues for security problems.
