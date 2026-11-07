---
created: 2026-11-06T12:00:00.000Z
title: A root-signed host-name scope that the signer and the client both enforce
area: auth
severity: minor
resolves_phase: 4
files:
  - internal/trust/policy.go
  - internal/directory/directory.go
  - internal/signer/directory.go
  - cmd/keyroster/knownhosts.go
  - docs/runbooks/enroll-user.md
  - docs/runbooks/host-setup.md
---

## Problem

The 03-09b pre-merge review (PR #89) found that the client pins whatever host principals an admin-quorum-signed directory lists. `keyroster login` and `keyroster known-hosts sync` write them into the strict Host block and the `@cert-authority` lines; hostTrustName checks their form only. A quorum can therefore make every user's ssh trust only the organisation's host CA for an external name (a public service such as `git.example.com`), so ssh refuses that service's own host key, and anyone holding the org host CA could stand in for it. A mistaken name (a typo, an address) has the same effect. Because the client's names only grow, a wrong name stays in the block, refused, after the admins fix or remove the entry. Only deleting the four files on each client drops it.

The review refuted this as a defect of the PR, since the admin quorum is trusted to name hosts. Owner decision D-R3 (2026-11-06) keeps it as a design gap. For now, enroll-user.md ("Which names every client pins") and host-setup.md (the approval step) tell admins and users what the names mean and how a user recovers.

## Solution

Add a host-name scope to the root-signed trust policy, for example a list of allowed domain suffixes, with explicit single names as an option:
- The signer refuses to install a directory version with a host principal outside the scope (a new install refusal with its own error code).
- The client refuses to pin a principal outside the scope, using the policy it already verifies against the root pins, so a server cannot widen the scope.
- Changing the scope is a root ceremony, like any other policy change.

Open questions for the phase: whether an absent scope means "any name" (today's behaviour, for homelabs) or "none"; how a narrowed scope affects names a client already holds (refused, never dropped silently); and whether a principal that is an IP address is allowed at all.

Tests:
- a directory version with a principal outside the scope is refused by the signer, and by the client when a server serves one anyway;
- a scope change without root signatures is refused;
- names already pinned are handled as decided above.

Sources: 03-09b-PLAN.md (D2, T-03-59), 03-09b-SUMMARY.md ("Pre-merge review", D-R3).
