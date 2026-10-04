# API Coverage — GitHub REST API (repository administration surface)

> Full coverage by default. Opt-outs are explicit, reasoned decisions.

Scope: the keyroster product itself integrates no external API in Phase 1 (self-hosted, no external service in the core path). The phase does use the GitHub REST API, through `gh` and `gh api`, to administer the public repository `Labontese/keyroster` (REPO-01..04, D-04..D-06). The matrix below enumerates that repository-administration surface and records what plans 01-01, 01-02, 01-03, 01-10 and 01-12 integrate. Owner-token calls change settings and rulesets; bot-token calls (`scripts/gh-as-bot.sh`) only push branches, open and auto-merge PRs, and create issues/labels.

| capability | decision | reason |
|---|---|---|
| repos.create (public repository) | INTEGRATE | |
| repos.update (merge methods, auto-merge, branch cleanup, wiki/projects off) | INTEGRATE | |
| rulesets (list, create, update, get) | INTEGRATE | |
| rules for a branch (read effective rules) | INTEGRATE | |
| collaborators (invite with push permission, read permission) | INTEGRATE | |
| user repository invitations (accept as bot) | INTEGRATE | |
| user SSH signing keys (owner and bot) | INTEGRATE | |
| security_and_analysis: secret scanning | INTEGRATE | |
| security_and_analysis: secret scanning push protection | INTEGRATE | |
| private vulnerability reporting | INTEGRATE | |
| vulnerability alerts (Dependabot alerts) | INTEGRATE | |
| automated security fixes (Dependabot security updates) | INTEGRATE | |
| actions permissions (enabled, allowed_actions=selected, sha_pinning_required) | INTEGRATE | |
| actions selected-actions allowlist | INTEGRATE | |
| actions workflow permissions (default token read, cannot approve PRs) | INTEGRATE | |
| actions workflow dispatch and run listing/watching | INTEGRATE | |
| code-scanning analyses (read, to verify CodeQL and Scorecard uploads) | INTEGRATE | |
| commits and check-runs (read: signature and required-check evidence) | INTEGRATE | |
| pull requests (create, checks, auto-merge squash) | INTEGRATE | |
| issues and labels (create needs-hardware tracking) | INTEGRATE | |
| classic branch protection | OPT-OUT | explicitly out of scope — superseded by the two-ruleset design, which supports audited bypass in pull_request mode |
| code-scanning default setup | OPT-OUT | explicitly out of scope — the advanced, SHA-pinned CodeQL workflow (Go + Actions, security-extended) replaces it |
| secret scanning non-provider patterns and validity checks | OPT-OUT | not needed yet — free-tier availability for public repos unverified; revisit in the Phase 6 security review |
| tag rulesets and release immutability | OPT-OUT | not needed yet — releases and signed tags arrive in Phase 6 (REPO-06) |
| artifact attestations | OPT-OUT | not needed yet — SLSA provenance is Phase 6 (REPO-06) |
| environments and deployment protection rules | OPT-OUT | not needed — Phase 1 has no deployments from GitHub |
| actions secrets and variables | OPT-OUT | not needed — no workflow in Phase 1 uses secrets |
| merge queue | OPT-OUT | not needed — single maintainer and low PR volume; strict required status checks suffice |
| webhooks and GitHub Apps | OPT-OUT | explicitly out of scope — no external service in keyroster's core path |
| Pages, wiki and projects | OPT-OUT | explicitly out of scope — disabled to reduce attack surface |
