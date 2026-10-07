# Contributing to keyroster

keyroster is pre-alpha security software. Every change reaches `main` through
a pull request that is signed, green in CI and reviewed. This file describes
how that works and which exceptions exist.

## Pull request titles: Conventional Commits

`main` only accepts squash merges, and the squash commit takes the PR title as
its subject and the PR body as its message. The PR title is therefore the
commit message, and it must follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>)!: <description>
```

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`. The scope uses lower-case letters, digits
and `. _ / -`; the description is 1-100 characters. The `pr-title` check runs
`scripts/check-pr-title.sh` on every PR. Its workflow also triggers on
`edited`, so editing the title runs the check again, and a title broken
after the check passed fails it again. UNVERIFIED: the re-run on a title
edit has not yet been observed on a PR.

## Signed commits

Every commit on a PR branch must be signed and show as **Verified** on
GitHub; the `main-integrity` ruleset rejects unsigned commits, and GitHub
cannot squash-merge a branch that contains one. We sign with SSH keys
(ordinary ed25519 keys in `ssh-agent`, no per-commit touch):

1. Add your public key to GitHub as a **signing** key, not only as an
   authentication key:

   ```
   gh ssh-key add ~/.ssh/id_ed25519.pub --type signing --title "commit signing"
   ```

2. Commit with an email address that is verified on your GitHub account
   (your `ID+login@users.noreply.github.com` address works).

3. Configure git (repository-local or global):

   ```
   git config gpg.format ssh
   git config user.signingkey "key::$(cat ~/.ssh/id_ed25519.pub)"
   git config commit.gpgsign true
   git config tag.gpgsign true
   ```

   The `key::` form makes git ask `ssh-agent` for the private key, so the
   key file itself never needs to be on disk.

**Windows:** the `ssh-keygen` bundled with Git for Windows cannot reach the
Windows OpenSSH agent. Point git at the system OpenSSH instead:

```
git config gpg.ssh.program C:/Windows/System32/OpenSSH/ssh-keygen.exe
```

## Required checks

The `main-integrity` ruleset requires these 17 checks. Each name is a job
name (with its matrix value) in one of the workflows under
`.github/workflows/`:

| Check | Workflow | What it does |
|---|---|---|
| `build-test` | `ci.yml` | `go mod verify`, static build, cross-compile for windows/darwin/freebsd, `go vet`, `gofmt`, tests with the race detector |
| `lint` | `ci.yml` | golangci-lint v2.14.0 with `.golangci.yml` |
| `govulncheck` | `ci.yml` | reachable-vulnerability scan of the default build with the pinned govulncheck in `tools/go.mod` (the `-tags piv` build is scanned in `build-piv`) |
| `dependency-firewall` | `ci.yml` | `scripts/dep-firewall.sh`: no banned package in keyroster-signer's dependency graph, with and without `-tags piv` |
| `capslock` | `ci.yml` | `scripts/capslock-check.sh`: no new (package, capability) pair for keyroster-signer compared with `test/capslock/keyroster-signer.json` |
| `fuzz` | `ci.yml` | `scripts/fuzz.sh`: every native fuzz target for 30 s; fails when any target fails or when zero targets ran |
| `pr-title` | `pr-title.yml` | Conventional Commits check of the PR title (runs on pull requests only, also when the title is edited) |
| `e2e (9.5p1)` | `e2e.yml` | the `test/e2e` suite against a non-root sshd built from portable OpenSSH 9.5p1 (`scripts/build-openssh.sh`: SHA-256-pinned, GPG-verified) |
| `e2e (10.5p1)` | `e2e.yml` | the same suite against portable OpenSSH 10.5p1 |
| `e2e-pkcs11 (distro-p256)` | `e2e-pkcs11.yml` | the PKCS#11 path with P-256 keys in SoftHSM2, reached through Ubuntu's own ssh-agent |
| `e2e-pkcs11 (10.5p1-ed25519)` | `e2e-pkcs11.yml` | the PKCS#11 path with Ed25519 keys in SoftHSM2, reached through the OpenSSH 10.5p1 ssh-agent |
| `e2e-tpm` | `e2e-tpm.yml` | `ca-init --backend tpm` and the TPM keystore tests against swtpm |
| `build-piv` | `piv.yml` | govulncheck, vet, lint, tests and build of the `-tags piv` YubiKey backend, and proof that default builds link neither piv-go nor cgo; also runs nightly |
| `systemd-sandbox` | `systemd.yml` | keyroster-signer under its real systemd units: bootstrap, issuance, `lo`-only network namespace, `systemd-analyze security` gate |
| `pinned-actions` | `workflow-lint.yml` | `scripts/check-pinned-actions.sh`: every action is pinned to a commit SHA |
| `Analyze (go)` | `codeql.yml` | CodeQL analysis of the Go code, built both static and with `-tags piv` (UNVERIFIED: that the extractor picks up the piv files from the second build has not been checked in a CI run) |
| `Analyze (actions)` | `codeql.yml` | CodeQL analysis of the workflows |

**OpenSSH 9.5p2 is not covered by CI.** Windows ships Microsoft's own
`OpenSSH_for_Windows_9.5p2`, which has no upstream release. Portable 9.5p1 is
the closest upstream code, so CI runs that; the evidence for Windows OpenSSH
9.5p2 is the manual check in `test/manual/` (see its README for the last
result).

The checks are strict: the branch must be up to date with `main` before it
can merge. Renaming a job or changing a matrix blocks every merge until
the ruleset is updated, so job names change only together with
`.github/rulesets/main-integrity.json`.

## Pull request flow

1. Branch from the current `origin/main` (`git fetch origin && git switch -c
   <branch> origin/main`).
2. Commit signed commits, push the branch and open a PR with a Conventional
   Commits title.
3. Enable auto-merge with squash (`gh pr merge --auto --squash`). GitHub
   merges as soon as every rule is satisfied.
4. The code owner (`@Labontese`, see `.github/CODEOWNERS`) reviews and
   approves. A new push dismisses an earlier approval, the approval must come
   from someone other than the last pusher, and every review thread must be
   resolved.

### Claude's pull requests (keyroster-bot)

Claude works through its own GitHub account, `keyroster-bot`, so that
required review involves two real identities. The bot is a collaborator with
write access only: it can push branches and open PRs, but it cannot approve
its own PRs, bypass a ruleset or administer the repository. It signs its
commits with its own SSH key.

- `scripts/gh-as-bot.sh` runs `gh` as the bot (its own gh config directory,
  with `GH_TOKEN` and `GITHUB_TOKEN` unset so the owner's token never
  applies).
- Each Claude PR carries the code of one plan together with that plan's
  planning documents (SUMMARY and tracking updates), and ends at a merge gate
  driven by `scripts/merge-gate.sh BRANCH`. The script reports whether the
  owner's approval is pending, waits for auto-merge after approval and then
  fast-forwards local `main`. It talks to GitHub only as the bot, never
  submits a review and never merges as administrator. It carries its own
  copy of the `gh-as-bot.sh` command, because after switching to the PR
  branch the file on disk is the PR's unreviewed copy, and it stops unless
  `gh api user` answers `keyroster-bot`. Its `git fetch` and `git push` set
  their own credential helper (the bot's gh login, `GH_TOKEN` and
  `GITHUB_TOKEN` unset), so the clone's or the user's git credential
  configuration cannot make the force-push go out as the owner.
- When `main` moved after the PR was opened, the bot rebases the feature
  branch onto `origin/main`, re-signs the commits, force-pushes with lease and
  waits for green checks; the owner then approves the new head.
- **The owner never clicks "Update branch" on a bot PR.** That would make the
  owner the last pusher, and `require_last_push_approval` would then refuse
  the owner's own approval. The bot rebases instead.
- Claude never approves or merges a PR with the owner's credentials.

## Owner bypass policy

The repository has two rulesets on the default branch, and GitHub enforces
the union of both:

- **`main-integrity`** — no bypass actors at all. It blocks deletion and
  force pushes, requires linear history and signed commits, and requires the
  checks above. Nobody, including the owner, can skip it.
- **`main-review`** — requires one approving code-owner review with stale
  review dismissal, last-push approval and resolved threads, and allows only
  squash merges. Its single bypass actor is the repository **admin** role in
  `pull_request` mode.

The bypass exists because this is a small team: the owner's own PRs have no
second human reviewer. The rules for using it:

- It skips **only** the review requirement of `main-review`. Signed commits,
  CI and every other rule of `main-integrity` still apply.
- It works **only through a pull request**. A direct push to `main` is
  rejected for everyone, the owner included (`pull_request` bypass mode, never
  `exempt`, so GitHub writes an audit entry for every use).
- Every use is logged by GitHub (rule insights and the audit log).
- The PR body must declare it with this exact line:

  ```
  Bypass: owner-authored, no second reviewer
  ```

- It is never used for a bot PR. Bot PRs always wait for the owner's
  approval.
- The bot never holds admin rights, so it can never use the bypass.

## Changing the rulesets

The rulesets live in `.github/rulesets/` as JSON. A change goes through a
normal PR; after it merges, the owner runs `bash scripts/apply-rulesets.sh`
with the owner's gh login, which creates or updates each ruleset by name.

A new required check is the exception to "after it merges". A check becomes
required only after it has reported success on the PR that introduces it,
because a required check that never reports blocks every merge. The owner
applies that ruleset from the PR branch once the new check is green on the
PR, and before approving. The PR then shows that the new context resolves
before anything merges. If that PR is later abandoned, the owner runs the
script again from `main` to restore the previous list.

## Security issues

Do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
