#!/usr/bin/env bash
# Check that a pull request title follows Conventional Commits. The squash
# commit on main uses the PR title, so this keeps main's history conventional.
#
# The title comes from the PR_TITLE environment variable, never from a
# command-line argument or template interpolation, because it is
# attacker-controlled input.
set -euo pipefail

pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: .{1,100}$'

title="${PR_TITLE-}"
if [ -z "$title" ]; then
	echo "PR_TITLE is empty or unset" >&2
	exit 1
fi

if printf '%s' "$title" | grep -Eq -- "$pattern" && [ "$(printf '%s' "$title" | wc -l)" -eq 0 ]; then
	echo "PR title OK"
	exit 0
fi

cat >&2 <<'EOF'
PR title does not follow Conventional Commits.

Expected: <type>[(<scope>)][!]: <description>
  type:        feat, fix, docs, style, refactor, perf, test, build, ci, chore or revert
  scope:       optional; lower-case letters, digits and . _ / -
  description: 1 to 100 characters

Examples:
  feat(ca): add certificate issuance
  docs: add contributing guide and repository rulesets
EOF
printf 'Got: %s\n' "$title" >&2
exit 1
