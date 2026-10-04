#!/usr/bin/env bash
# Apply the repository's security and GitHub Actions settings (REPO-02,
# REPO-03) and print the resulting state.
#
#   bash scripts/apply-security-settings.sh
#
# Every call is idempotent, so the script can be rerun at any time to restore
# the intended state. Like scripts/apply-rulesets.sh it must run with the
# owner's gh login: these endpoints need admin rights, which keyroster-bot
# deliberately does not have.
set -euo pipefail

repo=Labontese/keyroster

login=$(gh api user --jq .login)
echo "applying security settings to $repo as $login"

# Secret scanning and push protection (T-01-20).
printf '%s' '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' |
	gh api -X PATCH "repos/$repo" --input - --silent
echo "secret scanning + push protection: enabled"

# Private vulnerability reporting, the only reporting channel (T-01-21).
gh api -X PUT "repos/$repo/private-vulnerability-reporting" --silent
echo "private vulnerability reporting: enabled"

# Dependabot alerts, then security updates (which require alerts) (T-01-22).
gh api -X PUT "repos/$repo/vulnerability-alerts" --silent
gh api -X PUT "repos/$repo/automated-security-fixes" --silent
echo "dependabot alerts + security updates: enabled"

# GITHUB_TOKEN read-only by default; Actions may never approve a PR (T-01-18).
gh api -X PUT "repos/$repo/actions/permissions/workflow" \
	-f default_workflow_permissions=read \
	-F can_approve_pull_request_reviews=false --silent
echo "workflow token: read-only, cannot approve pull requests"

# Only selected actions, pinned to full commit SHAs (T-01-19). If the API
# rejects sha_pinning_required, scripts/check-pinned-actions.sh (the
# pinned-actions check) still enforces pinning.
if gh api -X PUT "repos/$repo/actions/permissions" \
	-F enabled=true -f allowed_actions=selected -F sha_pinning_required=true --silent; then
	echo "actions: selected only, sha_pinning_required accepted"
else
	echo "actions: API rejected sha_pinning_required; retrying without it" >&2
	gh api -X PUT "repos/$repo/actions/permissions" \
		-F enabled=true -f allowed_actions=selected --silent
	echo "actions: selected only, sha_pinning_required NOT set"
fi

printf '%s' '{"github_owned_allowed":true,"verified_allowed":false,"patterns_allowed":["golangci/golangci-lint-action@*","ossf/scorecard-action@*"]}' |
	gh api -X PUT "repos/$repo/actions/permissions/selected-actions" --input - --silent
echo "allowed actions: GitHub-owned, golangci/golangci-lint-action, ossf/scorecard-action"

echo
echo "resulting state:"
gh api "repos/$repo" --jq '.security_and_analysis | "  secret_scanning=\(.secret_scanning.status) push_protection=\(.secret_scanning_push_protection.status) dependabot_security_updates=\(.dependabot_security_updates.status)"'
gh api "repos/$repo/private-vulnerability-reporting" --jq '"  private_vulnerability_reporting=\(.enabled)"'
if gh api "repos/$repo/vulnerability-alerts" --silent 2>/dev/null; then
	echo "  vulnerability_alerts=enabled"
else
	echo "  vulnerability_alerts=DISABLED"
fi
gh api "repos/$repo/actions/permissions/workflow" --jq '"  default_workflow_permissions=\(.default_workflow_permissions) can_approve_pull_request_reviews=\(.can_approve_pull_request_reviews)"'
gh api "repos/$repo/actions/permissions" --jq '"  actions_enabled=\(.enabled) allowed_actions=\(.allowed_actions) sha_pinning_required=\(.sha_pinning_required)"'
gh api "repos/$repo/actions/permissions/selected-actions" --jq '"  github_owned_allowed=\(.github_owned_allowed) verified_allowed=\(.verified_allowed) patterns_allowed=\(.patterns_allowed | join(","))"'
