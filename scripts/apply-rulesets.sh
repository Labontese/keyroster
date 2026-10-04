#!/usr/bin/env bash
# Create or update the repository rulesets from .github/rulesets/*.json.
#
#   bash scripts/apply-rulesets.sh
#
# Each file is named after its ruleset (main-integrity.json holds the ruleset
# "main-integrity"). An existing ruleset with that name is replaced with PUT,
# a missing one is created with POST. Rulesets change only through a reviewed
# PR followed by this script, run by the owner with the owner's gh login
# (keyroster-bot has no admin rights and cannot change rulesets).
set -euo pipefail

repo=Labontese/keyroster
cd "$(git rev-parse --show-toplevel)"

login=$(gh api user --jq .login)
echo "applying rulesets to $repo as $login"

shopt -s nullglob
files=(.github/rulesets/*.json)
if [ "${#files[@]}" -eq 0 ]; then
	echo "no ruleset files in .github/rulesets" >&2
	exit 1
fi

for file in "${files[@]}"; do
	name=$(basename "$file" .json)
	if ! grep -q "\"name\": \"$name\"" "$file"; then
		echo "$file: the \"name\" field must be \"$name\"" >&2
		exit 1
	fi
	id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
	if [ -n "$id" ]; then
		gh api -X PUT "repos/$repo/rulesets/$id" --input "$file" --jq '"updated \(.name) (id \(.id))"'
	else
		gh api -X POST "repos/$repo/rulesets" --input "$file" --jq '"created \(.name) (id \(.id))"'
	fi
done
