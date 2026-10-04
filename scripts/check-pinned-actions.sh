#!/usr/bin/env bash
# Fail when a workflow references an action or reusable workflow by anything
# other than a full commit SHA. Tags and branches are mutable: whoever controls
# the action's repository can point them at new code, which then runs with the
# job's token and our source checkout (T-01-19). Local actions (./path) are
# allowed.
#
#   bash scripts/check-pinned-actions.sh [DIR]
#
# DIR defaults to .github/workflows and every file below it is scanned.
# Exit 0 when every uses: reference is pinned, 1 when any is not (each one is
# printed as file:line), 2 on usage errors.
set -euo pipefail

dir=${1:-.github/workflows}
if [ ! -d "$dir" ]; then
	echo "check-pinned-actions: $dir is not a directory" >&2
	exit 2
fi

# A uses: key, optionally as the first key of a list item.
uses_re='^[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*(.*)$'
# owner/repo[/path]@ followed by exactly 40 lowercase hex characters.
pinned_re='^[^@[:space:]]+@[0-9a-f]{40}$'

refs=0
bad=0
while IFS= read -r -d '' file; do
	lineno=0
	while IFS= read -r line || [ -n "$line" ]; do
		lineno=$((lineno + 1))
		line=${line%$'\r'}
		[[ $line =~ $uses_re ]] || continue
		value=${BASH_REMATCH[2]}
		value=${value%%#*} # trailing "# v1.2.3" comment
		value=${value%"${value##*[![:space:]]}"}
		value=${value#[\"\']}
		value=${value%[\"\']}
		refs=$((refs + 1))
		if [[ $value == ./* ]] || [[ $value =~ $pinned_re ]]; then
			continue
		fi
		echo "$file:$lineno: not pinned to a 40-character commit SHA: ${value:-<empty>}"
		bad=$((bad + 1))
	done <"$file"
done < <(find "$dir" -type f -print0 | sort -z)

if [ "$bad" -gt 0 ]; then
	echo "check-pinned-actions: $bad of $refs uses: references are not pinned to a commit SHA" >&2
	exit 1
fi
echo "check-pinned-actions: all $refs uses: references in $dir are pinned to commit SHAs"
