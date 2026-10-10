#!/usr/bin/env bash
# Merge gate of the phase Delivery Protocol (01-SKELETON.md): drives one plan
# PR from "waiting for the owner" to "squash-merged and local main
# fast-forwarded".
#
#   bash scripts/merge-gate.sh [--check] BRANCH
#
# Exit codes:
#   0  merged; local main equals origin/main
#   1  error: closed PR, failing check, timeout, dirty or diverged checkout,
#      a rebase in progress, or this file is not origin/main's copy
#   2  owner approval pending (the PR URL is printed)
#   3  main moved: the branch was rebased onto origin/main with signed
#      commits, force-pushed with lease and is green again; GitHub dismissed
#      the approval, so the owner must approve the new head
#   4  rebase conflict; the rebase is left in progress on BRANCH for manual
#      resolution, so the checkout cannot return to main (the message says
#      how to resume; the script refuses to run until the rebase is done)
#
# --check is read-only (apart from `git fetch`): exit 0 only when the PR is
# merged and local main equals origin/main, otherwise exit 1.
#
# The script runs only as origin/main's reviewed copy (F-WR-03): after its
# fetch it compares its own blob with origin/main's scripts/merge-gate.sh and
# stops when they differ, for example when the checkout is on a PR branch
# that changes this file. Run it from an up-to-date main. Every exit after it
# switched to the PR branch switches back to main, except exit 4.
#
# Every gh call runs as keyroster-bot through bot_gh below, and the script
# checks that identity before it does anything else. Every git fetch and push
# uses the same bot login through bot_git, independent of the clone's
# credential helper. The script never submits
# a review and never merges with administrator rights: approval belongs to
# the owner in the GitHub UI, and GitHub's auto-merge does the squash merge
# once the rulesets are satisfied (D-05).
#
# MERGE_GATE_TIMEOUT (seconds, default 900) bounds the wait for auto-merge
# after approval.
#
# The whole body is functions called on the last line, so bash has parsed
# the complete script before a branch switch replaces this file on disk. That
# is also why bot_gh is defined here instead of calling scripts/gh-as-bot.sh:
# after the switch to the PR branch, that file is the PR's unreviewed copy
# (E-WR-02). The same holds for this file, hence the origin/main check in
# main and the switch back to main.

# bot_gh runs gh as keyroster-bot: the bot's own gh config directory, with
# GH_TOKEN and GITHUB_TOKEN unset because either one would override that
# config and make the command run as the owner. Keep the unset list in sync
# with scripts/gh-as-bot.sh.
bot_gh() {
	env -u GH_TOKEN -u GITHUB_TOKEN \
		GH_CONFIG_DIR="${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot}" gh "$@"
}

# bot_git runs git with the bot's credentials for github.com, whatever
# credential helper the clone or the user configured (E-WR-03). The empty
# helper value clears every helper configured before it (system, global,
# local; -c is read last), and the second one asks gh for the token of the
# same config directory as bot_gh, with the same unset list. The push in
# rebase_onto_main therefore goes out as keyroster-bot, not as the owner.
bot_git() {
	local dir=${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot}
	case $dir in
	*"'"*)
		echo "KEYROSTER_BOT_GH_CONFIG must not contain a single quote" >&2
		return 1
		;;
	esac
	git -c credential.https://github.com.helper= \
		-c "credential.https://github.com.helper=!env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR='$dir' gh auth git-credential" \
		"$@"
}

main() {
	set -euo pipefail

	local args="$*" check=0
	if [ "${1:-}" = "--check" ]; then
		check=1
		shift
	fi
	if [ "$#" -ne 1 ] || [ -z "$1" ]; then
		echo "usage: $0 [--check] BRANCH" >&2
		return 1
	fi
	local branch=$1

	# The blob of the file bash is running, hashed before the cd below so
	# that a relative $0 still names it. Empty when $0 is no file (bash -s).
	local self
	self=$(git hash-object -- "$0" 2>/dev/null) || self=

	cd "$(git rev-parse --show-toplevel)"

	if [ -d "$(git rev-parse --git-path rebase-merge)" ] || [ -d "$(git rev-parse --git-path rebase-apply)" ]; then
		echo "a rebase is in progress: finish it as the earlier exit 4 said, or run 'git rebase --abort'; then 'git switch main' and rerun" >&2
		return 1
	fi

	local login
	login=$(bot_gh api user --jq .login) || {
		echo "cannot ask GitHub who gh runs as; check KEYROSTER_BOT_GH_CONFIG" >&2
		return 1
	}
	if [ "$login" != keyroster-bot ]; then
		echo "gh runs as '$login', not keyroster-bot; check KEYROSTER_BOT_GH_CONFIG" >&2
		return 1
	fi

	bot_git fetch --quiet origin

	# Run only as the reviewed copy (F-WR-03). ls-tree rather than
	# rev-parse origin/main:path, which Git Bash's path conversion can mangle.
	local reviewed
	reviewed=$(git ls-tree origin/main -- scripts/merge-gate.sh | awk '{print $3}')
	if [ -z "$self" ] || [ "$self" != "$reviewed" ]; then
		echo "this merge-gate.sh (blob ${self:-unknown: not run from a file}) is not origin/main's reviewed copy (blob ${reviewed:-missing}); refusing to run" >&2
		echo "run it from an up-to-date main: git switch main && git merge --ff-only origin/main && bash scripts/merge-gate.sh $args" >&2
		return 1
	fi

	local view number state decision merge_state url
	# "|" separates the fields: a tab would collapse an empty reviewDecision.
	view=$(bot_gh pr view "$branch" --json number,state,reviewDecision,mergeStateStatus,url \
		--jq '[(.number | tostring), .state, (.reviewDecision // ""), (.mergeStateStatus // ""), .url] | join("|")')
	IFS='|' read -r number state decision merge_state url <<<"$view"

	if [ "$check" -eq 1 ]; then
		if [ "$state" = MERGED ] && [ "$(git rev-parse --verify --quiet main)" = "$(git rev-parse origin/main)" ]; then
			echo "merged #$number; main equals origin/main"
			return 0
		fi
		echo "not complete: PR #$number is $state; main $(git rev-parse --verify --quiet main || echo missing), origin/main $(git rev-parse origin/main)" >&2
		return 1
	fi

	case "$state" in
	MERGED)
		fast_forward_main
		echo "merged #$number"
		return 0
		;;
	CLOSED)
		echo "PR #$number is closed without merge: $url" >&2
		return 1
		;;
	esac

	if ! git merge-base --is-ancestor origin/main "origin/$branch"; then
		rebase_onto_main "$branch" "$url" || return
		return 3
	fi

	if [ "$decision" != APPROVED ]; then
		echo "$url"
		echo "awaiting owner approval (review: ${decision:-none}, merge state: $merge_state)"
		return 2
	fi

	local timeout=${MERGE_GATE_TIMEOUT:-900} waited=0
	echo "approved; waiting for auto-merge of #$number"
	while [ "$state" != MERGED ]; do
		if [ "$state" = CLOSED ]; then
			echo "PR #$number was closed without merge: $url" >&2
			return 1
		fi
		if [ "$waited" -ge "$timeout" ]; then
			echo "timed out after ${timeout}s; mergeStateStatus=$merge_state: $url" >&2
			return 1
		fi
		sleep 15
		waited=$((waited + 15))
		view=$(bot_gh pr view "$branch" --json state,mergeStateStatus \
			--jq '[.state, (.mergeStateStatus // "")] | join("|")')
		IFS='|' read -r state merge_state <<<"$view"
	done

	bot_git fetch --quiet origin
	fast_forward_main
	echo "merged #$number"
	return 0
}

# Switch to main (created from origin/main if missing) and fast-forward it.
fast_forward_main() {
	if git rev-parse --verify --quiet refs/heads/main >/dev/null; then
		git switch --quiet main
	else
		git switch --quiet -c main --track origin/main
	fi
	git merge --quiet --ff-only origin/main
}

# Switch back to main (created from origin/main if missing) after
# rebase_onto_main switched to the PR branch, so that the checkout does not
# stay on the PR's copy of this script. It does not move main.
back_to_main() {
	if git rev-parse --verify --quiet refs/heads/main >/dev/null; then
		git switch --quiet main
	else
		git switch --quiet -c main --track origin/main
	fi || {
		echo "could not switch back to main; run 'git switch main' before rerunning this script" >&2
		return 1
	}
}

# Rebase BRANCH onto origin/main with signed commits, then push it and wait
# for the required checks (push_rebased), and switch back to main. Returns 0
# when the rebased head is green, 1 on error, 4 on a rebase conflict (the
# rebase stays in progress on BRANCH).
#
# The caller invokes this in an `||` list, where bash suspends errexit, so
# every step that can fail checks its own status.
rebase_onto_main() {
	local branch=$1 url=$2 remote_sha rc=0
	remote_sha=$(git rev-parse "origin/$branch") || return 1

	if git rev-parse --verify --quiet "refs/heads/$branch" >/dev/null; then
		if [ "$(git rev-parse "refs/heads/$branch")" != "$remote_sha" ]; then
			echo "local $branch differs from origin/$branch; push or reset it first" >&2
			return 1
		fi
		git switch --quiet "$branch" || return 1
	else
		git switch --quiet -c "$branch" --track "origin/$branch" || return 1
	fi

	# --autostash keeps unrelated local edits (for example GSD's working
	# state files) out of the way of the rebase and restores them afterwards.
	if ! git rebase --quiet --autostash --gpg-sign origin/main; then
		echo "rebase conflict in:" >&2
		git diff --name-only --diff-filter=U >&2
		echo "The rebase is left in progress on $branch, so the checkout cannot return to main," >&2
		echo "and this script refuses to run until the rebase is finished or aborted. To resume:" >&2
		echo "  1. resolve the conflicts, 'git add' them and run 'git rebase --continue';" >&2
		echo "  2. push the result as keyroster-bot (bot_git's credential helper, never the" >&2
		echo "     clone's: the owner must not become the last pusher), with a lease on the" >&2
		echo "     head this script saw:" >&2
		echo "     git -c credential.https://github.com.helper= -c 'credential.https://github.com.helper=!env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR=\"${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot}\" gh auth git-credential' push --force-with-lease=refs/heads/$branch:$remote_sha origin $branch" >&2
		echo "  3. 'git switch main', then rerun this script from main." >&2
		echo "To give up instead: 'git rebase --abort', then 'git switch main'." >&2
		return 4
	fi

	push_rebased "$branch" "$remote_sha" || rc=$?
	if [ "$rc" -eq 0 ]; then
		# Before the switch, so a failed switch still reports the push.
		echo "rebased onto main: owner re-approval needed"
		echo "$url"
	fi
	back_to_main || return 1
	return "$rc"
}

# Force-push the rebased BRANCH with a lease on REMOTE_SHA, keep auto-merge
# enabled and wait for the required checks. Returns 0 when they pass, 1
# otherwise.
push_rebased() {
	local branch=$1 remote_sha=$2 auto
	bot_git push --quiet --force-with-lease="refs/heads/$branch:$remote_sha" origin "$branch" || return 1

	auto=$(bot_gh pr view "$branch" --json autoMergeRequest --jq '.autoMergeRequest == null') || return 1
	if [ "$auto" = true ]; then
		bot_gh pr merge "$branch" --auto --squash || return 1
	fi

	wait_for_required_checks "$branch" || return 1
}

# Wait until GitHub has registered the required checks for the pushed head,
# then watch them. Returns non-zero when a required check fails.
wait_for_required_checks() {
	local branch=$1 head tries=0 rc
	head=$(git rev-parse "$branch")
	until [ "$(bot_gh pr view "$branch" --json headRefOid --jq .headRefOid)" = "$head" ]; do
		tries=$((tries + 1))
		[ "$tries" -le 24 ] || { echo "GitHub never saw head $head" >&2; return 1; }
		sleep 5
	done
	tries=0
	while :; do
		rc=0
		bot_gh pr checks "$branch" --required >/dev/null 2>&1 || rc=$?
		# 0 = all passed, 8 = some pending; anything else usually means the
		# checks have not been reported yet right after a push.
		if [ "$rc" -eq 0 ] || [ "$rc" -eq 8 ]; then
			break
		fi
		tries=$((tries + 1))
		[ "$tries" -le 24 ] || break
		sleep 5
	done
	bot_gh pr checks "$branch" --required --watch
}

main "$@"; exit
