#!/usr/bin/env bash
# Merge gate of the phase Delivery Protocol (01-SKELETON.md): drives one plan
# PR from "waiting for the owner" to "squash-merged and local main
# fast-forwarded".
#
#   bash scripts/merge-gate.sh [--check] BRANCH
#
# Exit codes:
#   0  merged; local main equals origin/main
#   1  error: closed PR, failing check, timeout, dirty or diverged checkout
#   2  owner approval pending (the PR URL is printed)
#   3  main moved: the branch was rebased onto origin/main with signed
#      commits, force-pushed with lease and is green again; GitHub dismissed
#      the approval, so the owner must approve the new head
#   4  rebase conflict; the rebase is left in progress for manual resolution
#
# --check is read-only (apart from `git fetch`): exit 0 only when the PR is
# merged and local main equals origin/main, otherwise exit 1.
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
# (E-WR-02).

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

	local check=0
	if [ "${1:-}" = "--check" ]; then
		check=1
		shift
	fi
	if [ "$#" -ne 1 ] || [ -z "$1" ]; then
		echo "usage: $0 [--check] BRANCH" >&2
		return 1
	fi
	local branch=$1

	cd "$(git rev-parse --show-toplevel)"

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

# Rebase BRANCH onto origin/main with signed commits, force-push it with lease,
# keep auto-merge enabled and wait for the required checks. Returns 0 when the
# rebased head is green, 1 on error, 4 on a rebase conflict.
#
# The caller invokes this in an `||` list, where bash suspends errexit, so
# every step that can fail checks its own status.
rebase_onto_main() {
	local branch=$1 url=$2 remote_sha auto
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
		echo "resolve, run 'git rebase --continue', then rerun this script" >&2
		return 4
	fi

	bot_git push --quiet --force-with-lease="refs/heads/$branch:$remote_sha" origin "$branch" || return 1

	auto=$(bot_gh pr view "$branch" --json autoMergeRequest --jq '.autoMergeRequest == null') || return 1
	if [ "$auto" = true ]; then
		bot_gh pr merge "$branch" --auto --squash || return 1
	fi

	wait_for_required_checks "$branch" || return 1
	echo "rebased onto main: owner re-approval needed"
	echo "$url"
	return 0
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
