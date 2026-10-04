#!/usr/bin/env bash
# Run gh as keyroster-bot, the identity Claude uses for commits, pushes and
# pull requests (D-05). The bot's token lives in its own gh config directory,
# created by the owner's interactive `gh auth login`. GH_TOKEN and
# GITHUB_TOKEN are unset because either one would override that config and
# make the command run as the owner.
#
#   scripts/gh-as-bot.sh pr view p01/01-contributing
#
# Set KEYROSTER_BOT_GH_CONFIG to use a config directory other than
# $HOME/.config/gh-keyroster-bot.
exec env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR="${KEYROSTER_BOT_GH_CONFIG:-$HOME/.config/gh-keyroster-bot}" gh "$@"
