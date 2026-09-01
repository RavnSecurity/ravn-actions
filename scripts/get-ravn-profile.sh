#!/usr/bin/env bash
# Ravn reporter onboarding — RETIRED. This script now points you at the portal.
#
#   curl -fsSL https://raw.githubusercontent.com/RavnSecurity/ravn-actions/main/scripts/get-ravn-profile.sh | bash
#
# ❗WHY IT IS A REDIRECT AND NOT A DELETION.
#
# This URL is in blog posts, chat scrollback and bookmarks we cannot edit, and a
# 404 tells a reporter that Ravn is broken. A sentence pointing them at the thing
# that does work costs one file and keeps every stale link useful.
#
# ❗WHY IT NO LONGER DOES THE WORK.
#
# It drove the `ravn-profile-template` + `ravn.config.yml` flow, which ADR
# security-005 §4 retires: a collection now exists only if the reporter registered
# one in the portal, and the collector fetches its config over OIDC against that
# registration. A run with no registration is refused `no-binding` BEFORE anything
# is collected — by design, and correctly.
#
# So this script could still create a repository, still set a secret, still start
# a workflow, and still go green — and the run would be refused. A reporter would
# read that refusal in a workflow log and conclude the platform is broken, having
# spent twenty minutes to get there. A script that runs, succeeds, and produces a
# guaranteed failure is worse than one that is gone: it spends the reporter's time
# and then blames the platform.
#
# Exits 0. Nothing here failed — the way in moved.
set -euo pipefail

PORTAL_URL="${RAVN_PORTAL_URL:-https://apps.ravnsecurity.io/app/profile}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'; CYAN=$'\033[36m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
  BOLD=""; CYAN=""; YELLOW=""; RESET=""
fi

cat <<BANNER

${BOLD}Ravn reporter onboarding has moved to the portal.${RESET}

  ${YELLOW}This script no longer collects anything, and running it would not have
  worked.${RESET} It set up the old \`ravn.config.yml\` flow, which Ravn has retired: a
  collection now exists only once you have registered one, so a run started this
  way is refused before it collects a thing.

${BOLD}What to do instead${RESET}

  1. Open ${CYAN}${PORTAL_URL}${RESET}
  2. Connect a source — choose the repository, and tick what it may gather.
     You see exactly what will leave your runner, and what will not, before
     anything is created.
  3. Copy the one command it gives you. It creates the repository if you do not
     have one, sets your secrets locally, commits the collector pinned at an
     approved version, and offers to start the run.
  4. Read the bundle it produces, then upload it. Nothing leaves your machine
     until you have looked at it.

${BOLD}Why the change${RESET}

  What you agreed to share now travels inside the signed digest, so anyone
  reading your evidence can see the shape of your disclosure — including what you
  chose to withhold. That is only honest if the config comes from a place you
  agreed to it, which is why it is issued to a collection you registered rather
  than read from a file in a repository.

BANNER
