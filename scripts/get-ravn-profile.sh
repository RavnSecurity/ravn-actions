#!/usr/bin/env bash
# Ravn reporter onboarding.
#
# Creates your own copy of Ravn's profile-template repo, optionally wires
# up a read-only PAT for full visibility, runs the collector workflow, and
# hands you back a signed, verifiable profile digest — all from your
# terminal, with no state left anywhere except the repo it creates for you.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RavnSecurity/ravn-actions/main/scripts/get-ravn-profile.sh | bash
#
# Requires: gh (authenticated via `gh auth login`), git.
set -euo pipefail

TEMPLATE_SOURCE="RavnSecurity/ravn-profile-template"
WORKFLOW_NAME="Generate Ravn Profile"
SECRET_NAME="RAVN_READONLY_TOKEN"

# ---------- output helpers ----------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

TOTAL_STEPS=9
STEP_NUM=0
step()  { STEP_NUM=$((STEP_NUM + 1)); printf '\n%s[%d/%d] %s%s\n' "${BOLD}${CYAN}" "$STEP_NUM" "$TOTAL_STEPS" "$1" "$RESET"; }
info()  { printf '    %s\n' "$1"; }
ok()    { printf '    %s%s%s\n' "$GREEN" "$1" "$RESET"; }
warn()  { printf '    %s%s%s\n' "$YELLOW" "$1" "$RESET"; }
err()   { printf '%s%s%s\n' "$RED" "$1" "$RESET" >&2; }

confirm() { # confirm "question" Y|N(default) -> exit status
  local reply default="${2:-Y}" prompt="[y/N]"
  [ "$default" = "Y" ] && prompt="[Y/n]"
  read -r -p "    $1 $prompt " reply
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy] ]]
}

ask() { # ask "question" default -> echoes the answer
  local reply
  read -r -p "    $1 [$2]: " reply
  echo "${reply:-$2}"
}

trap 'err "Something went wrong. Re-running this script is safe — it picks up where it left off."' ERR

# curl | bash leaves stdin attached to the piped script, not your keyboard.
# Reattach it to the real terminal so prompts below actually work.
if [ -r /dev/tty ]; then
  exec < /dev/tty
else
  err "No interactive terminal available (needed to prompt you for choices)."
  exit 1
fi

printf '%s\n' "${BOLD}Ravn profile setup${RESET}"
info "This creates your own copy of $TEMPLATE_SOURCE, runs Ravn's"
info "collector workflow inside it, and gives you back a signed digest"
info "you can hand to a triager. Nothing leaves your GitHub account"
info "except what you explicitly opt into below."

# ---------- 1. prerequisites ----------
step "Checking prerequisites"
command -v git >/dev/null 2>&1 || { err "git is required. Install it and re-run."; exit 1; }
ok "git found"
command -v gh  >/dev/null 2>&1 || { err "GitHub CLI (gh) is required: https://cli.github.com"; exit 1; }
ok "gh found"

if ! gh auth status >/dev/null 2>&1; then
  warn "You're not logged into gh yet."
  if confirm "Run 'gh auth login' now?" Y; then
    gh auth login
  else
    err "Can't continue without gh auth. Run 'gh auth login' and re-run this script."
    exit 1
  fi
fi
ME=$(gh api user --jq .login)
ok "Logged in as $ME"

# ---------- 2. where should this live ----------
step "Choosing where your copy lives"
OWNER=$(ask "GitHub owner to create the repo under" "$ME")
REPO_NAME=$(ask "Repository name" "ravn-profile-template")
REPO="$OWNER/$REPO_NAME"

REUSE=0
if gh repo view "$REPO" >/dev/null 2>&1; then
  warn "$REPO already exists."
  if confirm "Reuse it (clone instead of creating)?" Y; then
    REUSE=1
  else
    err "Pick a different name and re-run."
    exit 1
  fi
fi

echo
info "About to create ${BOLD}$REPO${RESET} (public — required for signed"
info "attestations) generated from $TEMPLATE_SOURCE."
confirm "Proceed?" Y || { info "Stopped — nothing created."; exit 0; }

# ---------- 3. create + clone ----------
step "Creating your repo"
if [ "$REUSE" = 1 ]; then
  [ -d "$REPO_NAME" ] || gh repo clone "$REPO"
else
  gh repo create "$REPO" --template "$TEMPLATE_SOURCE" --public --clone
fi
cd "$REPO_NAME"
WORKDIR="$(pwd)"
ok "Ready at $WORKDIR"

# ---------- 4. optional PAT ----------
step "Optional: read-only PAT for full visibility"
info "Without this, the collector only sees this one repo (via the run's"
info "own token) — account age and contribution history still populate"
info "from public data, but repo/language signal comes back empty."

SET_PAT=0
if gh secret list --repo "$REPO" --json name --jq '.[].name' 2>/dev/null | grep -qx "$SECRET_NAME"; then
  warn "$SECRET_NAME is already set on this repo."
  confirm "Replace it?" N && SET_PAT=1
else
  confirm "Set one up now? (opens github.com in your browser)" Y && SET_PAT=1
fi

if [ "$SET_PAT" = 1 ]; then
  PAT_URL="https://github.com/settings/personal-access-tokens/new"
  info "1. Resource owner: yourself"
  info "2. Repository access: All repositories (needed to see private repos)"
  info "3. Permissions -> Repository permissions -> Metadata: Read-only"
  info "4. Set an expiration, generate, then copy the token"
  if command -v open >/dev/null 2>&1; then
    open "$PAT_URL" 2>/dev/null || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$PAT_URL" 2>/dev/null || true
  fi
  info "$PAT_URL"
  read -rs -p "    Paste the token here (input hidden): " RAVN_PAT
  echo
  if [ -n "$RAVN_PAT" ]; then
    printf '%s' "$RAVN_PAT" | gh secret set "$SECRET_NAME" --repo "$REPO"
    unset RAVN_PAT
    ok "$SECRET_NAME set."
  else
    warn "No token entered — skipping."
  fi
fi

# ---------- 5. sharing preferences ----------
step "What are you comfortable sharing?"
CONFIG_FILE="ravn.config.yml"
info "Current settings in $CONFIG_FILE:"
grep -E '^share_' "$CONFIG_FILE" | sed 's/^/      /'

if ! confirm "Keep these as-is?" Y; then
  while IFS= read -r line; do
    key="${line%%:*}"
    rest="${line#*: }"
    cur="${rest%%[[:space:]]*}"
    desc="${line#*# }"
    default="N"; [ "$cur" = "true" ] && default="Y"
    new=false
    confirm "  $key — $desc" "$default" && new=true
    tmp=$(mktemp)
    # Literal (non-regex) match on "key: current-value" only — leaves spacing
    # and the trailing comment (which may itself contain "/") untouched.
    sed "s/^${key}: ${cur}/${key}: ${new}/" "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
  done < <(grep -E '^share_' "$CONFIG_FILE")

  if ! git diff --quiet -- "$CONFIG_FILE"; then
    git commit -qam "Adjust ravn.config.yml sharing preferences"
    git push -q
    ok "Pushed updated $CONFIG_FILE."
  else
    info "No changes."
  fi
fi

# ---------- 6. run the collector ----------
step "Running the collector"
gh workflow run "$WORKFLOW_NAME" --repo "$REPO"
info "Triggered — waiting for it to register…"
RUN_ID=""
for _ in $(seq 1 15); do
  RUN_ID=$(gh run list --repo "$REPO" --workflow "$WORKFLOW_NAME" --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
  [ -n "$RUN_ID" ] && break
  sleep 2
done
if [ -z "$RUN_ID" ]; then
  err "Couldn't find the run. Check the Actions tab: https://github.com/$REPO/actions"
  exit 1
fi
ok "Run: https://github.com/$REPO/actions/runs/$RUN_ID"

if ! gh run watch "$RUN_ID" --repo "$REPO" --exit-status; then
  err "The workflow run failed. Check the log:"
  err "  https://github.com/$REPO/actions/runs/$RUN_ID"
  exit 1
fi

# ---------- 7. download the digest ----------
step "Downloading your digest"
OUTDIR="$WORKDIR/ravn-profile-digest"
rm -rf "$OUTDIR"
gh run download "$RUN_ID" --repo "$REPO" -n ravn-profile-digest -D "$OUTDIR"
ok "Saved to $OUTDIR"
echo
cat "$OUTDIR/profile-summary.md"

# ---------- 8. verify the signature ----------
step "Verifying the signature"
if gh attestation verify "$OUTDIR/profile-digest.json" --owner "$OWNER"; then
  ok "Signature checks out."
else
  warn "Signature check failed — don't submit this digest as-is."
fi

# ---------- 9. done ----------
step "Done"
info "Digest:  $OUTDIR/profile-digest.json"
info "Summary: $OUTDIR/profile-summary.md"
info "Hand profile-digest.json to your Ravn contact along with the repo"
info "it came from ($REPO) — they'll re-verify it against Ravn's approved"
info "workflow list before trusting it as triager context."
