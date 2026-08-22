#!/usr/bin/env bash
# Ravn reporter onboarding.
#
# Creates your own copy of Ravn's profile-template repo, optionally wires
# up a read-only PAT for full visibility, runs the collector workflow, and
# hands you back a signed, verifiable profile digest PLUS the submission
# bundle (ravn-profile-bundle.json) the Ravn portal accepts — all from your
# terminal, with no state left anywhere except the repo it creates for you.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/RavnSecurity/ravn-actions/main/scripts/get-ravn-profile.sh | bash
#
# Requires: gh (authenticated via `gh auth login`), git, jq.
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

TOTAL_STEPS=10
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

# sha256 across coreutils (sha256sum) and macOS (shasum) flavors.
sha256_file()  { { command -v sha256sum >/dev/null 2>&1 && sha256sum "$1" || shasum -a 256 "$1"; } | awk '{print $1}'; }
sha256_stdin() { { command -v sha256sum >/dev/null 2>&1 && sha256sum      || shasum -a 256;      } | awk '{print $1}'; }

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
command -v jq  >/dev/null 2>&1 || { err "jq is required (bundle assembly): https://jqlang.org"; exit 1; }
ok "jq found"

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
if [ "$REUSE" = 1 ] && ! git pull -q --ff-only 2>/dev/null; then
  warn "Couldn't fast-forward your clone (diverged/offline?) — using it as-is."
fi
ok "Ready at $WORKDIR"

# An existing copy may be pinned to an older collector. The pin is what ends up
# in the signed provenance, so newer = the hardened workflow + the in-run
# bundle assembly. Old pins still verify (the approved list is append-only) —
# this is an upgrade offer, not a requirement.
if [ "$REUSE" = 1 ]; then
  WF_FILE=".github/workflows/generate-ravn-profile.yml"
  # Raw media type: no base64 decode (BSD/GNU flag mess) and no newline question.
  LATEST_PIN=$(gh api -H "Accept: application/vnd.github.raw" \
      "repos/$TEMPLATE_SOURCE/contents/$WF_FILE" 2>/dev/null \
    | grep -oE 'collect-profile\.yml@[0-9a-f]{40}' | head -n1 | cut -d@ -f2 || true)
  LOCAL_PIN=$(grep -oE 'collect-profile\.yml@[0-9a-f]{40}' "$WF_FILE" | head -n1 | cut -d@ -f2 || true)
  if [ -n "$LATEST_PIN" ] && [ -n "$LOCAL_PIN" ] && [ "$LATEST_PIN" != "$LOCAL_PIN" ]; then
    warn "Your copy pins collector ${LOCAL_PIN:0:7}; the template now pins ${LATEST_PIN:0:7}."
    if confirm "Update your copy to the latest collector?" Y; then
      tmp=$(mktemp)
      sed "s/collect-profile\.yml@${LOCAL_PIN}/collect-profile.yml@${LATEST_PIN}/" "$WF_FILE" > "$tmp" \
        && mv "$tmp" "$WF_FILE"
      # ❗Pathspec commit, never -a: a reused clone may carry the user's own
      # uncommitted work, which is not ours to publish — or to destroy when
      # unwinding below. Guarded: a machine with no git identity fails here,
      # not the whole onboarding.
      if git commit -q -m "Update collector pin to ${LATEST_PIN:0:7} (latest approved)" -- "$WF_FILE" \
        && git push -q; then
        # gh's own OAuth token carries the workflow scope, so the push
        # normally succeeds; a bare PAT without it lands in the else.
        ok "Pinned to ${LATEST_PIN:0:7} and pushed."
      else
        # Unwind ONLY our change, whichever step refused: drop the pin commit
        # if it was made, restore just the workflow file, touch nothing else.
        git log -1 --format=%s 2>/dev/null | grep -q '^Update collector pin' && git reset -q HEAD~1
        git checkout -q HEAD -- "$WF_FILE" 2>/dev/null || true
        warn "Couldn't push the pin update (missing git identity, or a git"
        warn "credential without the 'workflow' scope). Your files are untouched —"
        warn "update the pin by editing $WF_FILE in the GitHub web UI instead."
      fi
    fi
  elif [ -n "$LATEST_PIN" ] && [ -n "$LOCAL_PIN" ]; then
    ok "Collector pin is current in your clone (${LOCAL_PIN:0:7})."
  else
    warn "Couldn't check the template's latest pin (offline?) — continuing with yours."
  fi
fi

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

# ---------- 5b. what else should count? ----------
#
# Ravn cannot enumerate every project or platform that matters, and pretending
# otherwise is how good reporters get under-read. So we ask.
#
# ❗Everything captured here is carried as the reporter's OWN assertion and is
# labelled that way end to end. Riding inside the signed digest makes it
# tamper-evident and non-repudiable; it never makes it verified.

# ❗Splice under the KEY, never append at EOF. `ravn.config.yml` ends with the
# assertions block, so a `>>` append files nominated repositories as assertions —
# silently, and the digest looks fine.
yaml_splice() { # $1 = top-level key, $2 = file of lines to insert beneath it
  _tmp=$(mktemp)
  awk -v key="$1:" -v ins="$2" '
    { print }
    !done && $0 == key { while ((getline line < ins) > 0) print line; close(ins); done = 1 }
  ' "$CONFIG_FILE" > "$_tmp" && mv "$_tmp" "$CONFIG_FILE"
  rm -f "$2"
}

step "Anything else we should count?"
info "Ravn checks a published list of notable projects automatically."
info "You can also point us at work that list misses."

if confirm "Nominate repositories you have contributed to?" N; then
  PENDING=$(mktemp)
  while true; do
    printf '  owner/repo (blank to finish): '
    read -r nr || break
    [ -z "$nr" ] && break
    case "$nr" in
      */*) printf '  - %s\n' "$nr" >> "$PENDING"; ok "Added $nr." ;;
      *) warn "Expected owner/repo — skipped." ;;
    esac
  done
  if [ -s "$PENDING" ]; then
    sed -i.bak 's/^nominate_repos: \[\]$/nominate_repos:/' "$CONFIG_FILE" && rm -f "$CONFIG_FILE.bak"
    yaml_splice nominate_repos "$PENDING"
  else
    rm -f "$PENDING"
  fi
fi

if confirm "Point us at anything else (another platform, a CVE, a package, a talk)?" N; then
  PENDING=$(mktemp)
  while true; do
    printf '  URL (blank to finish): '
    read -r ptr || break
    [ -z "$ptr" ] && break
    printf '  what kind is it? [profile/advisory/package/talk/other]: '
    read -r knd || knd=other
    [ -z "$knd" ] && knd=other
    printf '  short label: '
    read -r lbl || lbl=""
    [ -z "$lbl" ] && lbl="$ptr"
    {
      printf '  - kind: %s\n' "$knd"
      printf '    pointer: %s\n' "$ptr"
      printf '    label: %s\n' "$lbl"
    } >> "$PENDING"
    ok "Added $lbl."
  done
  if [ -s "$PENDING" ]; then
    sed -i.bak 's/^assertions: \[\]$/assertions:/' "$CONFIG_FILE" && rm -f "$CONFIG_FILE.bak"
    yaml_splice assertions "$PENDING"
    info "Ravn cannot verify these yet — they are shown labelled as YOUR assertion."
    info "What reporters point at most often is what Ravn builds next."
  else
    rm -f "$PENDING"
  fi
fi

if ! git diff --quiet -- "$CONFIG_FILE"; then
  git commit -qam "Add nominations and assertions to ravn.config.yml"
  git push -q
  ok "Pushed updated $CONFIG_FILE."
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
# ~/Downloads when it exists (where people look for downloaded things), else
# next to the clone. A dated subdir so re-runs never clobber an old profile.
if [ -d "$HOME/Downloads" ]; then
  OUTDIR="$HOME/Downloads/ravn-profile-$(date +%Y%m%d-%H%M%S)"
else
  OUTDIR="$WORKDIR/ravn-profile-digest"
  rm -rf "$OUTDIR"
fi
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

# ---------- 9. assemble the submission bundle ----------
step "Assembling your submission bundle"
DIGEST_FILE="$OUTDIR/profile-digest.json"
BUNDLE_FILE="$OUTDIR/ravn-profile-bundle.json"
DIGEST_SHA=$(sha256_file "$DIGEST_FILE")

# Collectors since the in-run assembly step ship the bundle IN the artifact —
# nothing to fetch or staple. The client-side path below stays as the fallback
# for copies still pinned to an older collector.
if [ -s "$BUNDLE_FILE" ]; then
  ok "The workflow already assembled the bundle (in-run) — verifying it."
fi
if [ ! -s "$BUNDLE_FILE" ]; then

# The Sigstore bundle GitHub stored for the digest. gh's native command first
# (gh >= 2.49 writes a sha256:<hex>.jsonl, one bundle per line, newest first);
# older gh builds get the same bundle object from the attestations REST API.
fetch_attestation() {
  local dir file
  dir=$(mktemp -d)
  if (cd "$dir" && gh attestation download "$DIGEST_FILE" --repo "$REPO" >/dev/null 2>&1); then
    file=$(find "$dir" -name '*.jsonl' 2>/dev/null | head -n 1)
    if [ -n "$file" ] && [ -s "$file" ]; then
      head -n 1 "$file" | jq 'if type == "object" and has("bundle") then .bundle else . end'
      rm -rf "$dir"
      return 0
    fi
  fi
  rm -rf "$dir"
  gh api "repos/$REPO/attestations/sha256:$DIGEST_SHA" --jq '.attestations[0].bundle'
}

ATTESTATION=$(fetch_attestation)
if [ -z "$ATTESTATION" ] || [ "$ATTESTATION" = "null" ]; then
  err "Couldn't fetch the attestation for your digest, so no bundle was assembled."
  err "  Retry in a minute, or check https://github.com/$REPO/attestations"
  exit 1
fi

# ravn.profile-bundle/v0: the digest rides as the EXACT file bytes in a JSON
# string (--rawfile) so any verifier hashes precisely what was attested before
# parsing it; the attestation is the Sigstore bundle object as-is.
jq -n --rawfile digest "$DIGEST_FILE" --argjson attestation "$ATTESTATION" \
  '{schema: "ravn.profile-bundle/v0", digest: $digest, attestation: $attestation}' \
  > "$BUNDLE_FILE"

fi # ! -s BUNDLE_FILE — the fallback client-side assembly

# Self-check the binding Ravn re-verifies server-side: the embedded string must
# round-trip to bytes whose sha256 equals the signed in-toto subject digest.
EMBEDDED_SHA=$(jq -j '.digest' "$BUNDLE_FILE" | sha256_stdin)
SUBJECT_SHA=$(jq -r \
  '.attestation.dsseEnvelope.payload | @base64d | fromjson | .subject[0].digest.sha256 // empty' \
  "$BUNDLE_FILE")
if [ -n "$SUBJECT_SHA" ] && [ "$EMBEDDED_SHA" = "$SUBJECT_SHA" ]; then
  ok "Bundle written — sha256(digest) matches the attestation subject."
else
  warn "Bundle self-check FAILED (subject: ${SUBJECT_SHA:-none}, digest: $EMBEDDED_SHA)."
  warn "Don't submit this bundle — re-run the script, or file an issue on ravn-actions."
fi

# ---------- 10. done ----------
step "Done"
info "Digest:  $DIGEST_FILE"
info "Summary: $OUTDIR/profile-summary.md"
info "Bundle:  $BUNDLE_FILE"
echo
info "Next: open ${BOLD}https://apps.ravnsecurity.io/app/profile${RESET},"
info "sign in, click ${BOLD}Enroll${RESET} (first visit only), then upload"
info "${BOLD}$BUNDLE_FILE${RESET}"
info "(it's in your Downloads folder when one exists)."
info "Ravn re-verifies the signature and the workflow version against its"
info "approved list (RavnSecurity/ravn-actions/approved-workflow-shas.txt)"
info "before the profile is shown to triagers. No portal access yet? Hand"
info "the bundle to your Ravn contact instead."
