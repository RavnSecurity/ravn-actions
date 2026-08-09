#!/usr/bin/env bash
# Ravn profile-bundle verifier — for a third party, with no trust in Ravn's servers required.
#
# Takes a ravn-profile-bundle.json (schema ravn.profile-bundle/v0) and checks, in order:
#   1. BINDING    sha256 of the embedded digest bytes == the attestation's in-toto subject
#                 digest. The digest rides in the envelope as an exact JSON string precisely
#                 so this hash runs over the attested bytes, never a re-serialization.
#   2. SIGNATURE  the attestation is a valid Sigstore bundle whose signing identity is Ravn's
#                 collector REUSABLE WORKFLOW (gh attestation verify --signer-workflow). The
#                 identity comes from the OIDC job_workflow_ref claim, which the repo that
#                 ran the workflow cannot forge.
#   3. VERSION    the exact workflow commit (the cert's Build Signer Digest, i.e.
#                 job_workflow_sha — the same commit the collector script is checked out at)
#                 is on Ravn's published approved list.
# The digest JSON is parsed only AFTER the hash binding holds.
#
# Usage:    verification/verify.sh <ravn-profile-bundle.json>
# Requires: jq, sha256sum or shasum, curl, gh >= 2.49 authenticated (`gh auth login` — gh
#           needs API access for the Sigstore trust root; everything else is local except
#           the approved-list fetch).
# Env:      RAVN_PROFILE_APPROVED_SHAS_URL overrides where the approved list comes from.
#
# WITHOUT gh: deliberately not implemented here — the same bundle verifies with cosign
# (>= 2.2) instead:
#     jq -j '.digest'   ravn-profile-bundle.json > profile-digest.json
#     jq '.attestation' ravn-profile-bundle.json > attestation.sigstore.json
#     cosign verify-blob-attestation profile-digest.json \
#       --bundle attestation.sigstore.json --new-bundle-format \
#       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#       --certificate-identity-regexp \
#         '^https://github\.com/RavnSecurity/ravn-actions/\.github/workflows/collect-profile\.yml@'
# then check the cert's Build Signer Digest (OID 1.3.6.1.4.1.57264.1.10) against the
# approved list yourself. Steps 1 and 3 above apply unchanged.
set -euo pipefail

SIGNER_WORKFLOW="RavnSecurity/ravn-actions/.github/workflows/collect-profile.yml"
APPROVED_URL="${RAVN_PROFILE_APPROVED_SHAS_URL:-https://raw.githubusercontent.com/RavnSecurity/ravn-actions/main/approved-workflow-shas.txt}"

ok()   { printf 'ok    %s\n' "$1"; }
info() { printf '      %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

BUNDLE="${1:-}"
if [ -z "$BUNDLE" ]; then
  echo "Usage: $0 <ravn-profile-bundle.json>" >&2
  exit 2
fi
[ -f "$BUNDLE" ] || fail "no such file: $BUNDLE"

command -v jq   >/dev/null 2>&1 || fail "jq is required: https://jqlang.org"
command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "sha256sum or shasum is required"
fi
command -v gh >/dev/null 2>&1 \
  || fail "gh is required for the signature check — see this file's header for the cosign path"
gh auth status >/dev/null 2>&1 || fail "gh isn't authenticated — run 'gh auth login' first"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------- 0. envelope shape ----------
SCHEMA=$(jq -r '.schema // empty' "$BUNDLE")
[ "$SCHEMA" = "ravn.profile-bundle/v0" ] \
  || fail "unexpected schema '${SCHEMA:-<missing>}' (want ravn.profile-bundle/v0)"
jq -e '.digest | type == "string"' "$BUNDLE" >/dev/null \
  || fail "envelope .digest must be a JSON string (the exact attested bytes)"
jq -e '.attestation | type == "object"' "$BUNDLE" >/dev/null \
  || fail "envelope .attestation must be an object (the Sigstore bundle)"

DIGEST_FILE="$WORK/profile-digest.json"
ATT_FILE="$WORK/attestation.sigstore.json"
jq -j '.digest' "$BUNDLE" > "$DIGEST_FILE" # -j: raw bytes, no added newline
jq '.attestation' "$BUNDLE" > "$ATT_FILE"

# ---------- 1. binding: digest bytes <-> attestation subject ----------
FILE_SHA=$(sha256_file "$DIGEST_FILE")
SUBJECT_SHA=$(jq -r \
  '.dsseEnvelope.payload | @base64d | fromjson | .subject[0].digest.sha256 // empty' "$ATT_FILE")
[ -n "$SUBJECT_SHA" ] || fail "attestation carries no in-toto subject digest"
[ "$FILE_SHA" = "$SUBJECT_SHA" ] \
  || fail "digest bytes don't match the attestation subject (file $FILE_SHA, subject $SUBJECT_SHA)"
ok "sha256(digest bytes) == attestation subject: $FILE_SHA"

# ---------- 2. Sigstore signature + signer identity ----------
# --repo is the repo the run executed in, read from the signed provenance itself. The check
# that actually gates trust is --signer-workflow (job_workflow_ref): Ravn's file, no matter
# whose repo ran it.
SOURCE_REPO=$(jq -r '.dsseEnvelope.payload | @base64d | fromjson
    | .predicate.buildDefinition.externalParameters.workflow.repository // empty' "$ATT_FILE" \
  | sed 's#^https://github.com/##')
[ -n "$SOURCE_REPO" ] \
  || fail "provenance carries no source repository (externalParameters.workflow.repository)"

VERIFY_JSON=$(gh attestation verify "$DIGEST_FILE" --repo "$SOURCE_REPO" --bundle "$ATT_FILE" \
  --signer-workflow "$SIGNER_WORKFLOW" --format json) \
  || fail "Sigstore verification failed (gh attestation verify)"
ok "Sigstore signature valid; signer workflow is $SIGNER_WORKFLOW"

# ---------- 3. workflow version vs the approved list ----------
WORKFLOW_SHA=$(printf '%s' "$VERIFY_JSON" \
  | jq -r '.[0].verificationResult.signature.certificate.buildSignerDigest // empty')
[ -n "$WORKFLOW_SHA" ] || fail "couldn't read the Build Signer Digest from the verify result"

APPROVED=$(curl -fsSL "$APPROVED_URL") || fail "couldn't fetch the approved list: $APPROVED_URL"
if printf '%s\n' "$APPROVED" | sed -e 's/#.*//' -e 's/[[:space:]]//g' | grep -qx "$WORKFLOW_SHA"; then
  ok "workflow commit $WORKFLOW_SHA is on the approved list"
else
  fail "workflow commit $WORKFLOW_SHA is NOT on the approved list ($APPROVED_URL)"
fi

# ---------- verdict (digest parsed only now, after the binding held) ----------
LOGIN=$(jq -r '.subject.github_login // "?"' "$DIGEST_FILE")
GH_ID=$(jq -r '.subject.github_id // "?"' "$DIGEST_FILE")
GENERATED=$(jq -r '.generated_at // "?"' "$DIGEST_FILE")
echo
ok "VERIFIED: $LOGIN (github id $GH_ID), generated $GENERATED"
info "workflow $SIGNER_WORKFLOW @ $WORKFLOW_SHA"
info "The digest is untampered and was produced by an approved Ravn collector version."
