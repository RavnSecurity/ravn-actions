# ravn-actions

Ravn's reporter-profile collector: a reusable GitHub Actions workflow that runs in a
reporter's OWN repo, aggregates their GitHub track record into a small privacy-scoped digest,
signs it via GitHub's attestations API, and hands back a bundle anyone can verify without
trusting Ravn's servers.

Part of the attested reporter-profile pipeline (RavnSecurity/ravn-platform#133 / #137). The
digest is informational context for triagers — verified as untampered and weighed by humans,
not a score.

## The trust story

Three links, each independently checkable:

1. **The workflow identity cannot be forged.** Reporters call
   `.github/workflows/collect-profile.yml` as a REUSABLE WORKFLOW
   (`uses: RavnSecurity/ravn-actions/.github/workflows/collect-profile.yml@<sha>`). The OIDC
   token GitHub mints for that job carries a `job_workflow_ref` claim naming this file at
   that exact SHA, and `actions/attest-build-provenance` bakes it into the Sigstore signing
   certificate. A composite action would not appear in OIDC claims — the caller could swap
   its body and the provenance would look identical. With a reusable workflow, the signed
   claim says which collector version ran, regardless of anything else in the caller's repo.
2. **The collector code rides the same SHA as the claim.** The workflow checks out its own
   scripts at `${{ github.job_workflow_sha }}` — the attested workflow commit — so the code
   that produced the digest and the version the claim names cannot diverge (the script-pin
   gap, ravn-platform#133).
3. **Approved versions are published.** [`approved-workflow-shas.txt`](approved-workflow-shas.txt)
   lists every collector commit Ravn trusts (append-only, `#` comments, revocation lane TBD
   ravn-platform#137). Verifiers check the certificate's Build Signer Digest
   (`job_workflow_sha`) against it. Ravn's control plane re-runs the whole verification
   server-side on upload.

## Generating a profile

```sh
curl -fsSL https://raw.githubusercontent.com/RavnSecurity/ravn-actions/main/scripts/get-ravn-profile.sh | bash
```

Requires `git`, `jq`, and an authenticated `gh`. The script creates your own copy of
[`RavnSecurity/ravn-profile-template`](https://github.com/RavnSecurity/ravn-profile-template),
walks you through sharing preferences (`ravn.config.yml` — conservative defaults; only
aggregates ever leave the runner), runs the collector, downloads the digest, verifies the
signature, and assembles `ravn-profile-bundle.json`. Upload that bundle in the Ravn portal at
**https://apps.ravnsecurity.io/app/profile**.

## The bundle format (`ravn.profile-bundle/v0`)

```json
{
  "schema": "ravn.profile-bundle/v0",
  "digest": "<the EXACT bytes of profile-digest.json, as a JSON string>",
  "attestation": { "the Sigstore bundle from GitHub's attestations API": "..." }
}
```

`digest` is a STRING, not nested JSON, so a verifier can hash the exact attested bytes before
parsing anything — re-serialized JSON would not hash identically. Inside is a
`ravn.profile-digest/v0` document (`subject.github_login`/`github_id`, `generated_at`, the
redaction config, and the signals). `attestation` is the Sigstore bundle object exactly as
`gh attestation download` / `GET /repos/{o}/{r}/attestations/sha256:<digest>` returns it.

## Verifying a bundle

```sh
verification/verify.sh ravn-profile-bundle.json
```

Checks, in order: sha256(digest bytes) == the attestation's in-toto subject digest; the
Sigstore signature with `gh attestation verify --signer-workflow
RavnSecurity/ravn-actions/.github/workflows/collect-profile.yml`; and the certificate's Build
Signer Digest against the approved list (fetched from raw `main`, overridable via
`RAVN_PROFILE_APPROVED_SHAS_URL`). Needs `jq`, `sha256sum`/`shasum`, `curl`, and an
authenticated `gh` >= 2.49. Without `gh`, the same bundle verifies with cosign — the exact
commands are in the header of [`verification/verify.sh`](verification/verify.sh).

## Approving a new collector version (maintainers)

The SHA that matters is the commit reachable from `main` that a caller pins (for squash/merge
PRs: the merge commit on `main`). After a collector change lands:

1. Append the new commit SHA to `approved-workflow-shas.txt` with a
   `# <sha> <date> <why>` comment line. Never rewrite existing entries.
2. Bump the pinned `uses:` SHA in
   `ravn-profile-template/.github/workflows/generate-ravn-profile.yml` to the same commit.

## Repo layout

- `.github/workflows/collect-profile.yml` — the reusable collector workflow (the attested
  identity).
- `scripts/collect.mjs` — the collection script; config-driven redaction, aggregates only.
- `scripts/get-ravn-profile.sh` — reporter onboarding (curl | bash).
- `verification/verify.sh` — third-party bundle verifier.
- `approved-workflow-shas.txt` — the published trust list.
