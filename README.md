# ravn-actions

Ravn's reporter-profile collector: a reusable GitHub Actions workflow that runs in a
reporter's OWN repo, aggregates their GitHub track record into a small privacy-scoped digest,
signs it via GitHub's attestations API, and hands back a bundle anyone can verify without
trusting Ravn's servers.

**The collector states what it SAW. It assigns no scores and draws no conclusions.** What an
observation is worth is decided by a versioned model on Ravn's side, so changing our mind about
weighting never costs a reporter a re-run. If something in here starts to look like a weighting,
it belongs over there instead.

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
2. **The collector code rides the same SHA as the claim.** Before anything is checked out,
   the workflow mints an OIDC token, reads the `job_workflow_sha` claim out of its payload,
   and checks its own scripts out at *that* commit — the attested workflow commit — so the
   code that produced the digest and the version the claim names cannot diverge (the
   script-pin gap, ravn-platform#133). It then asserts the checked-out `HEAD` is that commit
   and prints both, because "checkout quietly resolved the ref to something else" is the
   precise failure this link is here to prevent.

   ❗**This did not hold before [#8](https://github.com/RavnSecurity/ravn-actions/issues/8),
   and every collector SHA approved before it is affected.** The step read
   `${{ github.job_workflow_sha }}`, and that context value is *empty* inside a reusable
   workflow — measured, not inferred. `actions/checkout` treats an empty `ref` as "give me
   the default branch", so the claim named collector SHA *X* while the code that ran was
   whatever `main` held. It failed open and it failed silently: the run went green. The OIDC
   token is the only place the value is actually populated, which is why it is now read from
   there, and why an empty, missing or malformed claim **aborts the run** rather than falling
   through to a branch.

   The token is decoded, not signature-verified, and that is deliberate: GitHub minted it for
   this job seconds earlier, and Ravn re-verifies the same claim server-side on ingest — so a
   tampered value is refused there rather than yielding a trusted digest.
3. **Approved versions are published.** [`approved-workflow-shas.txt`](approved-workflow-shas.txt)
   lists every collector commit Ravn trusts (append-only, `#` comments, revocation lane TBD
   ravn-platform#137). Verifiers check the certificate's Build Signer Digest
   (`job_workflow_sha`) against it. Ravn's control plane re-runs the whole verification
   server-side on upload.

The same OIDC token is what authenticates the config fetch below. That is why the fetch is a
step in **this** workflow and not in the caller's: a fetch in the caller's workflow presents a
token naming the caller's own file, which is self-referential and proves nothing (ADR
security-005 D13).

## Where the config comes from

`ravn.config.yml` in the reporter's repository is **retired** (ADR security-005 §4). The
collector now asks Ravn for its config at the start of every run:

1. It mints a GitHub OIDC token with Ravn's audience (`https://ravnsecurity.io`) and POSTs it
   to `<ravn-base-url>/attestations/config`. There is no request body — owner, repo, actor,
   event and runner all arrive in the verified claims, and a body would be unauthenticated
   input duplicating what the token already proves.
2. Ravn answers with `{ job: { id, expiresAt }, config }`, or refuses with a code and a
   deeplink (`no-binding`, `job-locked`, `job-expired`, `repo-mismatch`,
   `event-not-dispatch`, `invalid-token`, `missing-token`). **A refusal stops the run
   before anything is collected**, printing the code and the page that fixes it.

   ❗The deeplink field is **`help`** — that is what svc-reputation sends, and it is now
   the name to write down. ADR security-005 §4 requires a deeplink but never named the
   field, so the two halves picked different ones and every refusal in prod dropped its
   link for weeks with both test suites green (#11). The collector also accepts `link`
   and `url`, in that order of preference, because widening the reader is the change
   that does not need a re-approval. It is tolerance, not a second contract.
3. Required secrets are checked in **preflight**, so a missing one fails naming itself rather
   than turning up as a thin digest an hour later.

❗**The token is a channel credential, not an identity.** It proves which repository, workflow
and commit are executing. Who the reporter *is* still comes from the account behind
`RAVN_READONLY_TOKEN` — the PAT they mint, that Ravn never holds.

❗**You still see what you agreed to share, and so does a triager.** Server-delivered config
would otherwise move "what you share" from the reporter to Ravn's server. Two things prevent
that, and neither is optional (D12): the config is **printed verbatim to the run log before
anything is collected**, while the run can still be cancelled; and it is **embedded in
`profile-digest.json` before the file is hashed**, so it is covered by the signature.

### Generating a profile

**Start in the Ravn portal**, at [`/app/profile`](https://apps.ravnsecurity.io/app/profile).
Connect a source, and it hands you a `curl … | bash` generated for that collection — one that
creates the repository if you do not have one, sets the secrets it actually needs, commits this
collector pinned at an approved SHA, and offers to start the run.

❗**`scripts/get-ravn-profile.sh` no longer collects anything.** It drove the
`ravn-profile-template` + `ravn.config.yml` flow that security-005 §4 retires, and under the OIDC
flow described above a run it started would be refused `no-binding` before collecting a thing —
because a collection now exists only once a reporter has registered one. The script is kept as a
one-screen redirect rather than deleted: the URL is in blog posts and bookmarks nobody can edit,
and a 404 reads as "Ravn is broken" where a sentence reads as "it moved".

❗A script that runs, goes green, and produces a guaranteed refusal is worse than one that is
gone. It spends the reporter's time and then blames the platform.

## What gets collected (`ravn.profile-digest/v1`)

The digest carries `observations` — individually typed facts — alongside the `signals` object v0
emitted, which is still produced so anything reading the old shape keeps working.

Two fields ride at the top level, and both are written **before the file is hashed** — which is
the only placement worth anything, since `attest-build-provenance` signs the SHA-256 of
`profile-digest.json` and anything beside that file is strippable:

- `collection_config` — the config Ravn delivered, verbatim, alongside the `redaction` object
  holding the sharing preferences this collector version actually resolved from it. What Ravn
  asked for and what the collector did with it are different questions, so they are different
  fields.
- `job_id` — the collection job this run was issued (D7). Bundles are bearer artifacts: a
  genuine, untampered digest belonging to Alice verifies perfectly when uploaded by Bob. The
  job id is the nonce that keeps "which job produced this?" answerable, and it is stamped from
  day one because provenance cannot be backfilled.

The schema stays `v1`: both are additive optional fields, and the extractor ignores keys it
does not know.

**The strongest thing in it is upstream contribution.** `github.upstream_contribution` records
merged pull requests into projects on Ravn's published notability list. That observation is
different in kind from everything else here, because **merged PRs into public repositories are
public**: Ravn re-checks them server-side and does not have to trust the digest at all. The
attestation is not what makes those claims true — it is what makes them worth an API call.

v0 could not see upstream work at all. It read `/user/repos`, which only ever returns
repositories you own or are a member of; the strongest available signal was missing rather than
weak. v1 uses `contributionsCollection`, which is the API that makes contributions to other
people's projects visible.

### HackerOne: what you have FOUND

The GitHub collector answers "what has this person built". The HackerOne collector answers
"what has this person **found**", which is the question a PSIRT team is actually asking when a
report lands. They are different signals and neither substitutes for the other.

It runs in the same job, before the GitHub collector, and writes `hackerone-digest.json` — a
fragment `collect.mjs` folds into `profile-digest.json` **before hashing**. One run, one
signature, one job: a second bundle would mean a second collection job, a second attestation
and a second upload for what is one act.

**Two secrets, and the first one is a trap.** HackerOne's API is HTTP Basic over
`identifier:token`, where the identifier is the API token's **name** — not your HackerOne
handle. Entering the handle is the obvious thing to do and returns a 401 that explains nothing,
so the collector says so explicitly when it sees one.

| secret | what it is |
| --- | --- |
| `H1_API_IDENTIFIER` | the **name** shown beside your API token in HackerOne settings |
| `H1_API_TOKEN` | the token value |

Neither ever reaches Ravn. Both are read inside your own runner.

**Identity comes from the API, never from the credential.** Because the identifier is an
arbitrary label you chose, it cannot name anybody — so the collector reads the authenticated
account from the `reporter` relationship on your own reports (there is no documented
`/hackers/me` on the hacker API). A hacker with no reports cannot be identified this way, and
the collector **refuses** rather than falling back to a handle you typed. Refusing is the
feature: a self-declared handle is the exact thing this design exists not to trust.

What is collected, all of it opt-out-able and two of them opt-in only:

| preference | default | what leaves the runner |
| --- | --- | --- |
| `share_report_counts` | on | totals and counts by state. No titles, no targets, no bodies |
| `share_programs` | on | program handles you have reported to, with counts |
| `share_severity_breakdown` | on | how many reports at each rating |
| `share_disclosed_reports` | on | reports HackerOne has **already published** |
| `share_cve_credits` | on | CVE ids credited to your reports |
| `share_report_titles` | **off** | titles of reports that are NOT disclosed |
| `share_bounty_totals` | **off** | one aggregate figure — never per-program |

The two `off` defaults are the ones that matter. The title of an undisclosed report can
describe a live, unfixed vulnerability in somebody else's product; that is not yours to share
by default, and a checkbox pre-ticked on your behalf is not consent.

The two strongest are `share_disclosed_reports` and `share_cve_credits`, for the same reason
upstream contribution is strongest on the GitHub side: **the underlying facts are already
public**, so Ravn can confirm them without trusting the digest at all.

Every HackerOne observation names its own account, and Ravn records it against **that** account
rather than against the GitHub identity the run's OIDC token belongs to. Attributing it to the
GitHub account would put "resolved 40 reports on HackerOne" on a GitHub profile — wrong on its
face, and wrong in a way that survives every later merge.

### Notability is not the reporter's call

[`notability/notable-projects.txt`](notability/notable-projects.txt) decides what counts as a
notable project, and it **ships in this repository at the same commit the collector is pinned
to** — so the attested `job_workflow_sha` covers the list as well as the code. A fork with a
padded list produces a different SHA and fails verification, exactly as a modified collector
does. It is deliberately *not* fetched at runtime: a list pulled from the network mid-run is a
list nobody attested, and "which version of the list ran" would be unanswerable at precisely the
moment it mattered.

Adding a project is a PR to that file, which forces a new approved SHA. That speed bump is the
point — the file decides what "well-known" means.

### Pointing at what the list misses

Absence from the notability list is not a judgement about a project; it means Ravn has not
curated it. Two keys in the GitHub collector's `metadata` let a reporter say so:

- `nominate_repos:` — repositories to collect merged-PR counts for. Emitted with
  `notable: false, nominated: true`, and Ravn claims them separately and at lower weight.
- `assertions:` — anything else: another platform's profile, a CVE credit, a package, a talk.

Both ride **inside** the signed digest, which makes them tamper-evident and non-repudiable — and
both are **typed as assertions end to end**, so being inside a signed envelope never makes them
verified. Ravn carries them at the `DISCLOSED` trust class and labels them as the reporter's
words wherever they appear.

They are also how Ravn picks what to build next: what reporters point at most often is the
integration backlog, ranked by real behaviour rather than by guesswork.

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
`ravn.profile-digest/v1` document (`job_id`, `subject.github_login`/`github_id`/`external_id`,
`generated_at`, `collection_config` and the resolved redaction config, the notability set id
and hash, `observations`, `assertions`, and the v0 `signals` object). `attestation` is the
Sigstore bundle object exactly
as `gh attestation download` / `GET /repos/{o}/{r}/attestations/sha256:<digest>` returns it.

The envelope is unchanged at v1 — a verifier hashes bytes and checks a signature, and neither
depends on what the digest says. Bundles produced by a v0 collector still verify and are still
ingested.

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

## ❗Every change to `collect-profile.yml` un-approves the collector

The SHA is the identity. Changing this workflow changes the SHA in the signing certificate, so
until the new one is approved AND the caller is pinned to it, nothing has shipped:

1. Land the collector change on `main`, then append that commit SHA to
   `approved-workflow-shas.txt` (RavnSecurity/ravn-actions#6).
2. Bump the `uses:` pin in the caller — `ravn-attestations`
   (RavnSecurity/ravn-attestations#1), and `ravn-profile-template` while it is still the
   template flow — to the same commit.

Both are required. Approving the SHA without bumping the pin changes nothing; bumping the pin
without approving the SHA makes every submission fail closed as `workflow-not-approved`.

❗The OIDC config change also alters the collector's **inputs**: `config-path` is gone and
`ravn-base-url` is new. A caller that still passes `config-path` fails at dispatch with
"Invalid input", so the pin bump and the `with:` block have to move together.

## Tests

```sh
node --test test/*.test.mjs
```

Node's own test runner against real loopback servers standing in for Ravn and for GitHub — no
dependencies, nothing to install, consistent with the collector itself shipping none. The
collector scripts run as child processes, which is how a runner runs them and the only way to
assert on what they print and write.

`test/collect.test.mjs` carries the proof that matters: it hashes `profile-digest.json` exactly
as the workflow attests it, then shows the hash moves when `job_id` or `collection_config` is
removed. A field whose removal does not change the hash was never covered by it.

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
- `scripts/fetch-config.mjs` — preflight: mints the OIDC token, fetches the config, prints it,
  checks required secrets. ❗Lives here, not in the caller's workflow (D13).
- `scripts/collect.mjs` — the collection script; config-driven redaction, aggregates only.
- `scripts/lib/collection.mjs` — the runner's side of `ravn.collection-config/v1`: the provider
  registry, the refusal table, preflight.
- `scripts/lib/config.mjs` — sharing preferences and their conservative defaults. ❗Deliberately
  dependency-free, like everything else here: this runs in the reporter's environment against a
  token they mint, and they should be able to audit it in two minutes. `npm install` in the
  collector step would also mean the attested SHA no longer pins everything that runs.
- `scripts/lib/notability.mjs` — loads and hashes the notability set from disk.
- `test/` — `node --test`, real loopback mocks, no dependencies. Run it as
  `node --test test/*.test.mjs`; `node --test test/` sweeps the helper modules in and
  fails misleadingly.
- `test/fixtures/refusals-live.json` — refusal bodies **captured verbatim from production**,
  with the exact request and capture time recorded alongside each one. The tests that read it
  take the expected deeplink out of the captured body rather than restating it, so a
  server-side rename fails the build instead of passing unnoticed. Never hand-edit a
  `bodyText`: a fixture we wrote ourselves is what let #11 through.
- `scripts/get-ravn-profile.sh` — ❗RETIRED. A redirect to the portal; it collects nothing.
- `notability/notable-projects.txt` — the published notability set. Governed like the SHA list.
- `verification/verify.sh` — third-party bundle verifier.
- `approved-workflow-shas.txt` — the published trust list.

## Where the trust list is read from

Ravn fetches `approved-workflow-shas.txt` from raw `main`. ❗The filename matters: the platform
fails **closed**, so a wrong URL and an empty list are the same value, and every submission is
rejected as `workflow-not-approved` with nothing saying why. If submissions start failing that
way, check `RAVN_APPROVED_SHAS_URL` first.
