#!/usr/bin/env node
/**
 * Preflight: authenticate to Ravn with GitHub's OIDC token, fetch this run's
 * collection config, print it, and stop the run if anything is wrong — before a
 * single API call is made against the reporter's account.
 *
 * ── ❗Why this step lives HERE, in the collector ────────────────────────────
 *
 * It must not be a step in the caller's workflow. The claim Ravn authenticates
 * is `job_workflow_ref`, and that claim only anchors when the executing
 * workflow lives in ANOTHER repository:
 *
 *   plain job in the caller     -> caller's own workflow @refs/heads/main
 *   local reusable (`./…`)      -> caller's other workflow @refs/heads/main
 *   cross-repo reusable         -> THIS repo @<sha>          <- the only useful one
 *
 * A fetch in the caller's workflow yields a token naming a file the caller
 * fully controls: self-referential, and it proves nothing. Ravn would be
 * authenticating the caller's assertion about itself. ADR security-005 D13 —
 * do not move this step.
 *
 * ── What the token is, and is not ──────────────────────────────────────────
 *
 * It is a CHANNEL credential (D1). It proves which repository this run is in,
 * which workflow file at which commit is executing, who dispatched it, and what
 * triggered it. It says nothing about who the reporter is — that comes from
 * whoever minted the PAT the collector then reads the account with (D2).
 *
 * Usage: node scripts/fetch-config.mjs
 *   RAVN_BASE_URL                  Ravn API base (a workflow input, not baked in)
 *   RAVN_OIDC_AUDIENCE             defaults to https://ravnsecurity.io
 *   RAVN_COLLECTION_CONFIG                where to write the response (default ravn-collection-config.json)
 *   ACTIONS_ID_TOKEN_REQUEST_URL   set by Actions when the job has `id-token: write`
 *   ACTIONS_ID_TOKEN_REQUEST_TOKEN ditto
 */

import { writeFileSync } from "node:fs";
import { collectorFor, describeRefusal, preflight, validateResponse } from "./lib/collection.mjs";
import { resolveConfig } from "./lib/config.mjs";

const BASE_URL = (process.env.RAVN_BASE_URL || "").replace(/\/+$/, "");
const AUDIENCE = process.env.RAVN_OIDC_AUDIENCE || "https://ravnsecurity.io";
const OUT = process.env.RAVN_COLLECTION_CONFIG || "ravn-collection-config.json";

const die = (msg) => {
  console.error(`::error::${String(msg).split("\n")[0]}`);
  console.error(msg);
  process.exit(1);
};

/**
 * Mint an OIDC token for Ravn's audience.
 *
 * ❗The empty-URL case is called out on its own because every downstream error
 * it causes is misleading. When `id-token: write` is missing from the job — or
 * an org policy blocks OIDC — Actions simply does not inject
 * ACTIONS_ID_TOKEN_REQUEST_URL, and the run then fails with an unauthenticated
 * request against Ravn, which reads as "Ravn is broken" or "my job is not
 * registered". Naming the real cause here saves the reporter that hunt.
 *
 * ❗The default audience is NOT usable. GitHub's default is the repository
 * owner's URL, and every repo in every org already holds such a token — so it
 * is not a credential, and Ravn refuses it. The audience is always explicit.
 */
async function mintOidcToken() {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;

  if (!url || !requestToken) {
    die(
      [
        "No OIDC token endpoint available to this job.",
        "",
        "ACTIONS_ID_TOKEN_REQUEST_URL is empty, which means one of:",
        "  - the job is missing `permissions: id-token: write`;",
        "  - an organisation or enterprise policy disables OIDC for this repository;",
        "  - this is not a GitHub-hosted Actions run at all.",
        "",
        "Ravn's config endpoint authenticates with that token and nothing else, so",
        "the run stops here. Every later error would be a misleading symptom of this one.",
      ].join("\n"),
    );
  }

  const res = await fetch(`${url}&audience=${encodeURIComponent(AUDIENCE)}`, {
    headers: { Authorization: `Bearer ${requestToken}`, Accept: "application/json" },
  }).catch((e) => die(`Could not reach the Actions OIDC token endpoint: ${e.message}`));

  if (!res.ok) die(`Actions refused to mint an OIDC token: HTTP ${res.status} ${res.statusText}`);
  const body = await res.json().catch(() => null);
  const token = body?.value;
  if (!token) die("The Actions OIDC endpoint returned no token value.");

  // Belt and braces: never printed by this script, but a mask means an
  // accidental echo anywhere later in the job is redacted rather than logged.
  console.log(`::add-mask::${token}`);
  return token;
}

async function fetchConfig(token) {
  if (!BASE_URL) die("RAVN_BASE_URL is empty. Pass the `ravn-base-url` input to the collector.");
  const endpoint = `${BASE_URL}/attestations/config`;

  // ❗No request body, by design (ADR §4). Owner, repo, actor, event and runner
  // all arrive in the verified claims; a body would be unauthenticated input
  // duplicating what the token already proves.
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  }).catch((e) =>
    die(
      `Could not reach ${endpoint}: ${e.message}\n` +
        "  Nothing has been collected. If Ravn is up, check the `ravn-base-url` input.",
    ),
  );

  const text = await res.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    /* handled below — a non-JSON body is only ever an error path */
  }

  if (!res.ok) {
    // Ravn's refusals carry a code and a deeplink; tolerate both a flat body and
    // one nested under `error`, so a shape change downgrades the message rather
    // than swallowing the reason.
    const err = body?.error && typeof body.error === "object" ? body.error : body;
    die(
      `${describeRefusal({
        status: res.status,
        code: err?.code,
        message: err?.message,
        link: err?.link ?? err?.url,
      })}\n\nNothing was collected.`,
    );
  }

  if (!body) die(`Ravn returned HTTP ${res.status} with a body that is not JSON:\n${text.slice(0, 500)}`);

  const errs = validateResponse(body);
  if (errs.length) {
    die(`Ravn's config response is not one this collector version can execute:\n  - ${errs.join("\n  - ")}`);
  }
  return { body, text };
}

async function main() {
  const token = await mintOidcToken();
  const { body, text } = await fetchConfig(token);

  console.log(`Collection job ${body.job.id} (expires ${body.job.expiresAt})`);
  console.log("");

  // ── ❗D12, half one: the reporter sees what is about to happen while they can
  //    still cancel. Printed BEFORE preflight and long before collection, so
  //    even a run that fails preflight shows the config it was handed.
  console.log("::group::Resolved collection config (as delivered by Ravn, verbatim)");
  console.log(text);
  console.log("::endgroup::");
  console.log("Collection config:");
  console.log(JSON.stringify(body.config, null, 2));

  const github = collectorFor(body.config, "github");
  if (github) {
    const { cfg, unknown } = resolveConfig(github.metadata);
    console.log("");
    console.log("GitHub sharing preferences, resolved over this collector's defaults:");
    for (const [k, v] of Object.entries(cfg)) {
      console.log(`  ${k}: ${JSON.stringify(v)}`);
    }
    if (unknown.length) {
      console.log(`  note: keys this collector version does not know, ignored: ${unknown.join(", ")}`);
    }
  }
  console.log("");

  // ── preflight (ADR §4): a missing secret fails HERE, naming itself.
  const { missing, unsupported, runnable } = preflight(body.config);
  for (const p of unsupported) {
    console.log(
      `::warning::Config asks for provider '${p}', which this collector version cannot run. Skipping it.`,
    );
  }
  if (missing.length) {
    die(
      [
        "Preflight failed: a secret this config requires is not set on the runner.",
        "",
        ...missing.map((m) => `  - ${m.secret}  (required by the '${m.provider}' collector)`),
        "",
        "Set it as a repository secret and re-run. Nothing has been collected.",
      ].join("\n"),
    );
  }
  if (!runnable.length) {
    die("Preflight failed: this config names no provider that this collector version can run.");
  }

  // The exact bytes Ravn sent, on disk for the collector to embed in the digest.
  writeFileSync(OUT, text);
  console.log(`Preflight OK — providers to run: ${runnable.join(", ")}. Config written to ${OUT}.`);
}

main().catch((e) => die(e?.stack || String(e)));
