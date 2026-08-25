/**
 * The runner's side of `ravn.collection-config/v1` — ADR security-005 §4.
 *
 * Ravn validates a config on WRITE, at job creation, where a human is present to
 * fix what is refused (`ravn-platform` services/reputation/src/collection/config.ts).
 * This module is the READ side: it does the small number of checks a runner has
 * to do anyway to execute the document, and nothing more.
 *
 * ❗The document is executed, never interpreted. `provider` selects a collector
 * the runner already knows how to run; `required.secrets` is a preflight
 * contract; `metadata` is the provider's own. Nothing here reasons about what
 * Ravn "meant" — a config the runner cannot execute is a refusal the reporter
 * reads, not a guess the runner makes on their behalf.
 */

import { existsSync, readFileSync } from "node:fs";

/** The schema this runner speaks. Carried alongside the document, never inside. */
export const COLLECTION_CONFIG_SCHEMA = "ravn.collection-config/v1";
export const COLLECTION_CONFIG_VERSION = 1;

/**
 * Providers this collector version can actually execute, and the secrets each
 * one reads.
 *
 * ❗Mirrors `PROVIDER_SECRETS` on Ravn's write side, and the mirror is the point:
 * the bug the registry exists to catch is a config naming a secret no collector
 * reads, which sends the reporter to set something that changes nothing.
 *
 * ❗`RAVN_READONLY_TOKEN`, not `GH_TOKEN`. `GH_TOKEN` is the GitHub CLI's own
 * credential variable, so that name would quietly promote a narrow, read-only
 * PAT into the ambient credential for every tool in the job.
 */
export const IMPLEMENTED_PROVIDERS = {
  github: { secrets: ["RAVN_READONLY_TOKEN"] },
  /**
   * ❗TWO secrets, not one. HackerOne's API is HTTP Basic over
   * `identifier:token`, so a token on its own cannot authenticate — and the
   * identifier is the API token's NAME, not the reporter's HackerOne handle.
   * Naming only the token here would pass preflight and then 401 in the middle
   * of the run, which is the precise failure this registry exists to prevent.
   */
  hackerone: { secrets: ["H1_API_IDENTIFIER", "H1_API_TOKEN"] },
};

/**
 * Where a reporter goes when Ravn refuses.
 *
 * ❗The link Ravn sends WITH the refusal wins; this table is the fallback for a
 * response that carries a code and no link, and for a transport failure where
 * there is no response at all. A refusal that sends someone to a search engine
 * is a refusal that costs them an afternoon.
 */
export const PORTAL_URL = process.env.RAVN_PORTAL_URL || "https://apps.ravnsecurity.io/app/profile";

/** Per-code guidance. Keys are the codes in ADR security-005 §4's refusal table. */
export const REFUSALS = {
  "missing-token": "The collector presented no bearer token. This is a collector bug — please report it.",
  "invalid-token":
    "Ravn could not verify the OIDC token (signature, issuer, audience or expiry). If this run is not on a GitHub-hosted runner, or the workflow was copied rather than called as a reusable workflow, that is the usual cause.",
  "event-not-dispatch":
    "Collection runs only on `workflow_dispatch`. Start it from the Actions tab; a push, schedule or pull_request trigger is refused server-side.",
  "no-binding":
    "No active collection job for this owner/repo. Create one in the Ravn portal, naming THIS repository, then re-run.",
  "repo-mismatch":
    "This job is bound to a different repository than the one this run is in. A job binds to the first repository that fetches it.",
  "job-locked":
    "You accepted the result of this job, so it is frozen. Draft a new config from it in the portal and re-run.",
  "job-expired": "This job is past its expiry. Create a new one in the portal and re-run.",
};

/** Format a refusal for the run log: what happened, and where to go about it. */
export function describeRefusal({ status, code, message, link }) {
  const known = code && Object.hasOwn(REFUSALS, code);
  const lines = [
    `Ravn refused the config request: ${code ?? "unknown"}${status ? ` (HTTP ${status})` : ""}`,
  ];
  if (message) lines.push(`  ${message}`);
  if (known) lines.push(`  ${REFUSALS[code]}`);
  else if (!message) lines.push("  Ravn returned no code this collector version recognises.");
  lines.push(`  ${link ? link : `${PORTAL_URL}  (Ravn sent no deeplink with this refusal)`}`);
  return lines.join("\n");
}

/**
 * Shape checks on a 200 body. Deliberately shallow.
 *
 * ❗Structural only — enough to know the runner can execute the document, not a
 * re-implementation of Ravn's validator. Duplicating that here would put two
 * definitions of "valid" in two repos on two release cadences, and the one that
 * runs in the reporter's environment would be the stale one.
 */
export function validateResponse(body) {
  const errs = [];
  const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
  if (!isObj(body)) return ["response body is not an object"];

  if (!isObj(body.job)) errs.push("job is missing");
  else {
    if (typeof body.job.id !== "string" || body.job.id === "") errs.push("job.id is missing");
    // ISO 8601 at UTC on a type-lossy boundary; carried, not parsed into a Date.
    if (typeof body.job.expiresAt !== "string" || body.job.expiresAt === "") {
      errs.push("job.expiresAt is missing");
    }
  }

  if (!isObj(body.config)) {
    errs.push("config is missing");
    return errs;
  }
  if (body.config.version !== COLLECTION_CONFIG_VERSION) {
    errs.push(`config.version must be ${COLLECTION_CONFIG_VERSION}, got ${JSON.stringify(body.config.version)}`);
  }
  if (!Array.isArray(body.config.collectors) || body.config.collectors.length === 0) {
    errs.push("config.collectors must be a non-empty array");
  }
  return errs;
}

/** The collector entry for a provider, or null. */
export function collectorFor(config, provider) {
  return (config?.collectors ?? []).find((c) => c?.provider === provider) ?? null;
}

/**
 * Preflight: which required secrets are absent from the environment.
 *
 * ❗Checked BEFORE collecting, so a missing secret fails naming something the
 * reporter can act on — rather than as a thin or empty digest they discover an
 * hour later and cannot explain.
 *
 * ❗Only providers this collector version implements are checked. A config
 * naming a provider we cannot run yet (`hackerone` is specified but not built)
 * is reported as a skip, not as a missing secret: failing there would tell the
 * reporter to set a secret that nothing on this runner would read.
 */
export function preflight(config, env = process.env) {
  const missing = [];
  const unsupported = [];
  const runnable = [];

  for (const c of config?.collectors ?? []) {
    const provider = c?.provider;
    const impl = provider && Object.hasOwn(IMPLEMENTED_PROVIDERS, provider) ? IMPLEMENTED_PROVIDERS[provider] : null;
    if (!impl) {
      unsupported.push(String(provider ?? "(unnamed)"));
      continue;
    }
    runnable.push(provider);
    for (const name of c?.required?.secrets ?? []) {
      if (typeof name !== "string" || name === "") continue;
      if (!env[name]) missing.push({ provider, secret: name });
    }
  }
  return { missing, unsupported, runnable };
}

/**
 * The config `fetch-config.mjs` wrote, as the collectors read it.
 *
 * ❗One reader, because there are now two collectors. This was inline in
 * `collect.mjs`; a second copy in the HackerOne collector would be a second
 * place for the env-var name and the "run fetch-config first" message to drift,
 * and the drift would only show up as a confusing failure inside someone else's
 * Actions run.
 */
export function readDeliveredConfig() {
  const path = process.env.RAVN_COLLECTION_CONFIG || "ravn-collection-config.json";
  if (!existsSync(path)) {
    console.error(
      `::error::No collection config at ${path}. This script runs after ` +
        "scripts/fetch-config.mjs, which fetches the config over OIDC and writes it there.",
    );
    process.exit(1);
  }
  const response = JSON.parse(readFileSync(path, "utf8"));
  return { response, config: response.config, jobId: response.job?.id ?? null };
}
