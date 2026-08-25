#!/usr/bin/env node
/**
 * Ravn HackerOne collector.
 *
 * Runs INSIDE the reporter's own Actions environment, alongside the GitHub
 * collector, and writes `hackerone-digest.json` — a fragment that `collect.mjs`
 * folds into `profile-digest.json` before it is hashed and signed.
 *
 * ── Why a fragment rather than its own bundle ──────────────────────────────
 *
 * One run, one signature, one job. A second bundle would mean a second
 * collection job, a second attestation and a second upload for what is one act:
 * "here is who I am, across the places I work". The digest already carries facts
 * from more than one place; what it did not carry, until now, is WHICH account
 * each fact was about — so every observation this collector emits names its own
 * account, and ravn-platform records it against that account rather than against
 * the run's GitHub subject.
 *
 * ── The credential ─────────────────────────────────────────────────────────
 *
 * `H1_API_IDENTIFIER` and `H1_API_TOKEN`, both repository secrets, neither ever
 * seen by Ravn. The identifier is the API token's NAME, not the HackerOne handle
 * — see `lib/hackerone.mjs`. Both are required because HackerOne's API is HTTP
 * Basic over the pair; a token alone cannot authenticate, which is why the
 * provider registry names two secrets and not one.
 *
 * ── Identity ───────────────────────────────────────────────────────────────
 *
 * ❗Read from the API's own answer about the caller, never from the credential
 * and never from config. A reporter who has filed no reports cannot be
 * identified this way, and this refuses rather than falling back to something
 * they typed. Refusing is the feature.
 */

import { writeFileSync } from "node:fs";
import {
  HackerOneError,
  authHeader,
  earningsObservation,
  getAll,
  identityFrom,
  observationsFrom,
  resolveH1Config,
} from "./lib/hackerone.mjs";
import { collectorFor, readDeliveredConfig } from "./lib/collection.mjs";

const OUT = "hackerone-digest.json";

const IDENTIFIER = process.env.H1_API_IDENTIFIER;
const TOKEN = process.env.H1_API_TOKEN;

function die(message, ...detail) {
  console.error(`::error::${message}`);
  for (const line of detail) console.error(line);
  process.exit(1);
}

/**
 * ❗A missing secret is a preflight concern, and `fetch-config.mjs` has already
 * refused the run if the config asked for this provider without them. Reaching
 * here without them means this script was invoked directly, so say that rather
 * than repeating preflight's message.
 */
if (!IDENTIFIER || !TOKEN) {
  die(
    "H1_API_IDENTIFIER and H1_API_TOKEN must both be set.",
    "Both are repository secrets. The identifier is the API token's NAME as shown in your",
    "HackerOne settings — not your HackerOne handle. Ravn never sees either value.",
  );
}

const { config } = readDeliveredConfig();
const collector = collectorFor(config, "hackerone");
if (!collector) {
  die(
    "This collection config does not ask for the 'hackerone' provider.",
    "Tick the HackerOne options when you register or draft a collection in the Ravn portal.",
  );
}

const { cfg, unknown } = resolveH1Config(collector.metadata);
const warnings = [];
if (unknown.length) warnings.push(`unknown hackerone config keys ignored: ${unknown.join(", ")}`);

const auth = authHeader(IDENTIFIER, TOKEN);

/**
 * ❗The window is computed ONCE, here, and passed down — so every observation in
 * this digest is scoped by the same boundary. Recomputing `now` inside the
 * mapping would make the window drift across a long collection, which is a
 * difference nobody would ever notice and nobody could ever reproduce.
 */
const years = Math.min(Math.max(Number(cfg.lookback_years) || 5, 1), 10);
const since = new Date(Date.now() - years * 365 * 86_400_000).toISOString();

let reports = [];
try {
  const page = await getAll(fetchImplementation(), auth, "/hackers/me/reports");
  reports = page.items;
  if (page.truncated) {
    // ❗Said out loud, and it travels inside the signed digest. A truncated
    //   collection presenting itself as complete is a quietly wrong number.
    warnings.push(
      "report history was truncated at the page cap; counts below are a lower bound",
    );
  }
} catch (err) {
  if (err instanceof HackerOneError) die(err.message);
  throw err;
}

console.log(`Fetched ${reports.length} report(s) from the HackerOne hacker API.`);

const identity = identityFrom(reports);
if (!identity) {
  die(
    "Could not establish which HackerOne account this token belongs to.",
    "Identity is read from the reports the API returns for the authenticated caller, and this",
    "account has none that name a reporter. Ravn will not fall back to a handle you typed —",
    "a self-declared handle is exactly what this collector exists not to trust.",
    "",
    "If you have filed reports and still see this, the token may lack read access to them.",
  );
}

console.log(`HackerOne identity resolved from the API: ${identity.username} (id ${identity.id})`);

const { observations, warnings: mapWarnings } = observationsFrom(reports, cfg, { since });
warnings.push(...mapWarnings);

// ── earnings, only if asked for, and never fatal ───────────────────────────
/*
 * ❗A failure here does NOT stop the run. Payments are a different permission on
 * a HackerOne token than reports are, so a token that reads reports may simply
 * not be allowed to read earnings — and losing an entire collection over an
 * optional aggregate would be absurd. It is recorded as a warning, inside the
 * signed digest, so the gap is visible rather than mysterious.
 */
if (cfg.share_bounty_totals) {
  try {
    const { items } = await getAll(fetchImplementation(), auth, "/hackers/payments/earnings", {
      maxPages: 10,
    });
    const observation = earningsObservation(items);
    if (observation) observations.push(observation);
    else warnings.push("bounty totals were requested, but the API returned no earnings");
  } catch (err) {
    warnings.push(
      `bounty totals were requested but could not be read: ${
        err instanceof HackerOneError ? err.message : String(err)
      }`,
    );
  }
}

/**
 * ❗EVERY observation names its own account.
 *
 * The run's OIDC identity is a GitHub one, and the digest's `subject` is a
 * GitHub account. Nothing about a HackerOne fact belongs to that account, and
 * attributing it there would put "resolved 40 reports on HackerOne" on a GitHub
 * profile — wrong on its face, and wrong in a way that survives every merge.
 *
 * `fact.account_source` / `account_external_id` have been columns since V1.2.0
 * for exactly this; ravn-platform reads this field per observation and falls
 * back to the digest subject when it is absent, so older digests are unaffected.
 */
const account = { source: "hackerone", external_id: identity.id, handle: identity.username };
for (const o of observations) o.account = account;

const fragment = {
  schema: "ravn.hackerone-digest/v1",
  account,
  generated_at: new Date().toISOString(),
  window: { since, lookback_years: years },
  // The preferences travel with the observations they governed, so a triager
  // verifying the bundle can see what was WITHHELD. What was withheld is signal.
  redaction: cfg,
  observations,
  warnings,
};

writeFileSync(OUT, `${JSON.stringify(fragment, null, 2)}\n`);
console.log(
  `HackerOne fragment written: ${observations.length} observations for ${identity.username}` +
    `${warnings.length ? `, ${warnings.length} warning(s)` : ""} → ${OUT}`,
);
for (const w of warnings) console.log(`::warning::${w}`);

/** Indirection so a test can hand in its own fetch without a live account. */
function fetchImplementation() {
  return globalThis.fetch;
}
