/**
 * The HackerOne collector.
 *
 * ❗What is actually being guarded here is CONSENT and ATTRIBUTION, in that
 * order. Everything else in this file is scaffolding around those two:
 *
 *   1. Nothing leaves the runner that the reporter did not tick. A collector
 *      that "helpfully" emits one extra field is the only bug in this design
 *      that cannot be taken back, because by the time anyone notices it is
 *      already in a signed digest on Ravn's side.
 *
 *   2. A HackerOne fact is attributed to the HackerOne ACCOUNT, not to the
 *      GitHub account the run's OIDC identity belongs to. Get that wrong and
 *      "resolved 40 reports on HackerOne" lands on a GitHub profile — wrong on
 *      its face, and wrong in a way that survives every later merge.
 *
 * And one thing that is not a nicety: identity comes from the API's own answer,
 * never from the credential and never from config. The Basic-auth username is
 * the reporter's USERNAME on this API (the token's identifier on the program-side
 * one, which is a different API) — and a username is a thing they typed, so it
 * cannot name anybody. A collector that trusted it would be trusting a
 * self-declared handle, which is the exact thing this design exists to refuse.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { REPO, run, scratch } from "./helpers.mjs";
import { startGitHub, startHackerOne } from "./mocks.mjs";
import {
  earningsObservation,
  identityFrom,
  observationsFrom,
  resolveH1Config,
} from "../scripts/lib/hackerone.mjs";

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

const JOB = { id: "6b1f0a3e-1f7c-4a2b-9f11-6c9a2f0f7e21", expiresAt: "2026-08-24T21:00:00.000Z" };

/** A delivered config asking for the hackerone collector, with `metadata`. */
function configWith(metadata) {
  return {
    job: JOB,
    config: {
      version: 1,
      type: "profile",
      collectors: [
        {
          provider: "hackerone",
          required: { secrets: ["H1_API_IDENTIFIER", "H1_API_TOKEN"] },
          metadata,
        },
      ],
    },
  };
}

async function collect({ metadata = {}, h1 = {}, env = {} } = {}) {
  const mock = await startHackerOne(h1);
  const cwd = scratch();
  writeFileSync(join(cwd, "ravn-collection-config.json"), JSON.stringify(configWith(metadata)));
  const r = await run("collect-hackerone.mjs", {
    cwd,
    env: {
      H1_API_IDENTIFIER: mock.identifier,
      H1_API_TOKEN: mock.token,
      RAVN_H1_API: mock.origin,
      ...env,
    },
  });
  const path = join(cwd, "hackerone-digest.json");
  const fragment = r.code === 0 ? JSON.parse(readFileSync(path, "utf8")) : null;
  await mock.close();
  return { ...r, fragment, mock };
}

const typesIn = (fragment) => new Set(fragment.observations.map((o) => o.type));

// ── identity ───────────────────────────────────────────────────────────────

test("identity is read from the API, never from the credential", async () => {
  const { code, fragment } = await collect({ h1: { username: "ave.rez", userId: 88213 } });
  assert.equal(code, 0);
  assert.equal(fragment.account.source, "hackerone");
  assert.equal(fragment.account.handle, "ave.rez");
  assert.equal(fragment.account.external_id, "88213");
});

test("❗the token IDENTIFIER never becomes the account handle", async () => {
  // The identifier is an arbitrary label. If it ever leaks into the account,
  // a reporter could name themselves anything simply by renaming their token.
  const { code, fragment } = await collect({
    h1: { identifier: "definitely-not-my-handle", username: "ave.rez" },
  });
  assert.equal(code, 0);
  assert.equal(fragment.account.handle, "ave.rez");
  assert.notEqual(fragment.account.handle, "definitely-not-my-handle");
  assert.ok(
    !JSON.stringify(fragment).includes("definitely-not-my-handle"),
    "the credential identifier must not appear anywhere in the fragment",
  );
});

test("no reports means no identity, and the run REFUSES rather than guessing", async () => {
  const { code, stderr } = await collect({ h1: { reports: [] } });
  assert.notEqual(code, 0, "a collection that cannot identify its subject must fail");
  assert.match(stderr, /Could not establish which HackerOne account/i);
  assert.match(stderr, /self-declared handle/i);
});

test("a wrong credential says WHY, and says the RIGHT why", async () => {
  const { code, stderr } = await collect({ env: { H1_API_IDENTIFIER: "ave.rez" } });
  assert.notEqual(code, 0);
  assert.match(stderr, /401/);

  /*
   * ❗THIS ASSERTED THE WRONG ADVICE AND SO DEFENDED IT. The message used to tell
   * reporters the username had to be the token's IDENTIFIER and "not your
   * HackerOne handle" — true of HackerOne's CUSTOMER/program API, false of the
   * hacker API this collector calls, which is Basic over `username:token`. So
   * the 401 explanation recommended the one value guaranteed to produce a 401,
   * and this test held it in place.
   */
  assert.match(stderr, /USERNAME/);
  assert.match(stderr, /handle you log in with/i);
  assert.doesNotMatch(stderr, /not your HackerOne handle/i);
  // and it points at where a token is actually issued
  assert.match(stderr, /settings\/api_token/);
});

// ── consent ────────────────────────────────────────────────────────────────

test("defaults emit counts, and never a title of an undisclosed report", async () => {
  const { code, fragment } = await collect();
  assert.equal(code, 0);

  const types = typesIn(fragment);
  assert.ok(types.has("hackerone.report_counts"));
  assert.ok(types.has("hackerone.program"));
  assert.ok(types.has("hackerone.severity"));
  assert.ok(!types.has("hackerone.report_title"), "titles are opt-in and were not opted into");
  assert.ok(!types.has("hackerone.bounty_totals"), "money is opt-in and was not opted into");

  // ❗The specific leak this guards. The mock's triaged report has a title that
  //   describes a live, unfixed vulnerability in somebody else's product.
  assert.ok(
    !JSON.stringify(fragment).includes("SSRF in the internal metadata proxy"),
    "an undisclosed report's title must not appear anywhere in the digest",
  );
});

test("a DISCLOSED report's title is carried — it is already published", async () => {
  const { fragment } = await collect();
  const disclosed = fragment.observations.filter((o) => o.type === "hackerone.disclosed_report");
  assert.equal(disclosed.length, 1);
  assert.equal(disclosed[0].payload.report_id, "2140960");
  assert.equal(disclosed[0].subject, "https://hackerone.com/reports/2140960");
  assert.ok(disclosed[0].payload.disclosed_at.endsWith("Z"), "ISO 8601 at UTC");
});

test("every share_* toggle OFF produces a digest with no observations", async () => {
  // ❗The whole-hog check. Individual toggles can be right while some section
  //   nobody remembered stays unconditional, and this is the only assertion
  //   that catches that: everything off must mean nothing collected.
  const { code, fragment } = await collect({
    metadata: {
      share_report_counts: false,
      share_programs: false,
      share_severity_breakdown: false,
      share_disclosed_reports: false,
      share_cve_credits: false,
      share_report_titles: false,
      share_bounty_totals: false,
    },
  });
  assert.equal(code, 0);
  assert.deepEqual(fragment.observations, []);
});

test("opting in to titles carries them, and only for the undisclosed ones", async () => {
  const { fragment } = await collect({ metadata: { share_report_titles: true } });
  const titles = fragment.observations.filter((o) => o.type === "hackerone.report_title");
  assert.ok(titles.length > 0);
  assert.ok(
    titles.every((t) => t.payload.title),
    "every title observation carries a title",
  );
  // The disclosed one is emitted by the disclosed-report branch, not twice.
  assert.ok(!titles.some((t) => t.payload.report_id === "2140960"));
});

test("opting in to bounty totals gives an AGGREGATE, never a per-program figure", async () => {
  const { fragment } = await collect({ metadata: { share_bounty_totals: true } });
  const bounty = fragment.observations.find((o) => o.type === "hackerone.bounty_totals");
  assert.ok(bounty, "the observation is present when opted into");
  assert.equal(bounty.payload.total, 2000.5);
  assert.equal(bounty.payload.count, 2);
  assert.deepEqual(bounty.payload.currencies, ["USD"]);
  // What a specific company paid for a specific bug is not the reporter's alone.
  assert.ok(!("by_program" in bounty.payload));
});

// ── attribution ────────────────────────────────────────────────────────────

test("❗every observation names the HackerOne account, not the run's identity", async () => {
  const { fragment } = await collect();
  assert.ok(fragment.observations.length > 0);
  for (const o of fragment.observations) {
    assert.equal(o.account?.source, "hackerone", `${o.type} was attributed to the wrong source`);
    assert.equal(o.account?.external_id, "88213");
  }
});

// ── the window, and honesty about limits ───────────────────────────────────

test("the lookback window is applied, and the reports it dropped are declared", async () => {
  const { fragment } = await collect();
  const counts = fragment.observations.find((o) => o.type === "hackerone.report_counts");
  // Four in the 5-year window; the 2015 one is outside it.
  assert.equal(counts.payload.total, 4);
  assert.ok(
    fragment.warnings.some((w) => /fell outside the 5-year window/.test(w)),
    `expected a window warning, got ${JSON.stringify(fragment.warnings)}`,
  );
  assert.ok(!JSON.stringify(fragment).includes("oldcorp"), "an out-of-window program leaked");
});

test("the resolved preferences travel inside the fragment", async () => {
  // What was WITHHELD is signal, and a triager verifying the bundle can only
  // see it if the config that governed the collection is carried with it.
  const { fragment } = await collect({ metadata: { share_programs: false } });
  assert.equal(fragment.redaction.share_programs, false);
  assert.equal(fragment.redaction.share_report_counts, true);
});

test("an unknown preference is reported, not fatal", async () => {
  const { code, fragment } = await collect({ metadata: { share_something_we_removed: true } });
  assert.equal(code, 0, "a key this version does not know must not lose the whole run");
  assert.ok(fragment.warnings.some((w) => /share_something_we_removed/.test(w)));
});

// ── the pure mapping, directly ─────────────────────────────────────────────

test("resolveH1Config keeps conservative defaults for absent keys", () => {
  const { cfg } = resolveH1Config({ share_report_counts: false });
  assert.equal(cfg.share_report_counts, false);
  assert.equal(cfg.share_report_titles, false, "an absent key resolves to the DEFAULT");
  assert.equal(cfg.share_disclosed_reports, true);
});

test("resolveH1Config will not be talked into a truthy string", () => {
  // ❗A server that sent `"false"` must not turn a toggle ON. Booleans are
  //   compared to `true`, never coerced — `Boolean("false")` is `true`.
  const { cfg } = resolveH1Config({ share_report_titles: "false" });
  assert.equal(cfg.share_report_titles, false);
});

test("identityFrom returns null rather than a partial answer", () => {
  assert.equal(identityFrom([]), null);
  assert.equal(identityFrom([{ relationships: {} }]), null);
  assert.equal(identityFrom([{ relationships: { reporter: { data: { id: 1 } } } }]), null);
});

test("observationsFrom is pure — same input, same output", () => {
  const reports = [
    {
      id: "1",
      attributes: { state: "resolved", created_at: "2026-01-01T00:00:00Z", cve_ids: [] },
      relationships: { program: { data: { attributes: { handle: "acme" } } } },
    },
  ];
  const { cfg } = resolveH1Config({});
  const a = observationsFrom(reports, cfg);
  const b = observationsFrom(reports, cfg);
  assert.deepEqual(a, b);
});

test("earnings across currencies are declared, not silently summed into one", () => {
  const o = earningsObservation([
    { attributes: { amount: "100", currency: "USD" } },
    { attributes: { amount: "50", currency: "EUR" } },
  ]);
  assert.deepEqual(o.payload.currencies, ["EUR", "USD"]);
  assert.equal(o.payload.count, 2);
});

test("no earnings at all is null, not a zero that reads as a fact", () => {
  assert.equal(earningsObservation([]), null);
});

// ── the fold-in: one digest, one signature ─────────────────────────────────

test("❗HackerOne observations land INSIDE the bytes that get attested", async () => {
  /*
   * The property this whole two-collector design rests on. `attest-build-provenance`
   * signs the SHA-256 of `profile-digest.json`. A fragment sitting BESIDE that
   * file is not covered by the signature — anyone can strip or swap it while the
   * attestation keeps verifying perfectly. So the assertion is not "the
   * observations are present"; it is that removing them CHANGES THE ATTESTED
   * HASH. A field whose removal does not move the hash was never signed by it.
   */
  const gh = await startGitHub();
  const cwd = scratch();
  writeFileSync(
    join(cwd, "ravn-collection-config.json"),
    JSON.stringify({
      job: JOB,
      config: {
        version: 1,
        type: "profile",
        collectors: [
          { provider: "github", required: { secrets: ["RAVN_READONLY_TOKEN"] }, metadata: {} },
        ],
      },
    }),
  );

  // What collect-hackerone.mjs leaves behind, verbatim in shape.
  const fragment = {
    schema: "ravn.hackerone-digest/v1",
    account: { source: "hackerone", external_id: "88213", handle: "ave.rez" },
    generated_at: "2026-08-25T09:00:00.000Z",
    redaction: { share_report_counts: true },
    observations: [
      {
        type: "hackerone.report_counts",
        subject: "",
        payload: { total: 4, by_state: { resolved: 2 } },
        account: { source: "hackerone", external_id: "88213", handle: "ave.rez" },
      },
    ],
    warnings: ["a note from the other collector"],
  };
  writeFileSync(join(cwd, "hackerone-digest.json"), JSON.stringify(fragment, null, 2));

  const r = await run("collect.mjs", {
    cwd,
    env: {
      RAVN_TOKEN: "ghp_fake_readonly",
      RAVN_ACTOR: "reporter",
      RAVN_GITHUB_API: gh.origin,
      RAVN_NOTABILITY_PATH: join(REPO, "notability/notable-projects.txt"),
    },
  });
  await gh.close();
  assert.equal(r.code, 0, r.out);

  const bytes = readFileSync(join(cwd, "profile-digest.json"));
  const text = bytes.toString("utf8");
  const attested = sha256(bytes);
  const digest = JSON.parse(text);

  // Present, and attributed to HackerOne rather than to the run's GitHub subject.
  const h1 = digest.observations.filter((o) => o.type === "hackerone.report_counts");
  assert.equal(h1.length, 1, "the fragment's observation did not reach the digest");
  assert.equal(h1[0].account.source, "hackerone");
  assert.equal(digest.subject.source, "github", "the subject must NOT be rewritten");

  // Both accounts are declared, so ingest knows whose facts these are.
  const sources = digest.collected_from.map((a) => a.source).sort();
  assert.deepEqual(sources, ["github", "hackerone"]);

  // The other collector's warnings survive, namespaced.
  assert.ok(digest.warnings.some((w) => /hackerone: a note from the other collector/.test(w)));

  // ── the proof: strip the HackerOne observations and the hash moves.
  const clone = JSON.parse(text);
  clone.observations = clone.observations.filter((o) => !o.type.startsWith("hackerone."));
  const stripped = sha256(Buffer.from(JSON.stringify(clone, null, 2), "utf8"));
  assert.notEqual(stripped, attested, "removing the HackerOne facts did not change the hash");
});

test("an absent fragment is normal, and a corrupt one is said out loud", async () => {
  // ❗Absent is the common case — most configs ask only for github. A fragment
  //   that is PRESENT but unreadable is different: a collector ran, believed it
  //   produced something, and its output is being dropped. Silence there would
  //   lose a reporter's HackerOne history with no trace.
  const gh = await startGitHub();
  const cwd = scratch();
  writeFileSync(
    join(cwd, "ravn-collection-config.json"),
    JSON.stringify({
      job: JOB,
      config: {
        version: 1,
        type: "profile",
        collectors: [
          { provider: "github", required: { secrets: ["RAVN_READONLY_TOKEN"] }, metadata: {} },
        ],
      },
    }),
  );
  writeFileSync(join(cwd, "hackerone-digest.json"), "{ this is not json");

  const r = await run("collect.mjs", {
    cwd,
    env: {
      RAVN_TOKEN: "ghp_fake_readonly",
      RAVN_ACTOR: "reporter",
      RAVN_GITHUB_API: gh.origin,
      RAVN_NOTABILITY_PATH: join(REPO, "notability/notable-projects.txt"),
    },
  });
  await gh.close();

  assert.equal(r.code, 0, "a corrupt fragment must not lose the GitHub collection too");
  const digest = JSON.parse(readFileSync(join(cwd, "profile-digest.json"), "utf8"));
  assert.ok(
    digest.warnings.some((w) => /hackerone-digest\.json could not be read/.test(w)),
    `expected a warning about the unreadable fragment, got ${JSON.stringify(digest.warnings)}`,
  );
});
