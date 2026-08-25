/**
 * The preflight step: mint, fetch, print, check secrets — and refuse loudly.
 *
 * ❗Every failing case here is one a reporter would otherwise debug alone, with
 * a symptom that points somewhere other than the cause. That is what these
 * assert: not that the collector stops, but that it says the true reason.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { REPO, run, scratch } from "./helpers.mjs";
import { startRavn } from "./mocks.mjs";

const FIXTURE = JSON.parse(
  readFileSync(join(REPO, "test/fixtures/collection-config-v1.json"), "utf8"),
);
const JOB = { id: "6b1f0a3e-1f7c-4a2b-9f11-6c9a2f0f7e21", expiresAt: "2026-08-24T21:00:00.000Z" };

const envFor = (ravn, extra = {}) => ({
  ACTIONS_ID_TOKEN_REQUEST_URL: ravn.oidcRequestUrl,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runtime-request-token",
  RAVN_BASE_URL: ravn.origin,
  RAVN_READONLY_TOKEN: "ghp_fake_readonly",
  ...extra,
});

test("fetches, echoes verbatim, and writes the config for the collector", async () => {
  const ravn = await startRavn({ respond: () => ({ status: 200, body: { job: JOB, config: FIXTURE } }) });
  const cwd = scratch();
  const r = await run("fetch-config.mjs", { cwd, env: envFor(ravn) });
  await ravn.close();

  assert.equal(r.code, 0, r.out);

  // The audience is Ravn's, explicitly. GitHub's default audience is the repo
  // owner's URL, which every repo in every org already holds — not a credential.
  assert.equal(ravn.seen.audience, "https://ravnsecurity.io");
  assert.equal(ravn.seen.bearer, "Bearer header.payload.signature");
  // ADR §4: the token, and nothing else. A body would be unauthenticated input.
  assert.equal(ravn.seen.method, "POST");
  assert.equal(ravn.seen.bodyBytes, 0);

  // D12 half one — printed before anything is collected.
  assert.match(r.stdout, /Resolved collection config \(as delivered by Ravn, verbatim\)/);
  assert.match(r.stdout, /"provider": "github"/);
  assert.match(r.stdout, new RegExp(JOB.id));
  assert.match(r.stdout, /share_private_repo_count: false/);
  // A provider this collector version cannot run is a warning and a skip, not a
  // demand for a secret nothing would read.
  assert.match(r.stdout, /::warning::Config asks for provider 'hackerone'/);
  assert.match(r.stdout, /Preflight OK — providers to run: github/);

  // The EXACT bytes Ravn sent, on disk for the digest to embed.
  const written = readFileSync(join(cwd, "ravn-collection-config.json"), "utf8");
  assert.deepEqual(JSON.parse(written), { job: JOB, config: FIXTURE });
  // The OIDC token is masked, and never printed.
  assert.match(r.stdout, /::add-mask::header\.payload\.signature/);
});

test("no OIDC endpoint names the real cause, not the symptom", async () => {
  const ravn = await startRavn({ respond: () => ({ status: 200, body: { job: JOB, config: FIXTURE } }) });
  const cwd = scratch();
  const r = await run("fetch-config.mjs", {
    cwd,
    env: { ...envFor(ravn), ACTIONS_ID_TOKEN_REQUEST_URL: "" },
  });
  await ravn.close();

  assert.equal(r.code, 1);
  assert.match(r.stderr, /No OIDC token endpoint available/);
  assert.match(r.stderr, /permissions: id-token: write/);
  assert.match(r.stderr, /policy disables OIDC/);
});

test("each refusal code is surfaced with its deeplink, and nothing is collected", async () => {
  const cases = [
    [401, "invalid-token", "https://apps.ravnsecurity.io/app/profile/help/invalid-token"],
    [403, "event-not-dispatch", "https://apps.ravnsecurity.io/app/profile/help/event-not-dispatch"],
    [404, "no-binding", "https://apps.ravnsecurity.io/app/profile/new?repo=reporter%2Fravn-attestations"],
    [409, "repo-mismatch", "https://apps.ravnsecurity.io/app/profile/jobs/abc"],
    [409, "job-locked", "https://apps.ravnsecurity.io/app/profile/jobs/abc/clone"],
    [410, "job-expired", "https://apps.ravnsecurity.io/app/profile/jobs/abc/renew"],
  ];

  for (const [status, code, link] of cases) {
    const ravn = await startRavn({
      respond: () => ({ status, body: { code, message: `refused: ${code}`, link } }),
    });
    const cwd = scratch();
    const r = await run("fetch-config.mjs", { cwd, env: envFor(ravn) });
    await ravn.close();

    assert.equal(r.code, 1, `${code} should stop the run`);
    assert.match(r.stderr, new RegExp(`Ravn refused the config request: ${code} \\(HTTP ${status}\\)`));
    assert.match(r.stderr, new RegExp(link.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(r.stderr, /Nothing was collected\./);
    assert.throws(() => readFileSync(join(cwd, "ravn-collection-config.json")));
  }
});

test("a refusal with no deeplink still lands the reporter somewhere real", async () => {
  const ravn = await startRavn({ respond: () => ({ status: 404, body: { code: "no-binding" } }) });
  const cwd = scratch();
  const r = await run("fetch-config.mjs", { cwd, env: envFor(ravn) });
  await ravn.close();

  assert.equal(r.code, 1);
  assert.match(r.stderr, /No active collection job for this owner\/repo/);
  assert.match(r.stderr, /https:\/\/apps\.ravnsecurity\.io\/app\/profile {2}\(Ravn sent no deeplink/);
});

test("a missing required secret fails in preflight, naming the secret", async () => {
  const ravn = await startRavn({ respond: () => ({ status: 200, body: { job: JOB, config: FIXTURE } }) });
  const cwd = scratch();
  const r = await run("fetch-config.mjs", {
    cwd,
    env: { ...envFor(ravn), RAVN_READONLY_TOKEN: "" },
  });
  await ravn.close();

  assert.equal(r.code, 1);
  assert.match(r.stderr, /Preflight failed/);
  assert.match(r.stderr, /RAVN_READONLY_TOKEN {2}\(required by the 'github' collector\)/);
  assert.match(r.stderr, /Nothing has been collected/);
  // The reporter still sees the config they were handed, even on a failed run.
  assert.match(r.stdout, /Resolved collection config/);
  assert.throws(() => readFileSync(join(cwd, "ravn-collection-config.json")));
});

test("a config this collector version cannot execute is refused, not guessed at", async () => {
  const ravn = await startRavn({
    respond: () => ({ status: 200, body: { job: JOB, config: { version: 2, type: "profile", collectors: [] } } }),
  });
  const cwd = scratch();
  const r = await run("fetch-config.mjs", { cwd, env: envFor(ravn) });
  await ravn.close();

  assert.equal(r.code, 1);
  assert.match(r.stderr, /config\.version must be 1, got 2/);
  assert.match(r.stderr, /config\.collectors must be a non-empty array/);
});
