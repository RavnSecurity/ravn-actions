/**
 * The script pin: the collector must run the code the attestation names.
 *
 * ❗These tests run the SHIPPED text. `pinResolver()` extracts the bash between
 * the `ravn:pin-resolver` markers out of `.github/workflows/collect-profile.yml`
 * rather than keeping a copy here, because a copy is exactly how a fix like this
 * rots: the workflow drifts, the copy still passes, and the property nobody can
 * see from a green run is the one that broke.
 *
 * That property is #8. `github.job_workflow_sha` is empty inside a reusable
 * workflow and `actions/checkout` treats an empty `ref` as "the default branch",
 * so the old step signed a digest for whatever `main` held. **A passing run
 * proved nothing** — which is why most of what is below asserts a FAILURE, and
 * asserts that no SHA reaches the checkout when it fails.
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { REPO, scratch } from "./helpers.mjs";
import { startRavn } from "./mocks.mjs";

const WORKFLOW = join(REPO, ".github/workflows/collect-profile.yml");
const SHA = "1f0e4d3c2b1a09876543210fedcba9876543210a"; // 40 hex, and not this repo's
const REF_PREFIX = "RavnSecurity/ravn-actions/.github/workflows/collect-profile.yml@";

/** The pin resolver, lifted verbatim from the workflow and dedented. */
function pinResolver() {
  const lines = readFileSync(WORKFLOW, "utf8").split("\n");
  const start = lines.findIndex((l) => l.includes("ravn:pin-resolver:begin"));
  const end = lines.findIndex((l) => l.includes("ravn:pin-resolver:end"));
  assert.ok(start > -1 && end > start, "pin-resolver markers missing from collect-profile.yml");
  const indent = lines[start].match(/^\s*/)[0];
  return `${lines
    .slice(start + 1, end)
    .map((l) => (l.startsWith(indent) ? l.slice(indent.length) : l))
    .join("\n")}\n`;
}

const b64url = (obj) => Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
const jwt = (claims) => `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url(claims)}.c2ln`;

/** Run a bash snippet the way the runner does: a child process, clean env. */
function bash(script, { cwd, env = {} }) {
  return new Promise((resolve) => {
    const path = join(cwd, "snippet.sh");
    writeFileSync(path, script);
    const child = spawn("bash", [path], { cwd, env: { PATH: process.env.PATH, ...env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("close", (code) => resolve({ code, stdout, stderr, out: stdout + stderr }));
  });
}

/**
 * Run the resolver against a mock Actions OIDC endpoint serving `token`, and
 * report what it wrote to GITHUB_OUTPUT — which is the only thing the checkout
 * step ever sees.
 */
async function resolve(token, { env = {} } = {}) {
  const ravn = await startRavn({ oidcToken: token });
  const cwd = scratch();
  const outFile = join(cwd, "github_output");
  writeFileSync(outFile, "");
  const r = await bash(pinResolver(), {
    cwd,
    env: {
      ACTIONS_ID_TOKEN_REQUEST_URL: ravn.oidcRequestUrl,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: "runtime-request-token",
      RAVN_OIDC_AUDIENCE: "https://ravnsecurity.io",
      EXPECT_REF_PREFIX: REF_PREFIX,
      CTX_JOB_WORKFLOW_SHA: "", // what the github context really holds here (#8)
      GITHUB_OUTPUT: outFile,
      ...env,
    },
  });
  await ravn.close();
  const stepOutput = readFileSync(outFile, "utf8");
  return { ...r, stepOutput, audience: ravn.seen.audience };
}

/** What the checkout step would receive: `steps.pin.outputs.sha`, or nothing. */
const resolvedSha = (stepOutput) => (stepOutput.match(/^sha=(.*)$/m) ?? [])[1];

test("resolves the collector SHA from the OIDC token and hands it to the checkout", async () => {
  const token = jwt({ job_workflow_sha: SHA, job_workflow_ref: `${REF_PREFIX}${SHA}` });
  const r = await resolve(token);

  assert.equal(r.code, 0, r.out);
  assert.equal(resolvedSha(r.stepOutput), SHA);

  // Printed, because a live cross-repo dispatch is verified from the run log —
  // there is no other way to see which code actually ran.
  assert.match(r.stdout, new RegExp(`Collector SHA resolved from OIDC claim job_workflow_sha: ${SHA}`));
  // The audience is Ravn's, not GitHub's default (the repo owner's URL, which
  // every repository already holds and which is therefore not a credential).
  assert.equal(r.audience, "https://ravnsecurity.io");
  // The token is a live credential for the length of the job. It is registered
  // as a mask — the one line where it legitimately appears — and nowhere else,
  // so any later echo of it anywhere in the job is redacted rather than logged.
  assert.match(r.stdout, new RegExp(`::add-mask::${token.replace(/[.]/g, "\\.")}`));
  assert.equal(r.out.split(token).length - 1, 1, "the JWT appears outside the ::add-mask:: line");
});

test("decodes base64url — the alphabet and the stripped padding, not just base64", async () => {
  // ❗Crafted so the payload segment actually exercises the decoder: both
  // substituted characters, and a length that needs padding restored. Asserted
  // rather than assumed, because a payload that happened to be plain base64
  // would make this test pass while proving nothing.
  const claims = {
    job_workflow_sha: SHA,
    job_workflow_ref: `${REF_PREFIX}${SHA}`,
    nonce: "?~>ÿ".repeat(3),
  };
  const payload = b64url(claims);
  assert.ok(payload.includes("-"), "payload should contain the base64url '-'");
  assert.ok(payload.includes("_"), "payload should contain the base64url '_'");
  assert.notEqual(payload.length % 4, 0, "payload should be missing its padding");

  // And the naive version really does fail, so the translation is load-bearing
  // rather than defensive decoration.
  const cwd = scratch();
  const naive = await bash(`printf '%s' "$P" | base64 -d`, { cwd, env: { P: payload } });
  assert.notEqual(naive.code, 0, `plain 'base64 -d' should reject base64url:\n${naive.out}`);

  const r = await resolve(jwt(claims));
  assert.equal(r.code, 0, r.out);
  assert.equal(resolvedSha(r.stepOutput), SHA);
});

/**
 * ⚠️ Fail closed. Every row is a shape that must ABORT.
 *
 * The assertion that matters in each is `resolvedSha === undefined`: nothing
 * written to GITHUB_OUTPUT means `steps.pin.outputs.sha` is empty, and an empty
 * `ref:`, which is what caused #8, can no longer be reached — the run is already
 * over. A non-zero exit alone would not prove that.
 */
const CLOSED = [
  {
    what: "the claim is present but empty — the #8 shape exactly",
    token: () => jwt({ job_workflow_sha: "", job_workflow_ref: `${REF_PREFIX}x` }),
    says: /carries no usable 'job_workflow_sha' claim \(absent, or present and empty\)/,
  },
  {
    what: "the claim is absent altogether",
    token: () => jwt({ job_workflow_ref: `${REF_PREFIX}x`, sub: "repo:acme/thing:ref:refs/heads/main" }),
    says: /carries no usable 'job_workflow_sha' claim \(absent, or present and empty\)/,
  },
  {
    what: "the claim is an abbreviated SHA",
    token: () => jwt({ job_workflow_sha: "d360e1a", job_workflow_ref: `${REF_PREFIX}x` }),
    says: /not a 40-character commit SHA: 'd360e1a'/,
  },
  {
    what: "the claim is a branch name rather than a SHA",
    token: () => jwt({ job_workflow_sha: "refs/heads/main", job_workflow_ref: `${REF_PREFIX}x` }),
    says: /not a 40-character commit SHA: 'refs\/heads\/main'/,
  },
  {
    what: "the claim is 40 characters but not hex",
    token: () => jwt({ job_workflow_sha: "Z".repeat(40), job_workflow_ref: `${REF_PREFIX}x` }),
    says: /not a 40-character commit SHA/,
  },
  {
    // Not a cross-repo reusable call: job_workflow_sha is then a real, valid SHA
    // — of the CALLER's workflow file. Fatal, and worth its own message.
    what: "the claim names a workflow in another repository",
    token: () =>
      jwt({
        job_workflow_sha: SHA,
        job_workflow_ref: "acme/thing/.github/workflows/build.yml@refs/heads/main",
      }),
    says: /does not name this collector/,
  },
  {
    what: "the endpoint returns something that is not a JWT",
    token: () => "not-a-jwt",
    says: /not a JWT/,
  },
  {
    what: "the JWT payload is not base64url at all",
    token: () => "aGVhZGVy.!!!not-base64!!!.c2ln",
    says: /base64url-decode|did not decode to JSON/,
  },
  {
    what: "the JWT payload decodes to something that is not JSON",
    token: () => `aGVhZGVy.${Buffer.from("plain text", "utf8").toString("base64url")}.c2ln`,
    says: /did not decode to JSON/,
  },
];

for (const row of CLOSED) {
  test(`fails closed: ${row.what}`, async () => {
    const r = await resolve(row.token());
    assert.notEqual(r.code, 0, `should have aborted:\n${r.out}`);
    assert.match(r.out, /::error::/);
    assert.match(r.out, row.says);
    // The point of the whole exercise: no SHA, therefore no checkout.
    assert.equal(resolvedSha(r.stepOutput), undefined, `leaked a ref: ${r.stepOutput}`);
    assert.match(r.out, /Nothing has been checked out/);
  });
}

test("fails closed: the job has no OIDC endpoint at all", async () => {
  const cwd = scratch();
  const outFile = join(cwd, "github_output");
  writeFileSync(outFile, "");
  // No ACTIONS_ID_TOKEN_REQUEST_* — what a job missing `id-token: write` sees.
  const r = await bash(pinResolver(), {
    cwd,
    env: { EXPECT_REF_PREFIX: REF_PREFIX, GITHUB_OUTPUT: outFile },
  });

  assert.notEqual(r.code, 0, r.out);
  assert.match(r.out, /No OIDC token endpoint is available to this job/);
  // Names the true cause. Everything downstream of a missing id-token permission
  // is a misleading symptom of it.
  assert.match(r.out, /permissions: id-token: write/);
  assert.equal(resolvedSha(readFileSync(outFile, "utf8")), undefined);
});

test("the checkout takes its ref from the pin step, and the empty context value is gone", () => {
  const wf = readFileSync(WORKFLOW, "utf8");

  // The regression, stated as the thing it is: `github.job_workflow_sha` must
  // never be a `ref:` again. It may still appear (it is printed for comparison),
  // so this asserts placement, not absence.
  const refs = [...wf.matchAll(/^\s*ref:\s*(.+)$/gm)].map((m) => m[1].trim());
  assert.deepEqual(refs, ["${{ steps.pin.outputs.sha }}"]);

  // Ordering is the constraint that shapes this whole fix: the token has to be
  // minted before the checkout, because the scripts that could mint it are
  // inside the checkout.
  const order = (needle) => wf.indexOf(needle);
  assert.ok(order("id: pin") < order("Checkout ravn-actions (pinned)"));
  assert.ok(order("Checkout ravn-actions (pinned)") < order("Verify the checkout is at the attested commit"));
  // Inline, therefore covered by the attested claim — not a checked-out script.
  assert.ok(!pinResolver().includes(".ravn-actions/"));
});
