/**
 * The digest, and the one property that matters about it.
 *
 * ❗`actions/attest-build-provenance` signs the SHA-256 of profile-digest.json.
 * So "the config is in the digest" is only worth something if the config is in
 * THE BYTES THAT WERE HASHED — not beside them in the envelope, not in an
 * artifact sidecar, either of which anyone can strip or swap while the
 * signature keeps verifying. The proof below therefore hashes the file exactly
 * as the workflow does, then shows the hash MOVES when either field is removed.
 * A field whose removal does not change the hash was never covered by it.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { REPO, run, scratch } from "./helpers.mjs";
import { startGitHub } from "./mocks.mjs";

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const JOB = { id: "6b1f0a3e-1f7c-4a2b-9f11-6c9a2f0f7e21", expiresAt: "2026-08-24T21:00:00.000Z" };

test("the resolved config and the job id are inside the hashed bytes", async () => {
  const config = JSON.parse(
    readFileSync(join(REPO, "test/fixtures/collection-config-github-metadata.json"), "utf8"),
  );
  const cwd = scratch();
  writeFileSync(join(cwd, "ravn-collection-config.json"), JSON.stringify({ job: JOB, config }));

  const gh = await startGitHub();
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

  // ── hash exactly what the workflow attests: the file, as bytes.
  const bytes = readFileSync(join(cwd, "profile-digest.json"));
  const attested = sha256(bytes);

  // ── the fields are IN those bytes, found by searching the bytes themselves.
  const text = bytes.toString("utf8");
  assert.ok(text.includes(`"job_id": "${JOB.id}"`), "job_id is not in the hashed bytes");
  assert.ok(text.includes('"collection_config"'), "collection_config is not in the hashed bytes");
  assert.ok(text.includes('"share_wishful_thinking": true'), "the delivered config is not verbatim");

  const digest = JSON.parse(text);
  assert.equal(digest.job_id, JOB.id);
  assert.deepEqual(digest.collection_config, config);
  // Resolved preferences: delivered keys applied, unknown key dropped and
  // reported, everything unmentioned left at the conservative default.
  assert.equal(digest.redaction.share_org_memberships, true);
  assert.equal(digest.redaction.lookback_years, 2);
  assert.equal(digest.redaction.share_private_repo_count, false);
  assert.equal(digest.redaction.share_wishful_thinking, undefined);
  assert.ok(
    digest.warnings.some((w) => w.includes("share_wishful_thinking")),
    "an ignored config key should be visible in the digest",
  );

  // ── the proof: remove either field and the attested hash is a different hash.
  const without = (key) => {
    const clone = JSON.parse(text);
    delete clone[key];
    return sha256(Buffer.from(`${JSON.stringify(clone, null, 2)}`, "utf8"));
  };
  const strippedJob = without("job_id");
  const strippedConfig = without("collection_config");
  assert.notEqual(strippedJob, attested);
  assert.notEqual(strippedConfig, attested);

  // Same serializer, nothing removed: the round trip itself is byte-identical,
  // so the differences above are the fields and not the re-serialization.
  const roundTrip = sha256(Buffer.from(`${JSON.stringify(JSON.parse(text), null, 2)}`, "utf8"));
  assert.equal(roundTrip, attested, "round-trip must be byte-identical for the proof to hold");

  console.log("");
  console.log("  attested sha256(profile-digest.json)      %s", attested);
  console.log("  same bytes, round-tripped through JSON    %s  (identical)", roundTrip);
  console.log("  with job_id removed                       %s  (moves)", strippedJob);
  console.log("  with collection_config removed            %s  (moves)", strippedConfig);
  console.log("");
  console.log("  first 24 lines of the bytes that were hashed:");
  for (const line of text.split("\n").slice(0, 24)) console.log(`    ${line}`);

  // The rest of the run still works: sharing preferences were honoured, and the
  // notability distinction survives.
  const upstream = digest.observations.filter((o) => o.type === "github.upstream_contribution");
  assert.deepEqual(
    upstream.map((o) => [o.subject, o.payload.notable, o.payload.nominated]),
    [
      ["golang/go", true, false],
      ["someone/not-on-the-list", false, true],
    ],
  );
  // A private repository never appears, by name or otherwise.
  assert.ok(!text.includes("acme/internal-thing"));
  assert.equal(digest.assertions.length, 1);
});

test("no delivered config means no run — there is no collect-with-defaults path", async () => {
  const gh = await startGitHub();
  const r = await run("collect.mjs", {
    cwd: scratch(),
    env: { RAVN_TOKEN: "ghp_fake_readonly", RAVN_ACTOR: "reporter", RAVN_GITHUB_API: gh.origin },
  });
  await gh.close();

  assert.equal(r.code, 1);
  assert.match(r.stderr, /No collection config at ravn-collection-config\.json/);
  assert.match(r.stderr, /runs after scripts\/fetch-config\.mjs/);
});
