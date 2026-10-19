/**
 * The deploy workflow's two decisions, run as shipped.
 *
 * ❗These tests execute the bash between the `ravn:lane-decider` and
 * `ravn:lane-recorder` markers in `.github/workflows/deploy.yml`, lifted out of
 * the file rather than copied here (the same discipline as the pin resolver,
 * test/pin-collector.test.mjs). The lane list is a scratch `lanes.yaml`, the
 * repositories are scratch git repositories with a real `origin`, and GitHub's
 * Contents API is a loopback server that remembers what was PUT. That is
 * enough to drive every row of ADR ops-007 §1's table — build, promote,
 * hotfix — and every refusal, without a lane, an App or a cluster. The
 * rollback path (argo-apps#12: a rollback is a deploy) adds a third block, the
 * ECR check, driven against a stand-in `aws` on PATH.
 */

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { REPO, scratch } from "./helpers.mjs";

const WORKFLOW = join(REPO, ".github/workflows/deploy.yml");
const RECORDS_REPO = "RavnSecurity/argo-apps";
const RUN_URL = "https://github.com/RavnSecurity/svc-greeter/actions/runs/42";
const ONE_LANE = "lanes:\n  - { env: prod, branch: main }\n";
const TWO_LANES = "lanes:\n  - { env: dev, branch: dev }\n  - { env: prod, branch: main }\n";

/** A marked bash block, lifted verbatim from the workflow and dedented. */
function block(name) {
  const lines = readFileSync(WORKFLOW, "utf8").split("\n");
  const start = lines.findIndex((l) => l.includes(`ravn:${name}:begin`));
  const end = lines.findIndex((l) => l.includes(`ravn:${name}:end`));
  assert.ok(start > -1 && end > start, `${name} markers missing from deploy.yml`);
  const indent = lines[start].match(/^\s*/)[0];
  return `${lines
    .slice(start + 1, end)
    .map((l) => (l.startsWith(indent) ? l.slice(indent.length) : l))
    .join("\n")}\n`;
}

function bash(script, { cwd, env }) {
  return new Promise((resolve) => {
    const path = join(scratch(), "snippet.sh");
    writeFileSync(path, script);
    const child = spawn("bash", [path], { cwd, env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env } });
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

// ── A loopback Contents API ──────────────────────────────────────────────────

const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const record = (tag) => `image:\n  tag: ${tag}\n`;

/**
 * GitHub's Contents API for one repository: GET returns `{content, sha}` or
 * 404, PUT records the call and answers like GitHub does. `conflictsOnce`
 * answers the first PUT of a path with 409, which is what a concurrent write
 * looks like.
 */
async function contentsApi({ files = {}, conflictsOnce = [] } = {}) {
  const store = new Map(Object.entries(files).map(([p, body]) => [p, { body, sha: `blob-${p.length}-${b64(p).slice(0, 8)}` }]));
  const puts = [];
  const gets = [];
  const pending409 = new Set(conflictsOnce);
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const m = url.pathname.match(new RegExp(`^/repos/${RECORDS_REPO}/contents/(.+)$`));
    if (!m) {
      res.writeHead(404).end("{}");
      return;
    }
    const path = decodeURIComponent(m[1]);
    const auth = req.headers.authorization;
    if (req.method === "GET") {
      gets.push({ path, ref: url.searchParams.get("ref"), auth });
      const f = store.get(path);
      if (!f) {
        res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ message: "Not Found" }));
        return;
      }
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ path, sha: f.sha, content: b64(f.body), encoding: "base64" }));
      return;
    }
    if (req.method === "PUT") {
      let data = "";
      req.on("data", (c) => {
        data += c;
      });
      req.on("end", () => {
        const body = JSON.parse(data);
        puts.push({ path, auth, ...body, decoded: Buffer.from(body.content, "base64").toString("utf8") });
        if (pending409.has(path)) {
          pending409.delete(path);
          res.writeHead(409, { "content-type": "application/json" }).end(JSON.stringify({ message: "is at X but expected Y" }));
          return;
        }
        const existing = store.get(path);
        if ((existing && existing.sha !== body.sha) || (!existing && body.sha)) {
          res.writeHead(409, { "content-type": "application/json" }).end(JSON.stringify({ message: "sha mismatch" }));
          return;
        }
        const sha = `blob-${puts.length}`;
        store.set(path, { body: puts.at(-1).decoded, sha });
        res
          .writeHead(existing ? 200 : 201, { "content-type": "application/json" })
          .end(JSON.stringify({ content: { path, sha }, commit: { sha: `commit-${puts.length}` } }));
      });
      return;
    }
    res.writeHead(405).end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    puts,
    gets,
    store,
    close: () => new Promise((r) => server.close(r)),
  };
}

// ── Scratch repositories ─────────────────────────────────────────────────────

const git = (cwd, ...args) =>
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.invalid",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.invalid",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
    },
  }).trim();

function commit(cwd, msg) {
  writeFileSync(join(cwd, `${msg.replace(/\W+/g, "_")}.txt`), `${msg}\n`);
  git(cwd, "add", "-A");
  git(cwd, "commit", "-q", "-m", msg);
  return git(cwd, "rev-parse", "HEAD");
}

/**
 * Two lanes' worth of history, pushed to a bare origin, then cloned the way
 * actions/checkout with fetch-depth 0 leaves it (every branch under origin/):
 *
 *   main:  A ── M ── H ── F        M = merge of dev (M^2 = B): a promotion
 *               │         │        H = a plain commit on main: a hotfix
 *   dev:   A ── B        feat      F = merge of a feature branch, not dev
 */
function history() {
  const bare = scratch();
  git(bare, "init", "-q", "--bare", "-b", "main");
  const work = scratch();
  git(work, "init", "-q", "-b", "main");
  git(work, "remote", "add", "origin", bare);
  const A = commit(work, "A");
  git(work, "checkout", "-q", "-b", "dev");
  const B = commit(work, "B");
  git(work, "checkout", "-q", "main");
  git(work, "merge", "-q", "--no-ff", "-m", "promote dev", "dev");
  const M = git(work, "rev-parse", "HEAD");
  const H = commit(work, "H hotfix");
  git(work, "checkout", "-q", "-b", "feat");
  commit(work, "feature");
  git(work, "checkout", "-q", "main");
  git(work, "merge", "-q", "--no-ff", "-m", "merge feat", "feat");
  const F = git(work, "rev-parse", "HEAD");
  git(work, "push", "-q", "origin", "main", "dev");
  const clone = scratch();
  git(clone, "clone", "-q", bare, ".");
  return { clone, A, B, M, H, F };
}

const short = (sha) => `sha-${sha.slice(0, 7)}`;
const outputs = (file) =>
  Object.fromEntries(
    readFileSync(file, "utf8")
      .split("\n")
      .filter((l) => l.includes("="))
      .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );

// ── The decider ──────────────────────────────────────────────────────────────

async function decide({ clone, head, ref, lanes = "", api, token = api ? "app-token" : "", images = '[{"name":"svc-greeter"}]', rollbackTo = "" }) {
  const outFile = join(scratch(), "github_output");
  writeFileSync(outFile, "");
  const r = await bash(block("lane-decider"), {
    cwd: clone,
    env: {
      DEPLOY_TOKEN: token,
      LANES_OVERRIDE: lanes,
      IMAGES: images,
      ROLLBACK_TO: rollbackTo,
      REF_NAME: ref,
      HEAD_SHA: head,
      GITHUB_API_URL: api ? api.origin : "http://127.0.0.1:9",
      GITHUB_OUTPUT: outFile,
      RECORDS_REPO,
      RECORDS_BRANCH: "main",
      LANES_PATH: "lanes/lanes.yaml",
    },
  });
  return { ...r, outputs: outputs(outFile) };
}

test("N = 1: a push to main is a build of HEAD, the lane list from the input", async () => {
  const { clone, F } = history();
  const r = await decide({ clone, head: F, ref: "main", lanes: ONE_LANE });
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.outputs, { mode: "build", env: "prod", tag: short(F), from_env: "", from_sha: "", build: "true" });
  assert.match(r.out, /Lane 0 of 1: prod \(main\)\. Decision: build/);
});

test("N = 1: the lane list is read from argo-apps with the App token when there is no input", async () => {
  const { clone, F } = history();
  const api = await contentsApi({ files: { "lanes/lanes.yaml": ONE_LANE } });
  try {
    const r = await decide({ clone, head: F, ref: "main", api });
    assert.equal(r.code, 0, r.out);
    assert.equal(r.outputs.mode, "build");
    assert.deepEqual(api.gets, [{ path: "lanes/lanes.yaml", ref: "main", auth: "Bearer app-token" }]);
  } finally {
    await api.close();
  }
});

test("N = 2: a push to the first lane builds, whatever HEAD looks like", async () => {
  const { clone, B } = history();
  const r = await decide({ clone, head: B, ref: "dev", lanes: TWO_LANES });
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.outputs, { mode: "build", env: "dev", tag: short(B), from_env: "", from_sha: "", build: "true" });
});

test("N = 2: a merge from dev whose record matches HEAD^2 PROMOTES, and does not build", async () => {
  const { clone, B, M } = history();
  const api = await contentsApi({ files: { "lanes/dev/svc-greeter.yaml": record(short(B)) } });
  try {
    const r = await decide({ clone, head: M, ref: "main", lanes: TWO_LANES, api });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(r.outputs, { mode: "promote", env: "prod", tag: short(B), from_env: "dev", from_sha: B, build: "false" });
    assert.doesNotMatch(r.out, /HOTFIX/);
  } finally {
    await api.close();
  }
});

test("N = 2: a merge from dev is refused while dev's record is still the previous sha", async () => {
  const { clone, A, M } = history();
  const api = await contentsApi({ files: { "lanes/dev/svc-greeter.yaml": record(short(A)) } });
  try {
    const r = await decide({ clone, head: M, ref: "main", lanes: TWO_LANES, api });
    assert.notEqual(r.code, 0);
    assert.match(r.out, new RegExp(`::error::Lane dev's record for svc-greeter is ${short(A)}; this merge brought`));
    assert.match(r.out, /re-run this workflow when it has/);
    assert.equal(r.outputs.mode, undefined, "no decision reaches the next step");
  } finally {
    await api.close();
  }
});

test("N = 2: a merge from dev is refused when dev has no record at all", async () => {
  const { clone, M } = history();
  const api = await contentsApi();
  try {
    const r = await decide({ clone, head: M, ref: "main", lanes: TWO_LANES, api });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /::error::Lane dev has no record for svc-greeter/);
  } finally {
    await api.close();
  }
});

test("N = 2: every image must be on dev's record before any is promoted", async () => {
  const { clone, B, M } = history();
  const api = await contentsApi({ files: { "lanes/dev/system.yaml": record(short(B)) } });
  try {
    const r = await decide({ clone, head: M, ref: "main", lanes: TWO_LANES, api, images: '[{"name":"system"},{"name":"portal"}]' });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /Lane dev has no record for portal/);
  } finally {
    await api.close();
  }
});

test("N = 2: a plain commit on main is a HOTFIX build, said loudly", async () => {
  const { clone, H } = history();
  const r = await decide({ clone, head: H, ref: "main", lanes: TWO_LANES });
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.outputs, { mode: "hotfix", env: "prod", tag: short(H), from_env: "", from_sha: "", build: "true" });
  assert.match(r.out, /::warning title=HOTFIX BUILD on lane prod::/);
  assert.match(r.out, /Merge main back into dev now/);
});

test("N = 2: a merge whose second parent is NOT on dev is a hotfix too", async () => {
  const { clone, F } = history();
  const r = await decide({ clone, head: F, ref: "main", lanes: TWO_LANES });
  assert.equal(r.code, 0, r.out);
  assert.equal(r.outputs.mode, "hotfix");
  assert.equal(r.outputs.tag, short(F));
});

test("a branch that is not a lane is refused, naming the lanes", async () => {
  const { clone, F } = history();
  const r = await decide({ clone, head: F, ref: "feat", lanes: TWO_LANES });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /::error::Branch 'feat' is not a lane\./);
  assert.match(r.out, /dev=dev.*prod=main/);
});

test("a lane list without a 'lanes' list, or with a lane missing its branch, is refused", async () => {
  const { clone, F } = history();
  for (const lanes of ["- env: prod\n", "lanes: []\n", "lanes:\n  - { env: prod }\n"]) {
    const r = await decide({ clone, head: F, ref: "main", lanes });
    assert.notEqual(r.code, 0, lanes);
    assert.match(r.out, /::error::/);
  }
});

test("'images' must be a list of names ECR and the record path can take", async () => {
  const { clone, F } = history();
  for (const images of ["[]", '[{"name":"Svc Greeter"}]', '{"name":"svc-greeter"}', "not json"]) {
    const r = await decide({ clone, head: F, ref: "main", lanes: ONE_LANE, images });
    assert.notEqual(r.code, 0, images);
    assert.match(r.out, /::error::'images' must be a non-empty JSON array/);
  }
});

test("with neither an App token nor a lane list, nothing is decided", async () => {
  const { clone, F } = history();
  const r = await decide({ clone, head: F, ref: "main" });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /::error::No App token and no 'lanes' input/);
});

test("when argo-apps does not hold the lane list yet, the run says who publishes it", async () => {
  const { clone, F } = history();
  const api = await contentsApi();
  try {
    const r = await decide({ clone, head: F, ref: "main", api });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /::error::Reading lanes\/lanes.yaml from RavnSecurity\/argo-apps failed with HTTP 404/);
    assert.match(r.out, /publish-lanes/);
  } finally {
    await api.close();
  }
});

// ── The recorder ─────────────────────────────────────────────────────────────

async function writeRecord({ clone, api, mode, tag, head, fromEnv = "", fromSha = "", dryRun = false, images = '[{"name":"svc-greeter"}]', token = "app-token", actor = "dave" }) {
  const summary = join(scratch(), "summary.md");
  writeFileSync(summary, "");
  const r = await bash(block("lane-recorder"), {
    cwd: clone,
    env: {
      DEPLOY_TOKEN: token,
      IMAGES: images,
      MODE: mode,
      LANE_ENV: "prod",
      TAG: tag,
      FROM_ENV: fromEnv,
      FROM_SHA: fromSha,
      HEAD_SHA: head,
      ACTOR: actor,
      DRY_RUN: dryRun ? "true" : "false",
      RUN_URL,
      GITHUB_API_URL: api.origin,
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_STEP_SUMMARY: summary,
      RECORDS_REPO,
      RECORDS_BRANCH: "main",
    },
  });
  return { ...r, summary: readFileSync(summary, "utf8") };
}

test("a build writes a new record through the Contents API, one commit per image, naming the run", async () => {
  const { clone, F } = history();
  const api = await contentsApi();
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 1);
    const put = api.puts[0];
    assert.equal(put.path, "lanes/prod/svc-greeter.yaml");
    assert.equal(put.auth, "Bearer app-token");
    assert.equal(put.branch, "main");
    assert.equal(put.sha, undefined, "a new file carries no blob sha");
    assert.equal(put.message, `lane prod: svc-greeter ${short(F)} ${RUN_URL}`);
    assert.match(put.decoded, /^# lanes\/prod\/svc-greeter.yaml — written by the deploy workflow\. Never hand-edited\.\n/);
    assert.match(put.decoded, new RegExp(`\nimage:\n  tag: ${short(F)}\n$`));
    assert.match(r.out, /Wrote lanes\/prod\/svc-greeter.yaml = sha-[0-9a-f]{7} in RavnSecurity\/argo-apps@commit-1/);
    assert.match(r.summary, /## Lane `prod`: build/);
  } finally {
    await api.close();
  }
});

test("a promotion updates the existing record with its blob sha and says where it came from", async () => {
  const { clone, A, B, M } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(A)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "promote", tag: short(B), head: M, fromEnv: "dev", fromSha: B });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 1);
    assert.equal(api.puts[0].message, `lane prod: svc-greeter ${short(B)} (promoted from dev @ ${B}) ${RUN_URL}`);
    assert.ok(api.puts[0].sha, "an update carries the current blob sha, or GitHub refuses it");
    assert.equal(api.store.get("lanes/prod/svc-greeter.yaml").body, api.puts[0].decoded);
    assert.match(r.summary, /promoted from `dev`/);
  } finally {
    await api.close();
  }
});

test("a hotfix says so in the message and the summary", async () => {
  const { clone, B, H } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(B)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "hotfix", tag: short(H), head: H });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts[0].message, `lane prod: svc-greeter ${short(H)} (hotfix) ${RUN_URL}`);
    assert.match(r.summary, /## ⚠️ HOTFIX build on lane `prod`/);
  } finally {
    await api.close();
  }
});

test("a record that already holds the tag is left alone", async () => {
  const { clone, F } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(F)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 0);
    assert.match(r.out, /already records/);
  } finally {
    await api.close();
  }
});

test("❗the rollback guard: a record newer than the commit being deployed is never overwritten", async () => {
  // Run 1 (sha-A) is re-run after run 2 wrote sha-H. H descends from A, so
  // writing A would roll prod back a release with a green build.
  const { clone, A, H } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(A), head: A });
    assert.notEqual(r.code, 0);
    assert.equal(api.puts.length, 0, "nothing was written");
    assert.match(r.out, new RegExp(`::error::Refusing to write lanes/prod/svc-greeter.yaml: it records ${short(H)}`));
    assert.match(r.out, new RegExp(`To roll back on purpose, run the caller's deploy.yml by hand .* with rollback_to: ${short(A)}`));
  } finally {
    await api.close();
  }
});

test("the rollback guard also stops a promotion that would drop a hotfix", async () => {
  // prod runs hotfix H; a dev → main promotion cut before H was merged back
  // would write B, which H does not descend from... and B does not contain H.
  const { clone, B, H } = history();
  // A promotion merge of dev cut from before H: its source is B.
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "promote", tag: short(B), head: B, fromEnv: "dev", fromSha: B });
    assert.notEqual(r.code, 0);
    assert.equal(api.puts.length, 0);
    assert.match(r.out, /is a hotfix, merge it back/);
  } finally {
    await api.close();
  }
});

test("a record whose tag is not a commit this repository knows does not trip the guard", async () => {
  const { clone, F } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record("sha-0000000") } });
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 1);
  } finally {
    await api.close();
  }
});

test("a 409 from a concurrent write is re-read and retried", async () => {
  const { clone, A, F } = history();
  const api = await contentsApi({
    files: { "lanes/prod/svc-greeter.yaml": record(short(A)) },
    conflictsOnce: ["lanes/prod/svc-greeter.yaml"],
  });
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 2);
    assert.match(r.out, /HTTP 409 on lanes\/prod\/svc-greeter.yaml \(attempt 1\)/);
    assert.match(r.out, /Wrote lanes\/prod\/svc-greeter.yaml/);
  } finally {
    await api.close();
  }
});

test("a monorepo writes one record per image, in order", async () => {
  const { clone, F } = history();
  const api = await contentsApi();
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F, images: '[{"name":"system"},{"name":"portal"}]' });
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(
      api.puts.map((p) => p.path),
      ["lanes/prod/system.yaml", "lanes/prod/portal.yaml"],
    );
    assert.equal(api.puts[1].message, `lane prod: portal ${short(F)} ${RUN_URL}`);
  } finally {
    await api.close();
  }
});

test("a dry run prints the record and the message it would write, and writes nothing", async () => {
  const { clone, F } = history();
  const api = await contentsApi();
  try {
    const r = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F, dryRun: true });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 0);
    assert.equal(api.gets.length, 0, "a dry run does not need the records");
    assert.match(r.out, /Dry run: would write lanes\/prod\/svc-greeter.yaml in RavnSecurity\/argo-apps:/);
    assert.match(r.out, new RegExp(`    image:\n      tag: ${short(F)}`));
    assert.match(r.out, new RegExp(`with the commit message: lane prod: svc-greeter ${short(F)} ${RUN_URL}`));
    assert.match(r.summary, /\*\*Dry run\.\*\* Would write `lanes\/prod\/svc-greeter.yaml`/);
  } finally {
    await api.close();
  }
});

test("any other HTTP failure stops the run with the status and the body", async () => {
  const { clone, F } = history();
  const api = await contentsApi();
  const broken = createServer((_req, res) => res.writeHead(500, { "content-type": "application/json" }).end('{"message":"boom"}'));
  await new Promise((r) => broken.listen(0, "127.0.0.1", r));
  try {
    const r = await writeRecord({ clone, api: { origin: `http://127.0.0.1:${broken.address().port}` }, mode: "build", tag: short(F), head: F });
    assert.notEqual(r.code, 0);
    assert.match(r.out, /::error::Reading lanes\/prod\/svc-greeter.yaml from RavnSecurity\/argo-apps failed with HTTP 500/);
    assert.match(r.out, /boom/);
  } finally {
    await api.close();
    await new Promise((r) => broken.close(r));
  }
});

// ── Rollback (argo-apps#12: a rollback is a deploy) ──────────────────────────
//
// `rollback_to` re-records an image an earlier run built: the decider resolves
// the target and checks it was on the lane's branch, the ECR check asks AWS
// whether every image is there at that tag, and the recorder writes over
// whatever the record holds, skipping the ancestor guard on purpose.

test("rollback_to a sha-<7> on the lane's branch is mode rollback: no build, and HEAD is not read", async () => {
  // HEAD F is a merge that would be a hotfix; none of that matters.
  const { clone, A, F } = history();
  const r = await decide({ clone, head: F, ref: "main", lanes: TWO_LANES, rollbackTo: short(A) });
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(r.outputs, { mode: "rollback", env: "prod", tag: short(A), from_env: "", from_sha: "", build: "false" });
  assert.match(r.out, /::notice title=ROLLBACK on lane prod::/);
  assert.doesNotMatch(r.out, /HOTFIX/);
  assert.match(r.out, /Decision: rollback/);
});

test("rollback_to a full commit SHA maps to its sha-<7> tag", async () => {
  const { clone, A, F } = history();
  const r = await decide({ clone, head: F, ref: "main", lanes: ONE_LANE, rollbackTo: A });
  assert.equal(r.code, 0, r.out);
  assert.equal(r.outputs.mode, "rollback");
  assert.equal(r.outputs.tag, short(A));
});

test("a rollback target that was never on this lane's branch is refused", async () => {
  // H is a hotfix on main. dev never carried it, so dev cannot be 'rolled back' to it.
  const { clone, B, H } = history();
  const r = await decide({ clone, head: B, ref: "dev", lanes: TWO_LANES, rollbackTo: short(H) });
  assert.notEqual(r.code, 0);
  assert.match(r.out, new RegExp(`::error::Refusing to roll back dev to ${H.slice(0, 7)}: that commit was never on dev\\.`));
  assert.equal(r.outputs.mode, undefined, "no decision reaches the next step");
});

test("a rollback target this repository does not know, or that is not a sha at all, is refused", async () => {
  const { clone, F } = history();
  for (const [to, want] of [
    ["sha-0000000", /::error::'rollback_to' sha-0000000 is not a commit of this repository\./],
    ["v1.2.3", /::error::'rollback_to' must be a sha-<7> image tag or a commit SHA/],
    ["sha-abc", /::error::'rollback_to' must be a sha-<7> image tag or a commit SHA/],
  ]) {
    const r = await decide({ clone, head: F, ref: "main", lanes: ONE_LANE, rollbackTo: to });
    assert.notEqual(r.code, 0, to);
    assert.match(r.out, want);
  }
});

/**
 * The ECR check, with a stand-in `aws` ahead of the real one on PATH: the
 * images named in $FAKE_ECR (`ravn/<name>:<tag>`) exist; anything else gets
 * the ImageNotFoundException the real CLI prints; `deny` gets an access error.
 */
async function ecrCheck({ tag, inEcr, images = '[{"name":"svc-greeter"}]', accountId = "123456789012", dryRun = false }) {
  const bin = scratch();
  writeFileSync(
    join(bin, "aws"),
    [
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      '[ "$1 $2" = "ecr describe-images" ] || { echo "unexpected aws call: $*" >&2; exit 2; }',
      'repo=""; tag=""',
      'while [ $# -gt 0 ]; do case "$1" in --repository-name) repo=$2; shift ;; --image-ids) tag=${2#imageTag=}; shift ;; esac; shift; done',
      '[ "$FAKE_ECR" != deny ] || { echo "An error occurred (AccessDeniedException) when calling the DescribeImages operation: not allowed" >&2; exit 254; }',
      'for have in $FAKE_ECR; do [ "$have" = "$repo:$tag" ] && { echo "2026-10-19T00:00:00+00:00"; exit 0; }; done',
      "echo \"An error occurred (ImageNotFoundException) when calling the DescribeImages operation: The image with imageId {imageTag: '$tag'} does not exist within the repository with name '$repo' in the registry with id '123456789012'\" >&2",
      "exit 254",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  return bash(block("ecr-check"), {
    cwd: scratch(),
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      FAKE_ECR: inEcr.join(" "),
      IMAGES: images,
      TAG: tag,
      AWS_ACCOUNT_ID: accountId,
      ECR_PREFIX: "ravn",
      DRY_RUN: dryRun ? "true" : "false",
      RECORDS_REPO,
    },
  });
}

test("a rollback asks ECR for every image at the tag, and goes on when all are there", async () => {
  const r = await ecrCheck({ tag: "sha-abc1234", images: '[{"name":"system"},{"name":"portal"}]', inEcr: ["ravn/system:sha-abc1234", "ravn/portal:sha-abc1234"] });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /ravn\/system:sha-abc1234 is in ECR \(pushed 2026-10-19/);
  assert.match(r.out, /ravn\/portal:sha-abc1234 is in ECR/);
});

test("❗a rollback to a tag any image is missing from ECR is refused, naming the missing ones", async () => {
  const r = await ecrCheck({ tag: "sha-abc1234", images: '[{"name":"system"},{"name":"portal"}]', inEcr: ["ravn/system:sha-abc1234"] });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /ravn\/portal:sha-abc1234 is NOT in ECR\./);
  assert.match(r.out, /::error::Refusing to roll back: not in ECR: ravn\/portal:sha-abc1234\./);
  assert.doesNotMatch(r.out, /not in ECR:.*ravn\/system/);
  assert.match(r.out, /Nothing has been written/);
});

test("an ECR error that is not 'not found' stops the run with the error, not a false 'missing'", async () => {
  const r = await ecrCheck({ tag: "sha-abc1234", inEcr: ["deny"] });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /::error::Asking ECR about ravn\/svc-greeter:sha-abc1234 failed\./);
  assert.match(r.out, /AccessDeniedException/);
  assert.doesNotMatch(r.out, /Refusing to roll back/);
});

test("a dry run with no aws_account_id cannot ask ECR, and says so instead of guessing", async () => {
  const r = await ecrCheck({ tag: "sha-abc1234", inEcr: [], accountId: "", dryRun: true });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /::notice::Dry run with no aws_account_id: whether the images are in ECR at sha-abc1234 is not checked\./);
});

test("❗a rollback writes over a NEWER record, skipping the guard, and says what it rolled back from and who did it", async () => {
  // prod runs H. Rolling back to A, an ancestor of H, is exactly what the
  // guard refuses for a build; a rollback does it on purpose.
  const { clone, A, H } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "rollback", tag: short(A), head: H, actor: "dave" });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 1);
    assert.equal(api.puts[0].message, `lane prod: svc-greeter ${short(A)} (rollback from ${short(H)}, by dave) ${RUN_URL}`);
    assert.ok(api.puts[0].sha, "an update carries the current blob sha");
    assert.match(api.puts[0].decoded, new RegExp(`\nimage:\n  tag: ${short(A)}\n$`));
    assert.match(r.out, new RegExp(`::warning title=ROLLBACK on lane prod::svc-greeter: ${short(H)} → ${short(A)}, by dave`));
    assert.match(r.summary, /## ⏪ ROLLBACK on lane `prod` to `sha-[0-9a-f]{7}`/);
    assert.match(r.summary, /mode=rollback, by \*\*dave\*\*/);
    assert.match(r.summary, new RegExp("`" + short(H) + "` → `" + short(A) + "`"));
  } finally {
    await api.close();
  }
});

test("❗the ordinary deploy after a rollback still writes: the rolled-back record is an ancestor of the new HEAD", async () => {
  const { clone, A, H, F } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const back = await writeRecord({ clone, api, mode: "rollback", tag: short(A), head: H });
    assert.equal(back.code, 0, back.out);
    assert.match(api.store.get("lanes/prod/svc-greeter.yaml").body, new RegExp(`tag: ${short(A)}`));
    // The fix lands: a push to main builds F, which descends from A. The guard passes.
    const next = await writeRecord({ clone, api, mode: "build", tag: short(F), head: F });
    assert.equal(next.code, 0, next.out);
    assert.equal(api.puts.length, 2);
    assert.equal(api.puts[1].message, `lane prod: svc-greeter ${short(F)} ${RUN_URL}`);
    assert.match(api.store.get("lanes/prod/svc-greeter.yaml").body, new RegExp(`tag: ${short(F)}`));
    assert.doesNotMatch(next.out, /Refusing/);
  } finally {
    await api.close();
  }
});

test("a rollback to what the record already holds is left alone", async () => {
  const { clone, A } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(A)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "rollback", tag: short(A), head: A });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 0);
    assert.match(r.out, /already records/);
    assert.doesNotMatch(r.out, /::warning/);
  } finally {
    await api.close();
  }
});

test("a rollback dry run reads the record to name what it would roll back from, prints the record, and writes nothing", async () => {
  const { clone, A, H } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "rollback", tag: short(A), head: H, dryRun: true, actor: "dave" });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 0, "nothing was written");
    assert.deepEqual(api.gets.map((g) => g.path), ["lanes/prod/svc-greeter.yaml"]);
    assert.match(r.out, /Dry run: would write lanes\/prod\/svc-greeter.yaml in RavnSecurity\/argo-apps:/);
    assert.match(r.out, new RegExp(`    image:\n      tag: ${short(A)}`));
    assert.match(r.out, new RegExp(`with the commit message: lane prod: svc-greeter ${short(A)} \\(rollback from ${short(H)}, by dave\\) ${RUN_URL}`));
    assert.doesNotMatch(r.out, /::warning/, "nothing happened, so nothing to warn about");
    assert.match(r.summary, /## ⏪ ROLLBACK on lane `prod`/);
    assert.match(r.summary, new RegExp("`" + short(H) + "` → `" + short(A) + "` \\(dry run, not written\\)"));
  } finally {
    await api.close();
  }
});

test("a rollback dry run with no App token (a test caller) says the old tag was not read, and still prints the record", async () => {
  const { clone, A, H } = history();
  const api = await contentsApi({ files: { "lanes/prod/svc-greeter.yaml": record(short(H)) } });
  try {
    const r = await writeRecord({ clone, api, mode: "rollback", tag: short(A), head: H, dryRun: true, token: "" });
    assert.equal(r.code, 0, r.out);
    assert.equal(api.puts.length, 0);
    assert.equal(api.gets.length, 0);
    assert.match(r.out, new RegExp(`with the commit message: lane prod: svc-greeter ${short(A)} \\(rollback from \\(not read: no App token\\), by dave\\)`));
  } finally {
    await api.close();
  }
});

test("the workflow holds contents: read and id-token: write, and nothing writes the caller's repo", () => {
  const text = readFileSync(WORKFLOW, "utf8");
  assert.doesNotMatch(text, /contents:\s*write/);
  assert.match(text, /permissions:\n\s+contents: read\n\s+id-token: write/);
  assert.doesNotMatch(text, /git push/);
  assert.match(text, /rollback_to:\n\s+description:/, "the rollback_to input is declared");
  assert.match(text, /if: steps\.decide\.outputs\.mode == 'rollback'\n/, "the ECR check runs for rollbacks only");
});
