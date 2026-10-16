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
 * hotfix — and every refusal, without a lane, an App or a cluster.
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

async function decide({ clone, head, ref, lanes = "", api, token = api ? "app-token" : "", images = '[{"name":"svc-greeter"}]' }) {
  const outFile = join(scratch(), "github_output");
  writeFileSync(outFile, "");
  const r = await bash(block("lane-decider"), {
    cwd: clone,
    env: {
      DEPLOY_TOKEN: token,
      LANES_OVERRIDE: lanes,
      IMAGES: images,
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

async function writeRecord({ clone, api, mode, tag, head, fromEnv = "", fromSha = "", dryRun = false, images = '[{"name":"svc-greeter"}]' }) {
  const summary = join(scratch(), "summary.md");
  writeFileSync(summary, "");
  const r = await bash(block("lane-recorder"), {
    cwd: clone,
    env: {
      DEPLOY_TOKEN: "app-token",
      IMAGES: images,
      MODE: mode,
      LANE_ENV: "prod",
      TAG: tag,
      FROM_ENV: fromEnv,
      FROM_SHA: fromSha,
      HEAD_SHA: head,
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
    assert.match(r.out, /revert the record commit/);
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

test("the workflow holds contents: read and id-token: write, and nothing writes the caller's repo", () => {
  const text = readFileSync(WORKFLOW, "utf8");
  assert.doesNotMatch(text, /contents:\s*write/);
  assert.match(text, /permissions:\n\s+contents: read\n\s+id-token: write/);
  assert.doesNotMatch(text, /git push/);
});
