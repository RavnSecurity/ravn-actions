#!/usr/bin/env node
/**
 * Ravn profile collector.
 *
 * Runs INSIDE the reporter's own Actions environment. It may see their full
 * picture (via a read-only PAT they mint), but only aggregate/digested
 * observations are written to profile-digest.json. Private repo names, commit
 * messages and issue bodies never leave the runner.
 *
 * ── What changed at digest v1, and why it matters ──────────────────────────
 *
 * v0 emitted `signals` — a bag of aggregates about the reporter's OWN account:
 * how many repos, which languages, how many followers. All true, all weak, and
 * all self-selected.
 *
 * v1 adds `observations`: individually-typed facts, the most important of which
 * is CONTRIBUTION TO NOTABLE UPSTREAM PROJECTS. That one is different in kind
 * from everything else here, because merged pull requests into public
 * repositories are PUBLIC — Ravn can go and confirm them without trusting this
 * digest at all. The attestation is not what makes those claims true; it is what
 * makes them worth an API call.
 *
 * ❗The collector states what it SAW. It assigns no scores and draws no
 * conclusions. What an observation is WORTH is a versioned model on Ravn's side,
 * so that changing our mind never costs a reporter a re-run. Anything in this
 * file that starts to look like a weighting belongs over there instead.
 *
 * ❗Notability is decided by notability/notable-projects.txt, which ships at this
 * same commit and is therefore covered by the same attestation. The reporter may
 * nominate additional repositories, and those are marked as their assertion —
 * never as a notable-project claim.
 *
 * ── Where the config comes from, since security-005 ────────────────────────
 *
 * `ravn.config.yml` in the reporter's repo is retired. The config is fetched by
 * `scripts/fetch-config.mjs` over an OIDC-authenticated channel and left on disk
 * for this script to read.
 *
 * ❗Two things then have to be true, or server-delivered config quietly moves
 * "what you share" from the reporter to Ravn's server (D12):
 *
 *   - the fetch step PRINTS the config before anything is collected, and
 *   - this script embeds it in the digest BEFORE hashing.
 *
 * The second is what keeps security-004's promise — that a triager verifying a
 * bundle can see what was withheld — true. Config outside the hashed bytes is
 * config anyone can substitute after the fact.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { collectorFor } from "./lib/collection.mjs";
import { resolveConfig } from "./lib/config.mjs";
import { isNotable, loadNotabilitySet } from "./lib/notability.mjs";

const TOKEN = process.env.RAVN_TOKEN;
const ACTOR = process.env.RAVN_ACTOR;
const CONFIG_PATH = process.env.RAVN_COLLECTION_CONFIG || "ravn-collection-config.json";

if (!TOKEN) {
  console.error("No token available; aborting.");
  process.exit(1);
}

// ❗Fail if the fetch step did not run. There is no "collect with defaults"
// fallback on purpose: a run that collects against a config nobody delivered
// produces a digest whose `collection_config` is a fiction, and D7's job id
// would be absent from a bundle that otherwise looks complete.
if (!existsSync(CONFIG_PATH)) {
  console.error(
    `No collection config at ${CONFIG_PATH}. This script runs after scripts/fetch-config.mjs, ` +
      "which fetches the config over OIDC and writes it there; aborting.",
  );
  process.exit(1);
}

const response = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
const collectionConfig = response.config;
const JOB_ID = response.job?.id ?? null;
const githubCollector = collectorFor(collectionConfig, "github");
if (!githubCollector) {
  console.error("The delivered config has no 'github' collector; aborting.");
  process.exit(1);
}
// Per-provider `metadata` is where the reporter's sharing preferences live.
const { cfg, unknown } = resolveConfig(githubCollector.metadata);

// ---------- GitHub API helpers ----------
// The base is overridable so the collector can be exercised end to end against
// a mock; in a real run nothing sets it and it is api.github.com.
const API = process.env.RAVN_GITHUB_API || "https://api.github.com";
const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
};

async function rest(path) {
  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json();
}

async function graphql(query, variables = {}) {
  const res = await fetch(`${API}/graphql`, {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
  });
  const body = await res.json();
  if (body.errors) throw new Error(JSON.stringify(body.errors));
  return body.data;
}

// ---------- collection ----------
async function main() {
  const user = await rest("/user").catch(() => rest(`/users/${ACTOR}`));
  const login = user.login;
  const notability = loadNotabilitySet();
  const warnings = [];
  if (unknown.length) {
    warnings.push(
      `config keys this collector version does not know, ignored: ${unknown.join(", ")}`,
    );
  }
  if (notability.missing) warnings.push("notability list not found; upstream matching skipped");

  const digest = {
    schema: "ravn.profile-digest/v1",
    // ❗D7 — the job id is a TOP-LEVEL digest field, written before the file is
    // hashed and therefore covered by the signature. It is the nonce: bundles
    // are bearer artifacts, and a genuine untampered digest belonging to Alice
    // verifies perfectly when uploaded by Bob. Carrying it in the envelope or an
    // artifact sidecar instead would make it strippable, and D7 would buy
    // nothing. Stamped from day one even though enforcement is deferred —
    // provenance cannot be backfilled.
    job_id: JOB_ID,
    subject: {
      source: "github",
      github_login: login,
      github_id: user.id,
      // ❗The STABLE id, named the way Ravn's verifier reads it. A login is
      // renameable and recyclable; binding evidence to one binds it to a
      // spelling somebody else can later hold.
      external_id: user.id,
    },
    generated_at: new Date().toISOString(),
    // ❗D12 — the config Ravn delivered, verbatim, inside the hashed bytes. The
    // reporter no longer holds a file they can point at, so this IS the record
    // of what they agreed to: printed to the run log before collection, signed
    // here, and readable by anyone verifying the bundle.
    collection_config: collectionConfig,
    // The RESOLVED sharing preferences — the delivered metadata merged over this
    // collector version's defaults. Kept distinct from `collection_config`
    // because they answer different questions: what Ravn asked for, versus what
    // this collector version actually did with it. An absent key resolves to the
    // conservative default, and the difference is visible only here.
    redaction: cfg,
    notability: { set: notability.id, sha256: notability.sha256 },
    /**
     * Every account this run actually observed, `subject` included.
     *
     * ❗`subject` stays exactly what it was — the GitHub account the OIDC
     * identity and the collection job belong to. It is NOT a list, and widening
     * it would change what the job binds to. This is the additive answer to a
     * different question: "whose facts are in here", which used to have only one
     * possible answer and now does not.
     */
    collected_from: [
      { source: "github", external_id: user.id, handle: login, schema: "ravn.profile-digest/v1" },
    ],
    observations: [],
    assertions: [],
    // v0's shape, still emitted so anything reading the old format keeps working.
    signals: {},
    warnings,
  };

  const observe = (type, subject, payload) =>
    digest.observations.push({ type, subject: String(subject ?? ""), payload });

  // ── account standing
  if (cfg.share_account_age) {
    const account = {
      created_at: user.created_at,
      account_age_days: Math.floor((Date.now() - new Date(user.created_at).getTime()) / 86_400_000),
      followers: user.followers,
      public_repos: user.public_repos,
    };
    digest.signals.account = account;
    observe("github.account", "", account);
  }

  const thisYear = new Date().getUTCFullYear();
  const createdYear = new Date(user.created_at).getUTCFullYear();
  const lookback = Math.max(1, Math.min(10, Number(cfg.lookback_years) || 5));
  const startYear = Math.max(createdYear, thisYear - lookback);

  // ── yearly contribution totals
  if (cfg.share_contribution_totals) {
    const years = [];
    for (let y = startYear; y <= thisYear; y++) {
      const data = await graphql(
        `query($login:String!,$from:DateTime!,$to:DateTime!){
          user(login:$login){
            contributionsCollection(from:$from,to:$to){
              totalCommitContributions
              totalPullRequestContributions
              totalPullRequestReviewContributions
              totalIssueContributions
              restrictedContributionsCount
            }
          }
        }`,
        { login, from: `${y}-01-01T00:00:00Z`, to: `${y}-12-31T23:59:59Z` },
      ).catch(() => null);
      const c = data?.user?.contributionsCollection;
      if (!c) continue;
      const row = {
        year: y,
        commits: c.totalCommitContributions,
        prs: c.totalPullRequestContributions,
        reviews: c.totalPullRequestReviewContributions,
        issues: c.totalIssueContributions,
        // "restricted" = private contributions GitHub already aggregates
        private_contributions: c.restrictedContributionsCount,
      };
      years.push(row);
      observe("github.contribution_year", y, row);
    }
    digest.signals.contributions_by_year = years;
  }

  // ── ❗upstream contributions: the strongest thing in this file, and the only
  //    one Ravn can confirm without trusting the digest.
  if (cfg.share_upstream_contributions && !notability.missing) {
    const nominated = new Set(
      (cfg.nominate_repos ?? [])
        .map((r) => String(r ?? "").trim().toLowerCase())
        .filter((r) => /^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(r)),
    );
    const candidates = await upstreamCandidates(login, startYear, thisYear);

    let emitted = 0;
    for (const [nameWithOwner, seen] of candidates) {
      const key = nameWithOwner.toLowerCase();
      const notable = isNotable(notability, key);
      const isNominated = nominated.has(key);
      // ❗Public only, and on a list only. A private repository never appears
      // here even by name, and an arbitrary public one does not either — this
      // cannot be turned into a directory of what the reporter works on.
      if (seen.isPrivate) continue;
      if (!notable && !isNominated) continue;
      if (emitted >= 100) {
        warnings.push("upstream observation cap (100) reached");
        break;
      }

      const merged = await mergedPrCount(key, login);
      if (merged === 0 && seen.commits === 0) continue;

      observe("github.upstream_contribution", key, {
        merged_prs: merged,
        prs_opened: seen.prs,
        commits: seen.commits,
        first_year: seen.firstYear,
        last_year: seen.lastYear,
        stars: seen.stars,
        // ❗The distinction the whole design turns on. `notable` means the
        // project is on Ravn's published, attested list. `nominated` means the
        // reporter asked for it — carried, and never conflated with the former.
        notable,
        nominated: isNominated,
        notability_set: notability.id,
      });
      emitted += 1;
    }
    digest.signals.upstream_contributions = emitted;
  }

  // ── repos, languages, orgs, security signal (v0 parity, now also observed)
  const repos = await allRepos();
  const pub = repos.filter((r) => !r.private);
  const priv = repos.filter((r) => r.private);

  const repoStats = {
    public_count: pub.length,
    ...(cfg.share_private_repo_count ? { private_count: priv.length } : {}),
    public_original_count: pub.filter((r) => !r.fork).length,
  };
  digest.signals.repos = repoStats;
  observe("github.repos", "", repoStats);

  if (cfg.share_public_repo_names) {
    const top = pub
      .filter((r) => !r.fork)
      .sort((a, b) => new Date(b.pushed_at) - new Date(a.pushed_at))
      .slice(0, 10)
      .map((r) => ({ name: r.full_name, stars: r.stargazers_count, language: r.language }));
    digest.signals.repos.top_public = top;
    for (const r of top) observe("github.own_repo", r.name, r);
  }

  if (cfg.share_language_breakdown) {
    const langTotals = {};
    const visible = cfg.share_private_repo_count ? repos : pub;
    for (const r of visible) {
      if (r.language) langTotals[r.language] = (langTotals[r.language] || 0) + 1;
    }
    const sorted = Object.fromEntries(
      Object.entries(langTotals)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8),
    );
    digest.signals.languages = sorted;
    for (const [lang, count] of Object.entries(sorted)) {
      observe("github.language", lang, { repos: count });
    }
  }

  if (cfg.share_org_memberships) {
    const orgs = await rest(`/users/${login}/orgs`).catch(() => []);
    const logins = orgs.map((o) => o.login);
    digest.signals.public_orgs = logins;
    for (const l of logins) observe("github.org", l, { login: l });
  }

  // Cheap "security-adjacent" heuristic over PUBLIC repos only: topic/name
  // match. A triager reads this as a hint, not a verdict.
  if (cfg.share_security_signal) {
    const KEYWORDS = /secur|vuln|cve|exploit|fuzz|sbom|vex|psirt|advisor/i;
    const count = pub.filter(
      (r) => KEYWORDS.test(r.name) || (r.topics || []).some((t) => KEYWORDS.test(t)),
    ).length;
    digest.signals.security_adjacent_public_repos = count;
    observe("github.security_signal", "", { count });
  }

  // ── ❗the reporter's own pointers. They ride inside the signed digest, which
  //    makes them tamper-evident and non-repudiable — but they are TYPED as
  //    assertions end to end, so being inside a signed envelope never makes them
  //    verified. Ravn carries them at the DISCLOSED trust class and labels them
  //    as the reporter's words wherever they appear.
  for (const a of cfg.assertions ?? []) {
    if (!a || typeof a !== "object") continue;
    const pointer = String(a.pointer ?? "").trim();
    if (!pointer) continue;
    digest.assertions.push({
      kind: String(a.kind ?? "other")
        .trim()
        .slice(0, 40),
      pointer: pointer.slice(0, 200),
      label: a.label ? String(a.label).slice(0, 200) : null,
    });
  }

  /*
   * ── fold in any other collector's fragment ──────────────────────────────
   *
   * ❗ONE digest, one signature, one job. The HackerOne collector runs before
   * this script and leaves `hackerone-digest.json`; folding it in HERE, before
   * the file is written, is what puts it inside the bytes that get hashed and
   * attested. Anything carried beside `profile-digest.json` is not signed, and
   * an unsigned fragment is not evidence.
   *
   * ❗Its observations already name their own account. They are appended
   * verbatim — this file does not re-attribute them, does not merge them into a
   * GitHub section, and does not interpret them. Ravn records each against the
   * account the observation names.
   */
  for (const fragment of readFragments(warnings)) {
    digest.observations.push(...fragment.observations);
    digest.collected_from.push({
      source: fragment.account.source,
      external_id: fragment.account.external_id,
      handle: fragment.account.handle ?? null,
      schema: fragment.schema,
      generated_at: fragment.generated_at,
      // The other collector's preferences, carried so a triager verifying this
      // bundle sees what THAT collector was allowed to look at too.
      redaction: fragment.redaction ?? null,
      observations: fragment.observations.length,
    });
    for (const w of fragment.warnings ?? []) warnings.push(`${fragment.account.source}: ${w}`);
  }

  writeFileSync("profile-digest.json", JSON.stringify(digest, null, 2));
  writeFileSync("profile-summary.md", summarize(digest));
  console.log(
    `Digest v1 written: ${digest.observations.length} observations, ` +
      `${digest.assertions.length} assertions, notability set ${notability.id}, ` +
      `job ${JOB_ID ?? "(none)"}.`,
  );
  if (digest.collected_from.length > 1) {
    console.log(
      `  accounts: ${digest.collected_from.map((a) => `${a.source}:${a.handle ?? a.external_id}`).join(", ")}`,
    );
  }
  for (const w of warnings) console.log(`  note: ${w}`);
}

/**
 * Repositories this account actually contributed to, including ones it does not
 * own.
 *
 * ❗`contributionsCollection` is the API that makes upstream work visible at all.
 * `/user/repos` only ever shows repositories you own or are a member of — which
 * is exactly why v0 could not see a single upstream contribution, and why the
 * strongest available signal was missing rather than weak. Capped at one year
 * per query by GitHub, hence the loop.
 */
async function upstreamCandidates(login, startYear, endYear) {
  const seen = new Map();
  const note = (repo, field, count, year) => {
    if (!repo?.nameWithOwner) return;
    const key = repo.nameWithOwner;
    const cur = seen.get(key) ?? {
      prs: 0,
      commits: 0,
      stars: repo.stargazerCount ?? 0,
      isPrivate: !!repo.isPrivate,
      firstYear: year,
      lastYear: year,
    };
    cur[field] += count;
    cur.firstYear = Math.min(cur.firstYear, year);
    cur.lastYear = Math.max(cur.lastYear, year);
    seen.set(key, cur);
  };

  for (let y = startYear; y <= endYear; y++) {
    const data = await graphql(
      `query($login:String!,$from:DateTime!,$to:DateTime!){
        user(login:$login){
          contributionsCollection(from:$from,to:$to){
            pullRequestContributionsByRepository(maxRepositories:100){
              repository{nameWithOwner isPrivate stargazerCount}
              contributions{totalCount}
            }
            commitContributionsByRepository(maxRepositories:100){
              repository{nameWithOwner isPrivate stargazerCount}
              contributions{totalCount}
            }
          }
        }
      }`,
      { login, from: `${y}-01-01T00:00:00Z`, to: `${y}-12-31T23:59:59Z` },
    ).catch(() => null);
    const c = data?.user?.contributionsCollection;
    if (!c) continue;
    for (const e of c.pullRequestContributionsByRepository ?? []) {
      note(e.repository, "prs", e.contributions?.totalCount ?? 0, y);
    }
    for (const e of c.commitContributionsByRepository ?? []) {
      note(e.repository, "commits", e.contributions?.totalCount ?? 0, y);
    }
  }
  return seen;
}

/**
 * Merged PRs by this account into this repository.
 *
 * ❗The number Ravn re-checks, so it is the number worth collecting. An
 * opened-PR count is not the same claim: anyone can open a pull request, and
 * "merged" is the word that means a maintainer agreed.
 */
async function mergedPrCount(nameWithOwner, login) {
  const data = await graphql(
    `query($q:String!){ search(query:$q, type:ISSUE, first:1){ issueCount } }`,
    { q: `repo:${nameWithOwner} author:${login} is:pr is:merged` },
  ).catch(() => null);
  return data?.search?.issueCount ?? 0;
}

async function allRepos() {
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await rest(
      `/user/repos?per_page=100&page=${page}&affiliation=owner,collaborator,organization_member`,
    ).catch(() => []);
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

function summarize(d) {
  const s = d.signals;
  const lines = [
    `# Ravn Profile Digest — ${d.subject.github_login}`,
    ``,
    `Generated: ${d.generated_at}`,
    `Schema: ${d.schema} · notability set: ${d.notability.set}`,
    ...(d.job_id ? [`Collection job: ${d.job_id}`] : []),
    ``,
  ];

  const upstream = d.observations.filter((o) => o.type === "github.upstream_contribution");
  const notable = upstream.filter((o) => o.payload.notable);
  if (notable.length) {
    lines.push(`## Upstream contributions (${notable.length} notable projects)`, ``);
    for (const o of notable
      .slice()
      .sort((a, b) => b.payload.merged_prs - a.payload.merged_prs)
      .slice(0, 20)) {
      lines.push(
        `- **${o.subject}** — ${o.payload.merged_prs} merged PRs, ${o.payload.commits} commits`,
      );
    }
    lines.push(``);
  }
  const nominated = upstream.filter((o) => !o.payload.notable && o.payload.nominated);
  if (nominated.length) {
    lines.push(`## Nominated by you (not on Ravn's notability list)`, ``);
    for (const o of nominated) lines.push(`- ${o.subject} — ${o.payload.merged_prs} merged PRs`);
    lines.push(``);
  }

  lines.push(`## Account`, ``);
  if (s.account) {
    lines.push(
      `- Account age: ${s.account.account_age_days} days (${s.account.followers} followers)`,
    );
  }
  if (s.repos) {
    lines.push(
      `- Public repos: ${s.repos.public_count} (${s.repos.public_original_count} original)` +
        (s.repos.private_count != null ? `, private: ${s.repos.private_count}` : ""),
    );
  }
  if (s.contributions_by_year) {
    const total = s.contributions_by_year.reduce((n, y) => n + y.commits + y.prs, 0);
    lines.push(`- ${total} commits+PRs across ${s.contributions_by_year.length} years`);
  }
  if (s.languages) lines.push(`- Top languages: ${Object.keys(s.languages).join(", ")}`);
  if (s.security_adjacent_public_repos != null) {
    lines.push(`- Security-adjacent public repos: ${s.security_adjacent_public_repos}`);
  }

  if (d.assertions.length) {
    lines.push(``, `## Your own assertions (Ravn has not verified these)`, ``);
    for (const a of d.assertions) lines.push(`- ${a.label ?? a.pointer} — ${a.pointer}`);
  }
  if (d.warnings?.length) {
    lines.push(``, `## Notes`, ``);
    for (const w of d.warnings) lines.push(`- ${w}`);
  }
  return `${lines.join("\n")}\n`;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

/**
 * Fragments written by the other collectors in this run.
 *
 * ❗Absent is NORMAL, not an error: a config that asks only for `github` leaves
 * no fragment, and that is the overwhelmingly common case. A fragment that is
 * present but unreadable IS worth saying out loud — it means a collector ran,
 * believed it produced something, and its output is being dropped.
 */
function readFragments(warnings) {
  const out = [];
  for (const path of ["hackerone-digest.json"]) {
    if (!existsSync(path)) continue;
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8"));
      if (!parsed?.account?.source || !Array.isArray(parsed.observations)) {
        warnings.push(`${path} is not a recognisable collector fragment; ignored`);
        continue;
      }
      out.push(parsed);
    } catch (err) {
      warnings.push(`${path} could not be read (${err.message}); ignored`);
    }
  }
  return out;
}
