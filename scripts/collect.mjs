#!/usr/bin/env node
/**
 * Ravn profile collector.
 *
 * Runs INSIDE the user's Actions environment. It may see the user's full
 * picture (via a read-only PAT), but only aggregate/digested signals are
 * written to profile-digest.json. Raw repo names for private repos, commit
 * messages, issue bodies, etc. never leave the runner.
 *
 * Redaction is config-driven (ravn.config.yml) so the user decides how much
 * signal to share. Defaults are conservative.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const TOKEN = process.env.RAVN_TOKEN;
const ACTOR = process.env.RAVN_ACTOR;
const CONFIG_PATH = process.env.RAVN_CONFIG_PATH || "ravn.config.yml";

if (!TOKEN) {
  console.error("No token available; aborting.");
  process.exit(1);
}

// ---------- config (tiny YAML subset parser: `key: value` lines) ----------
const DEFAULTS = {
  share_account_age: true,
  share_contribution_totals: true,        // yearly totals, no per-repo detail
  share_private_repo_count: false,        // count only, never names
  share_public_repo_names: false,         // top public repos by recent activity
  share_language_breakdown: true,         // aggregate across visible repos
  share_org_memberships: false,           // public org logins only
  share_security_signal: true,            // advisories/CVE-adjacent public repos touched
};

function loadConfig() {
  const cfg = { ...DEFAULTS };
  if (existsSync(CONFIG_PATH)) {
    for (const line of readFileSync(CONFIG_PATH, "utf8").split("\n")) {
      const m = line.match(/^\s*([a-z_]+)\s*:\s*(true|false)\s*(#.*)?$/);
      if (m && m[1] in cfg) cfg[m[1]] = m[2] === "true";
    }
  }
  return cfg;
}

// ---------- GitHub API helpers ----------
const API = "https://api.github.com";
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
  const cfg = loadConfig();
  const user = await rest("/user").catch(() => rest(`/users/${ACTOR}`));
  const login = user.login;

  const digest = {
    schema: "ravn.profile-digest/v0",
    generated_at: new Date().toISOString(),
    subject: {
      github_login: login,
      github_id: user.id, // stable even across renames
    },
    redaction: cfg,
    signals: {},
  };

  if (cfg.share_account_age) {
    digest.signals.account = {
      created_at: user.created_at,
      account_age_days: Math.floor(
        (Date.now() - new Date(user.created_at)) / 86400000
      ),
      followers: user.followers,
    };
  }

  // Contribution totals per year via GraphQL contributionsCollection.
  if (cfg.share_contribution_totals) {
    const createdYear = new Date(user.created_at).getFullYear();
    const thisYear = new Date().getFullYear();
    const startYear = Math.max(createdYear, thisYear - 5); // cap at 5y lookback
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
        { login, from: `${y}-01-01T00:00:00Z`, to: `${y}-12-31T23:59:59Z` }
      );
      const c = data.user.contributionsCollection;
      years.push({
        year: y,
        commits: c.totalCommitContributions,
        prs: c.totalPullRequestContributions,
        reviews: c.totalPullRequestReviewContributions,
        issues: c.totalIssueContributions,
        // "restricted" = private contributions GitHub already aggregates
        private_contributions: c.restrictedContributionsCount,
      });
    }
    digest.signals.contributions_by_year = years;
  }

  // Repos: aggregates only. Names optional, public-only, opt-in.
  const repos = await allRepos();
  const pub = repos.filter((r) => !r.private);
  const priv = repos.filter((r) => r.private);

  digest.signals.repos = {
    public_count: pub.length,
    ...(cfg.share_private_repo_count ? { private_count: priv.length } : {}),
    public_original_count: pub.filter((r) => !r.fork).length,
  };

  if (cfg.share_public_repo_names) {
    digest.signals.repos.top_public = pub
      .filter((r) => !r.fork)
      .sort((a, b) => new Date(b.pushed_at) - new Date(a.pushed_at))
      .slice(0, 10)
      .map((r) => ({ name: r.full_name, stars: r.stargazers_count }));
  }

  if (cfg.share_language_breakdown) {
    const langTotals = {};
    const visible = cfg.share_private_repo_count ? repos : pub;
    for (const r of visible) if (r.language)
      langTotals[r.language] = (langTotals[r.language] || 0) + 1;
    digest.signals.languages = Object.fromEntries(
      Object.entries(langTotals).sort((a, b) => b[1] - a[1]).slice(0, 8)
    );
  }

  if (cfg.share_org_memberships) {
    const orgs = await rest(`/users/${login}/orgs`).catch(() => []);
    digest.signals.public_orgs = orgs.map((o) => o.login);
  }

  // Cheap "security-adjacent" heuristic over PUBLIC repos only: topic/name
  // match. A triager reads this as a hint, not a verdict.
  if (cfg.share_security_signal) {
    const KEYWORDS = /secur|vuln|cve|exploit|fuzz|sbom|vex|psirt|advisor/i;
    digest.signals.security_adjacent_public_repos = pub.filter(
      (r) => KEYWORDS.test(r.name) || (r.topics || []).some((t) => KEYWORDS.test(t))
    ).length;
  }

  writeFileSync("profile-digest.json", JSON.stringify(digest, null, 2));
  writeFileSync("profile-summary.md", summarize(digest));
  console.log("Digest written. Keys:", Object.keys(digest.signals).join(", "));
}

async function allRepos() {
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await rest(
      `/user/repos?per_page=100&page=${page}&affiliation=owner,collaborator,organization_member`
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
    ``,
  ];
  if (s.account)
    lines.push(`- Account age: ${s.account.account_age_days} days (${s.account.followers} followers)`);
  if (s.repos)
    lines.push(`- Public repos: ${s.repos.public_count} (${s.repos.public_original_count} original)` +
      (s.repos.private_count != null ? `, private: ${s.repos.private_count}` : ""));
  if (s.contributions_by_year) {
    const total = s.contributions_by_year.reduce((n, y) => n + y.commits + y.prs, 0);
    lines.push(`- ${total} commits+PRs across ${s.contributions_by_year.length} years`);
  }
  if (s.languages)
    lines.push(`- Top languages: ${Object.keys(s.languages).join(", ")}`);
  if (s.security_adjacent_public_repos != null)
    lines.push(`- Security-adjacent public repos: ${s.security_adjacent_public_repos}`);
  return lines.join("\n") + "\n";
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
