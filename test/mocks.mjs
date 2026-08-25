/**
 * Mock Ravn and mock GitHub, on loopback.
 *
 * ❗Node's own `node:http` and `node:test`, and nothing else. This repo has no
 * dependencies on purpose: `npm install` in the collector step would mean the
 * attested SHA no longer pins everything that runs, and a test tree that needs
 * a package manager is a test tree that rots the moment the collector is the
 * only thing anyone touches.
 *
 * Real servers rather than a monkey-patched `fetch`, because the collector runs
 * as a child process here — which is how a runner runs it, and the only way to
 * observe what it actually writes to the log and to disk.
 */

import { createServer } from "node:http";

const listen = (handler) =>
  new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        server,
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });

const readBody = (req) =>
  new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
    });
    req.on("end", () => resolve(data));
  });

/**
 * Ravn's side: the Actions OIDC token endpoint (which is GitHub's, but lives
 * here so one server covers the whole exchange) and POST /attestations/config.
 *
 * `respond` receives the presented bearer token and returns `{status, body}`,
 * so a test drives a refusal without any special-casing in the collector.
 */
export async function startRavn({ respond, oidcToken = "header.payload.signature" } = {}) {
  const seen = { audience: null, bearer: null, requestToken: null, method: null, bodyBytes: null };

  const mock = await listen(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");

    if (url.pathname === "/oidc") {
      seen.audience = url.searchParams.get("audience");
      seen.requestToken = req.headers.authorization;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ value: oidcToken, count: 1 }));
      return;
    }

    if (url.pathname === "/attestations/config") {
      seen.bearer = req.headers.authorization;
      seen.method = req.method;
      seen.bodyBytes = (await readBody(req)).length;
      const { status, body } = respond ? respond(seen) : { status: 500, body: { code: "no-responder" } };
      res.writeHead(status, { "content-type": "application/json" });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ code: "not-found" }));
  });

  return { ...mock, seen, oidcRequestUrl: `${mock.origin}/oidc?api-version=2.0` };
}

/**
 * Enough of GitHub's REST and GraphQL surface for the collector to complete a
 * run: an account, a repo list, contribution totals, per-repository
 * contributions, and the merged-PR search.
 */
export async function startGitHub({ login = "reporter", id = 4242 } = {}) {
  const calls = [];

  const user = {
    login,
    id,
    created_at: "2015-03-04T10:00:00Z",
    followers: 128,
    public_repos: 31,
  };

  const repos = [
    { full_name: `${login}/sbom-differ`, name: "sbom-differ", private: false, fork: false, language: "Go", stargazers_count: 91, pushed_at: "2026-08-01T00:00:00Z", topics: ["sbom", "supply-chain"] },
    { full_name: `${login}/dotfiles`, name: "dotfiles", private: false, fork: false, language: "Shell", stargazers_count: 3, pushed_at: "2026-02-01T00:00:00Z", topics: [] },
    { full_name: `${login}/private-notes`, name: "private-notes", private: true, fork: false, language: "TypeScript", stargazers_count: 0, pushed_at: "2026-07-01T00:00:00Z", topics: [] },
  ];

  const mock = await listen(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    calls.push(`${req.method} ${url.pathname}`);
    const json = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.method === "GET" && url.pathname === "/user") return json(200, user);
    if (req.method === "GET" && url.pathname === "/user/repos") {
      return json(200, url.searchParams.get("page") === "1" ? repos : []);
    }
    if (req.method === "GET" && url.pathname === `/users/${login}/orgs`) {
      return json(200, [{ login: "openssf" }]);
    }

    if (req.method === "POST" && url.pathname === "/graphql") {
      const { query, variables } = JSON.parse(await readBody(req));
      const year = Number(String(variables?.from ?? "").slice(0, 4));

      if (query.includes("search(")) {
        // Merged PRs by this account into a given repo.
        return json(200, { data: { search: { issueCount: variables.q.includes("golang/go") ? 7 : 2 } } });
      }
      if (query.includes("pullRequestContributionsByRepository")) {
        return json(200, {
          data: {
            user: {
              contributionsCollection: {
                pullRequestContributionsByRepository: [
                  { repository: { nameWithOwner: "golang/go", isPrivate: false, stargazerCount: 123000 }, contributions: { totalCount: 3 } },
                  { repository: { nameWithOwner: "someone/not-on-the-list", isPrivate: false, stargazerCount: 40 }, contributions: { totalCount: 2 } },
                  { repository: { nameWithOwner: "acme/internal-thing", isPrivate: true, stargazerCount: 0 }, contributions: { totalCount: 9 } },
                ],
                commitContributionsByRepository: [
                  { repository: { nameWithOwner: "golang/go", isPrivate: false, stargazerCount: 123000 }, contributions: { totalCount: 11 } },
                ],
              },
            },
          },
        });
      }
      return json(200, {
        data: {
          user: {
            contributionsCollection: {
              totalCommitContributions: 100 + year,
              totalPullRequestContributions: 20,
              totalPullRequestReviewContributions: 5,
              totalIssueContributions: 3,
              restrictedContributionsCount: 40,
            },
          },
        },
      });
    }

    return json(404, { message: "not found" });
  });

  return { ...mock, calls, user };
}

/**
 * HackerOne's hacker API, enough of it for a collection to complete.
 *
 * ❗The credential is CHECKED, not ignored. The one failure a reporter will
 * really hit is putting their HackerOne handle where the token identifier goes,
 * and a mock that accepts anything cannot prove the collector says something
 * useful when that happens. So: this mock 401s unless the Basic pair matches,
 * exactly as HackerOne does.
 */
export async function startHackerOne({
  identifier = "ravn-collector-token",
  token = "h1_fake_token",
  username = "ave.rez",
  userId = 88213,
  reports = null,
  earnings = null,
} = {}) {
  const calls = [];
  const expected = `Basic ${Buffer.from(`${identifier}:${token}`).toString("base64")}`;

  const reporter = { id: userId, type: "user", attributes: { username } };
  const report = (over) => ({
    id: String(over.id),
    type: "report",
    attributes: {
      title: over.title ?? `Finding ${over.id}`,
      state: over.state ?? "resolved",
      created_at: over.created_at ?? "2025-06-01T10:00:00.000Z",
      disclosed_at: over.disclosed_at ?? null,
      cve_ids: over.cve_ids ?? [],
    },
    relationships: {
      reporter: { data: reporter },
      program: { data: { id: "1", attributes: { handle: over.program ?? "acme" } } },
      severity: { data: { id: "1", attributes: { rating: over.severity ?? "high" } } },
    },
  });

  const DEFAULT_REPORTS = [
    report({ id: 2140960, state: "resolved", severity: "critical", program: "xai",
             disclosed_at: "2025-11-02T00:00:00.000Z", cve_ids: ["CVE-2025-1234"] }),
    report({ id: 2140961, state: "resolved", severity: "high", program: "acme" }),
    report({ id: 2140962, state: "triaged", severity: "medium", program: "acme",
             title: "SSRF in the internal metadata proxy" }),
    report({ id: 2140963, state: "duplicate", severity: "low", program: "globex" }),
    // ❗Outside a 5-year window. The lookback is a real boundary, and a fixture
    //   where everything is in range cannot show that it is applied.
    report({ id: 2140900, state: "resolved", severity: "high", program: "oldcorp",
             created_at: "2015-01-01T00:00:00.000Z" }),
  ];

  const mock = await listen(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    calls.push(`${req.method} ${url.pathname}`);
    const json = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };

    if (req.headers.authorization !== expected) {
      return json(401, { errors: [{ title: "Unauthorized" }] });
    }

    const page = Number(url.searchParams.get("page[number]") ?? 1);

    if (url.pathname === "/v1/hackers/me/reports") {
      return json(200, { data: page === 1 ? (reports ?? DEFAULT_REPORTS) : [] });
    }
    if (url.pathname === "/v1/hackers/payments/earnings") {
      const data =
        earnings ??
        [
          { id: "1", attributes: { amount: "1500.0", currency: "USD" } },
          { id: "2", attributes: { amount: "500.5", currency: "USD" } },
        ];
      return json(200, { data: page === 1 ? data : [] });
    }
    return json(404, { errors: [{ title: "Not found" }] });
  });

  return {
    origin: `${mock.origin}/v1`,
    identifier,
    token,
    username,
    userId,
    calls,
    close: mock.close,
  };
}
