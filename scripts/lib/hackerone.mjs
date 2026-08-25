/**
 * The HackerOne hacker API, and the sharing preferences that govern it.
 *
 * ── Why this collector exists ──────────────────────────────────────────────
 *
 * The GitHub collector answers "what has this person built". This one answers
 * "what has this person FOUND", which is the question a PSIRT team is actually
 * asking when a report lands. They are different signals and neither substitutes
 * for the other.
 *
 * ── Two things about the credential, both of which look like bugs ──────────
 *
 * ❗HTTP Basic, and the username is the API TOKEN'S IDENTIFIER — the name given
 * to the token when it was created — not the HackerOne handle. Entering the
 * handle is the obvious thing to do and it fails with a 401 that says nothing
 * about why. `services/adapter-hackerone/src/hackerone.ts` in ravn-platform
 * carries the same note for the program-side API; this is the same trap.
 *
 * ❗Therefore the identifier CANNOT tell us who the reporter is. It is an
 * arbitrary label. Identity is read from what the API returns about the
 * authenticated caller — see `identityFrom` — and never from the credential,
 * never from config, never from anything the reporter typed. That is the same
 * rule the digest's subject hash follows in ravn-platform, and for the same
 * reason: a value you were handed is a claim, and a value you computed is a
 * fact.
 *
 * ── What is NOT here ───────────────────────────────────────────────────────
 *
 * No scoring, no weighting, no interpretation. The collector states what it saw;
 * what an observation is WORTH is a versioned model on Ravn's side, so that
 * changing our mind never costs a reporter a re-run. Anything here that starts
 * to look like a weighting belongs over there instead.
 */

/**
 * ❗Overridable so the suite can point at a loopback mock. There is no other way
 * to test this: the alternative is a live HackerOne account with a shaped report
 * history, which nobody else on the team could reproduce and which would make
 * the test fail for reasons that have nothing to do with the code.
 *
 * The override is read from the environment of the runner, which is the
 * reporter's own — so it cannot be used to redirect a real collection anywhere
 * Ravn would then trust, because Ravn trusts the signed COLLECTOR SHA, not the
 * host it talked to.
 */
const API = process.env.RAVN_H1_API || "https://api.hackerone.com/v1";

/**
 * Sharing preferences, with conservative defaults.
 *
 * ❗Everything that could expose something a program has not published starts
 * OFF. A hacker's unresolved and undisclosed reports are the most sensitive
 * thing in this API — they describe live, unfixed vulnerabilities — so the
 * defaults emit COUNTS of them and never titles, never bodies, never targets.
 *
 * ❗The two `share_*_disclosed` defaults are ON for the same reason the GitHub
 * collector's upstream contributions are: the underlying facts are already
 * public, so Ravn can confirm them without trusting this digest at all. That
 * makes them the strongest thing a reporter can bring, and they cannot leak
 * anything, because HackerOne has already published them.
 */
export const H1_DEFAULTS = {
  /** Totals and outcome counts. No titles, no targets, no bodies. */
  share_report_counts: true,
  /** Which programs, by public handle. Says where you work, not what you found. */
  share_programs: true,
  /** How many of your reports landed at each severity. Counts only. */
  share_severity_breakdown: true,
  /** Publicly disclosed reports — already published by the program. */
  share_disclosed_reports: true,
  /** CVE ids credited to your reports. Public by construction. */
  share_cve_credits: true,

  /**
   * ❗OFF. The title of an undisclosed report can describe a live vulnerability
   * in someone else's product. That is not the reporter's to share by default,
   * and a checkbox pre-ticked on their behalf is not consent.
   */
  share_report_titles: false,
  /** ❗OFF. Money. Aggregate only even when enabled — never per-report. */
  share_bounty_totals: false,

  /** How far back to look, in years. */
  lookback_years: 5,
};

/**
 * Merge a provider's `metadata` over the defaults, keeping only keys we know.
 *
 * ❗Unknown keys are IGNORED and reported, not fataled — same reasoning as the
 * GitHub collector's `resolveConfig`. By the time a document reaches a runner
 * the reporter cannot edit it, and losing a whole run to a key this version does
 * not understand is the wrong trade.
 */
export function resolveH1Config(metadata) {
  const cfg = { ...H1_DEFAULTS };
  const unknown = [];
  const source =
    metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {};
  for (const [k, v] of Object.entries(source)) {
    if (!(k in cfg)) {
      unknown.push(k);
      continue;
    }
    if (typeof cfg[k] === "boolean") cfg[k] = v === true;
    else if (typeof cfg[k] === "number") cfg[k] = Number.isFinite(Number(v)) ? Number(v) : cfg[k];
    else cfg[k] = v;
  }
  return { cfg, unknown };
}

export class HackerOneError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "HackerOneError";
    this.status = status;
  }
}

/** `Basic base64(identifier:token)`. See the header — identifier ≠ handle. */
export function authHeader(identifier, token) {
  return `Basic ${Buffer.from(`${identifier}:${token}`).toString("base64")}`;
}

/**
 * One page of a paginated collection.
 *
 * ❗401 is called out by name. It is overwhelmingly the failure a reporter will
 * hit, and overwhelmingly for one reason — they put their HackerOne username in
 * where the token identifier goes. A generic "request failed" here costs them an
 * afternoon; naming the likely cause costs us three lines.
 */
export async function getPage(fetchImpl, auth, path, params = {}) {
  const url = new URL(`${API}${path}`);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));

  const res = await fetchImpl(url.toString(), {
    headers: { authorization: auth, accept: "application/json" },
  });

  if (res.status === 401) {
    throw new HackerOneError(
      "HackerOne rejected the credential (401). The Basic-auth username must be the API " +
        "token's IDENTIFIER — the name shown next to the token in your HackerOne settings — " +
        "not your HackerOne handle. That is the usual cause of this.",
      401,
    );
  }
  if (res.status === 429) {
    throw new HackerOneError("HackerOne rate-limited this run (429). Try again shortly.", 429);
  }
  if (!res.ok) {
    throw new HackerOneError(`GET ${path} → ${res.status}`, res.status);
  }
  return res.json();
}

/**
 * Every page of a collection, up to a hard cap.
 *
 * ❗The cap is a real limit, not a formality, and when it is hit the caller says
 * so in `warnings` — which travel inside the signed digest. A truncated
 * collection that presents itself as complete is a quietly wrong number, and a
 * quietly wrong number is worse than a missing one.
 */
export async function getAll(fetchImpl, auth, path, { pageSize = 100, maxPages = 20 } = {}) {
  const items = [];
  let truncated = false;
  for (let page = 1; page <= maxPages; page++) {
    const body = await getPage(fetchImpl, auth, path, {
      "page[number]": page,
      "page[size]": pageSize,
    });
    const data = Array.isArray(body?.data) ? body.data : [];
    items.push(...data);
    if (data.length < pageSize) return { items, truncated };
    if (page === maxPages) truncated = true;
  }
  return { items, truncated };
}

/**
 * Who the API says is calling.
 *
 * ❗Read from the `reporter` relationship on the caller's OWN reports. There is
 * no documented `/hackers/me` on the hacker API (checked against
 * api.hackerone.com/hacker-resources), and `/hackers/me/reports` returns only
 * the authenticated user's reports — so the reporter on any of them IS the
 * authenticated user.
 *
 * ❗Returns null rather than guessing. A hacker with no reports cannot be
 * identified this way, and the honest response is to refuse the collection: the
 * alternative is trusting a self-declared handle, which is the exact thing this
 * whole design refuses to do.
 */
export function identityFrom(reports) {
  for (const r of reports) {
    const rep = r?.relationships?.reporter?.data;
    const username = rep?.attributes?.username;
    if (typeof username === "string" && username.trim() && rep?.id != null) {
      return { username: username.trim(), id: String(rep.id) };
    }
  }
  return null;
}

const iso = (v) => {
  if (typeof v !== "string") return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
};

/**
 * Reports → observations.
 *
 * ❗A pure function of (reports, cfg). No clock, no network, no environment —
 * which is what makes it testable against captured API shapes rather than
 * against a live account nobody else can reproduce.
 *
 * ❗Every branch is gated on a preference. A collector that "helpfully" emits
 * something the reporter did not tick is the one bug this whole consent model
 * exists to prevent, and it is the kind that is invisible until it is public.
 */
export function observationsFrom(reports, cfg, { since = null } = {}) {
  const observations = [];
  const warnings = [];
  const add = (type, subject, payload) =>
    observations.push({ type, subject: String(subject ?? ""), payload });

  const inWindow = (r) => {
    if (!since) return true;
    const created = iso(r?.attributes?.created_at);
    return created ? created >= since : false;
  };
  const scoped = reports.filter(inWindow);
  if (scoped.length !== reports.length) {
    warnings.push(
      `${reports.length - scoped.length} report(s) fell outside the ${cfg.lookback_years}-year window`,
    );
  }

  const stateOf = (r) => String(r?.attributes?.state ?? "unknown");
  const programOf = (r) => r?.relationships?.program?.data?.attributes?.handle ?? null;
  const severityOf = (r) => r?.relationships?.severity?.data?.attributes?.rating ?? null;

  // ── counts: the aggregate that says "this person finds things".
  if (cfg.share_report_counts) {
    const byState = {};
    for (const r of scoped) byState[stateOf(r)] = (byState[stateOf(r)] ?? 0) + 1;

    const created = scoped.map((r) => iso(r?.attributes?.created_at)).filter(Boolean).sort();
    add("hackerone.report_counts", "", {
      total: scoped.length,
      by_state: byState,
      first_report_at: created[0] ?? null,
      last_report_at: created[created.length - 1] ?? null,
    });
  }

  // ── programs: where they work. A handle is public; the reports are not.
  if (cfg.share_programs) {
    const byProgram = new Map();
    for (const r of scoped) {
      const handle = programOf(r);
      if (!handle) continue;
      const cur = byProgram.get(handle) ?? { handle, reports: 0, resolved: 0 };
      cur.reports += 1;
      if (stateOf(r) === "resolved") cur.resolved += 1;
      byProgram.set(handle, cur);
    }
    for (const p of byProgram.values()) add("hackerone.program", p.handle, p);
  }

  // ── severity: counts per rating, never per report.
  if (cfg.share_severity_breakdown) {
    const bySeverity = {};
    for (const r of scoped) {
      const rating = severityOf(r);
      if (rating) bySeverity[rating] = (bySeverity[rating] ?? 0) + 1;
    }
    for (const [rating, count] of Object.entries(bySeverity)) {
      add("hackerone.severity", rating, { rating, count });
    }
  }

  /*
   * ── disclosed reports: the strong ones.
   *
   * ❗Different IN KIND from everything above, and the difference is the whole
   * point. A disclosed report is PUBLIC — HackerOne published it — so Ravn can
   * go and confirm it without trusting this digest at all. The attestation is
   * not what makes these true; it is what makes them worth an API call.
   */
  if (cfg.share_disclosed_reports) {
    for (const r of scoped) {
      const disclosedAt = iso(r?.attributes?.disclosed_at);
      if (!disclosedAt) continue;
      const id = r?.id != null ? String(r.id) : null;
      if (!id) continue;
      add("hackerone.disclosed_report", `https://hackerone.com/reports/${id}`, {
        report_id: id,
        url: `https://hackerone.com/reports/${id}`,
        disclosed_at: disclosedAt,
        program: programOf(r),
        severity: severityOf(r),
        state: stateOf(r),
        // ❗Only on a DISCLOSED report. The title of one HackerOne has already
        //   published is public text; on any other report it is not.
        title: typeof r?.attributes?.title === "string" ? r.attributes.title : null,
      });
    }
  }

  // ── CVE credits: public by construction, and checkable against NVD.
  if (cfg.share_cve_credits) {
    for (const r of scoped) {
      const cves = Array.isArray(r?.attributes?.cve_ids) ? r.attributes.cve_ids : [];
      for (const cve of cves) {
        if (typeof cve !== "string" || !/^CVE-\d{4}-\d{4,}$/i.test(cve.trim())) continue;
        add("hackerone.cve_credit", cve.trim().toUpperCase(), {
          cve: cve.trim().toUpperCase(),
          report_id: r?.id != null ? String(r.id) : null,
          disclosed_at: iso(r?.attributes?.disclosed_at),
          program: programOf(r),
        });
      }
    }
  }

  /*
   * ❗Titles of reports that are NOT disclosed. Opt-in, and separate from the
   * disclosed-report title above, because they are different statements: one is
   * quoting something already published, the other is publishing it.
   */
  if (cfg.share_report_titles) {
    for (const r of scoped) {
      if (iso(r?.attributes?.disclosed_at)) continue; // already emitted above
      const title = typeof r?.attributes?.title === "string" ? r.attributes.title : null;
      if (!title) continue;
      add("hackerone.report_title", String(r?.id ?? ""), {
        report_id: r?.id != null ? String(r.id) : null,
        title,
        state: stateOf(r),
        program: programOf(r),
      });
    }
  }

  return { observations, warnings };
}

/**
 * Earnings → one aggregate observation.
 *
 * ❗Aggregate ONLY, even when the reporter opted in. A per-program bounty figure
 * says what a specific company paid for a specific class of bug, which is not
 * the reporter's alone to disclose. The total and the count are about them.
 */
export function earningsObservation(earnings) {
  let total = 0;
  let count = 0;
  const currencies = new Set();
  for (const e of earnings) {
    const amount = Number(e?.attributes?.amount);
    if (!Number.isFinite(amount)) continue;
    total += amount;
    count += 1;
    const currency = e?.attributes?.currency;
    if (typeof currency === "string") currencies.add(currency);
  }
  if (count === 0) return null;
  return {
    type: "hackerone.bounty_totals",
    subject: "",
    payload: {
      total: Math.round(total * 100) / 100,
      count,
      // ❗Plural is possible and is not an error — it is a fact about the data,
      //   and silently summing across currencies would be a wrong number.
      currencies: [...currencies].sort(),
    },
  };
}
