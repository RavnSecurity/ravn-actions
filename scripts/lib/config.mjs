/**
 * Sharing preferences — the "redaction config" that decides what the collector
 * is allowed to look at, and therefore what ends up in the digest.
 *
 * ── What changed, and why ──────────────────────────────────────────────────
 *
 * These preferences used to arrive as `ravn.config.yml`, a file in the
 * reporter's own repository, parsed here by a hand-rolled YAML subset. That
 * file is retired (ADR security-005 D12/§4). They now arrive over an
 * authenticated, per-run channel: the collector presents a GitHub OIDC token to
 * Ravn and is handed a `ravn.collection-config/v1` document back.
 *
 * ❗The retirement changes WHERE the config comes from and nothing about who it
 * belongs to. Server-delivered config introduces a failure mode the file did
 * not have — the reporter can no longer read what they agreed to share — so two
 * things are load-bearing and neither is optional:
 *
 *   1. `scripts/fetch-config.mjs` prints the delivered document verbatim to the
 *      run log BEFORE anything is collected, while the reporter can still
 *      cancel the run.
 *   2. `collect.mjs` embeds it in `profile-digest.json` BEFORE hashing, exactly
 *      as the local file was, so it is covered by the signature and a triager
 *      verifying the bundle can see what was withheld.
 *
 * Without both, "what you share" silently moves from the reporter to Ravn's
 * server and security-004's central promise stops being true.
 *
 * ── Where the preferences live in the delivered document ───────────────────
 *
 * The v1 config is a list of `collectors`, each with a `provider` and a
 * per-provider `metadata` object that the contract leaves deliberately
 * unconstrained. The GitHub collector's sharing preferences are that object:
 *
 *     { "version": 1, "type": "profile", "collectors": [
 *         { "provider": "github",
 *           "required": { "secrets": ["RAVN_READONLY_TOKEN"] },
 *           "metadata": { "share_org_memberships": true, "lookback_years": 3 } } ] }
 *
 * Keys are the same ones `ravn.config.yml` carried, so a reporter's answers
 * mean what they always meant and a digest reads the same either side of the
 * move.
 */

/**
 * Sharing preferences, with conservative defaults.
 *
 * ❗Every default that could expose something stays false. The reporter opts IN
 * to detail; nothing is opted in on their behalf, including by a future edit to
 * this list — and including by a config Ravn delivers, since an absent key
 * resolves to the default below rather than to whatever the server prefers.
 */
export const DEFAULTS = {
  share_account_age: true,
  share_contribution_totals: true, // yearly totals, no per-repo detail
  share_private_repo_count: false, // count only, never names
  share_public_repo_names: false, // top public repos by recent activity
  share_language_breakdown: true, // aggregate across visible repos
  share_org_memberships: false, // public org logins only
  share_security_signal: true, // count of security-adjacent public repos

  /**
   * Contributions to projects on Ravn's published notability list.
   *
   * ❗The strongest signal a reporter can share, and the only one Ravn can
   * confirm without trusting them: merged PRs into public repositories are
   * public. On by default because it emits ONLY repositories that are both
   * public and already on a published list — it cannot leak anything private.
   */
  share_upstream_contributions: true,
  /** How many years back to look. GitHub's own API is queried one year at a time. */
  lookback_years: 5,

  /**
   * Repositories the reporter wants counted that are not on the notability list,
   * and free-form pointers to anything else.
   *
   * ❗Both are carried as the reporter's OWN assertions and are labelled that way
   * end to end. We cannot enumerate every source of valid reporter signal, and
   * pretending otherwise is how this stalls — so the reporter points, and Ravn
   * either bridges it to something checkable or shows it clearly marked.
   */
  nominate_repos: [],
  assertions: [],
};

/**
 * Merge a provider's `metadata` over the defaults, keeping only keys we know.
 *
 * ❗Unknown keys are IGNORED here and reported, not fataled. Ravn's write side
 * refuses an unknown key at job-creation time, where a human is present to fix
 * it; by the time a document reaches a runner the reporter cannot edit it, and
 * losing a whole collection run to a key this version does not understand would
 * be the wrong trade. The digest records what was actually parsed, so an option
 * that silently did not apply is visible in the output rather than mysterious.
 */
export function resolveConfig(metadata) {
  const cfg = { ...DEFAULTS };
  const unknown = [];
  const source = metadata && typeof metadata === "object" && !Array.isArray(metadata) ? metadata : {};
  for (const [k, v] of Object.entries(source)) {
    if (!(k in cfg)) {
      unknown.push(k);
      continue;
    }
    if (Array.isArray(cfg[k])) cfg[k] = Array.isArray(v) ? v : [];
    else if (typeof cfg[k] === "boolean") cfg[k] = v === true;
    else if (typeof cfg[k] === "number") cfg[k] = Number.isFinite(Number(v)) ? Number(v) : cfg[k];
    else cfg[k] = v;
  }
  return { cfg, unknown };
}
