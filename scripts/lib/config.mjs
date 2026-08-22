/**
 * ravn.config.yml — a deliberately small YAML subset.
 *
 * ❗Why not a YAML library: this script runs in the reporter's own Actions
 * environment, and the reporter is a security person who can and should read it
 * before handing it a token. A dependency-free parser they can audit in two
 * minutes is worth more here than full YAML support. `npm install` in the
 * collector step would also mean the attested SHA no longer pins everything
 * that runs.
 *
 * What it supports, which is all the config format needs:
 *
 *     key: true                 # booleans
 *     key: 12                   # numbers
 *     key: some text            # strings
 *     key:                      # a list of scalars
 *       - one
 *       - two
 *     key:                      # a list of maps, one level deep
 *       - kind: profile
 *         pointer: https://...
 *
 * Anything else is ignored rather than fataled. ❗A reporter's typo must not cost
 * them a collection run — the digest records what was parsed, so an option that
 * silently did not apply is visible in the output rather than mysterious.
 */

const stripComment = (line) => {
  // Only strip a '#' that starts a comment, not one inside a quoted value.
  let out = "";
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      out += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === "#") break;
    out += ch;
  }
  return out;
};

const unquote = (v) => {
  const t = v.trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) {
    return t.slice(1, -1);
  }
  return t;
};

const scalar = (raw) => {
  const v = unquote(raw);
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "" || v === "null" || v === "~") return null;
  if (/^-?\d+$/.test(v)) return Number(v);
  return v;
};

/** Parse the subset above into a plain object. Never throws. */
export function parseConfig(text) {
  const out = {};
  const lines = String(text ?? "").split(/\r?\n/);

  let listKey = null; // the key whose list we are inside
  let listItem = null; // the map currently being built, if the list holds maps
  let itemIndent = 0;

  const closeItem = () => {
    if (listKey && listItem && Object.keys(listItem).length > 0) out[listKey].push(listItem);
    listItem = null;
  };
  const closeList = () => {
    closeItem();
    listKey = null;
  };

  for (const rawLine of lines) {
    const line = stripComment(rawLine);
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    // A list entry.
    if (trimmed.startsWith("- ") || trimmed === "-") {
      if (!listKey) continue; // a dash with no list above it: ignore.
      const rest = trimmed.slice(1).trim();
      const kv = rest.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
      if (kv) {
        // A map entry starts here; anything more-indented below belongs to it.
        closeItem();
        listItem = { [kv[1]]: scalar(kv[2]) };
        itemIndent = indent;
      } else if (rest) {
        closeItem();
        out[listKey].push(scalar(rest));
      }
      continue;
    }

    // A continuation of the map begun by the last '-' entry.
    if (listItem && indent > itemIndent) {
      const kv = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
      if (kv) listItem[kv[1]] = scalar(kv[2]);
      continue;
    }

    // A top-level key.
    const kv = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!kv) continue;
    closeList();
    const [, key, value] = kv;
    if (value.trim() === "") {
      // Either an empty value or the head of a list. Assume list; if nothing
      // follows, an empty array is a harmless and accurate answer.
      out[key] = [];
      listKey = key;
    } else {
      out[key] = scalar(value);
    }
  }
  closeList();
  return out;
}

/**
 * Sharing preferences, with conservative defaults.
 *
 * ❗Every default that could expose something stays false. The reporter opts IN
 * to detail; nothing is opted in on their behalf, including by a future edit to
 * this list.
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

/** Merge parsed config over the defaults, keeping only keys we know. */
export function resolveConfig(text) {
  const parsed = parseConfig(text);
  const cfg = { ...DEFAULTS };
  const unknown = [];
  for (const [k, v] of Object.entries(parsed)) {
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
