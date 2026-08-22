import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The notability set — which projects a contribution to is worth asserting.
 *
 * ❗Read from disk, NOT from the network. The file ships in this repository at
 * the same commit the collector is pinned to, so `job_workflow_sha` in the
 * signing certificate attests the list as well as the code. Fetching it at
 * runtime would mean the one input that decides what "well-known" means is the
 * one input nobody signed.
 *
 * The set id and content hash travel in every observation, so Ravn can tell
 * which version of the list produced a claim, and can re-derive against a
 * different one later without asking anyone to re-run a collection.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PATH = resolve(HERE, "../../notability/notable-projects.txt");

export function loadNotabilitySet(path = process.env.RAVN_NOTABILITY_PATH || DEFAULT_PATH) {
  if (!existsSync(path)) {
    // ❗Not fatal. A collector that cannot find its list should still produce a
    // digest — the reporter loses the strongest signal, not the whole run, and
    // the digest says so rather than looking mysteriously thin.
    return { id: "none", sha256: null, repos: new Set(), missing: true };
  }
  const text = readFileSync(path, "utf8");
  const sha256 = createHash("sha256").update(text, "utf8").digest("hex");

  let id = "unknown";
  const repos = new Set();
  for (const line of text.split(/\r?\n/)) {
    const setMatch = line.match(/^#\s*set:\s*(\S+)\s*$/);
    if (setMatch) {
      id = setMatch[1];
      continue;
    }
    const trimmed = line.replace(/#.*$/, "").trim().toLowerCase();
    if (!trimmed) continue;
    if (/^[a-z0-9._-]+\/[a-z0-9._-]+$/.test(trimmed)) repos.add(trimmed);
  }
  return { id, sha256, repos, missing: false };
}

/** Case-insensitive membership — GitHub `nameWithOwner` casing is not stable. */
export function isNotable(set, nameWithOwner) {
  return set.repos.has(String(nameWithOwner ?? "").toLowerCase());
}
