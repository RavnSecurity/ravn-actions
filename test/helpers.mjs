/** Run a collector script the way a runner does: a child process, in a scratch cwd. */
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const scratch = () => mkdtempSync(join(tmpdir(), "ravn-collector-"));

export function run(script, { cwd, env = {} }) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [join(REPO, "scripts", script)], {
      cwd,
      // A clean environment: the point of the preflight tests is what happens
      // when a variable is ABSENT, and an inherited one would hide that.
      env: { PATH: process.env.PATH, ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("close", (code) => resolvePromise({ code, stdout, stderr, out: stdout + stderr }));
  });
}
