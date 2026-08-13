import * as fs from "fs/promises";
import type { LockPackage } from "./npm";

/**
 * Minimal pnpm-lock.yaml parser for packages section (lockfile v5.4–v9).
 * Avoids a YAML dependency by extracting name/version pairs with line scanning.
 */
export async function parsePnpmLockfile(lockfilePath: string): Promise<LockPackage[]> {
  const raw = await fs.readFile(lockfilePath, "utf8");
  const out = new Map<string, LockPackage>();

  // Match keys like:  /lodash@4.17.21:  or  'lodash@4.17.21':  or  lodash@4.17.21:
  // Also scoped: /@scope/name@version:
  const keyRe =
    /^\s{2}['"]?(?:\/)?((?:@[^'@\s]+\/)?[^'@\s/]+)@([^'":\s]+)(?:\([^)]*\))?['"]?\s*:/;

  let inPackages = false;
  for (const line of raw.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line) && !line.startsWith(" ")) {
      inPackages = false;
    }
    if (!inPackages) {
      continue;
    }
    const m = line.match(keyRe);
    if (!m) {
      continue;
    }
    const name = m[1];
    const version = m[2];
    if (!name || !version || version.includes("/")) {
      continue;
    }
    const key = `${name}@${version}`;
    if (!out.has(key)) {
      out.set(key, {
        name,
        version,
        lockPath: `node_modules/${name}`,
      });
    }
  }

  return [...out.values()];
}
