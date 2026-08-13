import * as fs from "fs/promises";
import type { LockPackage } from "./npm";

/** Parse classic yarn.lock (v1) package entries. */
export async function parseYarnLockfile(lockfilePath: string): Promise<LockPackage[]> {
  const raw = await fs.readFile(lockfilePath, "utf8");
  if (/^__metadata:\s*$/m.test(raw)) {
    throw new Error(
      "Yarn Berry (v2+) lockfiles are not supported yet; use package-lock.json, pnpm-lock.yaml, or Yarn Classic."
    );
  }
  const out = new Map<string, LockPackage>();

  // Blocks start with: "lodash@^4.0.0", "lodash@~4.17.0":
  // or lodash@^4.0.0:
  const headerRe = /^"?((?:@[^@"]+\/)?[^@"\s]+)@[^:]+"?:/;
  const versionRe = /^\s+version\s+"([^"]+)"/;

  let currentName: string | undefined;
  for (const line of raw.split(/\r?\n/)) {
    const h = line.match(headerRe);
    if (h && !line.startsWith(" ")) {
      currentName = h[1];
      continue;
    }
    if (currentName) {
      const v = line.match(versionRe);
      if (v) {
        const version = v[1];
        const key = `${currentName}@${version}`;
        if (!out.has(key)) {
          out.set(key, {
            name: currentName,
            version,
            lockPath: `node_modules/${currentName}`,
          });
        }
        currentName = undefined;
      }
    }
  }

  return [...out.values()];
}
