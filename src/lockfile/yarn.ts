import * as fs from "fs/promises";
import type { LockPackage } from "./npm";

/** Parse classic yarn.lock (v1) or Yarn Berry (v2+) lockfiles. */
export async function parseYarnLockfile(lockfilePath: string): Promise<LockPackage[]> {
  const raw = await fs.readFile(lockfilePath, "utf8");
  return /^__metadata:\s*$/m.test(raw) ? parseYarnBerry(raw) : parseYarnClassic(raw);
}

function parseYarnClassic(raw: string): LockPackage[] {
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

function parseYarnBerry(raw: string): LockPackage[] {
  const out = new Map<string, LockPackage>();
  const versionRe = /^\s+version:\s*"?([^"\s]+)"?/;

  let currentName: string | undefined;
  for (const line of raw.split(/\r?\n/)) {
    if (!line.startsWith(" ") && !line.startsWith("\t") && line.includes("@")) {
      const key = line.replace(/:\s*$/, "").replace(/^"|"$/g, "");
      currentName = yarnBerryName(key);
      continue;
    }
    if (!currentName) {
      continue;
    }
    const v = line.match(versionRe);
    if (!v) {
      continue;
    }
    const version = v[1];
    if (version === "0.0.0-use.local") {
      currentName = undefined;
      continue;
    }
    const id = `${currentName}@${version}`;
    if (!out.has(id)) {
      out.set(id, {
        name: currentName,
        version,
        lockPath: `node_modules/${currentName}`,
      });
    }
    currentName = undefined;
  }

  return [...out.values()];
}

function yarnBerryName(key: string): string | undefined {
  const descriptors = key.split(/",\s*"|, (?=(?:@[^@/]+\/)?[^@\s]+@)/);
  for (const descriptor of descriptors) {
    const cleaned = descriptor.replace(/^"|"$/g, "").trim();
    if (/@(workspace:|file:|link:|portal:|exec:)/.test(cleaned)) {
      continue;
    }
    const match = cleaned.match(/^((?:@[^@/]+\/)?[^@/]+)@/);
    if (match) {
      return match[1];
    }
  }
  return undefined;
}
