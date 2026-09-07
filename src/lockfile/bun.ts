import { parse } from "jsonc-parser";
import * as fs from "fs/promises";
import type { LockPackage } from "./npm";

/**
 * Parse text bun.lock (Bun 1.2+ JSONC). Binary bun.lockb is rejected.
 */
export async function parseBunLockfile(lockfilePath: string): Promise<LockPackage[]> {
  const raw = await fs.readFile(lockfilePath, "utf8");
  if (lockfilePath.endsWith(".lockb") || raw.includes("\0")) {
    throw new Error(
      "Binary bun.lockb is not supported; run bun install (Bun 1.2+) to generate bun.lock."
    );
  }

  const json = parse(raw) as { packages?: Record<string, unknown> } | undefined;
  if (!json || typeof json !== "object") {
    throw new Error("Invalid bun.lock (expected a JSONC object).");
  }

  const packages = json.packages;
  if (!packages || typeof packages !== "object") {
    return [];
  }

  const out = new Map<string, LockPackage>();
  for (const [key, value] of Object.entries(packages)) {
    const locators: string[] = [];
    if (typeof value === "string") {
      locators.push(value);
    } else if (Array.isArray(value) && typeof value[0] === "string") {
      locators.push(value[0]);
    } else if (key.includes("@")) {
      locators.push(key);
    }

    for (const locator of locators) {
      const parsed = bunLocator(locator);
      if (!parsed) {
        continue;
      }
      const id = `${parsed.name}@${parsed.version}`;
      if (!out.has(id)) {
        out.set(id, {
          name: parsed.name,
          version: parsed.version,
          lockPath: `node_modules/${parsed.name}`,
        });
      }
    }
  }
  return [...out.values()];
}

function bunLocator(spec: string): { name: string; version: string } | undefined {
  const at = spec.startsWith("@") ? spec.indexOf("@", 1) : spec.indexOf("@");
  if (at <= 0) {
    return undefined;
  }
  const name = spec.slice(0, at);
  let version = spec.slice(at + 1);
  if (version.startsWith("npm:")) {
    version = version.slice(4);
  }
  if (!name || !version) {
    return undefined;
  }
  if (/^(workspace:|file:|link:|git\+?|github:|https?:|http:)/i.test(version)) {
    return undefined;
  }
  return { name, version };
}
