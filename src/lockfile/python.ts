import * as fs from "fs/promises";
import type { LockPackage } from "./npm";

export interface PythonManifest {
  direct: Set<string>;
  requiresPython?: string;
}

export async function parseUvLockfile(lockfilePath: string): Promise<LockPackage[]> {
  return parseTomlPackageBlocks(await fs.readFile(lockfilePath, "utf8"));
}

export async function parsePoetryLockfile(lockfilePath: string): Promise<LockPackage[]> {
  return parseTomlPackageBlocks(await fs.readFile(lockfilePath, "utf8"));
}

export async function parsePipfileLock(lockfilePath: string): Promise<LockPackage[]> {
  const json = JSON.parse(await fs.readFile(lockfilePath, "utf8")) as Record<
    string,
    Record<string, { version?: string; git?: string; path?: string; file?: string }>
  >;
  const out = new Map<string, LockPackage>();
  for (const section of ["default", "develop"]) {
    const deps = json[section];
    if (!deps || typeof deps !== "object") {
      continue;
    }
    for (const [name, meta] of Object.entries(deps)) {
      if (!meta || meta.git || meta.path || meta.file) {
        continue;
      }
      const version = meta.version?.replace(/^==/, "");
      if (!name || !version) {
        continue;
      }
      out.set(`${name}@${version}`, pypiPackage(name, version));
    }
  }
  return [...out.values()];
}

export async function parseRequirementsFile(filePath: string): Promise<{
  packages: LockPackage[];
  direct: Set<string>;
  unpinned: number;
}> {
  const raw = await fs.readFile(filePath, "utf8");
  const packages: LockPackage[] = [];
  const direct = new Set<string>();
  let unpinned = 0;

  for (const line of raw.split(/\r?\n/)) {
    const spec = line.replace(/#.*$/, "").trim();
    if (
      !spec ||
      spec.startsWith("-") ||
      spec.startsWith(".") ||
      /^(git\+|git@|https?:|file:|ssh:|svn\+|hg\+)/i.test(spec) ||
      spec.includes("://")
    ) {
      continue;
    }
    const name = requirementName(spec);
    if (!name) {
      continue;
    }
    direct.add(name);
    const pinned = spec.match(/==\s*([^\s;]+)/);
    if (pinned) {
      packages.push(pypiPackage(name, pinned[1].replace(/[\\]+$/, "")));
    } else {
      unpinned += 1;
    }
  }

  return { packages, direct, unpinned };
}

export async function readPythonManifest(manifestPath: string): Promise<PythonManifest> {
  const raw = await fs.readFile(manifestPath, "utf8");
  const direct = new Set<string>();
  let requiresPython: string | undefined;
  let section = "";
  let inProjectDependencies = false;

  for (const line of raw.split(/\r?\n/)) {
    const header = line.match(/^\[([^\]]+)\]\s*$/);
    if (header) {
      section = header[1];
      inProjectDependencies = false;
      continue;
    }
    const requires = line.match(/^\s*requires-python\s*=\s*["']([^"']+)["']/i);
    if (requires) {
      requiresPython = requires[1];
    }
    if (section === "project" && /^\s*dependencies\s*=/.test(line)) {
      inProjectDependencies = true;
    }
    const collectQuoted =
      inProjectDependencies ||
      section.startsWith("project.optional-dependencies") ||
      section === "dependency-groups";
    if (collectQuoted) {
      const quoted = line.match(/["']([^"']+)["']/);
      const name = quoted ? requirementName(quoted[1]) : undefined;
      if (name) {
        direct.add(name);
      }
      if (inProjectDependencies && line.includes("]")) {
        inProjectDependencies = false;
      }
    }
    if (
      section === "tool.poetry.dependencies" ||
      /^tool\.poetry\.group\.[^.]+\.dependencies$/.test(section)
    ) {
      const key = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
      if (key && key[1].toLowerCase() !== "python") {
        direct.add(key[1]);
      }
    }
  }

  return { direct, requiresPython };
}

function parseTomlPackageBlocks(raw: string): LockPackage[] {
  const out = new Map<string, LockPackage>();
  let name: string | undefined;
  let version: string | undefined;
  let skip = false;

  const commit = (): void => {
    if (name && version && !skip) {
      out.set(`${name}@${version}`, pypiPackage(name, version));
    }
    name = undefined;
    version = undefined;
    skip = false;
  };

  for (const line of raw.split(/\r?\n/)) {
    if (/^\[\[package\]\]\s*$/.test(line)) {
      commit();
      continue;
    }
    const nameMatch = line.match(/^\s*name\s*=\s*"([^"]+)"/);
    if (nameMatch) {
      name = nameMatch[1];
      continue;
    }
    const versionMatch = line.match(/^\s*version\s*=\s*"([^"]+)"/);
    if (versionMatch) {
      version = versionMatch[1];
      continue;
    }
    if (/^\s*source\s*=\s*\{[^}]*(git|path|editable|directory)\s*=/i.test(line)) {
      skip = true;
      continue;
    }
    if (/^\s*source\s*=\s*\{[^}]*url\s*=/i.test(line) && !/\/simple/i.test(line)) {
      skip = true;
      continue;
    }
    if (/^\s*type\s*=\s*"(git|directory|file|url|path)"/i.test(line)) {
      skip = true;
    }
  }
  commit();
  return [...out.values()];
}

function pypiPackage(name: string, version: string): LockPackage {
  return {
    name,
    version,
    lockPath: `pypi/${name}`,
    ecosystem: "pypi",
  };
}

export function requirementName(spec: string): string | undefined {
  const cleaned = spec.trim().replace(/^['"]|['"]$/g, "");
  const match = cleaned.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
  return match?.[1];
}
