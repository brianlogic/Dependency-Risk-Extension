/**
 * Python manifest and lockfile parsing. Line-based (no TOML dependency): reads uv.lock and
 * poetry.lock (same `[[package]]` layout), requirements*.txt and pyproject.toml.
 * Only registry-hosted packages are returned; git/path/editable sources are skipped.
 */
import * as fs from "fs/promises";
import type { LockPackage } from "./types";

/** Direct dependency names and the `requires-python` constraint declared by a pyproject.toml. */
export interface PythonManifest {
  direct: Set<string>;
  requiresPython?: string;
}

/** uv.lock and poetry.lock both use `[[package]]` blocks with `name` / `version`. */
async function parseTomlLockfile(lockfilePath: string): Promise<LockPackage[]> {
  return parseTomlPackageBlocks(await fs.readFile(lockfilePath, "utf8"));
}

export const parseUvLockfile = parseTomlLockfile;
export const parsePoetryLockfile = parseTomlLockfile;

/**
 * requirements*.txt: every named requirement is "direct", but only `==` pins become scannable
 * packages. `unpinned` counts the rest so the scan can report reduced coverage.
 */
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

/**
 * pyproject.toml: direct names from PEP 621 (`project.dependencies`, optional groups,
 * `dependency-groups`) and Poetry tables, plus `requires-python`.
 */
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

/** Collects name/version per `[[package]]` block; a non-registry `source` marks the block to skip. */
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

/** `lockPath` has no node_modules nesting for PyPI, so it is a flat `pypi/<name>`. */
function pypiPackage(name: string, version: string): LockPackage {
  return {
    name,
    version,
    lockPath: `pypi/${name}`,
    ecosystem: "pypi",
  };
}

/** Distribution name at the start of a requirement spec (before extras, markers or version). */
export function requirementName(spec: string): string | undefined {
  const cleaned = spec.trim().replace(/^['"]|['"]$/g, "");
  const match = cleaned.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/);
  return match?.[1];
}
