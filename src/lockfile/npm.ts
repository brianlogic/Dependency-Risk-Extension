import * as fs from "fs/promises";
import * as path from "path";

export interface LockPackage {
  name: string;
  version: string;
  /** Dependency path key from lockfile (e.g. node_modules/lodash). */
  lockPath: string;
}

export interface ManifestDeps {
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  enginesNode?: string;
}

interface NpmLockV2 {
  lockfileVersion?: number;
  packages?: Record<
    string,
    {
      name?: string;
      version?: string;
      optional?: boolean;
      dev?: boolean;
      peer?: boolean;
      link?: boolean;
    }
  >;
  dependencies?: Record<
    string,
    {
      version?: string;
      dependencies?: unknown;
    }
  >;
}

export function nameFromNodeModulesPath(lockPath: string): string | undefined {
  const parts = lockPath.split("/node_modules/");
  const leaf =
    parts.length > 1
      ? parts[parts.length - 1]
      : lockPath.startsWith("node_modules/")
        ? lockPath.slice("node_modules/".length)
        : undefined;
  if (!leaf) {
    return undefined;
  }
  if (leaf.startsWith("@")) {
    const [scope, name] = leaf.split("/");
    if (scope && name) {
      return `${scope}/${name}`;
    }
    return undefined;
  }
  return leaf.split("/")[0];
}

/** Root or workspace install, not a nested copy under another package. */
export function isHoistedOrWorkspaceInstall(lockPath: string, name: string): boolean {
  const suffix = `node_modules/${name}`;
  if (lockPath === suffix) {
    return true;
  }
  if (!lockPath.endsWith(`/${suffix}`)) {
    return false;
  }
  const prefix = lockPath.slice(0, lockPath.length - suffix.length);
  return !prefix.includes("node_modules");
}

export async function readPackageManifest(manifestPath: string): Promise<ManifestDeps> {
  const raw = await fs.readFile(manifestPath, "utf8");
  const json = JSON.parse(raw) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    peerDependencies?: Record<string, string>;
    engines?: { node?: string };
  };
  return {
    dependencies: json.dependencies ?? {},
    devDependencies: json.devDependencies ?? {},
    optionalDependencies: json.optionalDependencies ?? {},
    peerDependencies: json.peerDependencies ?? {},
    enginesNode: json.engines?.node,
  };
}

export function directDependencyNames(manifest: ManifestDeps): Set<string> {
  return new Set([
    ...Object.keys(manifest.dependencies),
    ...Object.keys(manifest.devDependencies),
    ...Object.keys(manifest.optionalDependencies),
    ...Object.keys(manifest.peerDependencies),
  ]);
}

/** Parse npm package-lock.json / npm-shrinkwrap.json (v1–v3). */
export async function parseNpmLockfile(lockfilePath: string): Promise<LockPackage[]> {
  const raw = await fs.readFile(lockfilePath, "utf8");
  const lock = JSON.parse(raw) as NpmLockV2;
  const out = new Map<string, LockPackage>();

  if (lock.packages && typeof lock.packages === "object") {
    for (const [lockPath, meta] of Object.entries(lock.packages)) {
      if (!lockPath || meta.link) {
        continue;
      }
      const name = meta.name ?? nameFromNodeModulesPath(lockPath);
      const version = meta.version;
      if (!name || !version) {
        continue;
      }
      const key = `${name}@${version}`;
      const existing = out.get(key);
      if (!existing || lockPathDepth(lockPath) < lockPathDepth(existing.lockPath)) {
        out.set(key, { name, version, lockPath });
      }
    }
    return [...out.values()];
  }

  // lockfileVersion 1
  function walk(deps: NpmLockV2["dependencies"], prefix = ""): void {
    if (!deps) {
      return;
    }
    for (const [name, meta] of Object.entries(deps)) {
      const version = meta.version?.replace(/^.*@/, "") ?? meta.version;
      const currentPath = prefix
        ? `${prefix}/node_modules/${name}`
        : `node_modules/${name}`;
      if (name && version) {
        const key = `${name}@${version}`;
        if (!out.has(key)) {
          out.set(key, {
            name,
            version,
            lockPath: currentPath,
          });
        }
      }
      walk(meta.dependencies as NpmLockV2["dependencies"], currentPath);
    }
  }
  walk(lock.dependencies);
  return [...out.values()];
}

function lockPathDepth(lockPath: string): number {
  return lockPath.split("/node_modules/").length;
}

export async function findLockfiles(workspaceRoot: string): Promise<string[]> {
  const candidates = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
  ];
  const found: string[] = [];
  for (const c of candidates) {
    const p = path.join(workspaceRoot, c);
    try {
      await fs.access(p);
      found.push(p);
    } catch {
      // missing
    }
  }
  return found;
}

export async function findPackageJsonFiles(workspaceRoot: string): Promise<string[]> {
  // Root + one level of workspaces packages/* — keep scan bounded
  const roots = [path.join(workspaceRoot, "package.json")];
  const pkgDirs = ["packages", "apps", "services"];
  for (const dir of pkgDirs) {
    const base = path.join(workspaceRoot, dir);
    try {
      const entries = await fs.readdir(base, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory()) {
          roots.push(path.join(base, e.name, "package.json"));
        }
      }
    } catch {
      // no such dir
    }
  }
  const existing: string[] = [];
  for (const p of roots) {
    try {
      await fs.access(p);
      existing.push(p);
    } catch {
      // skip
    }
  }
  return existing;
}
