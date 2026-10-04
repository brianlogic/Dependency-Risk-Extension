/**
 * Scan pipeline: turns a workspace folder into a ScanSummary.
 * Phases: parse lockfiles -> collect direct deps -> scan imports -> select packages
 * -> OSV batch query -> registry metadata -> hydrate + score -> runtime EOL -> summarize.
 * Network results go through RiskCache so repeat scans are mostly offline.
 */
import * as fs from "fs/promises";
import * as path from "path";
import * as vscode from "vscode";
import { getConfig, type DepRiskConfig } from "../config";
import { RiskCache } from "../cache/store";
import { collectImportedPackages } from "../graph/imports";
import {
  LOCKFILE_DISCOVERY_LIMIT,
  directDependencyNames,
  findLockfiles,
  isHoistedOrWorkspaceInstall,
  lockfileKind,
  mergeLockPackages,
  parseNpmLockfile,
  readPackageManifest,
  type LockfileKind,
} from "../lockfile/npm";
import type { LockPackage } from "../lockfile/types";
import { parsePnpmLockfile } from "../lockfile/pnpm";
import { parseYarnLockfile } from "../lockfile/yarn";
import { parseBunLockfile } from "../lockfile/bun";
import {
  parsePipfileLock,
  parsePoetryLockfile,
  parseRequirementsFile,
  parseUvLockfile,
  readPythonManifest,
} from "../lockfile/python";
import { OsvClient } from "../osv/client";
import { EolClient } from "../eol/endoflife";
import { NpmRegistry } from "../registry/npm";
import { PypiRegistry } from "../registry/pypi";
import type { RegistryClient } from "../registry/meta";
import { attachRegistrySignals, scorePackage, scoreRuntimeEol } from "../score/risk";
import { mapPool } from "../util/http";
import { packageNameKey, packageVersionKey } from "../util/packageKey";
import { isQueryableVersion, normalizePyName } from "../util/version";
import { TIER_ORDER, type Ecosystem, type PackageRef, type RiskResult, type ScanSummary, type RiskTier, type VulnSummary } from "../types";

/** Progress callback: `phase` is a short label, `detail` an optional count or note. */
export type ProgressFn = (phase: string, detail?: string) => void;

/** Owns the cache and API clients for one workspace folder; call `scan` to produce results. */
export class ScanPipeline {
  readonly cache: RiskCache;
  private readonly osv: OsvClient;
  private readonly npm: NpmRegistry;
  private readonly pypi: PypiRegistry;
  private readonly eol: EolClient;

  constructor(workspaceRoot: string) {
    const cachePath = path.join(workspaceRoot, ".dep-risk", "cache.json");
    this.cache = new RiskCache(cachePath);
    this.osv = new OsvClient(this.cache);
    this.npm = new NpmRegistry(this.cache);
    this.pypi = new PypiRegistry(this.cache);
    this.eol = new EolClient(this.cache);
  }

/**
 * Runs every phase and returns the summary. Failures in a single source (one package, one
 * registry) are collected in `summary.errors` instead of aborting, so results may be partial.
 */
  async scan(
    folder: vscode.WorkspaceFolder,
    opts?: { force?: boolean; token?: vscode.CancellationToken; onProgress?: ProgressFn }
  ): Promise<ScanSummary> {
    const cfg = getConfig();
    const errors: string[] = [];
    const onProgress = opts?.onProgress ?? (() => undefined);

    await this.cache.init();
    onProgress("Parsing lockfile");
    const lockPackages = await this.loadLockPackages(folder.uri.fsPath, errors);
    const workspace = await this.collectDirectDeps(folder, opts?.token, errors);

    onProgress("Scanning imports", `${workspace.packageJsonCount} package.json`);
    const imported = await collectImportedPackages(folder, opts?.token, (warning) =>
      errors.push(warning)
    );
    const packages = this.selectPackages(lockPackages, workspace.direct, imported, cfg, errors);

    onProgress("Querying OSV", `${packages.length} packages`);
    const batch = await this.osv.queryBatch(packages, { force: opts?.force });

// Registry metadata is only needed for packages the user cares about or that have advisories.
    const registryKeys = packages.filter((pkg) => {
      const refs = batch.get(packageVersionKey(pkg)) ?? [];
      return pkg.direct || pkg.imported || refs.length > 0;
    });
    onProgress("Fetching registry metadata", `${registryKeys.length} packages`);
    const metaByKey = await this.loadRegistryMeta(registryKeys, opts?.force, errors);
    const results = await this.scoreAll(packages, batch, metaByKey, cfg, opts?.token, errors);

    onProgress("Checking runtime EOL");
    await this.appendRuntimeEol(results, workspace.enginesNode, workspace.requiresPython, cfg, errors);
    await this.cache.flush();
    return summarize(packages.length, results, errors, onProgress);
  }

/**
 * Gathers names declared directly by the user (package.json, pyproject.toml, requirements*.txt)
 * plus runtime pins (Node / Python) used for the EOL check. Discovery is capped per file type
 * to keep huge monorepos fast; hitting a cap is reported in `errors`.
 */
  private async collectDirectDeps(
    folder: vscode.WorkspaceFolder,
    token: vscode.CancellationToken | undefined,
    errors: string[]
  ): Promise<{
    direct: Set<string>;
    packageJsonCount: number;
    enginesNode?: string;
    requiresPython?: string;
  }> {
    const find = async (glob: string, exclude: string, limit: number) => {
      const uris = await vscode.workspace.findFiles(new vscode.RelativePattern(folder, glob), exclude, limit + 1, token);
      return { paths: uris.slice(0, limit).map((uri) => uri.fsPath), overflow: uris.length > limit };
    };
    const each = async (paths: string[], read: (file: string) => Promise<void>) => {
      for (const file of paths) {
        try {
          await read(file);
        } catch (e) {
          errors.push(`Manifest ${file}: ${String(e)}`);
        }
      }
    };

    const direct = new Set<string>();
    let enginesNode: string | undefined;
    let requiresPython: string | undefined;

    const manifests = await find("**/package.json", "{**/node_modules/**,**/dist/**,**/out/**,**/build/**}", 200);
    if (manifests.overflow) {
      errors.push("Manifest discovery reached its 200-file limit; direct dependency signals may be incomplete.");
    }
    await each(manifests.paths, async (file) => {
      const m = await readPackageManifest(file);
      directDependencyNames(m).forEach((name) => direct.add(name));
      enginesNode = enginesNode ?? m.enginesNode;
    });

    const pyprojects = await find("**/pyproject.toml", "{**/node_modules/**,**/.venv/**,**/venv/**,**/dist/**}", 50);
    await each(pyprojects.paths, async (file) => {
      const manifest = await readPythonManifest(file);
      manifest.direct.forEach((name) => direct.add(name));
      requiresPython = requiresPython ?? manifest.requiresPython;
    });

    const requirements = await find("**/requirements*.txt", "{**/node_modules/**,**/.venv/**,**/venv/**}", 20);
    await each(requirements.paths, async (file) => {
      (await parseRequirementsFile(file)).direct.forEach((name) => direct.add(name));
    });

// Version-manager pin files (.nvmrc, .python-version) win over engines / requires-python.
    return {
      direct,
      packageJsonCount: manifests.paths.length,
      enginesNode: (await readPin(folder.uri.fsPath, [".nvmrc", ".node-version"], /^v?(\d+)(?:\.\d+){0,2}$/)) ?? enginesNode,
      requiresPython:
        (await readPin(folder.uri.fsPath, [".python-version", "runtime.txt"], /^(?:python-)?(\d+\.\d+)(?:\.\d+)?$/i)) ??
        requiresPython,
    };
  }

/**
 * Drops non-registry entries (git/file/link/workspace), then enforces `maxPackagesPerScan`,
 * keeping direct and imported packages ahead of the transitive rest.
 */
  private selectPackages(
    lockPackages: LockPackage[],
    direct: Set<string>,
    imported: Set<string>,
    cfg: DepRiskConfig,
    errors: string[]
  ): PackageRef[] {
    const queryable = lockPackages.filter((lp) =>
      isQueryableVersion(lp.version, lp.ecosystem ?? "npm")
    );
    if (queryable.length < lockPackages.length) {
      errors.push(
        `Skipped ${lockPackages.length - queryable.length} non-registry lockfile ${
          lockPackages.length - queryable.length === 1 ? "entry" : "entries"
        } (git/file/link/workspace).`
      );
    }

    let packages = this.toPackageRefs(queryable, direct, imported, cfg);
    if (packages.length > cfg.maxPackagesPerScan) {
      const omitted = packages.length - cfg.maxPackagesPerScan;
      errors.push(
        `Package limit reached: ${omitted} package${omitted === 1 ? " was" : "s were"} not scanned. Increase depRisk.maxPackagesPerScan for complete coverage.`
      );
      const priority = packages.filter((p) => p.direct || p.imported);
      const rest = packages.filter((p) => !p.direct && !p.imported);
      packages = [...priority, ...rest].slice(0, cfg.maxPackagesPerScan);
    }
    return packages;
  }

/** Fetches latest version / publish date / changelog URL once per package name (bounded concurrency). */
  private async loadRegistryMeta(
    registryKeys: PackageRef[],
    force: boolean | undefined,
    errors: string[]
  ): Promise<Map<string, { latest?: string; lastPublish?: string; changelog: string }>> {
    const metaByKey = new Map<string, { latest?: string; lastPublish?: string; changelog: string }>();
    await mapPool(uniqueByName(registryKeys), 6, async (pkg) => {
      try {
        const registry = this.registryFor(pkg.ecosystem);
        const meta = await registry.getMeta(pkg.name, { force });
        metaByKey.set(packageNameKey(pkg), {
          latest: meta?.latest,
          lastPublish: meta?.lastPublish,
          changelog: registry.changelogUrl(pkg.name, meta),
        });
      } catch (e) {
        errors.push(`${pkg.ecosystem} ${pkg.name}: ${String(e)}`);
      }
    });
    return metaByKey;
  }

/**
 * Hydrates advisories for each package (OSV batch only returns ids), combines them with registry
 * signals, and scores. Packages tiered "clear" are omitted from the results.
 */
  private async scoreAll(
    packages: PackageRef[],
    batch: Map<string, { id: string; modified?: string }[]>,
    metaByKey: Map<string, { latest?: string; lastPublish?: string; changelog: string }>,
    cfg: DepRiskConfig,
    token: vscode.CancellationToken | undefined,
    errors: string[]
  ): Promise<RiskResult[]> {
    const results: RiskResult[] = [];
    await mapPool(packages, 8, async (pkg) => {
      if (token?.isCancellationRequested) {
        return;
      }
      const refs = batch.get(packageVersionKey(pkg)) ?? [];
      let vulns: VulnSummary[] = [];
      try {
        vulns = refs.length ? await this.osv.hydrateVulns(pkg.name, refs, pkg.ecosystem) : [];
      } catch (e) {
        errors.push(`OSV hydrate ${pkg.name}: ${String(e)}`);
      }

      const meta = metaByKey.get(packageNameKey(pkg));
      const signals = attachRegistrySignals({ pkg, vulns }, meta?.latest, meta?.lastPublish);
      const scored = scorePackage(signals, cfg, meta?.changelog);
      if (scored.tier !== "clear") {
        results.push(scored);
      }
    });
    return results;
  }

/** Adds a result when the pinned Node or Python runtime is end-of-life. */
  private async appendRuntimeEol(
    results: RiskResult[],
    enginesNode: string | undefined,
    requiresPython: string | undefined,
    cfg: DepRiskConfig,
    errors: string[]
  ): Promise<void> {
    for (const [label, task] of [
      ["EOL node", () => this.eol.nodeRuntimeEol(enginesNode)],
      ["EOL python", () => this.eol.pythonRuntimeEol(requiresPython)],
    ] as const) {
      try {
        const eol = await task();
        if (eol) {
          const eolResult = scoreRuntimeEol(eol, cfg);
          if (eolResult) {
            results.push(eolResult);
          }
        }
      } catch (e) {
        errors.push(`${label}: ${String(e)}`);
      }
    }
  }

  private registryFor(ecosystem: Ecosystem): RegistryClient {
    return ecosystem === "pypi" ? this.pypi : this.npm;
  }

/**
 * Finds lockfiles and parses one JS kind and one Python kind (by priority) so the same
 * package is not counted twice. Multiple files of the chosen kind (monorepos) are merged.
 */
  private async loadLockPackages(root: string, errors: string[]): Promise<LockPackage[]> {
    const locks = await findLockfiles(root);
    if (!locks.length) {
      errors.push(
        "No lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, uv.lock, poetry.lock, Pipfile.lock, or pinned requirements.txt)."
      );
      return [];
    }
    if (locks.length >= LOCKFILE_DISCOVERY_LIMIT) {
      errors.push(
        `Lockfile discovery reached its ${LOCKFILE_DISCOVERY_LIMIT}-file limit; some nested lockfiles may be missing.`
      );
    }

    const byKind = new Map<LockfileKind, string[]>();
    for (const lock of locks) {
      const kind = lockfileKind(lock);
      if (!kind) {
        continue;
      }
      const list = byKind.get(kind) ?? [];
      list.push(lock);
      byKind.set(kind, list);
    }

    const JS_KINDS: LockfileKind[] = ["npm", "pnpm", "yarn", "bun"];
    const PY_KINDS: LockfileKind[] = ["uv", "poetry", "pipfile", "requirements"];
    const jsKind = firstKind(byKind, JS_KINDS);
    const pyKind = firstKind(byKind, PY_KINDS);
    for (const [label, kinds, priority] of [
      ["JavaScript", JS_KINDS, "npm, pnpm, Yarn, then Bun"],
      ["Python", PY_KINDS, "uv, Poetry, Pipfile, then pinned requirements.txt"],
    ] as const) {
      if (kinds.filter((kind) => byKind.has(kind)).length > 1) {
        errors.push(`Multiple ${label} lockfile types found; scanning by priority: ${priority}.`);
      }
    }

    if (!jsKind && !pyKind) {
      if (byKind.has("bun-binary")) {
        errors.push(
          "Found bun.lockb (binary). Generate bun.lock with bun install on Bun 1.2+, or add an npm/pnpm/Yarn lockfile."
        );
      }
      return [];
    }

    const batches: LockPackage[][] = [];
    for (const kind of [jsKind, pyKind]) {
      if (!kind) {
        continue;
      }
      const selected = byKind.get(kind) ?? [];
      if (selected.length > 1) {
        errors.push(
          `Scanning ${selected.length} ${kind} lockfiles (${selected.map((lock) => path.relative(root, lock) || path.basename(lock)).join(", ")}).`
        );
      }
      for (const lock of selected) {
        try {
          const parsed = await parseLockfile(lock, kind, errors);
          batches.push(parsed);
        } catch (e) {
          errors.push(`Lockfile parse ${path.relative(root, lock) || path.basename(lock)}: ${String(e)}`);
        }
      }
    }
    return mergeLockPackages(batches);
  }

/**
 * Marks each package direct / imported. npm "direct" also requires a hoisted or workspace install,
 * so a nested copy of a directly-declared name is treated as transitive. PyPI names are
 * compared after normalization (PEP 503).
 */
  private toPackageRefs(
    lockPackages: LockPackage[],
    direct: Set<string>,
    imported: Set<string>,
    cfg: DepRiskConfig
  ): PackageRef[] {
    const refs: PackageRef[] = [];
    const pyDirect = new Set([...direct].map(normalizePyName));
    const pyImported = new Set([...imported].map(normalizePyName));
    for (const lp of lockPackages) {
      const ecosystem: Ecosystem = lp.ecosystem ?? "npm";
      const isDirect =
        ecosystem === "pypi"
          ? pyDirect.has(normalizePyName(lp.name))
          : direct.has(lp.name) && isHoistedOrWorkspaceInstall(lp.lockPath, lp.name);
      const isImported = ecosystem === "pypi" ? pyImported.has(normalizePyName(lp.name)) : imported.has(lp.name);
      if (!cfg.scanTransitive && !isDirect && !isImported) {
        continue;
      }
      refs.push({
        name: lp.name,
        version: lp.version,
        ecosystem,
        direct: isDirect,
        imported: isImported,
      });
    }
    return refs;
  }
}

/** Dispatches to the parser for `kind`. Requirements files only count `==` pins; unpinned ones are reported. */
async function parseLockfile(
  lock: string,
  kind: LockfileKind,
  errors: string[]
): Promise<LockPackage[]> {
  switch (kind) {
    case "npm":
      return parseNpmLockfile(lock);
    case "pnpm":
      return parsePnpmLockfile(lock);
    case "yarn":
      return parseYarnLockfile(lock);
    case "bun":
      return parseBunLockfile(lock);
    case "uv":
      return parseUvLockfile(lock);
    case "poetry":
      return parsePoetryLockfile(lock);
    case "pipfile":
      return parsePipfileLock(lock);
    case "requirements": {
      const parsed = await parseRequirementsFile(lock);
      if (parsed.unpinned) {
        errors.push(
          `${path.basename(lock)} has ${parsed.unpinned} unpinned ${
            parsed.unpinned === 1 ? "requirement" : "requirements"
          }; only == pins are scanned.`
        );
      }
      return parsed.packages;
    }
    default:
      return [];
  }
}

/** First kind in priority `order` that was actually found. */
function firstKind(byKind: Map<LockfileKind, string[]>, order: LockfileKind[]): LockfileKind | undefined {
  return order.find((kind) => byKind.has(kind));
}

/** One entry per package name: metadata is per name, not per version. */
function uniqueByName(packages: PackageRef[]): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const pkg of packages) {
    const key = packageNameKey(pkg);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(pkg);
  }
  return out;
}

/** Counts results per tier and sorts: tier first, then imported > direct > transitive, then name. */
function summarize(
  packageCount: number,
  results: RiskResult[],
  errors: string[],
  onProgress: ProgressFn
): ScanSummary {
  const byTier = Object.fromEntries(
    TIER_ORDER.map((tier) => [tier, results.filter((r) => r.tier === tier).length])
  ) as Record<RiskTier, number>;

  const usage = (r: RiskResult) => Number(r.signals.pkg.imported) * 2 + Number(r.signals.pkg.direct);
  results.sort(
    (a, b) =>
      TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier) ||
      usage(b) - usage(a) ||
      a.signals.pkg.name.localeCompare(b.signals.pkg.name)
  );

  onProgress("Done", `${results.length} risks`);
  return {
    scannedAt: Date.now(),
    packageCount,
    byTier,
    results,
    errors,
  };
}

/** First line of the first existing file in `files` that matches `pattern`; returns capture group 1. */
async function readPin(root: string, files: string[], pattern: RegExp): Promise<string | undefined> {
  for (const filename of files) {
    try {
      const firstLine = (await fs.readFile(path.join(root, filename), "utf8")).trim().split(/\r?\n/)[0] ?? "";
      const match = firstLine.match(pattern);
      if (match) {
        return match[1];
      }
    } catch {
      // Optional runtime pin is absent.
    }
  }
  return undefined;
}
