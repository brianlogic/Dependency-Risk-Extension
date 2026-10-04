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
import { isQueryableVersion, namesMatch } from "../util/version";
import { TIER_ORDER, type Ecosystem, type PackageRef, type RiskResult, type ScanSummary, type RiskTier, type VulnSummary } from "../types";

export type ProgressFn = (phase: string, detail?: string) => void;

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

  async init(): Promise<void> {
    await this.cache.init();
  }

  async scan(
    folder: vscode.WorkspaceFolder,
    opts?: { force?: boolean; token?: vscode.CancellationToken; onProgress?: ProgressFn }
  ): Promise<ScanSummary> {
    const cfg = getConfig();
    const errors: string[] = [];
    const onProgress = opts?.onProgress ?? (() => undefined);

    await this.init();
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

    onProgress("Hydrating advisories");
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
    const manifestUris = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/package.json"),
      "{**/node_modules/**,**/dist/**,**/out/**,**/build/**}",
      201,
      token
    );
    if (manifestUris.length > 200) {
      errors.push("Manifest discovery reached its 200-file limit; direct dependency signals may be incomplete.");
    }
    const manifests = manifestUris.slice(0, 200).map((uri) => uri.fsPath);
    const direct = new Set<string>();
    let enginesNode: string | undefined;
    let requiresPython: string | undefined;

    for (const mf of manifests) {
      try {
        const m = await readPackageManifest(mf);
        for (const n of directDependencyNames(m)) {
          direct.add(n);
        }
        enginesNode = enginesNode ?? m.enginesNode;
      } catch (e) {
        errors.push(`Manifest ${mf}: ${String(e)}`);
      }
    }

    const pythonManifests = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/pyproject.toml"),
      "{**/node_modules/**,**/.venv/**,**/venv/**,**/dist/**}",
      51,
      token
    );
    for (const uri of pythonManifests.slice(0, 50)) {
      try {
        const manifest = await readPythonManifest(uri.fsPath);
        for (const name of manifest.direct) {
          direct.add(name);
        }
        requiresPython = requiresPython ?? manifest.requiresPython;
      } catch (e) {
        errors.push(`Manifest ${uri.fsPath}: ${String(e)}`);
      }
    }

    const requirementUris = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/requirements*.txt"),
      "{**/node_modules/**,**/.venv/**,**/venv/**}",
      21,
      token
    );
    for (const uri of requirementUris.slice(0, 20)) {
      try {
        const parsed = await parseRequirementsFile(uri.fsPath);
        for (const name of parsed.direct) {
          direct.add(name);
        }
      } catch (e) {
        errors.push(`Manifest ${uri.fsPath}: ${String(e)}`);
      }
    }

    return {
      direct,
      packageJsonCount: manifests.length,
      enginesNode: (await readPinnedNodeVersion(folder.uri.fsPath)) ?? enginesNode,
      requiresPython: (await readPinnedPythonVersion(folder.uri.fsPath)) ?? requiresPython,
    };
  }

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

    const jsKind = firstKind(byKind, ["npm", "pnpm", "yarn", "bun"]);
    const pyKind = firstKind(byKind, ["uv", "poetry", "pipfile", "requirements"]);
    const kindsPresent = [...byKind.keys()].filter((kind) => kind !== "bun-binary");
    if (kindsPresent.filter((kind) => ["npm", "pnpm", "yarn", "bun"].includes(kind)).length > 1) {
      errors.push(
        `Multiple JavaScript lockfile types found; scanning by priority: npm, pnpm, Yarn, then Bun.`
      );
    }
    if (kindsPresent.filter((kind) => ["uv", "poetry", "pipfile", "requirements"].includes(kind)).length > 1) {
      errors.push(
        `Multiple Python lockfile types found; scanning by priority: uv, Poetry, Pipfile, then pinned requirements.txt.`
      );
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

  private toPackageRefs(
    lockPackages: LockPackage[],
    direct: Set<string>,
    imported: Set<string>,
    cfg: DepRiskConfig
  ): PackageRef[] {
    const refs: PackageRef[] = [];
    for (const lp of lockPackages) {
      const ecosystem: Ecosystem = lp.ecosystem ?? "npm";
      const isDirect =
        ecosystem === "pypi"
          ? hasName(direct, lp.name)
          : direct.has(lp.name) && isHoistedOrWorkspaceInstall(lp.lockPath, lp.name);
      const isImported = ecosystem === "pypi" ? hasName(imported, lp.name) : imported.has(lp.name);
      if (!cfg.scanTransitive && !isDirect && !isImported) {
        continue;
      }
      refs.push({
        name: lp.name,
        version: lp.version,
        ecosystem,
        direct: isDirect,
        imported: isImported,
        usage: isDirect ? "direct" : "transitive",
      });
    }
    return refs;
  }
}

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

function firstKind(byKind: Map<LockfileKind, string[]>, order: LockfileKind[]): LockfileKind | undefined {
  return order.find((kind) => byKind.has(kind));
}

function hasName(names: Set<string>, pkgName: string): boolean {
  if (names.has(pkgName)) {
    return true;
  }
  for (const name of names) {
    if (namesMatch(name, pkgName)) {
      return true;
    }
  }
  return false;
}

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

function emptyTierCounts(): Record<RiskTier, number> {
  return Object.fromEntries(TIER_ORDER.map((tier) => [tier, 0])) as Record<RiskTier, number>;
}

function summarize(
  packageCount: number,
  results: RiskResult[],
  errors: string[],
  onProgress: ProgressFn
): ScanSummary {
  const byTier = emptyTierCounts();
  for (const r of results) {
    byTier[r.tier] += 1;
  }

  results.sort((a, b) => {
    const t = TIER_ORDER.indexOf(a.tier) - TIER_ORDER.indexOf(b.tier);
    if (t !== 0) {
      return t;
    }
    const ua = Number(a.signals.pkg.imported) * 2 + Number(a.signals.pkg.direct);
    const ub = Number(b.signals.pkg.imported) * 2 + Number(b.signals.pkg.direct);
    if (ub !== ua) {
      return ub - ua;
    }
    return a.signals.pkg.name.localeCompare(b.signals.pkg.name);
  });

  onProgress("Done", `${results.length} risks`);
  return {
    scannedAt: Date.now(),
    packageCount,
    byTier,
    results,
    errors,
  };
}

async function readPinnedPythonVersion(root: string): Promise<string | undefined> {
  for (const filename of [".python-version", "runtime.txt"]) {
    try {
      const value = (await fs.readFile(path.join(root, filename), "utf8")).trim().split(/\r?\n/)[0] ?? "";
      const match = value.match(/^(?:python-)?(\d+\.\d+)(?:\.\d+)?$/i);
      if (match) {
        return match[1];
      }
    } catch {
      // Optional runtime pin is absent.
    }
  }
  return undefined;
}

async function readPinnedNodeVersion(root: string): Promise<string | undefined> {
  for (const filename of [".nvmrc", ".node-version"]) {
    try {
      const value = (await fs.readFile(path.join(root, filename), "utf8")).trim();
      const match = value.match(/^(?:v)?(\d+)(?:\.\d+){0,2}$/);
      if (match) {
        return match[1];
      }
    } catch {
      // Optional runtime pin is absent.
    }
  }
  return undefined;
}
