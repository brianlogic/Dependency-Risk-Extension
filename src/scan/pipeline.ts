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
  type LockPackage,
  type LockfileKind,
} from "../lockfile/npm";
import { isQueryableNpmVersion } from "../util/semver";
import { parsePnpmLockfile } from "../lockfile/pnpm";
import { parseYarnLockfile } from "../lockfile/yarn";
import { parseBunLockfile } from "../lockfile/bun";
import { OsvClient } from "../osv/client";
import { EolClient } from "../eol/endoflife";
import { NpmRegistry } from "../registry/npm";
import { attachRegistrySignals, scorePackage, scoreRuntimeEol } from "../score/risk";
import { mapPool } from "../util/http";
import type { PackageRef, RiskResult, ScanSummary, RiskTier, VulnSummary } from "../types";

export type ProgressFn = (phase: string, detail?: string) => void;

export class ScanPipeline {
  readonly cache: RiskCache;
  private readonly osv: OsvClient;
  private readonly npm: NpmRegistry;
  private readonly eol: EolClient;

  constructor(workspaceRoot: string) {
    const cachePath = path.join(workspaceRoot, ".dep-risk", "cache.json");
    this.cache = new RiskCache(cachePath);
    this.osv = new OsvClient(this.cache);
    this.npm = new NpmRegistry(this.cache);
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
    const manifestUris = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/package.json"),
      "{**/node_modules/**,**/dist/**,**/out/**,**/build/**}",
      201,
      opts?.token
    );
    if (manifestUris.length > 200) {
      errors.push("Manifest discovery reached its 200-file limit; direct dependency signals may be incomplete.");
    }
    const manifests = manifestUris.slice(0, 200).map((uri) => uri.fsPath);
    const direct = new Set<string>();
    let enginesNode: string | undefined;

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
    enginesNode = (await readPinnedNodeVersion(folder.uri.fsPath)) ?? enginesNode;

    onProgress("Scanning imports", `${manifests.length} package.json`);
    const imported = await collectImportedPackages(folder, opts?.token, (warning) =>
      errors.push(warning)
    );

    const queryable = lockPackages.filter((lp) => isQueryableNpmVersion(lp.version));
    if (queryable.length < lockPackages.length) {
      errors.push(
        `Skipped ${lockPackages.length - queryable.length} non-registry lockfile ${
          lockPackages.length - queryable.length === 1 ? "entry" : "entries"
        } (git/file/link/workspace).`
      );
    }

    let packages = this.toPackageRefs(queryable, direct, imported, cfg);
    if (packages.length > cfg.maxPackagesPerScan) {
      // Prefer direct + imported, then fill with transitive
      const omitted = packages.length - cfg.maxPackagesPerScan;
      errors.push(
        `Package limit reached: ${omitted} package${omitted === 1 ? " was" : "s were"} not scanned. Increase depRisk.maxPackagesPerScan for complete coverage.`
      );
      const priority = packages.filter((p) => p.direct || p.imported);
      const rest = packages.filter((p) => !p.direct && !p.imported);
      packages = [...priority, ...rest].slice(0, cfg.maxPackagesPerScan);
    }

    onProgress("Querying OSV", `${packages.length} packages`);
    const batch = await this.osv.queryBatch(packages, { force: opts?.force });

    onProgress("Hydrating advisories");
    const results: RiskResult[] = [];

    // Unique package names for registry (direct + those with vulns + imported)
    const registryNames = new Set<string>();
    for (const pkg of packages) {
      const refs = batch.get(`${pkg.name}@${pkg.version}`) ?? [];
      if (pkg.direct || pkg.imported || refs.length) {
        registryNames.add(pkg.name);
      }
    }

    onProgress("Fetching npm metadata", `${registryNames.size} packages`);
    const metaByName = new Map<string, Awaited<ReturnType<NpmRegistry["getMeta"]>>>();
    await mapPool([...registryNames], 6, async (name) => {
      try {
        metaByName.set(name, await this.npm.getMeta(name, { force: opts?.force }));
      } catch (e) {
        errors.push(`npm ${name}: ${String(e)}`);
      }
    });

    await mapPool(packages, 8, async (pkg) => {
      if (opts?.token?.isCancellationRequested) {
        return;
      }
      const refs = batch.get(`${pkg.name}@${pkg.version}`) ?? [];
      let vulns: VulnSummary[] = [];
      try {
        vulns = refs.length ? await this.osv.hydrateVulns(pkg.name, refs) : [];
      } catch (e) {
        errors.push(`OSV hydrate ${pkg.name}: ${String(e)}`);
      }

      const meta = metaByName.get(pkg.name);
      const signals = attachRegistrySignals(
        { pkg, vulns },
        meta?.latest,
        meta?.lastPublish
      );

      const scored = scorePackage(signals, cfg, this.npm.changelogUrl(pkg.name, meta));
      if (scored.tier !== "clear") {
        results.push(scored);
      }
    });

    onProgress("Checking runtime EOL");
    try {
      const eol = await this.eol.nodeRuntimeEol(enginesNode);
      if (eol) {
        const eolResult = scoreRuntimeEol(eol, cfg);
        if (eolResult) {
          results.push(eolResult);
        }
      }
    } catch (e) {
      errors.push(`EOL: ${String(e)}`);
    }

    await this.cache.flush();

    const byTier = emptyTierCounts();
    for (const r of results) {
      byTier[r.tier] += 1;
    }

    // Sort: tier, then imported/direct first, then name
    const tierRank: Record<RiskTier, number> = {
      critical: 0,
      high: 1,
      stale: 2,
      eol: 3,
      clear: 4,
    };
    results.sort((a, b) => {
      const t = tierRank[a.tier] - tierRank[b.tier];
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
      packageCount: packages.length,
      byTier,
      results,
      errors,
    };
  }

  private async loadLockPackages(root: string, errors: string[]): Promise<LockPackage[]> {
    const locks = await findLockfiles(root);
    if (!locks.length) {
      errors.push("No lockfile found (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lock).");
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

    const selectedKind: LockfileKind | undefined = byKind.has("npm")
      ? "npm"
      : byKind.has("pnpm")
        ? "pnpm"
        : byKind.has("yarn")
          ? "yarn"
          : byKind.has("bun")
            ? "bun"
            : undefined;

    const kindsPresent = [...byKind.keys()].filter((kind) => kind !== "bun-binary");
    if (kindsPresent.length > 1) {
      errors.push(
        `Multiple lockfile types found (${kindsPresent.join(", ")}); scanning by priority: npm, pnpm, Yarn, then Bun.`
      );
    }

    if (!selectedKind) {
      if (byKind.has("bun-binary")) {
        errors.push(
          "Found bun.lockb (binary). Generate bun.lock with bun install on Bun 1.2+, or add an npm/pnpm/Yarn lockfile."
        );
      }
      return [];
    }

    const selected = byKind.get(selectedKind) ?? [];
    if (selected.length > 1) {
      errors.push(
        `Scanning ${selected.length} ${selectedKind} lockfiles (${selected.map((lock) => path.relative(root, lock) || path.basename(lock)).join(", ")}).`
      );
    }

    const batches: LockPackage[][] = [];
    for (const lock of selected) {
      try {
        batches.push(await parseLockfile(lock, selectedKind));
      } catch (e) {
        errors.push(`Lockfile parse ${path.relative(root, lock) || path.basename(lock)}: ${String(e)}`);
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
      const isDirect =
        direct.has(lp.name) && isHoistedOrWorkspaceInstall(lp.lockPath, lp.name);
      const isImported = imported.has(lp.name);
      if (!cfg.scanTransitive && !isDirect && !isImported) {
        continue;
      }
      refs.push({
        name: lp.name,
        version: lp.version,
        ecosystem: "npm",
        direct: isDirect,
        imported: isImported,
        usage: isDirect ? "direct" : "transitive",
      });
    }
    return refs;
  }
}

async function parseLockfile(lock: string, kind: LockfileKind): Promise<LockPackage[]> {
  switch (kind) {
    case "npm":
      return parseNpmLockfile(lock);
    case "pnpm":
      return parsePnpmLockfile(lock);
    case "yarn":
      return parseYarnLockfile(lock);
    case "bun":
      return parseBunLockfile(lock);
    default:
      return [];
  }
}

function emptyTierCounts(): Record<RiskTier, number> {
  return { critical: 0, high: 0, stale: 0, eol: 0, clear: 0 };
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
