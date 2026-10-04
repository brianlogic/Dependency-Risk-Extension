/**
 * Turns one workspace folder into a ScanSummary.
 *
 * Inventory is one JavaScript lockfile type and one Python lockfile type
 * (package-lock.json; and uv, then Poetry, pinned requirements). pnpm, Yarn, Bun, and
 * Pipfile lockfiles are not read; finding one adds a warning.
 * Both ecosystems are included when both are present. Parsing two types for the
 * same ecosystem would count one install twice. Git, file, link, and workspace
 * versions are dropped before any network call.
 *
 * OSV is queried for every selected package. Registry metadata is fetched only
 * for direct, imported, or already-vulnerable packages. A transitive package
 * with no advisory is therefore never marked stale: staleness needs a latest
 * version, and fetching every transitive packument is the expensive call.
 *
 * One package or one registry failing is recorded on `summary.errors` and the
 * scan continues, so a summary can be partial. Clear packages are omitted.
 * Repeat scans read RiskCache and only go to the network for misses, unless
 * the caller passes `force`.
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
import {
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
   * Runs every phase. `force` bypasses the OSV package-hit cache and the
   * registry cache; a full advisory record is still reused until its
   * `modified` timestamp changes. `token` skips packages that have not
   * started hydration. The querybatch call itself is not cancelled, and a
   * hydration request already in flight still finishes.
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

    // Transitive packages with no advisory skip the registry. Without a latest
    // version they cannot be stale, and they have nothing else to score.
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
   * Names the user declared (package.json, pyproject.toml, requirements) plus
   * the Node and Python pins used for EOL. Discovery is capped per file type;
   * hitting the package.json cap is reported because direct-dependency signals
   * may then be incomplete. A bad manifest is recorded and skipped.
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

    // .nvmrc and .python-version name the runtime in use. engines and
    // requires-python are often ranges, which the EOL check ignores, so a pin wins.
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
   * Drops versions OSV cannot query, then applies `maxPackagesPerScan`.
   * Direct and imported packages are kept ahead of the transitive rest so the
   * cap cuts packages the workspace does not name first. `scanTransitive`
   * false drops everything that is neither direct nor imported.
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

  /**
   * Latest version, last publish, and changelog URL, once per package name.
   * Versions of the same package share one registry document. Failures are
   * recorded per package; the others still return.
   */
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
   * Loads full advisories for the ids from querybatch, attaches registry
   * signals, and scores. A package whose hydration fails is scored with no
   * advisories and the error is recorded, so a bad record cannot hide the
   * rest of the inventory. Clear packages are left out of the list.
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

  /**
   * Adds an EOL result for a pinned Node or Python runtime that is already
   * past end-of-life or inside the configured horizon. An unreadable cycle
   * list is recorded; the package results already collected are kept.
   */
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
   * Parses every lockfile of the winning JavaScript kind and the winning
   * Python kind. Nested lockfiles of that kind are merged by name and version,
   * keeping the shallowest install path. Unsupported lockfiles (pnpm, Yarn, Bun,
   * Pipfile) are reported and not parsed. A file that fails to parse is skipped.
   */
  private async loadLockPackages(root: string, errors: string[]): Promise<LockPackage[]> {
    const locks = await findLockfiles(root);
    if (!locks.length) {
      errors.push("No lockfile found (package-lock.json, uv.lock, poetry.lock, or pinned requirements.txt).");
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

    const unsupported = byKind.get("unsupported");
    if (unsupported) {
      errors.push(
        `Unsupported lockfile${unsupported.length === 1 ? "" : "s"} ignored: ${unsupported
          .map((lock) => path.relative(root, lock) || path.basename(lock))
          .join(", ")}. Supported: package-lock.json, uv.lock, poetry.lock, pinned requirements.txt.`
      );
    }

    const PY_KINDS: LockfileKind[] = ["uv", "poetry", "requirements"];
    const jsKind: LockfileKind | undefined = byKind.has("npm") ? "npm" : undefined;
    const pyKind = firstKind(byKind, PY_KINDS);
    if (PY_KINDS.filter((kind) => byKind.has(kind)).length > 1) {
      errors.push("Multiple Python lockfile types found; scanning by priority: uv, Poetry, then pinned requirements.txt.");
    }

    if (!jsKind && !pyKind) {
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
   * Marks direct and imported. An npm package listed in package.json is direct
   * only when its lock path is a hoisted or workspace install, so a nested copy
   * of that same name stays transitive. PyPI names are compared after PEP 503
   * normalization (`Requests` matches `requests`).
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
    case "uv":
      return parseUvLockfile(lock);
    case "poetry":
      return parsePoetryLockfile(lock);
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

/**
 * Counts each tier, then orders results by severity, then by how close the
 * package is to the workspace (imported, then direct, then transitive), then by name.
 */
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
