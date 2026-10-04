import * as fs from "fs/promises";
import * as path from "path";
import type { PackageRegistryMeta } from "../registry/meta";

/** Hits older than this are re-queried from OSV. */
const PACKAGE_HIT_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Persistent cache in a hidden workspace folder (.dep-risk/cache.json).
 * Plain JSON tables without native bindings (reliable across Electron hosts).
 * Stores only what the scan reads back, never whole registry responses.
 */
interface CacheFile {
  version: 2;
  /** Advisory ids per `ecosystem:name@version`. */
  packageHits: Record<string, { vulnIds: string[]; modifiedById: Record<string, string>; cachedAt: number }>;
  /** Full OSV records by id; `modified` invalidates a stale record. */
  vulns: Record<string, { modified: string; vuln: unknown }>;
  /** Registry metadata per `ecosystem:name`. */
  meta: Record<string, { meta: PackageRegistryMeta; cachedAt: number }>;
  eol: Record<string, { data: unknown; cachedAt: number }>;
}

const emptyCache = (): CacheFile => ({ version: 2, packageHits: {}, vulns: {}, meta: {}, eol: {} });

/** JSON-file cache: lazily loaded, writes are debounced and atomic, `flush` forces a save (called at scan end). */
export class RiskCache {
  private data = emptyCache();
  private loaded = false;
  private dirty = false;
  private saveTimer: NodeJS.Timeout | undefined;
  private writing: Promise<void> = Promise.resolve();

  constructor(private readonly cachePath: string) {}

  /** Loads the file once; a missing, corrupt or old-format cache silently starts empty. */
  async init(): Promise<void> {
    if (this.loaded) {
      return;
    }
    try {
      const parsed = JSON.parse(await fs.readFile(this.cachePath, "utf8")) as CacheFile;
      if (parsed?.version === 2) {
        this.data = parsed;
      }
    } catch {
      // start empty
    }
    this.loaded = true;
  }

  private scheduleSave(): void {
    this.dirty = true;
    this.saveTimer ??= setTimeout(() => void this.flush().catch(() => undefined), 500);
  }

  async flush(): Promise<void> {
    clearTimeout(this.saveTimer);
    this.saveTimer = undefined;
    if (!this.dirty) {
      return this.writing;
    }
    const payload = JSON.stringify(this.data);
    this.dirty = false;
    // Serialized so two flushes never share the temp file.
    this.writing = this.writing.catch(() => undefined).then(() => this.writeAtomically(payload));
    try {
      await this.writing;
    } catch (error) {
      this.dirty = true;
      throw error;
    }
  }

  private async writeAtomically(payload: string): Promise<void> {
    await fs.mkdir(path.dirname(this.cachePath), { recursive: true });
    const temporaryPath = `${this.cachePath}.${process.pid}.tmp`;
    try {
      await fs.writeFile(temporaryPath, payload, "utf8");
      await fs.rename(temporaryPath, this.cachePath);
    } finally {
      await fs.rm(temporaryPath, { force: true });
    }
  }

  getPackageHit(key: string): { vulnIds: string[]; modifiedById: Record<string, string> } | undefined {
    const row = this.data.packageHits[key];
    return row && Date.now() - row.cachedAt <= PACKAGE_HIT_TTL_MS ? row : undefined;
  }

  setPackageHit(key: string, vulnIds: string[], modifiedById: Record<string, string>): void {
    this.data.packageHits[key] = { vulnIds, modifiedById, cachedAt: Date.now() };
    this.scheduleSave();
  }

  getVuln(id: string, modified?: string): unknown | undefined {
    const row = this.data.vulns[id];
    return row && !(modified && row.modified && row.modified !== modified) ? row.vuln : undefined;
  }

  setVuln(id: string, modified: string, vuln: unknown): void {
    this.data.vulns[id] = { modified, vuln };
    this.scheduleSave();
  }

  getMeta(key: string, maxAgeMs: number): PackageRegistryMeta | undefined {
    const row = this.data.meta[key];
    return row && Date.now() - row.cachedAt <= maxAgeMs ? row.meta : undefined;
  }

  setMeta(key: string, meta: PackageRegistryMeta): void {
    this.data.meta[key] = { meta, cachedAt: Date.now() };
    this.scheduleSave();
  }

  getEol(key: string, maxAgeMs: number): unknown | undefined {
    const row = this.data.eol[key];
    return row && Date.now() - row.cachedAt <= maxAgeMs ? row.data : undefined;
  }

  setEol(key: string, data: unknown): void {
    this.data.eol[key] = { data, cachedAt: Date.now() };
    this.scheduleSave();
  }
}
