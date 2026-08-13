import * as fs from "fs/promises";
import * as path from "path";

/**
 * Persistent cache in a hidden workspace folder (.dep-risk/cache.json).
 * SQLite-shaped tables without native bindings (reliable across Electron hosts).
 */
interface CacheFile {
  version: 1;
  packageHits: Record<
    string,
    { vulnIds: string[]; modifiedById: Record<string, string>; cachedAt: number }
  >;
  vulns: Record<string, { modified: string; json: string; cachedAt: number }>;
  npmMeta: Record<
    string,
    { latest: string; modified?: string; json: string; cachedAt: number }
  >;
  eol: Record<string, { json: string; cachedAt: number }>;
}

const EMPTY: CacheFile = {
  version: 1,
  packageHits: {},
  vulns: {},
  npmMeta: {},
  eol: {},
};

export class RiskCache {
  private data: CacheFile = structuredClone(EMPTY);
  private loaded = false;
  private dirty = false;
  private saveTimer: NodeJS.Timeout | undefined;
  private flushPromise: Promise<void> | undefined;

  constructor(private readonly cachePath: string) {}

  async init(): Promise<void> {
    if (this.loaded) {
      return;
    }
    try {
      await fs.mkdir(path.dirname(this.cachePath), { recursive: true });
      const raw = await fs.readFile(this.cachePath, "utf8");
      const parsed = JSON.parse(raw) as CacheFile;
      if (parsed?.version === 1) {
        this.data = parsed;
      }
    } catch {
      this.data = structuredClone(EMPTY);
    }
    this.loaded = true;
  }

  private scheduleSave(): void {
    this.dirty = true;
    if (this.saveTimer) {
      return;
    }
    this.saveTimer = setTimeout(() => {
      void this.flush();
    }, 500);
  }

  async flush(): Promise<void> {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = undefined;
    }
    if (this.flushPromise) {
      await this.flushPromise;
      if (this.dirty) {
        await this.flush();
      }
      return;
    }
    if (!this.dirty) {
      return;
    }

    const payload = JSON.stringify(this.data);
    this.dirty = false;
    this.flushPromise = this.writeAtomically(payload);
    try {
      await this.flushPromise;
    } catch (error) {
      this.dirty = true;
      throw error;
    } finally {
      this.flushPromise = undefined;
    }

    if (this.dirty) {
      await this.flush();
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

  getPackageHit(
    name: string,
    version: string,
    maxAgeMs = 24 * 60 * 60 * 1000
  ): { vulnIds: string[]; modifiedById: Record<string, string> } | undefined {
    const row = this.data.packageHits[`${name}@${version}`];
    if (!row || Date.now() - row.cachedAt > maxAgeMs) {
      return undefined;
    }
    return row;
  }

  setPackageHit(
    name: string,
    version: string,
    vulnIds: string[],
    modifiedById: Record<string, string>
  ): void {
    this.data.packageHits[`${name}@${version}`] = {
      vulnIds,
      modifiedById,
      cachedAt: Date.now(),
    };
    this.scheduleSave();
  }

  getVuln(id: string, modified?: string): unknown | undefined {
    const row = this.data.vulns[id];
    if (!row) {
      return undefined;
    }
    if (modified && row.modified && row.modified !== modified) {
      return undefined;
    }
    try {
      return JSON.parse(row.json);
    } catch {
      return undefined;
    }
  }

  setVuln(id: string, modified: string, payload: unknown): void {
    this.data.vulns[id] = {
      modified,
      json: JSON.stringify(payload),
      cachedAt: Date.now(),
    };
    this.scheduleSave();
  }

  getNpmMeta(name: string, maxAgeMs: number): { latest: string; modified?: string; raw: unknown } | undefined {
    const row = this.data.npmMeta[name];
    if (!row || Date.now() - row.cachedAt > maxAgeMs) {
      return undefined;
    }
    try {
      return { latest: row.latest, modified: row.modified, raw: JSON.parse(row.json) };
    } catch {
      return undefined;
    }
  }

  setNpmMeta(name: string, latest: string, modified: string | undefined, raw: unknown): void {
    this.data.npmMeta[name] = {
      latest,
      modified,
      json: JSON.stringify(raw),
      cachedAt: Date.now(),
    };
    this.scheduleSave();
  }

  getEol(key: string, maxAgeMs: number): unknown | undefined {
    const row = this.data.eol[key];
    if (!row || Date.now() - row.cachedAt > maxAgeMs) {
      return undefined;
    }
    try {
      return JSON.parse(row.json);
    } catch {
      return undefined;
    }
  }

  setEol(key: string, payload: unknown): void {
    this.data.eol[key] = { json: JSON.stringify(payload), cachedAt: Date.now() };
    this.scheduleSave();
  }
}
