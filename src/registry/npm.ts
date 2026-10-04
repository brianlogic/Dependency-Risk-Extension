import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";
import {
  REGISTRY_META_TTL_MS,
  normalizeRepoUrl,
  registryChangelogUrl,
  type PackageRegistryMeta,
  type RegistryClient,
} from "./meta";

const REGISTRY = "https://registry.npmjs.org";

export type NpmPackageMeta = PackageRegistryMeta;

interface NpmRegistryResponse {
  "dist-tags"?: { latest?: string };
  time?: Record<string, string>;
  homepage?: string;
  repository?: { url?: string } | string;
}

function encodeNpmName(name: string): string {
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash === -1) {
      return encodeURIComponent(name);
    }
    return `${name.slice(0, slash)}%2F${encodeURIComponent(name.slice(slash + 1))}`;
  }
  return encodeURIComponent(name);
}

export class NpmRegistry implements RegistryClient {
  constructor(private readonly cache: RiskCache) {}

  async getMeta(name: string, opts?: { force?: boolean }): Promise<NpmPackageMeta | undefined> {
    const cached = opts?.force ? undefined : this.cache.getNpmMeta(name, REGISTRY_META_TTL_MS);
    if (cached) {
      const raw = cached.raw as NpmRegistryResponse;
      return {
        latest: cached.latest,
        lastPublish: raw.time?.[cached.latest],
        homepage: raw.homepage,
        repositoryUrl: normalizeRepoUrl(raw.repository),
      };
    }

    const raw = await fetchJson<NpmRegistryResponse>(`${REGISTRY}/${encodeNpmName(name)}`, {
      timeoutMs: 20_000,
    });

    const latest = raw["dist-tags"]?.latest;
    if (!latest) {
      return undefined;
    }
    const lastPublish = raw.time?.[latest];
    this.cache.setNpmMeta(name, latest, lastPublish, raw);
    return {
      latest,
      lastPublish,
      homepage: raw.homepage,
      repositoryUrl: normalizeRepoUrl(raw.repository),
    };
  }

  changelogUrl(name: string, meta?: NpmPackageMeta): string {
    return registryChangelogUrl(meta, `https://www.npmjs.com/package/${name}?activeTab=versions`);
  }
}
