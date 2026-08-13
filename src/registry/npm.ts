import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";

const REGISTRY = "https://registry.npmjs.org";
const META_TTL_MS = 12 * 60 * 60 * 1000;

export interface NpmPackageMeta {
  latest: string;
  lastPublish?: string;
  homepage?: string;
  repositoryUrl?: string;
}

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

function normalizeRepoUrl(repo: NpmRegistryResponse["repository"]): string | undefined {
  if (!repo) {
    return undefined;
  }
  const url = typeof repo === "string" ? repo : repo.url;
  if (!url) {
    return undefined;
  }
  return url
    .replace(/^git\+/, "")
    .replace(/^ssh:\/\/git@/, "https://")
    .replace(/^git@github\.com:/, "https://github.com/")
    .replace(/\.git$/, "");
}

export class NpmRegistry {
  constructor(private readonly cache: RiskCache) {}

  async getMeta(name: string, opts?: { force?: boolean }): Promise<NpmPackageMeta | undefined> {
    const cached = opts?.force ? undefined : this.cache.getNpmMeta(name, META_TTL_MS);
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
    if (meta?.repositoryUrl && /github\.com|gitlab\.com/i.test(meta.repositoryUrl)) {
      return `${meta.repositoryUrl}/releases`;
    }
    if (meta?.homepage) {
      return meta.homepage;
    }
    if (meta?.repositoryUrl) {
      return meta.repositoryUrl;
    }
    return `https://www.npmjs.com/package/${name}?activeTab=versions`;
  }
}
