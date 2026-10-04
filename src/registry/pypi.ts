import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";
import {
  REGISTRY_META_TTL_MS,
  normalizeRepoUrl,
  registryChangelogUrl,
  type PackageRegistryMeta,
  type RegistryClient,
} from "./meta";

// PyPI JSON API client. Metadata comes from /pypi/{name}/json; the raw response is cached.
const REGISTRY = "https://pypi.org/pypi";

export type PypiPackageMeta = PackageRegistryMeta;

interface PypiResponse {
  info?: {
    version?: string;
    home_page?: string;
    project_urls?: Record<string, string>;
  };
  releases?: Record<string, Array<{ upload_time_iso_8601?: string; upload_time?: string }>>;
}

/** Latest version and upload time from PyPI. */
export class PypiRegistry implements RegistryClient {
  constructor(private readonly cache: RiskCache) {}

  async getMeta(name: string, opts?: { force?: boolean }): Promise<PypiPackageMeta | undefined> {
    const cached = opts?.force ? undefined : this.cache.getPypiMeta(name, REGISTRY_META_TTL_MS);
    if (cached) {
      return fromCached(cached.latest, cached.raw as PypiResponse);
    }

    const raw = await fetchJson<PypiResponse>(`${REGISTRY}/${encodeURIComponent(name)}/json`, {
      timeoutMs: 20_000,
    });
    const latest = raw.info?.version;
    if (!latest) {
      return undefined;
    }
    const lastPublish = uploadTime(raw, latest);
    this.cache.setPypiMeta(name, latest, lastPublish, raw);
    return fromCached(latest, raw);
  }

  changelogUrl(name: string, meta?: PypiPackageMeta): string {
    return registryChangelogUrl(meta, `https://pypi.org/project/${name}/`);
  }
}

/** Builds metadata from a raw response; the repository URL is guessed from project_urls in priority order. */
function fromCached(latest: string, raw: PypiResponse): PypiPackageMeta {
  const urls = raw.info?.project_urls ?? {};
  const repositoryUrl =
    firstUrl(urls, ["Source", "Repository", "Homepage", "Home", "Code"]) ??
    normalizeRepoUrl(raw.info?.home_page);
  return {
    latest,
    lastPublish: uploadTime(raw, latest),
    homepage: raw.info?.home_page || urls.Homepage || urls.Home,
    repositoryUrl,
  };
}

/** Upload time of the first file of `version` (any file is fine; they upload together). */
function uploadTime(raw: PypiResponse, version: string): string | undefined {
  const files = raw.releases?.[version] ?? [];
  return files.find((file) => file.upload_time_iso_8601)?.upload_time_iso_8601 ?? files[0]?.upload_time;
}

/** First project URL whose label matches one of `keys` (case-insensitive), normalized. */
function firstUrl(urls: Record<string, string>, keys: string[]): string | undefined {
  for (const key of keys) {
    const match = Object.entries(urls).find(([name]) => name.toLowerCase() === key.toLowerCase());
    if (match?.[1]) {
      return normalizeRepoUrl(match[1]);
    }
  }
  return undefined;
}
