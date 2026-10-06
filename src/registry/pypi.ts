import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";
import { packageNameKey } from "../util/packageKey";
import {
  REGISTRY_META_TTL_MS,
  normalizeRepoUrl,
  registryChangelogUrl,
  type PackageRegistryMeta,
  type RegistryClient,
} from "./meta";

// PyPI JSON API client. Metadata comes from /pypi/{name}/json; only the fields we use are cached.
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
    const key = packageNameKey({ ecosystem: "pypi", name });
    const cached = opts?.force ? undefined : this.cache.getMeta(key, REGISTRY_META_TTL_MS);
    if (cached) {
      return cached;
    }

    const raw = await fetchJson<PypiResponse>(`${REGISTRY}/${encodeURIComponent(name)}/json`, {
      timeoutMs: 20_000,
    });
    const latest = raw.info?.version;
    if (!latest) {
      return undefined;
    }
    const meta = toMeta(latest, raw);
    this.cache.setMeta(key, meta);
    return meta;
  }

  changelogUrl(name: string, meta?: PypiPackageMeta): string {
    return registryChangelogUrl(meta, `https://pypi.org/project/${name}/`);
  }
}

/** Reduces a raw response to the fields we keep; the repository URL is guessed from project_urls in priority order. */
function toMeta(latest: string, raw: PypiResponse): PypiPackageMeta {
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
