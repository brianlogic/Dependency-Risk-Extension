import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";

const REGISTRY = "https://pypi.org/pypi";
const META_TTL_MS = 12 * 60 * 60 * 1000;

export interface PypiPackageMeta {
  latest: string;
  lastPublish?: string;
  homepage?: string;
  repositoryUrl?: string;
}

interface PypiResponse {
  info?: {
    version?: string;
    home_page?: string;
    project_urls?: Record<string, string>;
  };
  releases?: Record<string, Array<{ upload_time_iso_8601?: string; upload_time?: string }>>;
}

export class PypiRegistry {
  constructor(private readonly cache: RiskCache) {}

  async getMeta(name: string, opts?: { force?: boolean }): Promise<PypiPackageMeta | undefined> {
    const cached = opts?.force ? undefined : this.cache.getPypiMeta(name, META_TTL_MS);
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
    if (meta?.repositoryUrl && /github\.com|gitlab\.com/i.test(meta.repositoryUrl)) {
      return `${meta.repositoryUrl}/releases`;
    }
    if (meta?.homepage) {
      return meta.homepage;
    }
    if (meta?.repositoryUrl) {
      return meta.repositoryUrl;
    }
    return `https://pypi.org/project/${name}/`;
  }
}

function fromCached(latest: string, raw: PypiResponse): PypiPackageMeta {
  const urls = raw.info?.project_urls ?? {};
  const repositoryUrl =
    firstUrl(urls, ["Source", "Repository", "Homepage", "Home", "Code"]) ??
    normalizeRepo(raw.info?.home_page);
  return {
    latest,
    lastPublish: uploadTime(raw, latest),
    homepage: raw.info?.home_page || urls.Homepage || urls.Home,
    repositoryUrl,
  };
}

function uploadTime(raw: PypiResponse, version: string): string | undefined {
  const files = raw.releases?.[version] ?? [];
  return files.find((file) => file.upload_time_iso_8601)?.upload_time_iso_8601 ?? files[0]?.upload_time;
}

function firstUrl(urls: Record<string, string>, keys: string[]): string | undefined {
  for (const key of keys) {
    const match = Object.entries(urls).find(([name]) => name.toLowerCase() === key.toLowerCase());
    if (match?.[1]) {
      return normalizeRepo(match[1]);
    }
  }
  return undefined;
}

function normalizeRepo(url?: string): string | undefined {
  if (!url) {
    return undefined;
  }
  return url
    .replace(/^git\+/, "")
    .replace(/^ssh:\/\/git@/, "https://")
    .replace(/^git@github\.com:/, "https://github.com/")
    .replace(/\.git$/, "");
}
