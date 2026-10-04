export interface PackageRegistryMeta {
  latest: string;
  lastPublish?: string;
  homepage?: string;
  repositoryUrl?: string;
}

export interface RegistryClient {
  getMeta(name: string, opts?: { force?: boolean }): Promise<PackageRegistryMeta | undefined>;
  changelogUrl(name: string, meta?: PackageRegistryMeta): string;
}

export const REGISTRY_META_TTL_MS = 12 * 60 * 60 * 1000;

export function normalizeRepoUrl(repo?: string | { url?: string }): string | undefined {
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

export function registryChangelogUrl(meta: PackageRegistryMeta | undefined, fallback: string): string {
  if (meta?.repositoryUrl && /github\.com|gitlab\.com/i.test(meta.repositoryUrl)) {
    return `${meta.repositoryUrl}/releases`;
  }
  if (meta?.homepage) {
    return meta.homepage;
  }
  if (meta?.repositoryUrl) {
    return meta.repositoryUrl;
  }
  return fallback;
}
