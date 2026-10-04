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

// npm registry client. Metadata comes from the full packument; only the fields we use are cached.
const REGISTRY = "https://registry.npmjs.org";

export type NpmPackageMeta = PackageRegistryMeta;

interface NpmRegistryResponse {
  "dist-tags"?: { latest?: string };
  time?: Record<string, string>;
  homepage?: string;
  repository?: { url?: string } | string;
}

/** Scoped names keep the `@scope` and encode the slash (`@a/b` -> `@a%2Fb`), as the registry expects. */
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

/** `latest` dist-tag and its publish time from the npm registry. */
export class NpmRegistry implements RegistryClient {
  constructor(private readonly cache: RiskCache) {}

  async getMeta(name: string, opts?: { force?: boolean }): Promise<NpmPackageMeta | undefined> {
    const key = packageNameKey({ ecosystem: "npm", name });
    const cached = opts?.force ? undefined : this.cache.getMeta(key, REGISTRY_META_TTL_MS);
    if (cached) {
      return cached;
    }

    const raw = await fetchJson<NpmRegistryResponse>(`${REGISTRY}/${encodeNpmName(name)}`, {
      timeoutMs: 20_000,
    });
    const latest = raw["dist-tags"]?.latest;
    if (!latest) {
      return undefined;
    }
    const meta: NpmPackageMeta = {
      latest,
      lastPublish: raw.time?.[latest],
      homepage: raw.homepage,
      repositoryUrl: normalizeRepoUrl(raw.repository),
    };
    this.cache.setMeta(key, meta);
    return meta;
  }

  changelogUrl(name: string, meta?: NpmPackageMeta): string {
    return registryChangelogUrl(meta, `https://www.npmjs.com/package/${name}?activeTab=versions`);
  }
}
