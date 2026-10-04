import { CVSS20, CVSS30, CVSS31, CVSS40 } from "@pandatix/js-cvss";
import { fetchJson, mapPool } from "../util/http";
import { packageVersionKey } from "../util/packageKey";
import { nextPatchAfter } from "../util/version";
import type { RiskCache } from "../cache/store";
import { osvEcosystem, type Ecosystem, type PackageRef, type VulnSummary } from "../types";

// OSV.dev API: querybatch returns only vuln ids per package; /vulns/{id} returns full records.
const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns";
// OSV accepts up to 1000 queries per querybatch request.
const BATCH_SIZE = 1000;

interface OsvBatchVulnRef {
  id: string;
  modified?: string;
}

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

interface OsvBatchResponse {
  results?: Array<{
    vulns?: OsvBatchVulnRef[];
    next_page_token?: string;
  }>;
}

interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: Array<{
    type?: string;
    events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
  }>;
  database_specific?: Record<string, unknown>;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  withdrawn?: string;
  severity?: Array<{ type?: string; score?: string }>;
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: Record<string, unknown>;
  affected?: OsvAffected[];
}

/** Splits `arr` into groups of at most `size`. */
function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    out.push(arr.slice(i, i + size));
  }
  return out;
}

/** Best-effort numeric CVSS score from OSV severity entries or database_specific, if any. */
export function parseCvssScore(vuln: Pick<OsvVuln, "severity" | "database_specific">): number | undefined {
  for (const s of vuln.severity ?? []) {
    if (!s.score) {
      continue;
    }

    const numeric = Number(s.score);
    if (Number.isFinite(numeric)) {
      return numeric;
    }

    try {
      if (s.score.startsWith("CVSS:4.0/")) {
        return new CVSS40(s.score).Score();
      }
      if (s.score.startsWith("CVSS:3.1/")) {
        return new CVSS31(s.score).BaseScore();
      }
      if (s.score.startsWith("CVSS:3.0/")) {
        return new CVSS30(s.score).BaseScore();
      }
      if (s.score.startsWith("CVSS:2.0/")) {
        return new CVSS20(s.score).BaseScore();
      }
      if (s.type === "CVSS_V2") {
        return new CVSS20(s.score).BaseScore();
      }
    } catch {
      // Malformed third-party vectors should not abort the entire inventory scan.
    }
  }
  const db = vuln.database_specific ?? {};
  if (typeof db.cvss === "object" && db.cvss && "score" in (db.cvss as object)) {
    const score = Number((db.cvss as { score?: number }).score);
    if (!Number.isNaN(score)) {
      return score;
    }
  }
  return undefined;
}

/** Prefers the database's own label; otherwise maps CVSS to the standard bands (9/7/4). */
function severityFromScore(
  score: number | undefined,
  dbSeverity?: unknown
): VulnSummary["severity"] {
  const label = String(dbSeverity ?? "").toUpperCase();
  if (label === "CRITICAL" || label === "HIGH" || label === "MODERATE" || label === "LOW") {
    return label;
  }
  if (score == null) {
    return "UNKNOWN";
  }
  if (score >= 9) {
    return "CRITICAL";
  }
  if (score >= 7) {
    return "HIGH";
  }
  if (score >= 4) {
    return "MODERATE";
  }
  return "LOW";
}

/** Heuristic text match for a public exploit; explicit "no exploit" phrases veto it. */
export function detectPublicExploit(vuln: Pick<OsvVuln, "details" | "references" | "database_specific">): boolean {
  const blob = `${vuln.details ?? ""} ${JSON.stringify(vuln.database_specific ?? {})}`.toLowerCase();
  if (
    blob.includes("no known exploit") ||
    blob.includes("no public exploit") ||
    blob.includes("not exploited") ||
    blob.includes("no exploit in the wild")
  ) {
    return false;
  }

  const exploitReference = (vuln.references ?? []).some((reference) => {
    const url = String(reference.url ?? "").toLowerCase();
    return (
      url.includes("exploit-db.com") ||
      url.includes("metasploit") ||
      url.includes("packetstormsecurity.com")
    );
  });

  return (
    exploitReference ||
    blob.includes("known exploited") ||
    blob.includes("actively exploited") ||
    blob.includes("public exploit") ||
    blob.includes("proof of concept") ||
    blob.includes("proof-of-concept") ||
    blob.includes("weaponized")
  );
}

/**
 * Versions that fix this advisory for the given package only (an advisory can cover several).
 * A `last_affected` boundary is turned into the next patch release.
 */
function fixedForPackage(vuln: OsvVuln, packageName: string, ecosystem: Ecosystem): string[] {
  const expected = osvEcosystem(ecosystem).toLowerCase();
  const fixed: string[] = [];
  for (const a of vuln.affected ?? []) {
    if (
      a.package?.ecosystem?.toLowerCase() !== expected ||
      a.package.name?.toLowerCase() !== packageName.toLowerCase()
    ) {
      continue;
    }
    for (const range of a.ranges ?? []) {
      if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") {
        continue;
      }
      for (const event of range.events ?? []) {
        if (event.fixed) {
          fixed.push(event.fixed);
          continue;
        }
        if (event.last_affected) {
          const next = nextPatchAfter(event.last_affected, ecosystem);
          if (next) {
            fixed.push(next);
          }
        }
      }
    }
  }
  return [...new Set(fixed)];
}

/** Flattens a raw OSV record into the VulnSummary the rest of the extension uses. */
export function toVulnSummary(
  raw: OsvVuln,
  packageName: string,
  ecosystem: Ecosystem = "npm"
): VulnSummary {
  const cvssScore = parseCvssScore(raw);
  const dbSev = raw.database_specific?.severity;
  return {
    id: raw.id,
    aliases: raw.aliases ?? [],
    summary: raw.summary || raw.details?.slice(0, 160) || raw.id,
    details: raw.details,
    severity: severityFromScore(cvssScore, dbSev),
    cvssScore,
    hasPublicExploit: detectPublicExploit(raw),
    fixedVersions: fixedForPackage(raw, packageName, ecosystem),
    references: (raw.references ?? []).map((r) => r.url).filter((u): u is string => !!u),
    modified: raw.modified,
  };
}

/** One ref per vuln id (later entries win). */
function dedupeVulnRefs(refs: OsvBatchVulnRef[]): OsvBatchVulnRef[] {
  const map = new Map<string, OsvBatchVulnRef>();
  for (const r of refs) {
    map.set(r.id, r);
  }
  return [...map.values()];
}

/** OSV.dev client with caching: per-package hits from cache, full records cached by id + modified time. */
export class OsvClient {
  private readonly inFlightVulns = new Map<string, Promise<OsvVuln>>();

  constructor(private readonly cache: RiskCache) {}

/**
 * Returns vuln refs keyed by packageVersionKey. Cached packages are skipped unless `force`;
 * the rest are sent in chunks and written back to the cache.
 */
  async queryBatch(
    packages: PackageRef[],
    opts?: { force?: boolean }
  ): Promise<Map<string, OsvBatchVulnRef[]>> {
    const result = new Map<string, OsvBatchVulnRef[]>();
    const toQuery: PackageRef[] = [];

    for (const pkg of packages) {
      const key = packageVersionKey(pkg);
      if (!opts?.force) {
        const hit = this.cache.getPackageHit(key);
        if (hit) {
          result.set(
            key,
            hit.vulnIds.map((id) => ({ id, modified: hit.modifiedById[id] }))
          );
          continue;
        }
      }
      toQuery.push(pkg);
    }

    for (const group of chunk(toQuery, BATCH_SIZE)) {
      const refsByIndex = await this.queryBatchWithPagination(group);
      group.forEach((pkg, i) => {
        const vulns = dedupeVulnRefs(refsByIndex[i] ?? []);
        const modifiedById: Record<string, string> = {};
        for (const v of vulns) {
          if (v.modified) {
            modifiedById[v.id] = v.modified;
          }
        }
        const key = packageVersionKey(pkg);
        this.cache.setPackageHit(key, vulns.map((v) => v.id), modifiedById);
        result.set(key, vulns);
      });
    }

    return result;
  }

/**
 * Runs one querybatch chunk, following `next_page_token` for packages with many advisories
 * (max 8 pages; throws if still unfinished). Result order matches `packages`.
 */
  private async queryBatchWithPagination(packages: PackageRef[]): Promise<OsvBatchVulnRef[][]> {
    const accumulated: OsvBatchVulnRef[][] = packages.map(() => []);
    let active: Array<{ index: number; query: OsvQuery }> = packages.map((p, index) => ({
      index,
      query: {
        package: { name: p.name, ecosystem: osvEcosystem(p.ecosystem) },
        version: p.version,
      },
    }));

    for (let page = 0; page < 8 && active.length; page++) {
      const body = await fetchJson<OsvBatchResponse>(OSV_BATCH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries: active.map((a) => a.query) }),
        timeoutMs: 60_000,
      });
      if (!Array.isArray(body.results) || body.results.length !== active.length) {
        throw new Error(
          `OSV querybatch returned ${body.results?.length ?? 0} results for ${active.length} queries`
        );
      }

      const nextActive: typeof active = [];
      active.forEach((a, j) => {
        const row = body.results?.[j];
        if (row?.vulns?.length) {
          accumulated[a.index].push(...row.vulns);
        }
        if (row?.next_page_token) {
          nextActive.push({
            index: a.index,
            query: { ...a.query, page_token: row.next_page_token },
          });
        }
      });
      active = nextActive;
    }

    if (active.length) {
      throw new Error(`OSV querybatch pagination exceeded 8 pages for ${active.length} package(s)`);
    }

    return accumulated;
  }

/**
 * Fetches full records for the given refs. The cache is keyed by id + modified, so updated
 * advisories refetch; concurrent requests for the same id are shared. Withdrawn ones are dropped.
 */
  async hydrateVulns(
    packageName: string,
    refs: OsvBatchVulnRef[],
    ecosystem: Ecosystem = "npm"
  ): Promise<VulnSummary[]> {
    const unique = dedupeVulnRefs(refs);
    const summaries = await mapPool(unique, 8, async (ref): Promise<VulnSummary | undefined> => {
      const cached = this.cache.getVuln(ref.id, ref.modified);
      if (cached) {
        const raw = cached as OsvVuln;
        return raw.withdrawn ? undefined : toVulnSummary(raw, packageName, ecosystem);
      }

      let request = this.inFlightVulns.get(ref.id);
      if (!request) {
        request = fetchJson<OsvVuln>(`${OSV_VULN}/${encodeURIComponent(ref.id)}`, {
          timeoutMs: 30_000,
        });
        this.inFlightVulns.set(ref.id, request);
      }

      let raw: OsvVuln;
      try {
        raw = await request;
        this.cache.setVuln(ref.id, raw.modified ?? ref.modified ?? "", raw);
      } finally {
        this.inFlightVulns.delete(ref.id);
      }
      return raw.withdrawn ? undefined : toVulnSummary(raw, packageName, ecosystem);
    });
    return summaries.filter((summary): summary is VulnSummary => summary !== undefined);
  }
}
