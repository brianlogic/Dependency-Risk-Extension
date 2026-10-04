export type Ecosystem = "npm" | "pypi";

/** Ecosystem name as the OSV API spells it. */
export function osvEcosystem(ecosystem: Ecosystem): string {
  return ecosystem === "pypi" ? "PyPI" : "npm";
}

export type RiskTier = "critical" | "high" | "stale" | "eol" | "clear";

export interface PackageRef {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** True when listed in package.json, pyproject.toml, or a requirements file. */
  direct: boolean;
  /** True when workspace source appears to import/require this package. */
  imported: boolean;
}

export interface VulnSummary {
  id: string;
  aliases: string[];
  summary: string;
  details?: string;
  severity?: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";
  cvssScore?: number;
  /** Heuristic: database_specific / references mention exploit/PoC. */
  hasPublicExploit: boolean;
  /** Fixed versions inferred from OSV affected ranges for this package. */
  fixedVersions: string[];
  references: string[];
  /** Modified timestamp from OSV (for cache invalidation). */
  modified?: string;
}

export interface RuntimeEolInfo {
  product: string;
  current: string;
  eolDate?: string;
  monthsUntilEol?: number;
  alreadyEol: boolean;
}

export interface PackageSignals {
  pkg: PackageRef;
  vulns: VulnSummary[];
  latestVersion?: string;
  majorsBehind?: number;
  /** ISO date of last registry publish. */
  lastPublish?: string;
  monthsSincePublish?: number;
  runtimeEol?: RuntimeEolInfo;
}

export interface RiskResult {
  tier: RiskTier;
  reasons: string[];
  /** Prefer patch/minor that clears vulns; may be a major when unavoidable. */
  recommendedBump?: string;
  isMajorBump: boolean;
  changelogUrl?: string;
  advisoryIds: string[];
  advisoryUrls: string[];
  signals: PackageSignals;
}

export interface ScanSummary {
  scannedAt: number;
  packageCount: number;
  byTier: Record<RiskTier, number>;
  results: RiskResult[];
  errors: string[];
}

// Tiers from most to least severe; the order drives sorting and display.
export const TIER_ORDER: RiskTier[] = ["critical", "high", "stale", "eol", "clear"];

export const TIER_LABEL: Record<RiskTier, string> = {
  critical: "Critical",
  high: "High",
  stale: "Stale",
  eol: "EOL-adjacent",
  clear: "Clear",
};
