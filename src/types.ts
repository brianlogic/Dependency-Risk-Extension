export type Ecosystem = "npm";

export type RiskTier = "critical" | "high" | "stale" | "eol" | "clear";

export type UsageKind = "direct" | "transitive";

export interface PackageRef {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** True when listed in package.json dependencies/devDependencies/optional/peer. */
  direct: boolean;
  /** True when workspace source appears to import/require this package. */
  imported: boolean;
  usage: UsageKind;
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
  /** ISO date of last npm publish (time.modified). */
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

export interface ScanProgress {
  phase: string;
  detail?: string;
}

export interface ScanSummary {
  scannedAt: number;
  packageCount: number;
  byTier: Record<RiskTier, number>;
  results: RiskResult[];
  errors: string[];
}

export const TIER_ORDER: RiskTier[] = ["critical", "high", "stale", "eol", "clear"];

export const TIER_LABEL: Record<RiskTier, string> = {
  critical: "Critical",
  high: "High",
  stale: "Stale",
  eol: "EOL-adjacent",
  clear: "Clear",
};

export const TIER_ICON: Record<RiskTier, string> = {
  critical: "flame",
  high: "warning",
  stale: "history",
  eol: "calendar",
  clear: "pass",
};
