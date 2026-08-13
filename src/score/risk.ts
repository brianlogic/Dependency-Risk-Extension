import {
  isMajorBump,
  majorsBehind,
  monthsBetween,
  pickSafeBumpForAdvisories,
} from "../util/semver";
import type { DepRiskConfig } from "../config";
import type { PackageSignals, RiskResult, VulnSummary } from "../types";

function advisoryUrl(v: VulnSummary): string {
  const ghsa =
    v.aliases.find((a) => a.startsWith("GHSA-")) ??
    (v.id.startsWith("GHSA-") ? v.id : undefined);
  if (ghsa) {
    return `https://github.com/advisories/${ghsa}`;
  }
  return `https://osv.dev/vulnerability/${v.id}`;
}

function isCriticalVuln(v: VulnSummary): boolean {
  return v.hasPublicExploit || (v.cvssScore ?? 0) >= 9 || v.severity === "CRITICAL";
}

function isHighVuln(v: VulnSummary): boolean {
  if (v.severity === "HIGH") {
    return true;
  }
  const score = v.cvssScore ?? 0;
  return score >= 7 && score < 9;
}

function vulnerabilityRank(vulnerability: VulnSummary): number {
  if (vulnerability.hasPublicExploit) {
    return 100;
  }
  if (vulnerability.cvssScore != null) {
    return vulnerability.cvssScore * 10;
  }
  switch (vulnerability.severity) {
    case "CRITICAL":
      return 90;
    case "HIGH":
      return 70;
    case "MODERATE":
      return 40;
    case "LOW":
      return 10;
    default:
      return 0;
  }
}

function usageLabel(pkg: PackageSignals["pkg"]): string {
  if (pkg.imported) {
    return "imported in workspace";
  }
  if (pkg.direct) {
    return "direct dependency";
  }
  return "transitive-only";
}

/**
 * Tier priority: critical > high > stale > eol > clear.
 *
 * Critical: exploit / CVSS≥9 / CRITICAL label, OR high-severity vuln on an imported code path.
 * High: any remaining known advisory.
 * Stale: >N majors behind or maintainer inactive.
 * EOL: runtime/framework within horizon (attached as a synthetic package result by pipeline).
 */
export function scorePackage(
  signals: PackageSignals,
  cfg: DepRiskConfig,
  changelogUrl?: string
): RiskResult {
  const { pkg, vulns } = signals;
  const orderedVulns = [...vulns].sort(
    (a, b) => vulnerabilityRank(b) - vulnerabilityRank(a)
  );
  const advisoryIds = vulns.map((v) => v.id);
  const advisoryUrls = vulns.map(advisoryUrl);
  const recommendedBump = pickSafeBumpForAdvisories(
    pkg.version,
    vulns.map((v) => v.fixedVersions)
  );
  const major = recommendedBump ? isMajorBump(pkg.version, recommendedBump) : false;

  if (vulns.length > 0) {
    const criticalHits = orderedVulns.filter(isCriticalVuln);
    const highOnImported =
      pkg.imported && orderedVulns.some((v) => isCriticalVuln(v) || isHighVuln(v));

    if (criticalHits.length > 0 || highOnImported) {
      const top = criticalHits[0] ?? orderedVulns.find(isHighVuln) ?? orderedVulns[0];
      return {
        tier: "critical",
        reasons: [
          top.summary || `${top.id} affects ${pkg.name}@${pkg.version}`,
          top.hasPublicExploit ? "Public exploit references found" : undefined,
          top.cvssScore != null ? `CVSS ${top.cvssScore}` : top.severity,
          `Usage: ${usageLabel(pkg)}`,
        ].filter((x): x is string => !!x),
        recommendedBump,
        isMajorBump: major,
        changelogUrl,
        advisoryIds,
        advisoryUrls,
        signals,
      };
    }

    const top = orderedVulns[0];
    return {
      tier: "high",
      reasons: [
        top.summary || `${top.id} affects ${pkg.name}@${pkg.version}`,
        top.severity && top.severity !== "UNKNOWN" ? `Severity ${top.severity}` : undefined,
        `Usage: ${usageLabel(pkg)}`,
      ].filter((x): x is string => !!x),
      recommendedBump,
      isMajorBump: major,
      changelogUrl,
      advisoryIds,
      advisoryUrls,
      signals,
    };
  }

  const staleReasons: string[] = [];
  if ((signals.majorsBehind ?? 0) >= cfg.staleMajorVersionsBehind) {
    staleReasons.push(
      `${signals.majorsBehind} major versions behind (latest ${signals.latestVersion})`
    );
  }
  if (
    signals.monthsSincePublish != null &&
    signals.monthsSincePublish >= cfg.maintainerInactiveMonths
  ) {
    staleReasons.push(
      `No npm publish in ~${Math.floor(signals.monthsSincePublish)} months`
    );
  }
  if (staleReasons.length) {
    return {
      tier: "stale",
      reasons: staleReasons,
      recommendedBump: signals.latestVersion,
      isMajorBump: signals.latestVersion
        ? isMajorBump(pkg.version, signals.latestVersion)
        : false,
      changelogUrl,
      advisoryIds: [],
      advisoryUrls: [],
      signals,
    };
  }

  return {
    tier: "clear",
    reasons: [],
    isMajorBump: false,
    advisoryIds: [],
    advisoryUrls: [],
    signals,
  };
}

export function scoreRuntimeEol(
  eol: NonNullable<PackageSignals["runtimeEol"]>,
  cfg: DepRiskConfig
): RiskResult | undefined {
  if (
    !eol.alreadyEol &&
    (eol.monthsUntilEol == null || eol.monthsUntilEol > cfg.eolHorizonMonths)
  ) {
    return undefined;
  }

  const synthetic: PackageSignals = {
    pkg: {
      name: eol.product,
      version: eol.current,
      ecosystem: "npm",
      direct: true,
      imported: true,
      usage: "direct",
    },
    vulns: [],
    runtimeEol: eol,
  };

  return {
    tier: "eol",
    reasons: [
      eol.alreadyEol
        ? `${eol.product} ${eol.current} is past end-of-life`
        : `${eol.product} ${eol.current} EOL in ~${Math.max(0, Math.round(eol.monthsUntilEol ?? 0))} mo` +
          (eol.eolDate ? ` (${eol.eolDate})` : ""),
    ],
    recommendedBump: undefined,
    isMajorBump: false,
    changelogUrl: `https://endoflife.date/${eol.product}`,
    advisoryIds: [],
    advisoryUrls: [],
    signals: synthetic,
  };
}

export function attachRegistrySignals(
  signals: PackageSignals,
  latest: string | undefined,
  lastPublish: string | undefined
): PackageSignals {
  const next = { ...signals };
  if (latest) {
    next.latestVersion = latest;
    next.majorsBehind = majorsBehind(signals.pkg.version, latest);
  }
  if (lastPublish) {
    next.lastPublish = lastPublish;
    next.monthsSincePublish = monthsBetween(lastPublish);
  }
  return next;
}
