/**
 * Turns package signals into one tier. Vulnerabilities outrank staleness, so a
 * package with an advisory is never also marked stale.
 *
 * Critical: a public exploit, CVSS >= 9, or a CRITICAL label. A high-severity
 * advisory on a package the workspace imports is also critical, because that
 * code is on a path the project loads. Other advisories are high.
 * Stale: no advisories, and either several majors behind latest or no publish
 * inside the inactivity window. The recommended bump for a stale package is latest.
 * Clear: none of the above. The pipeline omits these from the result list.
 *
 * `recommendedBump` is the smallest version that clears every advisory,
 * preferring a fix that stays on the current major. It is absent when any
 * advisory has no published fix newer than the installed version; callers
 * must not invent a target in that case.
 * EOL is not scored here. `scoreRuntimeEol` builds a synthetic result for the
 * pinned Node or Python runtime.
 */
import { advisoryUrl } from "../osv/urls";
import { monthsBetween } from "../util/semver";
import { isMajorBump, majorsBehind, pickSafeBumpForAdvisories } from "../util/version";
import type { DepRiskConfig } from "../config";
import type { PackageSignals, RiskResult, VulnSummary } from "../types";

/** Exploit, CVSS >= 9, or an explicit CRITICAL label. A HIGH label with a lower score is not critical. */
function isCriticalVuln(v: VulnSummary): boolean {
  return v.hasPublicExploit || (v.cvssScore ?? 0) >= 9 || v.severity === "CRITICAL";
}

/** HIGH label, whatever the score. With no label, a score in [7, 9); 9 and above is critical. */
function isHighVuln(v: VulnSummary): boolean {
  if (v.severity === "HIGH") {
    return true;
  }
  const score = v.cvssScore ?? 0;
  return score >= 7 && score < 9;
}

/** Sort weight so the most dangerous advisory is listed first (public exploit > CVSS > label). */
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

/** Shared fields of an advisory result; only the tier and the reason lines differ. */
function advisoryResult(
  tier: "critical" | "high",
  reasons: Array<string | undefined>,
  shared: Pick<
    RiskResult,
    "recommendedBump" | "isMajorBump" | "changelogUrl" | "advisoryIds" | "advisoryUrls" | "signals"
  >
): RiskResult {
  return {
    tier,
    reasons: reasons.filter((reason): reason is string => !!reason),
    ...shared,
  };
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
 * Picks the single tier for one package. Reasons lead with the worst advisory.
 * A high-or-worse advisory on an imported package is raised to critical; the
 * same advisory on a direct or transitive package stays high.
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
    vulns.map((v) => v.fixedVersions),
    pkg.ecosystem
  );
  const major = recommendedBump ? isMajorBump(pkg.version, recommendedBump, pkg.ecosystem) : false;
  const shared = { recommendedBump, isMajorBump: major, changelogUrl, advisoryIds, advisoryUrls, signals };

  if (vulns.length > 0) {
    const criticalHits = orderedVulns.filter(isCriticalVuln);
    const highOnImported =
      pkg.imported && orderedVulns.some((v) => isCriticalVuln(v) || isHighVuln(v));

    if (criticalHits.length > 0 || highOnImported) {
      const top = criticalHits[0] ?? orderedVulns.find(isHighVuln) ?? orderedVulns[0];
      return advisoryResult(
        "critical",
        [
          top.summary || `${top.id} affects ${pkg.name}@${pkg.version}`,
          top.hasPublicExploit ? "Public exploit references found" : undefined,
          top.cvssScore != null ? `CVSS ${top.cvssScore}` : top.severity,
          `Usage: ${usageLabel(pkg)}`,
        ],
        shared
      );
    }

    const top = orderedVulns[0];
    return advisoryResult(
      "high",
      [
        top.summary || `${top.id} affects ${pkg.name}@${pkg.version}`,
        top.severity && top.severity !== "UNKNOWN" ? `Severity ${top.severity}` : undefined,
        `Usage: ${usageLabel(pkg)}`,
      ],
      shared
    );
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
      `No ${pkg.ecosystem === "pypi" ? "PyPI" : "npm"} publish in ~${Math.floor(signals.monthsSincePublish)} months`
    );
  }
  if (staleReasons.length) {
    return {
      tier: "stale",
      reasons: staleReasons,
      recommendedBump: signals.latestVersion,
      isMajorBump: signals.latestVersion
        ? isMajorBump(pkg.version, signals.latestVersion, pkg.ecosystem)
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

/**
 * EOL is not a package. The synthetic ref lets the tree and the sort treat the
 * runtime like a direct, imported dependency. `recommendedBump` stays empty:
 * the fix is a runtime upgrade, and the changelog link points at endoflife.date.
 * Returns undefined while the pin is supported for longer than `eolHorizonMonths`.
 */
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
      ecosystem: eol.product === "python" ? "pypi" : "npm",
      direct: true,
      imported: true,
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

/**
 * Copies `signals` and fills latest version, majors behind, and months since
 * the last publish. Either input may be missing; a version pair that cannot
 * be compared leaves `majorsBehind` unset, so the package is not called stale.
 */
export function attachRegistrySignals(
  signals: PackageSignals,
  latest: string | undefined,
  lastPublish: string | undefined
): PackageSignals {
  const next = { ...signals };
  if (latest) {
    next.latestVersion = latest;
    next.majorsBehind = majorsBehind(signals.pkg.version, latest, signals.pkg.ecosystem);
  }
  if (lastPublish) {
    next.lastPublish = lastPublish;
    next.monthsSincePublish = monthsBetween(lastPublish);
  }
  return next;
}
