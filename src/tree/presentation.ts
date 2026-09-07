import type { RiskResult, RiskTier, ScanSummary } from "../types";

export const TIER_THEME_COLOR: Record<RiskTier, string> = {
  critical: "charts.red",
  high: "charts.orange",
  stale: "charts.yellow",
  eol: "charts.blue",
  clear: "charts.green",
};

export const TIER_BADGE: Record<RiskTier, string> = {
  critical: "C",
  high: "H",
  stale: "S",
  eol: "E",
  clear: "ok",
};

export const TIER_ICON_ID: Record<RiskTier, string> = {
  critical: "flame",
  high: "warning",
  stale: "history",
  eol: "calendar",
  clear: "pass",
};

export function worstTier(summary: ScanSummary): RiskTier {
  if (summary.byTier.critical) {
    return "critical";
  }
  if (summary.byTier.high) {
    return "high";
  }
  if (summary.byTier.stale) {
    return "stale";
  }
  if (summary.byTier.eol) {
    return "eol";
  }
  return "clear";
}

export function usageLabel(risk: RiskResult): string {
  const pkg = risk.signals.pkg;
  if (pkg.name === risk.signals.runtimeEol?.product) {
    return "runtime";
  }
  if (pkg.imported) {
    return "imported";
  }
  if (pkg.direct) {
    return "direct";
  }
  return "transitive";
}

export function packageGlance(risk: RiskResult): string {
  const parts = [
    risk.signals.pkg.ecosystem === "pypi" ? "PyPI" : undefined,
    usageLabel(risk),
  ].filter((part): part is string => !!part);
  const top = risk.signals.vulns[0];
  if (top?.cvssScore != null) {
    parts.push(`CVSS ${top.cvssScore}`);
  } else if (risk.signals.majorsBehind) {
    parts.push(`${risk.signals.majorsBehind} majors behind`);
  } else if (risk.signals.monthsSincePublish != null) {
    parts.push(`${Math.floor(risk.signals.monthsSincePublish)} mo stale`);
  } else if (risk.signals.runtimeEol?.alreadyEol) {
    parts.push("past EOL");
  } else if (risk.signals.runtimeEol?.monthsUntilEol != null) {
    parts.push(`EOL in ${Math.round(risk.signals.runtimeEol.monthsUntilEol)} mo`);
  }
  if (top?.hasPublicExploit) {
    parts.push("exploit");
  }
  return parts.join(" · ");
}

export function packageTooltip(risk: RiskResult): string {
  const pkg = risk.signals.pkg;
  const top = risk.signals.vulns[0];
  const lines = [
    `$(${TIER_ICON_ID[risk.tier]}) **${tierHeadline(risk.tier)}** \`${pkg.name}@${pkg.version}\``,
  ];
  if (risk.recommendedBump) {
    lines.push(
      `\n**Fix** → \`${risk.recommendedBump}\`${risk.isMajorBump ? "  $(alert) major" : ""}`
    );
  }
  lines.push(`\n${packageGlance(risk)}`);
  if (top?.summary) {
    lines.push(`\n${top.summary}`);
  }
  if (risk.reasons.length) {
    lines.push("", ...risk.reasons.map((reason) => `- ${reason}`));
  }
  if (risk.advisoryIds.length) {
    lines.push(`\nAdvisories: ${risk.advisoryIds.join(", ")}`);
  }
  return lines.filter((line) => line !== undefined).join("\n");
}

export function headline(summary: ScanSummary): string {
  const parts: string[] = [];
  if (summary.byTier.critical) {
    parts.push(`${summary.byTier.critical} critical`);
  }
  if (summary.byTier.high) {
    parts.push(`${summary.byTier.high} high`);
  }
  if (summary.byTier.stale) {
    parts.push(`${summary.byTier.stale} stale`);
  }
  if (summary.byTier.eol) {
    parts.push(`${summary.byTier.eol} EOL`);
  }
  return parts.join("  ·  ") || "All clear";
}

export function reasonIcon(reason: string): string {
  const text = reason.toLowerCase();
  if (text.includes("exploit")) {
    return "flame";
  }
  if (text.includes("cvss") || text.includes("advisory") || text.startsWith("ghsa-") || text.startsWith("cve-")) {
    return "link";
  }
  if (text.includes("usage") || text.includes("imported") || text.includes("direct")) {
    return "code";
  }
  if (text.includes("safe target") || text.includes("fix") || text.includes("→")) {
    return "arrow-up";
  }
  if (text.includes("eol")) {
    return "calendar";
  }
  if (text.includes("major") || text.includes("publish") || text.includes("stale")) {
    return "history";
  }
  return "info";
}

function tierHeadline(tier: RiskTier): string {
  switch (tier) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "stale":
      return "Stale";
    case "eol":
      return "EOL-adjacent";
    default:
      return "Clear";
  }
}
