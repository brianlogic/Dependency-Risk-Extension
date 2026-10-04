import type { RiskTier } from "../types";

export function cssVar(tier: RiskTier): string {
  return tier === "critical" ? "crit" : tier;
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

export function escapeAttr(value: string): string {
  return escapeHtml(value);
}
