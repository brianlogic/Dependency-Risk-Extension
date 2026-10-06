// Small helpers shared by the webviews. All dynamic text must go through escapeHtml/escapeAttr.
import type { RiskTier } from "../types";

/** CSS class/variable suffix for a tier (`critical` is shortened to `crit`). */
export function cssVar(tier: RiskTier): string {
  return tier === "critical" ? "crit" : tier;
}

/** Escapes text for HTML content. */
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

/** Escapes text for an HTML attribute value (same set as escapeHtml; quotes are covered). */
export function escapeAttr(value: string): string {
  return escapeHtml(value);
}
