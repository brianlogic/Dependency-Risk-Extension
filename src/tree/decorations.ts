// Colored letter badges on tier/package rows, via a `deprisk:` URI scheme the tree items use as resourceUri.
import * as vscode from "vscode";
import { TIER_BADGE, TIER_THEME_COLOR } from "./presentation";
import { TIER_LABEL, type RiskTier } from "../types";

export const DEPRISK_SCHEME = "deprisk";

/** URI encoding the tier so provideFileDecoration can pick badge and color. */
export function riskResourceUri(kind: "tier" | "pkg", tier: RiskTier, id: string): vscode.Uri {
  return vscode.Uri.from({
    scheme: DEPRISK_SCHEME,
    path: `/${kind}/${tier}/${encodeURIComponent(id)}`,
  });
}

/** Supplies the badge for `deprisk:` URIs; `refresh` re-evaluates all of them after a scan. */
export class DepRiskDecorationProvider implements vscode.FileDecorationProvider {
  private readonly _onDidChange = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
  readonly onDidChangeFileDecorations = this._onDidChange.event;

  refresh(): void {
    this._onDidChange.fire(undefined);
  }

  provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
    if (uri.scheme !== DEPRISK_SCHEME) {
      return undefined;
    }
    const tier = uri.path.split("/")[2] as RiskTier | undefined;
    if (!tier || !TIER_THEME_COLOR[tier]) {
      return undefined;
    }
    const decoration = new vscode.FileDecoration(
      TIER_BADGE[tier],
      TIER_LABEL[tier],
      new vscode.ThemeColor(TIER_THEME_COLOR[tier])
    );
    decoration.propagate = false;
    return decoration;
  }
}

/** Codicon, tinted with the tier color when a tier is given. */
export function themeIcon(id: string, tier?: RiskTier): vscode.ThemeIcon {
  if (!tier) {
    return new vscode.ThemeIcon(id);
  }
  return new vscode.ThemeIcon(id, new vscode.ThemeColor(TIER_THEME_COLOR[tier]));
}
