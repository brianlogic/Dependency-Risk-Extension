import * as vscode from "vscode";
import { TIER_BADGE, TIER_THEME_COLOR } from "./presentation";
import { TIER_LABEL, type RiskTier } from "../types";

export const DEPRISK_SCHEME = "deprisk";

export function riskResourceUri(kind: "tier" | "pkg", tier: RiskTier, id: string): vscode.Uri {
  return vscode.Uri.from({
    scheme: DEPRISK_SCHEME,
    path: `/${kind}/${tier}/${encodeURIComponent(id)}`,
  });
}

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

export function themeIcon(id: string, tier?: RiskTier): vscode.ThemeIcon {
  if (!tier) {
    return new vscode.ThemeIcon(id);
  }
  return new vscode.ThemeIcon(id, new vscode.ThemeColor(TIER_THEME_COLOR[tier]));
}
