import * as vscode from "vscode";
import { riskResourceUri, themeIcon } from "./decorations";
import { headline, packageGlance, packageTooltip, reasonIcon, usageLabel, worstTier } from "./presentation";
import { TIER_LABEL, TIER_ORDER, type RiskResult, type RiskTier, type ScanSummary } from "../types";

export type DepRiskTreeItem = SummaryItem | TierItem | PackageItem | ReasonItem | MessageItem;

export class MessageItem extends vscode.TreeItem {
  constructor(message: string, icon: string, tooltip?: string, tier?: RiskTier) {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "depRisk.message";
    this.iconPath = themeIcon(icon, tier);
    this.tooltip = tooltip;
  }
}

export class SummaryItem extends vscode.TreeItem {
  constructor(summary: ScanSummary) {
    super(headline(summary), vscode.TreeItemCollapsibleState.None);
    const tier = worstTier(summary);
    this.description = `${summary.packageCount} scanned`;
    this.iconPath = themeIcon("shield", tier);
    this.contextValue = "depRisk.summary";
    const tooltip = new vscode.MarkdownString(
      [
        `$(${tier === "clear" ? "pass" : "shield"}) **${headline(summary)}**`,
        `Scanned ${summary.packageCount} packages`,
        new Date(summary.scannedAt).toLocaleString(),
        summary.errors.length ? `\n$(warning) ${summary.errors.length} incomplete-scan warning(s)` : "",
      ]
        .filter(Boolean)
        .join("\n\n")
    );
    tooltip.supportThemeIcons = true;
    this.tooltip = tooltip;
  }
}

export class TierItem extends vscode.TreeItem {
  constructor(
    readonly tier: RiskTier,
    count: number
  ) {
    super(`${TIER_LABEL[tier]}`, vscode.TreeItemCollapsibleState.Expanded);
    this.description = `${count} package${count === 1 ? "" : "s"}`;
    this.contextValue = "depRisk.tier";
    this.iconPath = themeIcon(tier === "critical" ? "flame" : tier === "high" ? "warning" : tier === "stale" ? "history" : "calendar", tier);
    this.resourceUri = riskResourceUri("tier", tier, tier);
    const tooltip = new vscode.MarkdownString(
      `$(${tier === "critical" ? "flame" : tier === "high" ? "warning" : tier === "stale" ? "history" : "calendar"}) **${TIER_LABEL[tier]}** — ${count} package${count === 1 ? "" : "s"}`
    );
    tooltip.supportThemeIcons = true;
    this.tooltip = tooltip;
  }
}

export class PackageItem extends vscode.TreeItem {
  constructor(readonly risk: RiskResult) {
    const pkg = risk.signals.pkg;
    const target = risk.recommendedBump ? ` → ${risk.recommendedBump}` : "";
    super(`${pkg.name}  ${pkg.version}${target}`, vscode.TreeItemCollapsibleState.Collapsed);

    this.description = packageGlance(risk);
    const tooltip = new vscode.MarkdownString(packageTooltip(risk));
    tooltip.supportThemeIcons = true;
    tooltip.isTrusted = true;
    this.tooltip = tooltip;
    this.contextValue = risk.isMajorBump ? "depRisk.package.major" : "depRisk.package";
    this.iconPath = themeIcon(
      risk.signals.vulns[0]?.hasPublicExploit ? "flame" : risk.tier === "critical" ? "error" : risk.tier === "high" ? "warning" : risk.tier === "stale" ? "history" : "calendar",
      risk.tier
    );
    this.resourceUri = riskResourceUri("pkg", risk.tier, `${pkg.name}@${pkg.version}`);
    this.command = {
      command: "depRisk.openAdvisory",
      title: "Open Advisory",
      arguments: [this],
    };
    this.accessibilityInformation = {
      label: `${TIER_LABEL[risk.tier]} ${pkg.name} ${pkg.version}, ${usageLabel(risk)}`,
    };
  }
}

export class ReasonItem extends vscode.TreeItem {
  constructor(reason: string, tier?: RiskTier) {
    super(reason, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "depRisk.reason";
    this.iconPath = themeIcon(reasonIcon(reason), tier);
    this.tooltip = reason;
  }
}

export class DepRiskTreeProvider implements vscode.TreeDataProvider<DepRiskTreeItem> {
  private summary: ScanSummary | undefined;
  private readonly _onDidChange = new vscode.EventEmitter<DepRiskTreeItem | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  setSummary(summary: ScanSummary | undefined): void {
    this.summary = summary;
    this._onDidChange.fire();
  }

  getSummary(): ScanSummary | undefined {
    return this.summary;
  }

  getTreeItem(element: DepRiskTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: DepRiskTreeItem): DepRiskTreeItem[] {
    if (!this.summary) {
      return [new MessageItem("No scan yet — click Refresh", "info")];
    }

    if (!element) {
      const tiers = TIER_ORDER.filter((t) => t !== "clear" && (this.summary!.byTier[t] ?? 0) > 0);
      const items: DepRiskTreeItem[] = [new SummaryItem(this.summary)];
      if (this.summary.errors.length) {
        items.push(
          new MessageItem(
            `Scan incomplete (${this.summary.errors.length} source error${this.summary.errors.length === 1 ? "" : "s"})`,
            "warning",
            this.summary.errors.join("\n"),
            "high"
          )
        );
      }
      if (!tiers.length) {
        items.push(
          new MessageItem(
            this.summary.errors.length ? "No confirmed risks" : "No risks found",
            this.summary.errors.length ? "question" : "pass",
            undefined,
            this.summary.errors.length ? undefined : "clear"
          )
        );
        return items;
      }
      items.push(...tiers.map((t) => new TierItem(t, this.summary!.byTier[t])));
      return items;
    }

    if (element instanceof TierItem) {
      return this.summary.results
        .filter((r) => r.tier === element.tier)
        .map((r) => new PackageItem(r));
    }

    if (element instanceof PackageItem) {
      const items: DepRiskTreeItem[] = element.risk.reasons.map(
        (r) => new ReasonItem(r, element.risk.tier)
      );
      if (element.risk.recommendedBump) {
        items.push(
          new ReasonItem(
            `Safe target: ${element.risk.recommendedBump}${element.risk.isMajorBump ? " (major)" : ""}`,
            element.risk.tier
          )
        );
      }
      return items;
    }

    return [];
  }
}
