import * as vscode from "vscode";
import { TIER_ICON, TIER_LABEL, TIER_ORDER, type RiskResult, type RiskTier, type ScanSummary } from "../types";

export type DepRiskTreeItem = TierItem | PackageItem | ReasonItem | MessageItem;

export class MessageItem extends vscode.TreeItem {
  constructor(message: string, icon: string, tooltip?: string) {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "depRisk.message";
    this.iconPath = new vscode.ThemeIcon(icon);
    this.tooltip = tooltip;
  }
}

export class TierItem extends vscode.TreeItem {
  constructor(
    readonly tier: RiskTier,
    count: number
  ) {
    super(`${TIER_LABEL[tier]} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = "depRisk.tier";
    this.iconPath = new vscode.ThemeIcon(TIER_ICON[tier]);
  }
}

export class PackageItem extends vscode.TreeItem {
  constructor(readonly risk: RiskResult) {
    const pkg = risk.signals.pkg;
    const target = risk.recommendedBump ? ` → ${risk.recommendedBump}` : "";
    super(`${pkg.name}  ${pkg.version}${target}`, vscode.TreeItemCollapsibleState.Collapsed);

    const usage =
      pkg.name === risk.signals.runtimeEol?.product
        ? "runtime"
        : pkg.imported
          ? "imported"
          : pkg.direct
            ? "direct"
            : "transitive";

    this.description = usage;
    this.tooltip = new vscode.MarkdownString(
      [
        `**${pkg.name}@${pkg.version}**`,
        risk.recommendedBump ? `Recommended: \`${risk.recommendedBump}\`${risk.isMajorBump ? " (major)" : ""}` : "",
        "",
        ...risk.reasons.map((r) => `- ${r}`),
        risk.advisoryIds.length ? `\nAdvisories: ${risk.advisoryIds.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join("\n")
    );
    this.contextValue = risk.isMajorBump ? "depRisk.package.major" : "depRisk.package";
    this.iconPath = new vscode.ThemeIcon(TIER_ICON[risk.tier]);
    this.command = {
      command: "depRisk.openAdvisory",
      title: "Open Advisory",
      arguments: [this],
    };
  }
}

export class ReasonItem extends vscode.TreeItem {
  constructor(reason: string) {
    super(reason, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "depRisk.reason";
    this.iconPath = new vscode.ThemeIcon("info");
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
      const items: DepRiskTreeItem[] = [];
      if (this.summary.errors.length) {
        items.push(
          new MessageItem(
            `Scan incomplete (${this.summary.errors.length} source error${this.summary.errors.length === 1 ? "" : "s"})`,
            "warning",
            this.summary.errors.join("\n")
          )
        );
      }
      if (!tiers.length) {
        items.push(
          new MessageItem(
            this.summary.errors.length ? "No confirmed risks" : "No risks found",
            this.summary.errors.length ? "question" : "check"
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
      const items: DepRiskTreeItem[] = element.risk.reasons.map((r) => new ReasonItem(r));
      if (element.risk.recommendedBump) {
        items.push(
          new ReasonItem(
            `Safe target: ${element.risk.recommendedBump}${element.risk.isMajorBump ? " (major)" : ""}`
          )
        );
      }
      return items;
    }

    return [];
  }
}
