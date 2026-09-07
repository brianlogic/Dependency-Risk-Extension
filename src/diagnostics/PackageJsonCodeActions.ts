import * as vscode from "vscode";
import type { RiskResult } from "../types";

export interface RiskLookup {
  getRiskForDiagnostic(diagnostic: vscode.Diagnostic): RiskResult | undefined;
  findRiskAt(document: vscode.TextDocument, range: vscode.Range): RiskResult | undefined;
}

export class PackageJsonCodeActions implements vscode.CodeActionProvider {
  constructor(private readonly lookups: RiskLookup[]) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const seen = new Set<string>();
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "Dep Risk") {
        continue;
      }
      const risk = this.lookups
        .map((lookup) => lookup.getRiskForDiagnostic(diagnostic))
        .find((hit) => hit !== undefined);
      if (risk) {
        pushActions(actions, seen, risk, diagnostic);
      }
    }

    const atCursor = this.lookups
      .map((lookup) => lookup.findRiskAt(document, range))
      .find((hit) => hit !== undefined);
    if (atCursor) {
      pushActions(actions, seen, atCursor);
    }

    return actions;
  }
}

function pushActions(
  actions: vscode.CodeAction[],
  seen: Set<string>,
  risk: RiskResult,
  diagnostic?: vscode.Diagnostic
): void {
  const key = `${risk.signals.pkg.name}@${risk.signals.pkg.version}:${risk.tier}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);

  if (risk.tier !== "eol") {
    const ask = new vscode.CodeAction(
      `Ask Agent to Upgrade + Fix ${risk.signals.pkg.name}`,
      vscode.CodeActionKind.QuickFix
    );
    ask.command = {
      command: "depRisk.askAgentFix",
      title: ask.title,
      arguments: [{ risk }],
    };
    ask.isPreferred = risk.tier === "critical" || risk.tier === "high";
    if (diagnostic) {
      ask.diagnostics = [diagnostic];
    }
    actions.push(ask);
  }

  const url = risk.advisoryUrls[0] ?? risk.changelogUrl;
  if (url) {
    const open = new vscode.CodeAction(
      risk.advisoryUrls[0] ? "Open Advisory" : "Open Changelog / EOL page",
      vscode.CodeActionKind.QuickFix
    );
    open.command = {
      command: risk.advisoryUrls[0] ? "depRisk.openAdvisory" : "depRisk.openChangelog",
      title: open.title,
      arguments: [{ risk }],
    };
    if (diagnostic) {
      open.diagnostics = [diagnostic];
    }
    actions.push(open);
  }
}
