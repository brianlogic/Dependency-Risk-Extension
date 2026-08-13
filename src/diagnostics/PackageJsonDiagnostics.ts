import { findNodeAtLocation, parseTree } from "jsonc-parser";
import * as vscode from "vscode";
import type { RiskResult, ScanSummary } from "../types";

const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Warning,
  stale: vscode.DiagnosticSeverity.Information,
  eol: vscode.DiagnosticSeverity.Information,
};

/**
 * Surface lightweight diagnostics on package.json dependency lines for direct deps.
 */
export class PackageJsonDiagnostics implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly disposables: vscode.Disposable[] = [];
  private lastSummary: ScanSummary | undefined;
  private lastFolder: vscode.WorkspaceFolder | undefined;
  private reapplyTimer: NodeJS.Timeout | undefined;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("depRisk");
    this.disposables.push(
      this.collection,
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (e.document.fileName.endsWith("package.json") && this.lastFolder) {
          if (this.reapplyTimer) {
            clearTimeout(this.reapplyTimer);
          }
          this.reapplyTimer = setTimeout(() => {
            void this.apply(this.lastSummary, this.lastFolder!);
          }, 250);
        }
      })
    );
  }

  async apply(summary: ScanSummary | undefined, folder: vscode.WorkspaceFolder): Promise<void> {
    this.lastSummary = summary;
    this.lastFolder = folder;
    this.collection.clear();
    if (!summary) {
      return;
    }

    const byName = new Map<string, RiskResult>();
    for (const r of summary.results) {
      if (r.tier === "eol") {
        continue;
      }
      if (!r.signals.pkg.direct) {
        continue;
      }
      const prev = byName.get(r.signals.pkg.name);
      if (!prev || tierRank(r.tier) < tierRank(prev.tier)) {
        byName.set(r.signals.pkg.name, r);
      }
    }

    const manifests = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/package.json"),
      "**/node_modules/**",
      200
    );

    for (const uri of manifests) {
      try {
        const document = await vscode.workspace.openTextDocument(uri);
        const text = document.getText();
        const diagnostics: vscode.Diagnostic[] = [];
        for (const [name, risk] of byName) {
          const range = findDependencyRange(text, name);
          if (!range) {
            continue;
          }
          const target = risk.recommendedBump ? ` → ${risk.recommendedBump}` : "";
          const msg = `[${risk.tier}] ${name}@${risk.signals.pkg.version}${target}: ${risk.reasons[0] ?? risk.tier}`;
          const diag = new vscode.Diagnostic(
            range,
            msg,
            SEVERITY[risk.tier] ?? vscode.DiagnosticSeverity.Information
          );
          diag.source = "Dep Risk";
          diag.code = risk.advisoryIds[0] ?? risk.tier;
          diagnostics.push(diag);
        }
        this.collection.set(uri, diagnostics);
      } catch {
        // skip
      }
    }
  }

  dispose(): void {
    if (this.reapplyTimer) {
      clearTimeout(this.reapplyTimer);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}

function tierRank(tier: string): number {
  switch (tier) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "stale":
      return 2;
    default:
      return 9;
  }
}

/** Locate "name": "range" inside dependency blocks. */
export function findDependencyRange(text: string, packageName: string): vscode.Range | undefined {
  const root = parseTree(text);
  if (!root) {
    return undefined;
  }

  for (const section of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const valueNode = findNodeAtLocation(root, [section, packageName]);
    const propertyNode = valueNode?.parent;
    if (propertyNode) {
      return new vscode.Range(
        offsetToPosition(text, propertyNode.offset),
        offsetToPosition(text, propertyNode.offset + propertyNode.length)
      );
    }
  }
  return undefined;
}

function offsetToPosition(text: string, offset: number): vscode.Position {
  let line = 0;
  let col = 0;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === "\n") {
      line++;
      col = 0;
    } else {
      col++;
    }
  }
  return new vscode.Position(line, col);
}
