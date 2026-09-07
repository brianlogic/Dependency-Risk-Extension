import * as path from "path";
import * as vscode from "vscode";
import { findPythonDependencyNameAtOffset, findPythonDependencyOffsets } from "./pythonRanges";
import { namesMatch } from "../util/version";
import type { RiskResult, ScanSummary } from "../types";

const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Warning,
  stale: vscode.DiagnosticSeverity.Information,
  eol: vscode.DiagnosticSeverity.Information,
};

const IGNORE = "{**/node_modules/**,**/.venv/**,**/venv/**,**/.tox/**}";

/**
 * Surface diagnostics on requirements*.txt and pyproject.toml for direct PyPI deps.
 */
export class PythonDiagnostics implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly disposables: vscode.Disposable[] = [];
  private lastSummary: ScanSummary | undefined;
  private lastFolder: vscode.WorkspaceFolder | undefined;
  private reapplyTimer: NodeJS.Timeout | undefined;
  private readonly riskByDiagnostic = new WeakMap<vscode.Diagnostic, RiskResult>();

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("depRisk.python");
    this.disposables.push(
      this.collection,
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (isPythonManifest(e.document.fileName) && this.lastFolder) {
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
      if (r.tier === "eol" || r.signals.pkg.ecosystem !== "pypi" || !r.signals.pkg.direct) {
        continue;
      }
      const prev = byName.get(r.signals.pkg.name);
      if (!prev || tierRank(r.tier) < tierRank(prev.tier)) {
        byName.set(r.signals.pkg.name, r);
      }
    }

    const manifests = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "{**/requirements*.txt,**/pyproject.toml}"),
      IGNORE,
      200
    );

    for (const uri of manifests) {
      try {
        const document = await vscode.workspace.openTextDocument(uri);
        const text = document.getText();
        const diagnostics: vscode.Diagnostic[] = [];
        for (const [name, risk] of byName) {
          const offsets = findPythonDependencyOffsets(text, path.basename(uri.fsPath), name);
          if (!offsets) {
            continue;
          }
          const range = new vscode.Range(
            offsetToPosition(text, offsets.start),
            offsetToPosition(text, offsets.end)
          );
          const target = risk.recommendedBump ? ` → ${risk.recommendedBump}` : "";
          const msg = `[${risk.tier}] ${name}@${risk.signals.pkg.version}${target}: ${risk.reasons[0] ?? risk.tier}`;
          const diag = new vscode.Diagnostic(
            range,
            msg,
            SEVERITY[risk.tier] ?? vscode.DiagnosticSeverity.Information
          );
          diag.source = "Dep Risk";
          diag.code = risk.advisoryIds[0] ?? risk.tier;
          this.riskByDiagnostic.set(diag, risk);
          diagnostics.push(diag);
        }
        this.collection.set(uri, diagnostics);
      } catch {
        // skip
      }
    }
  }

  getRiskForDiagnostic(diagnostic: vscode.Diagnostic): RiskResult | undefined {
    return this.riskByDiagnostic.get(diagnostic);
  }

  findRiskAt(document: vscode.TextDocument, range: vscode.Range): RiskResult | undefined {
    if (!this.lastSummary || !isPythonManifest(document.fileName)) {
      return undefined;
    }
    const name = findPythonDependencyNameAtOffset(
      document.getText(),
      path.basename(document.fileName),
      document.offsetAt(range.start)
    );
    return name ? riskForName(this.lastSummary, name) : undefined;
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

export function isPythonManifest(fileName: string): boolean {
  const base = path.basename(fileName);
  return base === "pyproject.toml" || /^requirements.*\.txt$/i.test(base);
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

function riskForName(summary: ScanSummary, name: string): RiskResult | undefined {
  let best: RiskResult | undefined;
  for (const result of summary.results) {
    if (
      result.tier === "eol" ||
      result.signals.pkg.ecosystem !== "pypi" ||
      !result.signals.pkg.direct ||
      !namesMatch(result.signals.pkg.name, name)
    ) {
      continue;
    }
    if (!best || tierRank(result.tier) < tierRank(best.tier)) {
      best = result;
    }
  }
  return best;
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
