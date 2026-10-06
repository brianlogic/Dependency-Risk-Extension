// Squiggles on dependency lines in manifests, driven by the latest scan summary.
import * as fs from "fs/promises";
import * as path from "path";
import * as vscode from "vscode";
import type { Ecosystem, RiskResult, ScanSummary } from "../types";
import { rangeAt } from "../util/position";
import { isDowngrade } from "../util/version";

// Only critical/high get Error/Warning; other tiers fall back to Information.
const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Warning,
};

// Lower rank = worse. When one package has several results, the worst is shown.
const TIER_RANK: Record<string, number> = { critical: 0, high: 1, stale: 2 };
const rank = (tier: string): number => TIER_RANK[tier] ?? 9;

/**
 * Per-ecosystem strategy: which files to scan and how to locate a dependency in their text.
 * Keeps ManifestDiagnostics ecosystem-agnostic (see manifests.ts for the npm and Python configs).
 */
export interface ManifestConfig {
  collectionName: string;
  ecosystem: Ecosystem;
  include: string;
  exclude: string;
  isManifest(fileName: string): boolean;
  namesMatch(a: string, b: string): boolean;
  findOffsets(text: string, fileName: string, name: string): { start: number; end: number } | undefined;
  nameAtOffset(text: string, fileName: string, offset: number): string | undefined;
}

/** True when `version` appears as a whole version token in the dependency's manifest text. */
function declaresVersion(text: string, version: string): boolean {
  return new RegExp(`(?<![\\w.])${version.replace(/[.+]/g, "\\$&")}(?![\\w.])`).test(text);
}

/** Diagnostics on dependency lines of one ecosystem's manifests (direct deps only). */
export class ManifestDiagnostics implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;
  private readonly disposables: vscode.Disposable[] = [];
  private lastSummary: ScanSummary | undefined;
  private reapplyTimer: NodeJS.Timeout | undefined;
  private readonly pendingDocs = new Set<vscode.TextDocument>();
  private readonly riskByDiagnostic = new WeakMap<vscode.Diagnostic, RiskResult>();

  constructor(private readonly cfg: ManifestConfig) {
    this.collection = vscode.languages.createDiagnosticCollection(cfg.collectionName);
    this.disposables.push(
      this.collection,
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (!cfg.isManifest(e.document.fileName) || !this.lastSummary) {
          return;
        }
        // An edit only moves offsets in that file. Rebuild it, not every manifest.
        this.pendingDocs.add(e.document);
        clearTimeout(this.reapplyTimer);
        this.reapplyTimer = setTimeout(() => {
          const docs = [...this.pendingDocs];
          this.pendingDocs.clear();
          const byName = this.risksByName(this.lastSummary);
          if (!byName) {
            return;
          }
          for (const doc of docs) {
            this.collection.set(
              doc.uri,
              this.diagnosticsFor(doc.getText(), path.basename(doc.fileName), byName)
            );
          }
        }, 250);
      })
    );
  }

  /**
   * Replaces all diagnostics from `summary` (undefined clears). Remembers the inputs so edits to a
   * manifest can re-apply with fresh offsets. Reads files from disk and does not open them.
   */
  async apply(summary: ScanSummary | undefined, folder: vscode.WorkspaceFolder): Promise<void> {
    clearTimeout(this.reapplyTimer);
    this.pendingDocs.clear();
    this.lastSummary = summary;
    this.collection.clear();
    if (!summary) {
      return;
    }

    const byName = this.risksByName(summary);
    if (!byName) {
      return;
    }

    const manifests = await vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, this.cfg.include),
      this.cfg.exclude,
      200
    );

    for (const uri of manifests) {
      try {
        const text = await fs.readFile(uri.fsPath, "utf8");
        this.collection.set(uri, this.diagnosticsFor(text, path.basename(uri.fsPath), byName));
      } catch {
        // skip
      }
    }
  }

  /** The risk a diagnostic from this collection was created for (used by quick fixes). */
  getRiskForDiagnostic(diagnostic: vscode.Diagnostic): RiskResult | undefined {
    return this.riskByDiagnostic.get(diagnostic);
  }

  /** Worst direct risk for the dependency under the cursor, even without a diagnostic on that exact range. */
  findRiskAt(document: vscode.TextDocument, range: vscode.Range): RiskResult | undefined {
    if (!this.lastSummary || !this.cfg.isManifest(document.fileName)) {
      return undefined;
    }
    const name = this.cfg.nameAtOffset(
      document.getText(),
      path.basename(document.fileName),
      document.offsetAt(range.start)
    );
    if (!name) {
      return undefined;
    }
    return this.directRisks(this.lastSummary)
      .filter((r) => this.cfg.namesMatch(r.signals.pkg.name, name))
      .reduce<RiskResult | undefined>((best, r) => (!best || rank(r.tier) < rank(best.tier) ? r : best), undefined);
  }

  /** Worst direct risk per package name, or undefined when there is nothing to flag. */
  private risksByName(summary: ScanSummary | undefined): Map<string, RiskResult> | undefined {
    if (!summary) {
      return undefined;
    }
    const byName = new Map<string, RiskResult>();
    for (const r of this.directRisks(summary)) {
      const prev = byName.get(r.signals.pkg.name);
      if (!prev || rank(r.tier) < rank(prev.tier)) {
        byName.set(r.signals.pkg.name, r);
      }
    }
    return byName;
  }

  /** Diagnostics for one manifest's text. Offsets and ranges come from the same string. */
  private diagnosticsFor(
    text: string,
    fileName: string,
    byName: Map<string, RiskResult>
  ): vscode.Diagnostic[] {
    const diagnostics: vscode.Diagnostic[] = [];
    for (const [name, risk] of byName) {
      const offsets = this.cfg.findOffsets(text, fileName, name);
      if (!offsets) {
        continue;
      }
      const target = risk.recommendedBump
        ? ` → ${risk.recommendedBump}${isDowngrade(risk) ? " (downgrade)" : ""}`
        : "";
      // Scans read the lockfile, so after Apply Safe Fix the finding persists until the user installs.
      const pendingInstall = risk.recommendedBump
        ? declaresVersion(text.slice(offsets.start, offsets.end), risk.recommendedBump)
        : false;
      const diag = new vscode.Diagnostic(
        rangeAt(text, offsets.start, offsets.end),
        pendingInstall
          ? `[${risk.tier}] ${name}@${risk.signals.pkg.version} is still locked; manifest already targets ${risk.recommendedBump}. Run your install command to refresh the lockfile.`
          : `[${risk.tier}] ${name}@${risk.signals.pkg.version}${target}: ${risk.reasons[0] ?? risk.tier}`,
        pendingInstall
          ? vscode.DiagnosticSeverity.Information
          : (SEVERITY[risk.tier] ?? vscode.DiagnosticSeverity.Information)
      );
      diag.source = "Dep Risk";
      diag.code = risk.advisoryIds[0] ?? risk.tier;
      this.riskByDiagnostic.set(diag, risk);
      diagnostics.push(diag);
    }
    return diagnostics;
  }

  /** Direct, non-runtime risks of this ecosystem; transitive packages have no manifest line to flag. */
  private directRisks(summary: ScanSummary): RiskResult[] {
    return summary.results.filter(
      (r) => r.tier !== "eol" && r.signals.pkg.ecosystem === this.cfg.ecosystem && r.signals.pkg.direct
    );
  }

  dispose(): void {
    clearTimeout(this.reapplyTimer);
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
