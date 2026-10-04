// Apply Safe Fix: rewrite the version spec in every matching manifest with one WorkspaceEdit (undoable).
import * as vscode from "vscode";
import { npmManifest, pythonManifest } from "../diagnostics/manifests";
import type { RiskResult } from "../types";
import { confirmRiskyBump } from "./askAgentFix";
import { rewriteNpmManifest, rewritePythonManifest, type TextEdit } from "./rewriteSpec";

// Same manifest globs the diagnostics use.
const GLOBS = {
  npm: { include: npmManifest.include, exclude: npmManifest.exclude },
  pypi: { include: pythonManifest.include, exclude: pythonManifest.exclude },
};

/**
 * Bumps (or downgrades) the package to `risk.recommendedBump` after confirming risky changes.
 * Edits manifests only; the user re-runs their install to refresh the lockfile.
 * Complex specs the rewriter can't handle are reported instead of guessed.
 */
export async function applySafeFix(risk: RiskResult): Promise<void> {
  const { name, ecosystem } = risk.signals.pkg;
  const target = risk.recommendedBump;
  if (risk.tier === "eol" || !target) {
    void vscode.window.showInformationMessage(`No safe fixed version is known for ${name}.`);
    return;
  }
  if (!(await confirmRiskyBump(risk))) {
    return;
  }

  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return;
  }
  const { include, exclude } = GLOBS[ecosystem];
  const uris = await vscode.workspace.findFiles(new vscode.RelativePattern(folder, include), exclude, 200);

  const edit = new vscode.WorkspaceEdit();
  const touched: string[] = [];
  for (const uri of uris) {
    const doc = await vscode.workspace.openTextDocument(uri);
    const text = doc.getText();
    const base = uri.fsPath.split(/[\\/]/).pop() ?? "";
    const edits: TextEdit[] =
      ecosystem === "npm"
        ? rewriteNpmManifest(text, name, target)
        : [rewritePythonManifest(text, base, name, target)].filter((e): e is TextEdit => !!e);
    for (const e of edits) {
      edit.replace(uri, new vscode.Range(doc.positionAt(e.start), doc.positionAt(e.end)), e.text);
    }
    if (edits.length) {
      touched.push(vscode.workspace.asRelativePath(uri));
    }
  }

  if (!touched.length) {
    void vscode.window.showWarningMessage(
      `Couldn't rewrite ${name} automatically (not a simple version spec). Edit it manually or ask the agent.`
    );
    return;
  }
  await vscode.workspace.applyEdit(edit);
  void vscode.window.showInformationMessage(
    `Updated ${name} to ${target} in ${touched.join(", ")}. Run your install command to refresh the lockfile.`
  );
}
