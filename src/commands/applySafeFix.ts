// Apply Safe Fix: rewrite the version spec in every matching manifest with one WorkspaceEdit (undoable).
import * as fs from "fs/promises";
import * as vscode from "vscode";
import { npmManifest, pythonManifest } from "../diagnostics/manifests";
import type { RiskResult } from "../types";
import { rangeAt } from "../util/position";
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
    // An already-open buffer wins so an unsaved edit is rewritten in place.
    // Closed files are read from disk and never opened.
    const open = vscode.workspace.textDocuments.find((doc) => doc.uri.toString() === uri.toString());
    const text = open ? open.getText() : await fs.readFile(uri.fsPath, "utf8");
    const base = uri.fsPath.split(/[\\/]/).pop() ?? "";
    const edits: TextEdit[] =
      ecosystem === "npm"
        ? rewriteNpmManifest(text, name, target)
        : [rewritePythonManifest(text, base, name, target)].filter((e): e is TextEdit => !!e);
    for (const e of edits) {
      edit.replace(uri, rangeAt(text, e.start, e.end), e.text);
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
    `Updated ${name} to ${target} in ${touched.join(", ")}. The warning stays until you run ${
      ecosystem === "npm" ? "your install command (e.g. npm install)" : "your install/lock command (e.g. pip install -r requirements.txt, uv lock)"
    } to refresh the lockfile; Dep Risk then rescans automatically.`
  );
}
