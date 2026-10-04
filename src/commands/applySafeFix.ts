// Apply Safe Fix: rewrite the version spec in every matching manifest with one WorkspaceEdit (undoable).
import * as fs from "fs/promises";
import * as vscode from "vscode";
import { npmManifest, pythonManifest } from "../diagnostics/manifests";
import type { RiskResult } from "../types";
import { openUrl } from "../util/openUrl";
import { rangeAt } from "../util/position";
import { isDowngrade } from "../util/version";
import { rewriteNpmManifest, rewritePythonManifest, type TextEdit } from "./rewriteSpec";

// Same manifest globs the diagnostics use.
const GLOBS = {
  npm: { include: npmManifest.include, exclude: npmManifest.exclude },
  pypi: { include: pythonManifest.include, exclude: pythonManifest.exclude },
};

/** Modal warning for major bumps and downgrades; true only if the user chooses to proceed. */
export async function confirmRiskyBump(risk: RiskResult): Promise<boolean> {
  const { name, version } = risk.signals.pkg;
  const downgrade = isDowngrade(risk);
  if (!downgrade && !risk.isMajorBump) {
    return true;
  }
  const proceed = "Proceed anyway";
  const changelog = "Review changelog";
  const message = downgrade
    ? `This moves ${name} backwards from ${version} to ${risk.recommendedBump}. Features or APIs added in newer versions may be missing, so code that uses them can break. Review the changelog before proceeding.`
    : `Upgrading ${name} to ${risk.recommendedBump} requires a major version bump with likely breaking changes. Review the changelog before proceeding.`;
  const choice = await vscode.window.showWarningMessage(message, { modal: true }, proceed, changelog);
  if (choice === changelog && risk.changelogUrl) {
    await openUrl(risk.changelogUrl);
  }
  return choice === proceed;
}

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
      `Couldn't rewrite ${name} automatically (not a simple version spec). Edit it manually.`
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
