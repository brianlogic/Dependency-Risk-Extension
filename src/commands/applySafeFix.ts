import * as vscode from "vscode";
import type { RiskResult } from "../types";
import { confirmMajorBump } from "./askAgentFix";
import { rewriteNpmManifest, rewritePythonManifest, type TextEdit } from "./rewriteSpec";

const GLOBS = {
  npm: { include: "**/package.json", exclude: "**/node_modules/**" },
  pypi: { include: "{**/requirements*.txt,**/pyproject.toml}", exclude: "{**/node_modules/**,**/.venv/**,**/venv/**}" },
};

export async function applySafeFix(risk: RiskResult): Promise<void> {
  const { name, ecosystem } = risk.signals.pkg;
  const target = risk.recommendedBump;
  if (risk.tier === "eol" || !target) {
    void vscode.window.showInformationMessage(`No safe fixed version is known for ${name}.`);
    return;
  }
  if (risk.isMajorBump && !(await confirmMajorBump(risk))) {
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
