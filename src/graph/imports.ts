import * as fs from "fs/promises";
import * as vscode from "vscode";
import { extractImportedPythonPackages } from "./pyImports";
import { extractImportedPackageNames } from "./specifiers";

const IGNORE =
  "{**/node_modules/**,**/dist/**,**/out/**,**/build/**,**/.git/**,**/coverage/**,**/.next/**,**/.venv/**,**/venv/**,**/.tox/**}";
const FILE_CAP = 4000;

/**
 * Scan workspace sources for import/require targets.
 * Coarse "used vs transitive" signal for risk elevation.
 */
export async function collectImportedPackages(
  folder: vscode.WorkspaceFolder,
  token?: vscode.CancellationToken,
  onWarning?: (message: string) => void
): Promise<Set<string>> {
  const imported = new Set<string>();
  const jsFiles = await vscode.workspace.findFiles(
    new vscode.RelativePattern(folder, "**/*.{js,jsx,ts,tsx,mjs,cjs,vue,svelte}"),
    IGNORE,
    FILE_CAP,
    token
  );
  const pyFiles = await vscode.workspace.findFiles(
    new vscode.RelativePattern(folder, "**/*.py"),
    IGNORE,
    FILE_CAP,
    token
  );

  if (jsFiles.length >= FILE_CAP || pyFiles.length >= FILE_CAP) {
    onWarning?.(
      `Import scan reached the ${FILE_CAP}-file cap; some used packages may be classified as transitive-only.`
    );
  }

  for (const uri of [...jsFiles, ...pyFiles]) {
    if (token?.isCancellationRequested) {
      break;
    }
    try {
      const text = await fs.readFile(uri.fsPath, "utf8");
      const names = uri.fsPath.endsWith(".py")
        ? extractImportedPythonPackages(text)
        : extractImportedPackageNames(text);
      for (const name of names) {
        imported.add(name);
      }
    } catch {
      // unreadable
    }
  }

  return imported;
}
