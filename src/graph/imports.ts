import * as fs from "fs/promises";
import * as vscode from "vscode";
import { mapPool } from "../util/http";
import { extractImportedPythonPackages } from "./pyImports";
import { extractImportedPackageNames } from "./specifiers";

// Search globs: skip dependency, build and virtualenv trees; cap files to keep large repos fast.
const IGNORE =
  "{**/node_modules/**,**/dist/**,**/out/**,**/build/**,**/.git/**,**/coverage/**,**/.next/**,**/.venv/**,**/venv/**,**/.tox/**}";
const FILE_CAP = 4000;
const READ_CONCURRENCY = 16;

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
  const [jsFiles, pyFiles] = await Promise.all([
    vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/*.{js,jsx,ts,tsx,mjs,cjs,vue,svelte}"),
      IGNORE,
      FILE_CAP,
      token
    ),
    vscode.workspace.findFiles(
      new vscode.RelativePattern(folder, "**/*.py"),
      IGNORE,
      FILE_CAP,
      token
    ),
  ]);

  if (jsFiles.length >= FILE_CAP || pyFiles.length >= FILE_CAP) {
    onWarning?.(
      `Import scan reached the ${FILE_CAP}-file cap; some used packages may be classified as transitive-only.`
    );
  }

  await mapPool([...jsFiles, ...pyFiles], READ_CONCURRENCY, async (uri) => {
    if (token?.isCancellationRequested) {
      return;
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
  });

  return imported;
}
