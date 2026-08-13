import * as fs from "fs/promises";
import * as vscode from "vscode";

const IGNORE = "{**/node_modules/**,**/dist/**,**/out/**,**/build/**,**/.git/**,**/coverage/**,**/.next/**}";

const IMPORT_RE =
  /(?:import\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?|export\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]/g;

function packageNameFromSpecifier(spec: string): string | undefined {
  if (!spec || spec.startsWith(".") || spec.startsWith("/") || spec.startsWith("node:")) {
    return undefined;
  }
  if (spec.startsWith("@")) {
    const parts = spec.split("/");
    if (parts.length >= 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return undefined;
  }
  return spec.split("/")[0];
}

/**
 * Scan workspace sources for import/require targets.
 * Coarse "used vs transitive" signal for risk elevation.
 */
export async function collectImportedPackages(
  folder: vscode.WorkspaceFolder,
  token?: vscode.CancellationToken
): Promise<Set<string>> {
  const imported = new Set<string>();
  const files = await vscode.workspace.findFiles(
    new vscode.RelativePattern(folder, "**/*.{js,jsx,ts,tsx,mjs,cjs,vue,svelte}"),
    IGNORE,
    4000,
    token
  );

  for (const uri of files) {
    if (token?.isCancellationRequested) {
      break;
    }
    try {
      const text = await fs.readFile(uri.fsPath, "utf8");
      IMPORT_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = IMPORT_RE.exec(text))) {
        const name = packageNameFromSpecifier(m[1]);
        if (name) {
          imported.add(name);
        }
      }
    } catch {
      // unreadable
    }
  }

  return imported;
}
