/**
 * Top-level module names from `import x` / `from x import y` lines (relative imports skipped).
 * Line-based on purpose: no parser needed to know a package is used.
 * Import names can differ from PyPI names; callers match with normalization.
 */
export function extractImportedPythonPackages(text: string): string[] {
  const names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.replace(/#.*$/, "").trim();
    if (!trimmed) {
      continue;
    }
    const from = trimmed.match(/^from\s+([A-Za-z_][\w.]*)\s+import\s+/);
    if (from && !from[1].startsWith(".")) {
      names.push(from[1].split(".")[0]);
      continue;
    }
    const direct = trimmed.match(/^import\s+(.+)$/);
    if (!direct) {
      continue;
    }
    for (const part of direct[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0]?.split(".")[0];
      if (name && /^[A-Za-z_]/.test(name)) {
        names.push(name);
      }
    }
  }
  return names;
}
