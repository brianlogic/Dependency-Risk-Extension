const IMPORT_RE =
  /(?:(?:import|export)(?!\s+type\b)\s+(?:[\s\S]*?\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]/g;

export function packageNameFromSpecifier(spec: string): string | undefined {
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

/** Extract runtime import/require package names from source text. */
export function extractImportedPackageNames(text: string): string[] {
  const names: string[] = [];
  const re = new RegExp(IMPORT_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const name = packageNameFromSpecifier(m[1]);
    if (name) {
      names.push(name);
    }
  }
  return names;
}
