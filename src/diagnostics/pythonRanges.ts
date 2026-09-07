import { requirementName } from "../lockfile/python";
import { namesMatch } from "../util/version";

export function findPythonDependencyOffsets(
  text: string,
  fileName: string,
  packageName: string
): { start: number; end: number } | undefined {
  if (fileName.endsWith(".toml")) {
    return findTomlOffsets(text, packageName);
  }
  return findRequirementsOffsets(text, packageName);
}

export function findPythonDependencyNameAtOffset(
  text: string,
  fileName: string,
  offset: number
): string | undefined {
  if (fileName.endsWith(".toml")) {
    const line = lineAt(text, offset);
    return (
      requirementName(line.match(/["']([^"']+)["']/)?.[1] ?? "") ??
      line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/)?.[1]
    );
  }
  const spec = lineAt(text, offset).replace(/#.*$/, "").trim();
  return requirementName(spec);
}

function findRequirementsOffsets(text: string, packageName: string): { start: number; end: number } | undefined {
  let cursor = 0;
  for (const line of text.split(/\r?\n/)) {
    const name = requirementName(line.replace(/#.*$/, "").trim());
    if (name && namesMatch(name, packageName)) {
      const start = cursor + (line.match(/^\s*/)?.[0].length ?? 0);
      return { start, end: cursor + line.length };
    }
    cursor += line.length + 1;
  }
  return undefined;
}

function findTomlOffsets(text: string, packageName: string): { start: number; end: number } | undefined {
  let cursor = 0;
  for (const line of text.split(/\r?\n/)) {
    const quoted = line.match(/["']([^"']+)["']/);
    const key = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/);
    const name = quoted ? requirementName(quoted[1]) : key?.[1];
    if (name && namesMatch(name, packageName)) {
      return { start: cursor, end: cursor + line.length };
    }
    cursor += line.length + 1;
  }
  return undefined;
}

function lineAt(text: string, offset: number): string {
  const start = text.lastIndexOf("\n", Math.max(0, offset - 1)) + 1;
  const end = text.indexOf("\n", offset);
  return text.slice(start, end === -1 ? undefined : end);
}
