// Pure text rewriters for manifests: return edits, never touch files (applySafeFix applies them).
import { findNodeAtLocation, parseTree } from "jsonc-parser";
import { findPythonDependencyOffsets } from "../diagnostics/pythonRanges";

/** Replace [start, end) of the document with `text`. */
export interface TextEdit {
  start: number;
  end: number;
  text: string;
}

// Only plain `1.2.3`-style specs (optional ^ ~ >= = prefix) are rewritten; ranges, tags and URLs are left alone.
const NPM_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"];
const SIMPLE_NPM = /^([\^~]|>=|=)?(\d+(?:\.\d+){0,2}(?:-[\w.]+)?)$/;

/** Edits that set `name` to `version` in a package.json, keeping ^/~/>= prefixes. Peer deps are left alone. */
export function rewriteNpmManifest(text: string, name: string, version: string): TextEdit[] {
  const root = parseTree(text);
  const edits: TextEdit[] = [];
  for (const section of NPM_SECTIONS) {
    const node = root && findNodeAtLocation(root, [section, name]);
    const match = typeof node?.value === "string" && SIMPLE_NPM.exec(node.value);
    if (node && match) {
      edits.push({ start: node.offset, end: node.offset + node.length, text: JSON.stringify((match[1] ?? "") + version) });
    }
  }
  return edits;
}

/** Edit for the first matching line in requirements*.txt / pyproject.toml; undefined if the spec isn't a single simple pin/bound. */
export function rewritePythonManifest(
  text: string,
  fileName: string,
  name: string,
  version: string
): TextEdit | undefined {
  const offsets = findPythonDependencyOffsets(text, fileName, name);
  if (!offsets) {
    return undefined;
  }
  const line = text.slice(offsets.start, offsets.end);
  // PEP 508: `name[extras] op version`, single clause only (a comma means an upper bound we can't safely keep)
  const pep = /(^|["'])(\s*[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*(?:==|>=|~=|===)\s*)([^\s,;"'#]+)(?=\s*(?:[;"'#]|$))/.exec(line);
  if (!pep) {
    return undefined;
  }
  const at = pep.index + pep[1].length + pep[2].length;
  const next = line.slice(0, at) + version + line.slice(at + pep[3].length);
  return { start: offsets.start, end: offsets.end, text: next };
}
