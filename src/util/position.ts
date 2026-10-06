import * as vscode from "vscode";

/**
 * Line and character for a UTF-16 offset in `text`.
 * Matches `TextDocument.positionAt` for the same string: a `\n` starts the next line,
 * and a preceding `\r` stays on the previous line.
 */
export function positionAt(text: string, offset: number): vscode.Position {
  const end = Math.max(0, Math.min(offset, text.length));
  let line = 0;
  let lineStart = 0;
  for (let i = 0; i < end; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lineStart = i + 1;
    }
  }
  return new vscode.Position(line, end - lineStart);
}

/** Range covering `[start, end)` in `text`. */
export function rangeAt(text: string, start: number, end: number): vscode.Range {
  return new vscode.Range(positionAt(text, start), positionAt(text, end));
}
