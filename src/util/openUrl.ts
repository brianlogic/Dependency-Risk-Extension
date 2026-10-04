import * as vscode from "vscode";

/** Open an http(s) URL in the browser; anything else (data from OSV/registries is untrusted) is ignored. */
export async function openUrl(url: string): Promise<void> {
  if (/^https?:\/\//i.test(url)) {
    await vscode.env.openExternal(vscode.Uri.parse(url));
  }
}
