import * as vscode from "vscode";
import type { RiskResult } from "../types";

export function buildAgentPrompt(risk: RiskResult): string {
  const pkg = risk.signals.pkg;
  const cves =
    risk.advisoryIds.join(", ") ||
    (risk.tier === "stale" ? "stale dependency risk" : "known dependency risk");

  const lines = risk.recommendedBump
    ? [
        `Upgrade npm package \`${pkg.name}\` from \`${pkg.version}\` → \`${risk.recommendedBump}\` to resolve ${cves}.`,
        `Update the lockfile (package-lock.json / pnpm-lock.yaml / yarn.lock), run the test suite, and fix any breakage.`,
        `Do not widen unrelated dependency bumps.`,
      ]
    : [
        `Investigate ${cves} affecting npm package \`${pkg.name}@${pkg.version}\`. No complete fixed version is published in the advisory data, so do not invent or blindly apply a target version.`,
        `Determine whether a mitigation, override, replacement package, or upstream update is appropriate. Run the test suite after any change and keep unrelated dependency versions unchanged.`,
      ];

  if (risk.isMajorBump) {
    lines.push(
      `NOTE: This is a major version upgrade and may include breaking changes. Review the changelog/release notes before applying broad refactors.`
    );
  }

  if (risk.changelogUrl) {
    lines.push(`Changelog / releases: ${risk.changelogUrl}`);
  }
  if (risk.advisoryUrls[0]) {
    lines.push(`Advisory: ${risk.advisoryUrls[0]}`);
  }

  return lines.join("\n");
}

async function openAgentWithPrompt(prompt: string): Promise<void> {
  // Cursor chat commands may exist but ignore programmatic prompt arguments.
  // Copy first, open a known chat surface, then paste into the focused input.
  await vscode.env.clipboard.writeText(prompt);
  const available = new Set(await vscode.commands.getCommands(true));
  const candidates = [
    "composer.newAgentChat",
    "aichat.newchataction",
    "workbench.action.chat.newChat",
    "workbench.action.chat.open",
  ];

  for (const command of candidates) {
    if (!available.has(command)) {
      continue;
    }
    try {
      await vscode.commands.executeCommand(command);
      await delay(300);
      await vscode.commands.executeCommand("editor.action.clipboardPasteAction");
      return;
    } catch {
      // try next
    }
  }

  const open = "Open Chat";
  const choice = await vscode.window.showInformationMessage(
    "Agent prompt copied to clipboard. Paste it into Cursor Agent / Composer.",
    open
  );
  if (choice === open) {
    try {
      await vscode.commands.executeCommand("workbench.action.chat.open");
    } catch {
      // ignore
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function askAgentFix(risk: RiskResult): Promise<void> {
  if (risk.tier === "eol") {
    const open = "Open EOL page";
    const choice = await vscode.window.showWarningMessage(
      risk.reasons[0] ?? "Runtime is EOL-adjacent. Upgrade the language/runtime, not a single npm package.",
      open
    );
    if (choice === open && risk.changelogUrl) {
      await vscode.env.openExternal(vscode.Uri.parse(risk.changelogUrl));
    }
    return;
  }

  const prompt = buildAgentPrompt(risk);

  if (risk.isMajorBump) {
    const proceed = "Proceed anyway";
    const changelog = "Review changelog";
    const choice = await vscode.window.showWarningMessage(
      `Upgrading ${risk.signals.pkg.name} to ${risk.recommendedBump} requires a major version bump with likely breaking changes. Review the changelog before proceeding.`,
      { modal: true },
      proceed,
      changelog
    );
    if (choice === changelog && risk.changelogUrl) {
      await vscode.env.openExternal(vscode.Uri.parse(risk.changelogUrl));
      return;
    }
    if (choice !== proceed) {
      return;
    }
  }

  await openAgentWithPrompt(prompt);
}

export async function copyAgentPrompt(risk: RiskResult): Promise<void> {
  const prompt = buildAgentPrompt(risk);
  await vscode.env.clipboard.writeText(prompt);
  void vscode.window.showInformationMessage("Agent prompt copied to clipboard.");
}
