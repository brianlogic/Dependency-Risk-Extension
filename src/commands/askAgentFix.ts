// "Ask Agent" flow: build a fix prompt for a risk and hand it to the editor's AI chat.
import * as vscode from "vscode";
import type { RiskResult } from "../types";
import { delay } from "../util/http";
import { openUrl } from "../util/openUrl";
import { isDowngrade } from "../util/version";

/**
 * Prompt text for the agent. Without a known fixed version it asks for investigation instead of
 * inventing a target; downgrades and major bumps add explicit warnings.
 */
export function buildAgentPrompt(risk: RiskResult): string {
  const pkg = risk.signals.pkg;
  const cves =
    risk.advisoryIds.join(", ") ||
    (risk.tier === "stale" ? "stale dependency risk" : "known dependency risk");

  const ecosystem = pkg.ecosystem === "pypi" ? "PyPI" : "npm";
  const lockfiles =
    pkg.ecosystem === "pypi"
      ? "uv.lock / poetry.lock / requirements.txt"
      : "package-lock.json";

  const lines = risk.recommendedBump
    ? [
        `Upgrade ${ecosystem} package \`${pkg.name}\` from \`${pkg.version}\` → \`${risk.recommendedBump}\` to resolve ${cves}.`,
        `Update the lockfile (${lockfiles}), run the test suite, and fix any breakage.`,
        `Do not widen unrelated dependency bumps.`,
      ]
    : [
        `Investigate ${cves} affecting ${ecosystem} package \`${pkg.name}@${pkg.version}\`. No complete fixed version is published in the advisory data, so do not invent or blindly apply a target version.`,
        `Determine whether a mitigation, override, replacement package, or upstream update is appropriate. Run the test suite after any change and keep unrelated dependency versions unchanged.`,
      ];

  if (isDowngrade(risk)) {
    lines.push(
      `WARNING: This moves \`${pkg.name}\` backwards. Before changing anything, check for APIs or features used in this repo that don't exist in \`${risk.recommendedBump}\`, and report them rather than silently removing code.`
    );
  }

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

/** No stable API accepts a prompt, so: copy to clipboard, open the first available chat command, paste. Falls back to a notice. */
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

/** Modal warning for major bumps and downgrades; true only if the user chooses to proceed. */
export async function confirmRiskyBump(risk: RiskResult): Promise<boolean> {
  const { name, version } = risk.signals.pkg;
  const downgrade = isDowngrade(risk);
  if (!downgrade && !risk.isMajorBump) {
    return true;
  }
  const proceed = "Proceed anyway";
  const changelog = "Review changelog";
  const message = downgrade
    ? `This moves ${name} backwards from ${version} to ${risk.recommendedBump}. Features or APIs added in newer versions may be missing, so code that uses them can break. Review the changelog before proceeding.`
    : `Upgrading ${name} to ${risk.recommendedBump} requires a major version bump with likely breaking changes. Review the changelog before proceeding.`;
  const choice = await vscode.window.showWarningMessage(message, { modal: true }, proceed, changelog);
  if (choice === changelog && risk.changelogUrl) {
    await openUrl(risk.changelogUrl);
  }
  return choice === proceed;
}

/** Runtime (EOL) risks just open the EOL page since no single package fixes them; others confirm then open the agent. */
export async function askAgentFix(risk: RiskResult): Promise<void> {
  if (risk.tier === "eol") {
    const open = "Open EOL page";
    const choice = await vscode.window.showWarningMessage(
      risk.reasons[0] ?? "Runtime is EOL-adjacent. Upgrade the language/runtime, not a single package.",
      open
    );
    if (choice === open && risk.changelogUrl) {
      await openUrl(risk.changelogUrl);
    }
    return;
  }

  const prompt = buildAgentPrompt(risk);

  if (!(await confirmRiskyBump(risk))) {
    return;
  }

  await openAgentWithPrompt(prompt);
}

/** Copies the agent prompt without opening any chat. */
export async function copyAgentPrompt(risk: RiskResult): Promise<void> {
  const prompt = buildAgentPrompt(risk);
  await vscode.env.clipboard.writeText(prompt);
  void vscode.window.showInformationMessage("Agent prompt copied to clipboard.");
}
