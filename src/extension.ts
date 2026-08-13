import * as vscode from "vscode";
import { getConfig } from "./config";
import { askAgentFix, copyAgentPrompt } from "./commands/askAgentFix";
import { PackageJsonDiagnostics } from "./diagnostics/PackageJsonDiagnostics";
import { ScanPipeline } from "./scan/pipeline";
import { DepRiskTreeProvider, PackageItem } from "./tree/DepRiskTreeProvider";
import type { ScanSummary } from "./types";

let pipeline: ScanPipeline | undefined;
let statusBar: vscode.StatusBarItem;
let dailyTimer: NodeJS.Timeout | undefined;
let scanInFlight: Thenable<void> | undefined;
let pendingScan: { folder: vscode.WorkspaceFolder; force: boolean } | undefined;
let scanCancellation: vscode.CancellationTokenSource | undefined;
let activeFolder: vscode.WorkspaceFolder | undefined;
let tree: DepRiskTreeProvider;
let diagnostics: PackageJsonDiagnostics;
let lockWatcher: vscode.FileSystemWatcher | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  tree = new DepRiskTreeProvider();
  diagnostics = new PackageJsonDiagnostics();

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "depRisk.show";
  statusBar.text = "$(shield) Dep Risk";
  statusBar.tooltip = "Open Dep Risk sidebar (issues by tier)";
  statusBar.show();

  context.subscriptions.push(
    diagnostics,
    statusBar,
    vscode.window.registerTreeDataProvider("depRisk.sidebar", tree),
    vscode.commands.registerCommand("depRisk.show", async () => {
      await vscode.commands.executeCommand("depRisk.sidebar.focus");
      const folder = requireFolder(false);
      if (folder && !tree.getSummary()) {
        await runScan(folder, false);
      }
    }),
    vscode.commands.registerCommand("depRisk.refresh", () => {
      const folder = requireFolder();
      if (folder) {
        return runScan(folder, true);
      }
    }),
    vscode.commands.registerCommand("depRisk.askAgentFix", async (item?: PackageItem) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk) {
        await askAgentFix(risk);
      }
    }),
    vscode.commands.registerCommand("depRisk.copyAgentPrompt", async (item?: PackageItem) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk) {
        await copyAgentPrompt(risk);
      }
    }),
    vscode.commands.registerCommand("depRisk.openAdvisory", async (item?: PackageItem) => {
      const risk = item?.risk ?? (await pickRisk());
      const url = risk?.advisoryUrls[0] ?? risk?.changelogUrl;
      if (url) {
        await vscode.env.openExternal(vscode.Uri.parse(url));
      }
    }),
    vscode.commands.registerCommand("depRisk.openChangelog", async (item?: PackageItem) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk?.changelogUrl) {
        await vscode.env.openExternal(vscode.Uri.parse(risk.changelogUrl));
      }
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      void bindWorkspace();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("depRisk") && activeFolder) {
        resetDailyTimer();
        void runScan(activeFolder, false);
      }
    })
  );

  await bindWorkspace();
}

export function deactivate(): void {
  if (dailyTimer) {
    clearInterval(dailyTimer);
  }
  lockWatcher?.dispose();
}

async function bindWorkspace(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const folderChanged = activeFolder?.uri.toString() !== folder?.uri.toString();
  if (folderChanged) {
    scanCancellation?.cancel();
  }
  if (!folder) {
    activeFolder = undefined;
    pipeline = undefined;
    lockWatcher?.dispose();
    lockWatcher = undefined;
    if (dailyTimer) {
      clearInterval(dailyTimer);
      dailyTimer = undefined;
    }
    tree.setSummary(undefined);
    statusBar.text = "$(shield) Dep Risk";
    statusBar.tooltip = "Open a folder with a lockfile to scan";
    return;
  }

  activeFolder = folder;
  pipeline = new ScanPipeline(folder.uri.fsPath);
  await pipeline.init();

  lockWatcher?.dispose();
  lockWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(
      folder,
      "{package.json,**/package.json,package-lock.json,npm-shrinkwrap.json,pnpm-lock.yaml,yarn.lock,.nvmrc,.node-version}"
    )
  );
  const schedule = debounce(() => {
    if (getConfig().autoScanOnLockfileChange && activeFolder) {
      void runScan(activeFolder, true);
    }
  }, 800);
  lockWatcher.onDidChange(schedule);
  lockWatcher.onDidCreate(schedule);
  lockWatcher.onDidDelete(schedule);

  resetDailyTimer();
  void runScan(folder, false);
}

function requireFolder(showWarning = true): vscode.WorkspaceFolder | undefined {
  const folder = activeFolder ?? vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    if (showWarning) {
      void vscode.window.showWarningMessage(
        "Dep Risk needs a workspace folder. Open a project that has package-lock.json (or use the sample fixture)."
      );
    }
    return undefined;
  }
  return folder;
}

function resetDailyTimer(): void {
  if (dailyTimer) {
    clearInterval(dailyTimer);
  }
  if (!activeFolder) {
    return;
  }
  const folder = activeFolder;
  const hours = getConfig().dailyRescanHours;
  dailyTimer = setInterval(
    () => {
      void runScan(folder, true);
    },
    Math.max(1, hours) * 60 * 60 * 1000
  );
}

function runScan(folder: vscode.WorkspaceFolder, force: boolean): Thenable<void> {
  if (scanInFlight) {
    pendingScan = {
      folder,
      force: force || pendingScan?.force === true,
    };
    return scanInFlight;
  }

  const scanPipeline =
    pipeline && activeFolder?.uri.toString() === folder.uri.toString()
      ? pipeline
      : new ScanPipeline(folder.uri.fsPath);
  const cancellation = new vscode.CancellationTokenSource();
  scanCancellation = cancellation;

  scanInFlight = vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: "Dep Risk",
      cancellable: true,
    },
    async (progress, token) => {
      const cancelSubscription = token.onCancellationRequested(() => cancellation.cancel());
      try {
        await scanPipeline.init();
        statusBar.text = "$(sync~spin) Dep Risk";
        const summary = await scanPipeline.scan(folder, {
          force,
          token: cancellation.token,
          onProgress: (phase, detail) => {
            progress.report({ message: detail ? `${phase}: ${detail}` : phase });
            statusBar.text = `$(sync~spin) Dep Risk: ${phase}`;
          },
        });
        if (
          cancellation.token.isCancellationRequested ||
          activeFolder?.uri.toString() !== folder.uri.toString()
        ) {
          return;
        }
        tree.setSummary(summary);
        await diagnostics.apply(summary, folder);
        updateStatus(summary);
        if (summary.errors.length) {
          console.warn("[depRisk] scan errors", summary.errors);
        }
      } catch (e) {
        if (!cancellation.token.isCancellationRequested) {
          statusBar.text = "$(error) Dep Risk";
          void vscode.window.showErrorMessage(`Dep Risk scan failed: ${String(e)}`);
        }
      } finally {
        cancelSubscription.dispose();
        cancellation.dispose();
        if (scanCancellation === cancellation) {
          scanCancellation = undefined;
        }
        scanInFlight = undefined;
        const queued = pendingScan;
        pendingScan = undefined;
        if (queued) {
          void runScan(queued.folder, queued.force);
        }
      }
    }
  );

  return scanInFlight;
}

function updateStatus(summary: ScanSummary): void {
  const c = summary.byTier.critical;
  const h = summary.byTier.high;
  const s = summary.byTier.stale;
  const e = summary.byTier.eol;
  const parts: string[] = [];
  if (c) {
    parts.push(`${c} crit`);
  }
  if (h) {
    parts.push(`${h} high`);
  }
  if (s) {
    parts.push(`${s} stale`);
  }
  if (e) {
    parts.push(`${e} eol`);
  }
  const icon = summary.errors.length ? "$(warning)" : "$(shield)";
  const result = parts.length ? parts.join(", ") : summary.errors.length ? "incomplete" : "clear";
  statusBar.text = `${icon} Dep Risk: ${result}`;
  statusBar.tooltip = [
    `Scanned ${summary.packageCount} packages at ${new Date(summary.scannedAt).toLocaleString()}`,
    summary.errors.length
      ? `${summary.errors.length} source error(s); results may be incomplete`
      : undefined,
  ]
    .filter(Boolean)
    .join("\n");
}

async function pickRisk() {
  const summary = tree.getSummary();
  if (!summary?.results.length) {
    void vscode.window.showInformationMessage("No risks to act on. Run Dep Risk: Refresh first.");
    return undefined;
  }
  const picked = await vscode.window.showQuickPick(
    summary.results.map((r) => ({
      label: `${r.signals.pkg.name}@${r.signals.pkg.version}`,
      description: r.tier,
      detail: r.reasons[0],
      risk: r,
    })),
    { placeHolder: "Select a package" }
  );
  return picked?.risk;
}

function debounce(fn: () => void, ms: number): () => void {
  let t: NodeJS.Timeout | undefined;
  return () => {
    if (t) {
      clearTimeout(t);
    }
    t = setTimeout(fn, ms);
  };
}
