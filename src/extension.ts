import * as vscode from "vscode";
import { getConfig } from "./config";
import { askAgentFix, copyAgentPrompt } from "./commands/askAgentFix";
import { PackageJsonCodeActions } from "./diagnostics/PackageJsonCodeActions";
import { PackageJsonDiagnostics } from "./diagnostics/PackageJsonDiagnostics";
import { PythonDiagnostics } from "./diagnostics/PythonDiagnostics";
import { ScanPipeline } from "./scan/pipeline";
import { DepRiskDecorationProvider } from "./tree/decorations";
import { DepRiskTreeProvider } from "./tree/DepRiskTreeProvider";
import { OverviewView } from "./tree/OverviewView";
import { RiskDetailView } from "./tree/RiskDetailView";
import { headline } from "./tree/presentation";
import type { RiskResult, ScanSummary } from "./types";

let pipeline: ScanPipeline | undefined;
let statusBar: vscode.StatusBarItem;
let dailyTimer: NodeJS.Timeout | undefined;
let scanInFlight: Thenable<void> | undefined;
let pendingScan: { folder: vscode.WorkspaceFolder; force: boolean } | undefined;
let scanCancellation: vscode.CancellationTokenSource | undefined;
let activeFolder: vscode.WorkspaceFolder | undefined;
let tree: DepRiskTreeProvider;
let overview: OverviewView;
let decorations: DepRiskDecorationProvider;
let diagnostics: PackageJsonDiagnostics;
let pythonDiagnostics: PythonDiagnostics;
let lockWatcher: vscode.FileSystemWatcher | undefined;

export function activate(context: vscode.ExtensionContext): void {
  // Register tree views before any await so Cursor/VS Code never shows
  // "There is no data provider registered that can provide view data."
  tree = new DepRiskTreeProvider();
  overview = new OverviewView();
  decorations = new DepRiskDecorationProvider();
  const treeViewOptions = { treeDataProvider: tree, showCollapseAll: true };
  context.subscriptions.push(
    vscode.window.createTreeView("depRisk.sidebar", treeViewOptions),
    vscode.window.createTreeView("depRisk.explorer", treeViewOptions),
    vscode.window.registerWebviewViewProvider(OverviewView.viewType, overview),
    vscode.window.registerFileDecorationProvider(decorations)
  );

  diagnostics = new PackageJsonDiagnostics();
  pythonDiagnostics = new PythonDiagnostics();

  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = "depRisk.show";
  statusBar.text = "$(shield) Dep Risk";
  statusBar.tooltip = "Open Dep Risk sidebar (issues by tier)";
  statusBar.show();

  context.subscriptions.push(
    diagnostics,
    pythonDiagnostics,
    statusBar,
    vscode.languages.registerCodeActionsProvider(
      [
        { language: "json", pattern: "**/package.json" },
        { language: "jsonc", pattern: "**/package.json" },
        { language: "pip-requirements", pattern: "**/requirements*.txt" },
        { pattern: "**/requirements*.txt" },
        { language: "toml", pattern: "**/pyproject.toml" },
        { pattern: "**/pyproject.toml" },
      ],
      new PackageJsonCodeActions([diagnostics, pythonDiagnostics]),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    ),
    vscode.commands.registerCommand("depRisk.show", async () => {
      await focusDepRiskView();
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
    vscode.commands.registerCommand("depRisk.askAgentFix", async (item?: { risk: RiskResult }) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk) {
        await askAgentFix(risk);
      }
    }),
    vscode.commands.registerCommand("depRisk.copyAgentPrompt", async (item?: { risk: RiskResult }) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk) {
        await copyAgentPrompt(risk);
      }
    }),
    vscode.commands.registerCommand("depRisk.showRisk", async (item?: { risk: RiskResult }) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk) {
        RiskDetailView.show(risk);
      }
    }),
    vscode.commands.registerCommand("depRisk.openAdvisory", async (item?: { risk?: RiskResult; url?: string }) => {
      const url = item?.url ?? item?.risk?.advisoryUrls[0] ?? item?.risk?.changelogUrl;
      if (url) {
        await vscode.env.openExternal(vscode.Uri.parse(url));
        return;
      }
      const risk = item?.risk ?? (await pickRisk());
      const fallback = risk?.advisoryUrls[0] ?? risk?.changelogUrl;
      if (fallback) {
        await vscode.env.openExternal(vscode.Uri.parse(fallback));
        return;
      }
      void vscode.window.showInformationMessage("No advisory or changelog URL is available for this item.");
    }),
    vscode.commands.registerCommand("depRisk.openChangelog", async (item?: { risk: RiskResult }) => {
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

  void bindWorkspace().catch((error) => {
    console.error("[depRisk] startup failed", error);
    void vscode.window.showErrorMessage(`Dep Risk failed to start: ${String(error)}`);
  });
}

export function deactivate(): void {
  scanCancellation?.cancel();
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
    overview.setSummary(undefined);
    decorations.refresh();
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
      "{package.json,**/package.json,**/package-lock.json,**/npm-shrinkwrap.json,**/pnpm-lock.yaml,**/yarn.lock,**/bun.lock,**/uv.lock,**/poetry.lock,**/Pipfile.lock,**/requirements*.txt,**/pyproject.toml,.nvmrc,.node-version,.python-version,runtime.txt}"
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
        "Dep Risk needs a workspace folder. Open a project that has a lockfile (or use the sample fixture)."
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
        overview.setSummary(summary);
        decorations.refresh();
        await Promise.all([
          diagnostics.apply(summary, folder),
          pythonDiagnostics.apply(summary, folder),
        ]);
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
  const parts: string[] = [];
  if (summary.byTier.critical) {
    parts.push(`$(flame)${summary.byTier.critical}`);
  }
  if (summary.byTier.high) {
    parts.push(`$(warning)${summary.byTier.high}`);
  }
  if (summary.byTier.stale) {
    parts.push(`$(history)${summary.byTier.stale}`);
  }
  if (summary.byTier.eol) {
    parts.push(`$(calendar)${summary.byTier.eol}`);
  }
  const icon = summary.errors.length ? "$(warning)" : "$(shield)";
  const result = parts.length ? parts.join(" ") : summary.errors.length ? "incomplete" : "$(pass) clear";
  statusBar.text = `${icon} Dep Risk ${result}`;
  statusBar.tooltip = [
    headline(summary),
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

async function focusDepRiskView(): Promise<void> {
  for (const command of ["depRisk.sidebar.focus", "depRisk.explorer.focus"]) {
    try {
      await vscode.commands.executeCommand(command);
      return;
    } catch {
      // Cursor may only surface the Explorer-hosted view.
    }
  }
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
