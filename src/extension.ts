/**
 * Extension host wiring. `activate` registers views and commands before any await,
 * because VS Code rejects a view that has no data provider yet. `bindWorkspace`
 * then attaches the scan to the first open folder: its cache, lockfile watcher,
 * and daily rescan.
 *
 * One scan runs at a time. A request that arrives mid-scan collapses into
 * `pendingScan` and runs when the current one finishes; if any queued request
 * asked to bypass the cache, the rerun does too. Results from a cancelled scan,
 * or from a folder that is no longer active, are discarded so they cannot
 * overwrite the scan that belongs to the new folder.
 *
 * State lives at module scope because the extension host calls `activate` once per window.
 */
import * as vscode from "vscode";
import { getConfig } from "./config";
import { applySafeFix } from "./commands/applySafeFix";
import { askAgentFix, copyAgentPrompt } from "./commands/askAgentFix";
import { ManifestCodeActions } from "./diagnostics/ManifestCodeActions";
import { ManifestDiagnostics } from "./diagnostics/ManifestDiagnostics";
import { npmManifest, pythonManifest, WORKSPACE_WATCH_GLOB } from "./diagnostics/manifests";
import { openUrl } from "./util/openUrl";
import { ScanPipeline } from "./scan/pipeline";
import { DepRiskDecorationProvider } from "./tree/decorations";
import { DepRiskTreeProvider } from "./tree/DepRiskTreeProvider";
import { OverviewView } from "./tree/OverviewView";
import { RiskDetailView } from "./tree/RiskDetailView";
import { TIER_ICON_ID, headline } from "./tree/presentation";
import { TIER_ORDER, type RiskResult, type ScanSummary } from "./types";

// Bound folder, the pipeline that owns its cache, and the single in-flight scan.
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
let diagnostics: ManifestDiagnostics;
let pythonDiagnostics: ManifestDiagnostics;
let lockWatcher: vscode.FileSystemWatcher | undefined;

/** Registers all UI and commands synchronously, then binds the first workspace folder in the background. */
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

  diagnostics = new ManifestDiagnostics(npmManifest);
  pythonDiagnostics = new ManifestDiagnostics(pythonManifest);

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
      new ManifestCodeActions([diagnostics, pythonDiagnostics]),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    ),
    // Palette commands have no tree row, so handlers fall back to pickRisk().
    // A tree click passes the row; Apply Safe Fix tooltips pass only name + ecosystem.
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
    vscode.commands.registerCommand("depRisk.applySafeFix", async (item?: { risk?: RiskResult; name?: string; ecosystem?: string }) => {
      // Tooltip links pass only name + ecosystem.
      const risk =
        item?.risk ??
        tree.getSummary()?.results.find(
          (r) => r.signals.pkg.name === item?.name && r.signals.pkg.ecosystem === item?.ecosystem
        ) ??
        (await pickRisk());
      if (risk) {
        await applySafeFix(risk);
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
      const risk = item?.url ? undefined : (item?.risk ?? (await pickRisk()));
      const url = item?.url ?? risk?.advisoryUrls[0] ?? risk?.changelogUrl;
      if (url) {
        await openUrl(url);
        return;
      }
      void vscode.window.showInformationMessage("No advisory or changelog URL is available for this item.");
    }),
    vscode.commands.registerCommand("depRisk.openChangelog", async (item?: { risk: RiskResult }) => {
      const risk = item?.risk ?? (await pickRisk());
      if (risk?.changelogUrl) {
        await openUrl(risk.changelogUrl);
      }
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      void bindWorkspace();
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("depRisk") && activeFolder) {
        // Re-score with the new thresholds, but keep cached OSV and registry
        // responses. Refresh, the lockfile watcher, and the daily timer bypass them.
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

/** Cancels any running scan and releases timers/watchers (other disposables are in context.subscriptions). */
export function deactivate(): void {
  scanCancellation?.cancel();
  if (dailyTimer) {
    clearInterval(dailyTimer);
  }
  lockWatcher?.dispose();
}

/**
 * (Re)binds to the first workspace folder: creates its pipeline, watches manifests/lockfiles
 * for changes, restarts the daily timer and kicks off a scan. With no folder, clears all UI.
 */
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
  await pipeline.cache.init();

  lockWatcher?.dispose();
  lockWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(
      folder,
      WORKSPACE_WATCH_GLOB
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

/** Active folder, or undefined (with an optional warning) when no folder is open. */
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

/** Restarts the periodic forced rescan using `depRisk.dailyRescanHours` (minimum 1h). */
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

/**
 * Single-flight scan. A second call while one is running replaces `pendingScan`
 * (a forced request stays forced) and returns the same promise. The progress
 * bar's cancel token is forwarded onto `scanCancellation`, which a folder
 * change also cancels.
 */
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
      // The progress UI and a folder switch share one token, so either one aborts the scan.
      const cancelSubscription = token.onCancellationRequested(() => cancellation.cancel());
      try {
        statusBar.text = "$(sync~spin) Dep Risk";
        const summary = await scanPipeline.scan(folder, {
          force,
          token: cancellation.token,
          onProgress: (phase, detail) => {
            progress.report({ message: detail ? `${phase}: ${detail}` : phase });
            statusBar.text = `$(sync~spin) Dep Risk: ${phase}`;
          },
        });
        // The folder may have changed during the await. Drop this summary so it
        // cannot replace the results for the folder now bound.
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

/** Status bar: per-tier counts with icons; warning icon when some sources failed. */
function updateStatus(summary: ScanSummary): void {
  const parts = TIER_ORDER.filter((tier) => summary.byTier[tier]).map(
    (tier) => `$(${TIER_ICON_ID[tier]})${summary.byTier[tier]}`
  );
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

/** Quick pick fallback for commands invoked from the palette instead of a tree row. */
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

/** Focuses the Dep Risk view in whichever container exists (Cursor may only show the Explorer one). */
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

/** Trailing-edge debounce. */
function debounce(fn: () => void, ms: number): () => void {
  let t: NodeJS.Timeout | undefined;
  return () => {
    if (t) {
      clearTimeout(t);
    }
    t = setTimeout(fn, ms);
  };
}
