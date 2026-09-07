import * as vscode from "vscode";
import { headline, packageGlance } from "./presentation";
import { TIER_LABEL, TIER_ORDER, type RiskResult, type RiskTier, type ScanSummary } from "../types";

export class OverviewView implements vscode.WebviewViewProvider {
  static readonly viewType = "depRisk.overview";

  private view?: vscode.WebviewView;
  private summary?: ScanSummary;

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = { enableScripts: true };
    webviewView.webview.onDidReceiveMessage((message: { type?: string; name?: string; version?: string }) => {
      if (message.type !== "open" || !message.name) {
        return;
      }
      const risk = this.summary?.results.find(
        (item) => item.signals.pkg.name === message.name && item.signals.pkg.version === message.version
      );
      if (!risk) {
        return;
      }
      void vscode.commands.executeCommand("depRisk.showRisk", { risk });
    });
    this.render();
  }

  setSummary(summary: ScanSummary | undefined): void {
    this.summary = summary;
    this.render();
  }

  private render(): void {
    if (!this.view) {
      return;
    }
    this.view.webview.html = renderOverview(this.view.webview, this.summary);
  }
}

function renderOverview(webview: vscode.Webview, summary: ScanSummary | undefined): string {
  const nonce = String(Date.now());
  const body = summary ? overviewBody(summary) : `<p class="muted">Scan a folder with a lockfile to see the risk mix.</p>`;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';" />
  <style>
    :root {
      --crit: var(--vscode-charts-red, #f14c4c);
      --high: var(--vscode-charts-orange, #e2a203);
      --stale: var(--vscode-charts-yellow, #cca700);
      --eol: var(--vscode-charts-blue, #3794ff);
      --clear: var(--vscode-charts-green, #3fc56b);
    }
    body {
      margin: 0;
      padding: 10px 12px 12px;
      font-family: var(--vscode-font-family);
      font-size: 12px;
      color: var(--vscode-foreground);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 13px;
      font-weight: 600;
    }
    .muted { opacity: 0.7; }
    .bar {
      display: flex;
      height: 8px;
      border-radius: 999px;
      overflow: hidden;
      background: var(--vscode-editorWidget-border, rgba(127,127,127,0.25));
      margin: 0 0 10px;
    }
    .seg { min-width: 2px; }
    .seg.critical { background: var(--crit); }
    .seg.high { background: var(--high); }
    .seg.stale { background: var(--stale); }
    .seg.eol { background: var(--eol); }
    .seg.clear { background: var(--clear); }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      margin: 0 0 10px;
    }
    .swatch {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-right: 5px;
    }
    .list { display: flex; flex-direction: column; gap: 6px; }
    button.row {
      display: flex;
      align-items: baseline;
      gap: 8px;
      width: 100%;
      text-align: left;
      border: 0;
      border-radius: 6px;
      padding: 6px 8px;
      color: inherit;
      background: var(--vscode-list-hoverBackground, transparent);
      cursor: pointer;
      font: inherit;
    }
    button.row:hover { outline: 1px solid var(--vscode-focusBorder); }
    .name { font-weight: 600; }
    .meta { opacity: 0.75; flex: 1; }
    .chip {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 1px 6px;
      border-radius: 999px;
      color: var(--vscode-editor-background);
    }
    .chip.critical { background: var(--crit); }
    .chip.high { background: var(--high); }
    .chip.stale { background: var(--stale); color: #111; }
    .chip.eol { background: var(--eol); }
  </style>
</head>
<body>
  ${body}
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    for (const button of document.querySelectorAll("button.row")) {
      button.addEventListener("click", () => {
        vscode.postMessage({
          type: "open",
          name: button.dataset.name,
          version: button.dataset.version,
        });
      });
    }
  </script>
</body>
</html>`;
}

function overviewBody(summary: ScanSummary): string {
  const total =
    summary.byTier.critical + summary.byTier.high + summary.byTier.stale + summary.byTier.eol;
  const barTotal = Math.max(total, 1);
  const segments = (["critical", "high", "stale", "eol"] as RiskTier[])
    .filter((tier) => summary.byTier[tier] > 0)
    .map((tier) => {
      const width = Math.max(6, Math.round((summary.byTier[tier] / barTotal) * 100));
      return `<div class="seg ${tier}" style="width:${width}%" title="${TIER_LABEL[tier]}: ${summary.byTier[tier]}"></div>`;
    })
    .join("");

  const legend = TIER_ORDER.filter((tier) => tier !== "clear" && summary.byTier[tier] > 0)
    .map(
      (tier) =>
        `<span><span class="swatch" style="background:var(--${cssVar(tier)})"></span>${summary.byTier[tier]} ${TIER_LABEL[tier]}</span>`
    )
    .join("");

  const top = summary.results.filter((risk) => risk.tier === "critical" || risk.tier === "high").slice(0, 5);
  const rows = top.length
    ? top.map((risk) => packageRow(risk)).join("")
    : `<p class="muted">No critical or high issues. ${escapeHtml(headline(summary))}.</p>`;

  const scanned = `${summary.packageCount} packages · ${new Date(summary.scannedAt).toLocaleTimeString()}`;
  const errors = summary.errors.length
    ? `<p class="muted">${summary.errors.length} source warning${summary.errors.length === 1 ? "" : "s"}</p>`
    : "";

  return `
    <h1>${escapeHtml(headline(summary))}</h1>
    <div class="bar">${segments || `<div class="seg clear" style="width:100%"></div>`}</div>
    <div class="legend muted">${legend || "No open risks"}</div>
    <div class="list">${rows}</div>
    <p class="muted">${escapeHtml(scanned)}</p>
    ${errors}
  `;
}

function packageRow(risk: RiskResult): string {
  const pkg = risk.signals.pkg;
  return `<button class="row" type="button" data-name="${escapeAttr(pkg.name)}" data-version="${escapeAttr(pkg.version)}">
    <span class="chip ${risk.tier}">${risk.tier === "critical" ? "CRIT" : "HIGH"}</span>
    <span class="name">${escapeHtml(pkg.name)}</span>
    <span class="meta">${escapeHtml(packageGlance(risk))}</span>
  </button>`;
}

function cssVar(tier: RiskTier): string {
  return tier === "critical" ? "crit" : tier;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function escapeAttr(value: string): string {
  return escapeHtml(value);
}
