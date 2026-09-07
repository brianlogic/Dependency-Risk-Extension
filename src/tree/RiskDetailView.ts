import * as vscode from "vscode";
import { excerptDetails, readingLinks } from "../osv/urls";
import { TIER_LABEL, type RiskResult, type RiskTier, type VulnSummary } from "../types";
import { packageGlance, usageLabel } from "./presentation";

/**
 * Editor tab that lists every advisory on a package, with click-through to the source.
 */
export class RiskDetailView {
  private static current: RiskDetailView | undefined;
  private risk: RiskResult;
  private readonly panel: vscode.WebviewPanel;

  static show(risk: RiskResult): void {
    if (RiskDetailView.current) {
      RiskDetailView.current.update(risk);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "depRisk.detail",
      panelTitle(risk),
      vscode.ViewColumn.Beside,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    RiskDetailView.current = new RiskDetailView(panel, risk);
  }

  private constructor(panel: vscode.WebviewPanel, risk: RiskResult) {
    this.panel = panel;
    this.risk = risk;
    this.panel.webview.onDidReceiveMessage((message: { type?: string; url?: string }) => {
      if (message.type === "openUrl" && message.url) {
        void vscode.env.openExternal(vscode.Uri.parse(message.url));
        return;
      }
      if (message.type === "askAgent") {
        void vscode.commands.executeCommand("depRisk.askAgentFix", { risk: this.risk });
      }
    });
    this.panel.onDidDispose(() => {
      if (RiskDetailView.current === this) {
        RiskDetailView.current = undefined;
      }
    });
    this.render();
  }

  private update(risk: RiskResult): void {
    this.risk = risk;
    this.panel.title = panelTitle(risk);
    this.render();
    this.panel.reveal(vscode.ViewColumn.Beside, true);
  }

  private render(): void {
    this.panel.webview.html = renderDetail(this.panel.webview, this.risk);
  }
}

function panelTitle(risk: RiskResult): string {
  return `${risk.signals.pkg.name}@${risk.signals.pkg.version}`;
}

function renderDetail(webview: vscode.Webview, risk: RiskResult): string {
  const nonce = String(Date.now());
  const pkg = risk.signals.pkg;
  const vulns = risk.signals.vulns;
  const issues = vulns.length
    ? vulns.map((vuln) => vulnCard(vuln)).join("")
    : `<p class="muted">No OSV advisories on this package. ${escapeHtml(risk.reasons[0] ?? "See the notes below.")}</p>`;

  const bump = risk.recommendedBump
    ? `<div class="fix">Safe target <code>${escapeHtml(risk.recommendedBump)}</code>${
        risk.isMajorBump ? " <span class=\"warn\">major</span>" : ""
      }</div>`
    : "";

  const extraLinks: string[] = [];
  if (risk.changelogUrl) {
    extraLinks.push(linkButton(risk.changelogUrl, risk.tier === "eol" ? "Open EOL page" : "Changelog"));
  }
  const ask =
    risk.tier === "eol"
      ? ""
      : `<button type="button" class="secondary" data-action="ask">Ask Agent to Upgrade + Fix</button>`;

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
    }
    body {
      margin: 0;
      padding: 16px 18px 24px;
      font-family: var(--vscode-font-family);
      font-size: 13px;
      color: var(--vscode-foreground);
      line-height: 1.45;
    }
    h1 { margin: 0 0 4px; font-size: 16px; }
    h2 { margin: 18px 0 8px; font-size: 13px; font-weight: 600; }
    .muted { opacity: 0.72; }
    .chip {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 2px 7px;
      border-radius: 999px;
      color: var(--vscode-editor-background);
      background: var(--${cssVar(risk.tier)});
      text-transform: uppercase;
    }
    .meta { margin: 6px 0 10px; }
    .fix { margin: 8px 0 12px; }
    .warn { color: var(--vscode-charts-orange, #e2a203); font-weight: 600; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 8px; }
    button, a.btn {
      display: inline-flex;
      align-items: center;
      border: 0;
      border-radius: 6px;
      padding: 5px 10px;
      font: inherit;
      cursor: pointer;
      color: var(--vscode-button-foreground);
      background: var(--vscode-button-background);
      text-decoration: none;
    }
    button.secondary, a.btn.secondary {
      color: var(--vscode-button-secondaryForeground);
      background: var(--vscode-button-secondaryBackground);
    }
    button:hover, a.btn:hover { outline: 1px solid var(--vscode-focusBorder); }
    .card {
      border: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.3));
      border-radius: 8px;
      padding: 10px 12px;
      margin: 0 0 10px;
      background: var(--vscode-editor-inactiveSelectionBackground, transparent);
    }
    .card h3 { margin: 0 0 4px; font-size: 13px; }
    .ids { opacity: 0.75; font-size: 12px; margin: 0 0 6px; }
    .details { margin: 8px 0; }
    .links { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    ul.notes { margin: 0; padding-left: 18px; }
    code { font-size: 12px; }
  </style>
</head>
<body>
  <div><span class="chip">${escapeHtml(TIER_LABEL[risk.tier])}</span></div>
  <h1><code>${escapeHtml(pkg.name)}</code> ${escapeHtml(pkg.version)}</h1>
  <p class="meta muted">${escapeHtml(packageGlance(risk))} · ${escapeHtml(usageLabel(risk))}${
    pkg.ecosystem === "pypi" ? " · PyPI" : " · npm"
  }</p>
  ${bump}
  <div class="actions">${ask}</div>
  <h2>${vulns.length === 1 ? "1 advisory" : `${vulns.length} advisories`}</h2>
  ${issues}
  ${
    risk.reasons.length
      ? `<h2>Notes</h2><ul class="notes">${risk.reasons
          .map((reason) => `<li>${escapeHtml(reason)}</li>`)
          .join("")}</ul>`
      : ""
  }
  ${extraLinks.length ? `<div class="actions" style="margin-top:14px">${extraLinks.join("")}</div>` : ""}
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.body.addEventListener("click", (event) => {
      const target = event.target.closest("[data-url], [data-action]");
      if (!target) { return; }
      event.preventDefault();
      if (target.dataset.action === "ask") {
        vscode.postMessage({ type: "askAgent" });
        return;
      }
      if (target.dataset.url) {
        vscode.postMessage({ type: "openUrl", url: target.dataset.url });
      }
    });
  </script>
</body>
</html>`;
}

function vulnCard(vuln: VulnSummary): string {
  const aliases = [vuln.id, ...vuln.aliases.filter((alias) => alias !== vuln.id)].join(" · ");
  const bits = [
    vuln.severity && vuln.severity !== "UNKNOWN" ? vuln.severity : undefined,
    vuln.cvssScore != null ? `CVSS ${vuln.cvssScore}` : undefined,
    vuln.hasPublicExploit ? "public exploit" : undefined,
    vuln.fixedVersions[0] ? `fixed in ${vuln.fixedVersions.join(", ")}` : undefined,
  ].filter((bit): bit is string => !!bit);
  const excerpt = excerptDetails(vuln.details);
  const [primary, ...more] = readingLinks(vuln);
  const links = [
    primary ? linkButton(primary.url, "Read full advisory") : "",
    ...more.map((link) => linkButton(link.url, link.label, "secondary")),
  ].join("");

  return `<article class="card">
    <h3>${escapeHtml(vuln.summary || vuln.id)}</h3>
    <div class="ids">${escapeHtml(aliases)}${bits.length ? ` — ${escapeHtml(bits.join(" · "))}` : ""}</div>
    ${excerpt ? `<p class="details">${escapeHtml(excerpt)}</p>` : ""}
    <div class="links">${links}</div>
  </article>`;
}

function linkButton(url: string, label: string, kind?: "secondary"): string {
  return `<button type="button" class="btn${kind ? ` ${kind}` : ""}" data-url="${escapeAttr(url)}">${escapeHtml(label)}</button>`;
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
