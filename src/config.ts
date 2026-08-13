import * as vscode from "vscode";

export interface DepRiskConfig {
  autoScanOnLockfileChange: boolean;
  dailyRescanHours: number;
  staleMajorVersionsBehind: number;
  maintainerInactiveMonths: number;
  eolHorizonMonths: number;
  scanTransitive: boolean;
  maxPackagesPerScan: number;
}

export function getConfig(): DepRiskConfig {
  const cfg = vscode.workspace.getConfiguration("depRisk");
  return {
    autoScanOnLockfileChange: cfg.get("autoScanOnLockfileChange", true),
    dailyRescanHours: cfg.get("dailyRescanHours", 24),
    staleMajorVersionsBehind: cfg.get("staleMajorVersionsBehind", 2),
    maintainerInactiveMonths: cfg.get("maintainerInactiveMonths", 18),
    eolHorizonMonths: cfg.get("eolHorizonMonths", 6),
    scanTransitive: cfg.get("scanTransitive", true),
    maxPackagesPerScan: cfg.get("maxPackagesPerScan", 1000),
  };
}
