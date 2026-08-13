import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DepRiskConfig } from "../src/config";
import { scorePackage } from "../src/score/risk";
import type { PackageSignals, VulnSummary } from "../src/types";

const config: DepRiskConfig = {
  autoScanOnLockfileChange: true,
  dailyRescanHours: 24,
  staleMajorVersionsBehind: 2,
  maintainerInactiveMonths: 18,
  eolHorizonMonths: 6,
  scanTransitive: true,
  maxPackagesPerScan: 1000,
};

function vulnerability(
  id: string,
  fixedVersions: string[],
  severity: VulnSummary["severity"] = "HIGH"
): VulnSummary {
  return {
    id,
    aliases: [],
    summary: `${id} summary`,
    severity,
    hasPublicExploit: false,
    fixedVersions,
    references: [],
  };
}

function signals(vulns: VulnSummary[], imported = false): PackageSignals {
  return {
    pkg: {
      name: "example",
      version: "1.2.3",
      ecosystem: "npm",
      direct: imported,
      imported,
      usage: imported ? "direct" : "transitive",
    },
    vulns,
    latestVersion: "3.0.0",
  };
}

describe("risk scoring", () => {
  it("elevates a high vulnerability on an imported package", () => {
    const result = scorePackage(
      signals([vulnerability("GHSA-test", ["1.2.4"])], true),
      config
    );
    assert.equal(result.tier, "critical");
    assert.equal(result.recommendedBump, "1.2.4");
  });

  it("keeps a transitive-only high vulnerability in the high tier", () => {
    const result = scorePackage(
      signals([vulnerability("GHSA-test", ["1.2.4"])]),
      config
    );
    assert.equal(result.tier, "high");
  });

  it("does not recommend latest when an advisory has no known fix", () => {
    const result = scorePackage(
      signals([
        vulnerability("GHSA-fixed", ["1.2.4"]),
        vulnerability("GHSA-unfixed", []),
      ]),
      config
    );
    assert.equal(result.recommendedBump, undefined);
  });
});
