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
    assert.equal(result?.tier, "critical");
    assert.equal(result?.recommendedBump, "1.2.4");
  });

  it("keeps a transitive-only high vulnerability in the high tier", () => {
    const result = scorePackage(
      signals([vulnerability("GHSA-test", ["1.2.4"])]),
      config
    );
    assert.equal(result?.tier, "high");
  });

  it("treats a public exploit, CVSS >= 9, or a CRITICAL label as critical even when not imported", () => {
    const exploit = { ...vulnerability("A", ["1.2.4"], "LOW"), hasPublicExploit: true };
    const cvss = { ...vulnerability("B", ["1.2.4"], undefined), cvssScore: 9.1 };
    for (const vuln of [exploit, cvss, vulnerability("C", ["1.2.4"], "CRITICAL")]) {
      assert.equal(scorePackage(signals([vuln]), config)?.tier, "critical", vuln.id);
    }
  });

  it("keeps a moderate advisory high on an imported package, but a HIGH label with a low CVSS is still elevated", () => {
    assert.equal(scorePackage(signals([vulnerability("M", ["1.2.4"], "MODERATE")], true), config)?.tier, "high");
    const lowScoreHigh = { ...vulnerability("H", ["1.2.4"], "HIGH"), cvssScore: 5 };
    assert.equal(scorePackage(signals([lowScoreHigh], true), config)?.tier, "critical");
  });

  it("returns nothing for a package with no advisories and no stale signals", () => {
    assert.equal(scorePackage({ ...signals([]), latestVersion: "1.2.4" }, config), undefined);
  });

  it("does not recommend latest when an advisory has no known fix", () => {
    const result = scorePackage(
      signals([
        vulnerability("GHSA-fixed", ["1.2.4"]),
        vulnerability("GHSA-unfixed", []),
      ]),
      config
    );
    assert.equal(result?.recommendedBump, undefined);
  });
});
