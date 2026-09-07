import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { headline, packageGlance, reasonIcon, worstTier } from "../src/tree/presentation";
import type { RiskResult, ScanSummary } from "../src/types";

function summary(byTier: Partial<ScanSummary["byTier"]>): ScanSummary {
  return {
    scannedAt: Date.now(),
    packageCount: 10,
    byTier: { critical: 0, high: 0, stale: 0, eol: 0, clear: 0, ...byTier },
    results: [],
    errors: [],
  };
}

function risk(overrides: Partial<RiskResult> = {}): RiskResult {
  return {
    tier: "high",
    reasons: ["Usage: imported in workspace"],
    isMajorBump: false,
    advisoryIds: ["GHSA-test"],
    advisoryUrls: [],
    signals: {
      pkg: {
        name: "lodash",
        version: "4.17.21",
        ecosystem: "npm",
        direct: true,
        imported: true,
        usage: "direct",
      },
      vulns: [{ id: "GHSA-test", aliases: [], summary: "ReDoS", severity: "HIGH", cvssScore: 7.5, hasPublicExploit: false, fixedVersions: ["4.17.22"], references: [] }],
    },
    ...overrides,
  };
}

describe("tree presentation", () => {
  it("summarizes counts and picks the worst open tier", () => {
    const scan = summary({ critical: 2, high: 4, stale: 1 });
    assert.equal(headline(scan), "2 critical  ·  4 high  ·  1 stale");
    assert.equal(worstTier(scan), "critical");
    assert.equal(worstTier(summary({})), "clear");
  });

  it("shows usage and CVSS at a glance", () => {
    assert.equal(packageGlance(risk()), "imported · CVSS 7.5");
  });

  it("picks reason icons from the text", () => {
    assert.equal(reasonIcon("Public exploit references found"), "flame");
    assert.equal(reasonIcon("Safe target: 4.17.22"), "arrow-up");
    assert.equal(reasonIcon("Usage: imported in workspace"), "code");
  });
});
