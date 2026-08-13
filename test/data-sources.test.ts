import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseDeclaredNodeMajor } from "../src/eol/endoflife";
import { parseCvssScore, toVulnSummary } from "../src/osv/client";

describe("data-source normalization", () => {
  it("calculates a numerical score from an OSV CVSS 3.1 vector", () => {
    const score = parseCvssScore({
      severity: [
        {
          type: "CVSS_V3",
          score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
      ],
    });
    assert.equal(score, 9.8);
  });

  it("accepts unambiguous Node runtime declarations", () => {
    assert.equal(parseDeclaredNodeMajor("18"), "18");
    assert.equal(parseDeclaredNodeMajor("^20.11.0"), "20");
    assert.equal(parseDeclaredNodeMajor("v22.3.0"), "22");
  });

  it("rejects compatibility ranges that do not identify the runtime", () => {
    assert.equal(parseDeclaredNodeMajor(">=18"), undefined);
    assert.equal(parseDeclaredNodeMajor("18 || 20"), undefined);
  });

  it("extracts fixes only from the matching npm affected block", () => {
    const summary = toVulnSummary(
      {
        id: "GHSA-test",
        affected: [
          {
            package: { ecosystem: "PyPI", name: "example" },
            ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "99.0.0" }] }],
          },
          {
            package: { ecosystem: "npm", name: "other" },
            ranges: [{ type: "SEMVER", events: [{ fixed: "88.0.0" }] }],
          },
          {
            package: { ecosystem: "npm", name: "example" },
            ranges: [{ type: "SEMVER", events: [{ fixed: "1.2.4" }] }],
          },
        ],
      },
      "example"
    );
    assert.deepEqual(summary.fixedVersions, ["1.2.4"]);
  });
});
