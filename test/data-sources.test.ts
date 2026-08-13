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

  it("treats last_affected as the next patch when no fixed event exists", () => {
    const summary = toVulnSummary(
      {
        id: "GHSA-last-affected",
        affected: [
          {
            package: { ecosystem: "npm", name: "lodash.template" },
            ranges: [{ type: "SEMVER", events: [{ last_affected: "4.5.0" }] }],
          },
        ],
      },
      "lodash.template"
    );
    assert.deepEqual(summary.fixedVersions, ["4.5.1"]);
  });

  it("does not treat negated exploit language as a public exploit", () => {
    const summary = toVulnSummary(
      {
        id: "GHSA-no-exploit",
        details: "There is no known exploit in the wild for this issue.",
        references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-no-exploit" }],
      },
      "example"
    );
    assert.equal(summary.hasPublicExploit, false);
  });

  it("flags exploit-db references as a public exploit", () => {
    const summary = toVulnSummary(
      {
        id: "GHSA-exploit",
        details: "A remote attacker can execute code.",
        references: [{ type: "EVIDENCE", url: "https://www.exploit-db.com/exploits/12345" }],
      },
      "example"
    );
    assert.equal(summary.hasPublicExploit, true);
  });
});
