import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDowngrade } from "../src/util/version";
import type { RiskResult } from "../src/types";

const risk = (version: string, to: string, ecosystem: "npm" | "pypi") =>
  ({ recommendedBump: to, signals: { pkg: { version, ecosystem } } }) as unknown as RiskResult;

describe("isDowngrade", () => {
  it("detects backwards targets for npm and pypi", () => {
    assert.equal(isDowngrade(risk("2.0.0", "1.9.9", "npm")), true);
    assert.equal(isDowngrade(risk("1.0.0", "1.0.1", "npm")), false);
    assert.equal(isDowngrade(risk("2.0", "1.9", "pypi")), true);
    assert.equal(isDowngrade(risk("1.0", "1.0.1", "pypi")), false);
    assert.equal(isDowngrade({ signals: { pkg: { version: "1", ecosystem: "npm" } } } as unknown as RiskResult), false);
  });
});
