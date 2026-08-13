import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  pickSafeBump,
  pickSafeBumpForAdvisories,
} from "../src/util/semver";

describe("safe upgrade targets", () => {
  it("prefers the smallest patch fix for one advisory", () => {
    assert.equal(
      pickSafeBump("4.17.1", "5.0.0", ["4.17.2", "4.19.2"]),
      "4.17.2"
    );
  });

  it("chooses a target that clears every advisory", () => {
    assert.equal(
      pickSafeBumpForAdvisories("1.2.3", [
        ["1.2.4", "2.0.1"],
        ["1.3.2", "2.0.2"],
      ]),
      "1.3.2"
    );
  });

  it("does not claim a safe target when one advisory is unfixed", () => {
    assert.equal(
      pickSafeBumpForAdvisories("1.2.3", [["1.2.4"], []]),
      undefined
    );
  });

  it("uses the smallest major jump when no same-major fix exists", () => {
    assert.equal(
      pickSafeBumpForAdvisories("1.9.0", [["2.0.1", "3.0.0"]]),
      "2.0.1"
    );
  });
});
