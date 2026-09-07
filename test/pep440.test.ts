import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  comparePep440,
  isQueryablePypiVersion,
  pep440MajorsBehind,
  pep440NextPatch,
  pickPep440SafeBumpForAdvisories,
} from "../src/util/pep440";
import { namesMatch } from "../src/util/version";

describe("PEP 440", () => {
  it("orders pre, final, and post releases", () => {
    assert.ok((comparePep440("1.0.dev1", "1.0a1") ?? 0) < 0);
    assert.ok((comparePep440("1.0a1", "1.0") ?? 0) < 0);
    assert.ok((comparePep440("1.0", "1.0.post1") ?? 0) < 0);
    assert.ok((comparePep440("1.0.post1", "1.0") ?? 0) > 0);
  });

  it("counts major versions behind", () => {
    assert.equal(pep440MajorsBehind("1.2.3", "3.0.0"), 2);
    assert.equal(pep440MajorsBehind("2.1.0", "2.9.0"), 0);
  });

  it("derives the next patch after last_affected", () => {
    assert.equal(pep440NextPatch("2.31.0"), "2.31.1");
    assert.equal(pep440NextPatch("1.0"), "1.0.1");
  });

  it("picks a same-major fix when one exists", () => {
    assert.equal(
      pickPep440SafeBumpForAdvisories("2.31.0", [
        ["2.32.0", "3.0.0"],
        ["2.31.1"],
      ]),
      "2.32.0"
    );
  });

  it("rejects VCS and path versions for OSV queries", () => {
    assert.equal(isQueryablePypiVersion("2.31.0"), true);
    assert.equal(isQueryablePypiVersion("1.0.dev1"), true);
    assert.equal(isQueryablePypiVersion("git+https://github.com/foo/bar.git"), false);
    assert.equal(isQueryablePypiVersion("file:../local"), false);
  });

  it("normalizes PyPI names for matching", () => {
    assert.equal(namesMatch("Foo_Bar", "foo-bar"), true);
    assert.equal(namesMatch("ruamel.yaml", "ruamel-yaml"), true);
    assert.equal(namesMatch("PIL", "Pillow"), false);
  });
});
