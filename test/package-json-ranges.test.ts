import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  findDependencyNameAtOffset,
  findDependencyOffsets,
} from "../src/diagnostics/packageJsonRanges";

const manifest = `{
  "dependencies": {
    "lodash": "^4.17.21",
    "@scope/pkg": "1.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
`;

describe("package.json dependency ranges", () => {
  it("locates a direct dependency property", () => {
    const range = findDependencyOffsets(manifest, "lodash");
    assert.ok(range);
    assert.equal(manifest.slice(range.start, range.end).includes("lodash"), true);
  });

  it("resolves the package name at an offset inside the property", () => {
    const range = findDependencyOffsets(manifest, "@scope/pkg");
    assert.ok(range);
    const mid = Math.floor((range.start + range.end) / 2);
    assert.equal(findDependencyNameAtOffset(manifest, mid), "@scope/pkg");
  });

  it("finds devDependencies", () => {
    assert.ok(findDependencyOffsets(manifest, "typescript"));
  });
});
