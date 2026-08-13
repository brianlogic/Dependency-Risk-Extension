import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { extractImportedPackageNames } from "../src/graph/specifiers";

describe("import extraction", () => {
  it("collects runtime imports and requires", () => {
    const names = extractImportedPackageNames(`
      import _ from "lodash";
      const minimist = require("minimist");
      export { foo } from "@scope/pkg/subpath";
    `);
    assert.deepEqual(names, ["lodash", "minimist", "@scope/pkg"]);
  });

  it("ignores type-only and relative imports", () => {
    const names = extractImportedPackageNames(`
      import type { Foo } from "typescript";
      export type { Bar } from "unused-types";
      import local from "./local";
      import fs from "node:fs";
    `);
    assert.deepEqual(names, []);
  });
});
