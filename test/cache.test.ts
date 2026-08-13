import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { RiskCache } from "../src/cache/store";

describe("persistent cache", () => {
  it("atomically replaces an existing cache file", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-cache-"));
    const filename = path.join(directory, "cache.json");
    try {
      const cache = new RiskCache(filename);
      await cache.init();
      cache.setPackageHit("one", "1.0.0", ["GHSA-one"], {
        "GHSA-one": "2026-01-01T00:00:00Z",
      });
      await cache.flush();

      cache.setPackageHit("two", "2.0.0", [], {});
      await cache.flush();

      const reloaded = new RiskCache(filename);
      await reloaded.init();
      assert.deepEqual(reloaded.getPackageHit("one", "1.0.0")?.vulnIds, [
        "GHSA-one",
      ]);
      assert.deepEqual(reloaded.getPackageHit("two", "2.0.0")?.vulnIds, []);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });
});
