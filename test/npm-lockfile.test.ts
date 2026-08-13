import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { isHoistedOrWorkspaceInstall, parseNpmLockfile } from "../src/lockfile/npm";
import { parseYarnLockfile } from "../src/lockfile/yarn";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    )
  );
});

async function writeLockfile(contents: unknown): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-"));
  temporaryDirectories.push(directory);
  const filename = path.join(directory, "package-lock.json");
  await writeFile(filename, JSON.stringify(contents), "utf8");
  return filename;
}

describe("npm lockfile parsing", () => {
  it("keeps the top-level path when the same version is also nested", async () => {
    const filename = await writeLockfile({
      lockfileVersion: 3,
      packages: {
        "node_modules/parent/node_modules/shared": { version: "1.0.0" },
        "node_modules/shared": { version: "1.0.0" },
      },
    });

    const packages = await parseNpmLockfile(filename);
    assert.deepEqual(packages, [
      { name: "shared", version: "1.0.0", lockPath: "node_modules/shared" },
    ]);
  });

  it("preserves the full nested path in lockfile v1", async () => {
    const filename = await writeLockfile({
      lockfileVersion: 1,
      dependencies: {
        parent: {
          version: "1.0.0",
          dependencies: {
            child: {
              version: "2.0.0",
              dependencies: {
                leaf: { version: "3.0.0" },
              },
            },
          },
        },
      },
    });

    const packages = await parseNpmLockfile(filename);
    assert.equal(
      packages.find((pkg) => pkg.name === "leaf")?.lockPath,
      "node_modules/parent/node_modules/child/node_modules/leaf"
    );
  });

  it("infers names from workspace node_modules paths", async () => {
    const filename = await writeLockfile({
      lockfileVersion: 3,
      packages: {
        "packages/app/node_modules/lodash": { version: "4.17.20" },
      },
    });

    const packages = await parseNpmLockfile(filename);
    assert.deepEqual(packages, [
      {
        name: "lodash",
        version: "4.17.20",
        lockPath: "packages/app/node_modules/lodash",
      },
    ]);
    assert.equal(isHoistedOrWorkspaceInstall("packages/app/node_modules/lodash", "lodash"), true);
    assert.equal(
      isHoistedOrWorkspaceInstall("node_modules/parent/node_modules/lodash", "lodash"),
      false
    );
  });
});

describe("Yarn lockfile parsing", () => {
  it("reports Yarn Berry instead of returning an empty inventory", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-yarn-"));
    temporaryDirectories.push(directory);
    const filename = path.join(directory, "yarn.lock");
    await writeFile(filename, "__metadata:\n  version: 8\n", "utf8");

    await assert.rejects(
      parseYarnLockfile(filename),
      /Yarn Berry \(v2\+\) lockfiles are not supported/
    );
  });
});
