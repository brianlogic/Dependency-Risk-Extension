import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import {
  findLockfiles,
  isHoistedOrWorkspaceInstall,
  lockfileKind,
  parseNpmLockfile,
} from "../src/lockfile/npm";

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

describe("lockfile classification", () => {
  it("recognizes unsupported lockfiles so the scan can warn about them", () => {
    for (const name of ["pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "Pipfile.lock"]) {
      assert.equal(lockfileKind(name), "unsupported", name);
    }
    assert.equal(lockfileKind("package-lock.json"), "npm");
    assert.equal(lockfileKind("uv.lock"), "uv");
  });
});

describe("lockfile discovery", () => {
  it("finds nested lockfiles and skips node_modules", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-discover-"));
    temporaryDirectories.push(directory);
    await writeFile(path.join(directory, "package-lock.json"), "{}", "utf8");
    await mkdir(path.join(directory, "apps", "web"), { recursive: true });
    await writeFile(path.join(directory, "apps", "web", "yarn.lock"), "lodash@^4.0.0:\n  version \"4.17.21\"\n", "utf8");
    await mkdir(path.join(directory, "node_modules", "foo"), { recursive: true });
    await writeFile(path.join(directory, "node_modules", "foo", "package-lock.json"), "{}", "utf8");

    const found = (await findLockfiles(directory)).map((file) => path.relative(directory, file)).sort();
    assert.deepEqual(found, ["apps/web/yarn.lock", "package-lock.json"]);
  });
});
