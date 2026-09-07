import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { findLockfiles } from "../src/lockfile/npm";
import {
  parsePipfileLock,
  parsePoetryLockfile,
  parseRequirementsFile,
  parseUvLockfile,
  readPythonManifest,
} from "../src/lockfile/python";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { force: true, recursive: true }))
  );
});

async function writeTemp(name: string, contents: string): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-py-"));
  temporaryDirectories.push(directory);
  const filename = path.join(directory, name);
  await writeFile(filename, contents, "utf8");
  return filename;
}

describe("uv.lock parsing", () => {
  it("keeps registry packages and skips git/path sources", async () => {
    const filename = await writeTemp(
      "uv.lock",
      [
        "[[package]]",
        'name = "requests"',
        'version = "2.32.3"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
        "[[package]]",
        'name = "local-tool"',
        'version = "0.1.0"',
        'source = { directory = "packages/local" }',
        "",
        "[[package]]",
        'name = "from-git"',
        'version = "1.0.0"',
        'source = { git = "https://github.com/foo/bar" }',
        "",
      ].join("\n")
    );

    const packages = await parseUvLockfile(filename);
    assert.deepEqual(
      packages.map((pkg) => `${pkg.name}@${pkg.version}`),
      ["requests@2.32.3"]
    );
    assert.equal(packages[0]?.ecosystem, "pypi");
  });
});

describe("poetry.lock parsing", () => {
  it("keeps PyPI simple sources and skips git/directory packages", async () => {
    const filename = await writeTemp(
      "poetry.lock",
      [
        "[[package]]",
        'name = "certifi"',
        'version = "2024.2.2"',
        "",
        "[package.source]",
        'type = "legacy"',
        'url = "https://pypi.org/simple"',
        "",
        "[[package]]",
        'name = "local-tool"',
        'version = "0.1.0"',
        "",
        "[package.source]",
        'type = "directory"',
        'url = ""',
        "",
        "[[package]]",
        'name = "from-git"',
        'version = "1.0.0"',
        "",
        "[package.source]",
        'type = "git"',
        'url = "https://github.com/foo/bar.git"',
        "",
      ].join("\n")
    );

    const packages = await parsePoetryLockfile(filename);
    assert.deepEqual(
      packages.map((pkg) => `${pkg.name}@${pkg.version}`),
      ["certifi@2024.2.2"]
    );
  });
});

describe("Pipfile.lock parsing", () => {
  it("reads default and develop pins and skips VCS entries", async () => {
    const filename = await writeTemp(
      "Pipfile.lock",
      JSON.stringify({
        default: {
          requests: { version: "==2.31.0" },
          local: { version: "==0.1.0", path: "." },
        },
        develop: {
          pytest: { version: "==8.0.0" },
          editable: { git: "https://github.com/foo/bar.git" },
        },
      })
    );

    const packages = await parsePipfileLock(filename);
    assert.deepEqual(
      packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort(),
      ["pytest@8.0.0", "requests@2.31.0"]
    );
  });
});

describe("requirements.txt parsing", () => {
  it("scans == pins and counts unpinned lines", async () => {
    const filename = await writeTemp(
      "requirements.txt",
      [
        "requests==2.31.0",
        "Flask>=2.0",
        "# comment",
        "-r other.txt",
        "git+https://github.com/foo/bar.git",
        "idna==3.7 ; python_version >= '3.8'",
        "",
      ].join("\n")
    );

    const parsed = await parseRequirementsFile(filename);
    assert.deepEqual(
      parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`).sort(),
      ["idna@3.7", "requests@2.31.0"]
    );
    assert.equal(parsed.direct.has("Flask"), true);
    assert.equal(parsed.unpinned, 1);
  });
});

describe("pyproject.toml manifests", () => {
  it("reads PEP 621 dependencies without treating project metadata as packages", async () => {
    const filename = await writeTemp(
      "pyproject.toml",
      [
        "[project]",
        'name = "my-app"',
        'version = "0.1.0"',
        'requires-python = ">=3.10"',
        "keywords = [\"http\", \"client\"]",
        "dependencies = [",
        '  "requests>=2.0",',
        '  "ruamel.yaml==0.18.0",',
        "]",
        "",
        "[dependency-groups]",
        'dev = ["ruff"]',
        "",
      ].join("\n")
    );

    const manifest = await readPythonManifest(filename);
    assert.deepEqual([...manifest.direct].sort(), ["requests", "ruamel.yaml", "ruff"]);
    assert.equal(manifest.requiresPython, ">=3.10");
  });
});

describe("Python lockfile discovery", () => {
  it("finds uv.lock and requirements files and skips .venv", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "dep-risk-py-discover-"));
    temporaryDirectories.push(directory);
    await writeFile(path.join(directory, "uv.lock"), "[[package]]\n", "utf8");
    await writeFile(path.join(directory, "requirements.txt"), "requests==2.31.0\n", "utf8");
    await mkdir(path.join(directory, ".venv", "lib"), { recursive: true });
    await writeFile(path.join(directory, ".venv", "lib", "poetry.lock"), "[[package]]\n", "utf8");

    const found = (await findLockfiles(directory)).map((file) => path.relative(directory, file)).sort();
    assert.deepEqual(found, ["requirements.txt", "uv.lock"]);
  });
});
