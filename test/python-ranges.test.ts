import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  findPythonDependencyNameAtOffset,
  findPythonDependencyOffsets,
} from "../src/diagnostics/pythonRanges";

const requirements = `requests==2.31.0
Flask>=2.0
# comment
idna==3.7
`;

const pyproject = `[project]
name = "demo"
dependencies = [
  "requests>=2.0",
  "ruamel.yaml==0.18.0",
]
`;

describe("Python dependency ranges", () => {
  it("locates a pinned requirements line", () => {
    const range = findPythonDependencyOffsets(requirements, "requirements.txt", "requests");
    assert.ok(range);
    assert.equal(requirements.slice(range.start, range.end).includes("requests"), true);
  });

  it("matches normalized PyPI names", () => {
    const range = findPythonDependencyOffsets(pyproject, "pyproject.toml", "ruamel-yaml");
    assert.ok(range);
    const mid = Math.floor((range.start + range.end) / 2);
    assert.equal(findPythonDependencyNameAtOffset(pyproject, "pyproject.toml", mid), "ruamel.yaml");
  });

  it("resolves the package name on a requirements line", () => {
    const range = findPythonDependencyOffsets(requirements, "requirements.txt", "Flask");
    assert.ok(range);
    assert.equal(
      findPythonDependencyNameAtOffset(requirements, "requirements.txt", range.start),
      "Flask"
    );
  });
});
