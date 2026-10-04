import * as path from "path";
import { namesMatch } from "../util/version";
import type { ManifestConfig } from "./ManifestDiagnostics";
import { findDependencyNameAtOffset, findDependencyOffsets } from "./packageJsonRanges";
import { findPythonDependencyNameAtOffset, findPythonDependencyOffsets } from "./pythonRanges";

// ManifestConfig for each ecosystem. npm names are exact; Python names are PEP 503-normalized.
export const npmManifest: ManifestConfig = {
  collectionName: "depRisk",
  ecosystem: "npm",
  include: "**/package.json",
  exclude: "**/node_modules/**",
  isManifest: (fileName) => fileName.endsWith("package.json"),
  namesMatch: (a, b) => a === b,
  findOffsets: (text, _file, name) => findDependencyOffsets(text, name),
  nameAtOffset: (text, _file, offset) => findDependencyNameAtOffset(text, offset),
};

export const pythonManifest: ManifestConfig = {
  collectionName: "depRisk.python",
  ecosystem: "pypi",
  include: "{**/requirements*.txt,**/pyproject.toml}",
  exclude: "{**/node_modules/**,**/.venv/**,**/venv/**,**/.tox/**}",
  isManifest: (fileName) => {
    const base = path.basename(fileName);
    return base === "pyproject.toml" || /^requirements.*\.txt$/i.test(base);
  },
  namesMatch,
  findOffsets: findPythonDependencyOffsets,
  nameAtOffset: findPythonDependencyNameAtOffset,
};

/** Lockfiles, manifests, and runtime pins that should trigger a rescan. */
export const WORKSPACE_WATCH_GLOB =
  "{package.json,**/package.json,**/package-lock.json,**/npm-shrinkwrap.json,**/uv.lock,**/poetry.lock,**/requirements*.txt,**/pyproject.toml,.nvmrc,.node-version,.python-version,runtime.txt}";
