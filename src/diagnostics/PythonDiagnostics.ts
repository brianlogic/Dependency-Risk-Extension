import * as path from "path";
import { namesMatch } from "../util/version";
import { ManifestDiagnostics } from "./ManifestDiagnostics";
import { findPythonDependencyNameAtOffset, findPythonDependencyOffsets } from "./pythonRanges";

export class PythonDiagnostics extends ManifestDiagnostics {
  constructor() {
    super({
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
    });
  }
}
