import { ManifestDiagnostics } from "./ManifestDiagnostics";
import { findDependencyNameAtOffset, findDependencyOffsets } from "./packageJsonRanges";

export class PackageJsonDiagnostics extends ManifestDiagnostics {
  constructor() {
    super({
      collectionName: "depRisk",
      ecosystem: "npm",
      include: "**/package.json",
      exclude: "**/node_modules/**",
      isManifest: (fileName) => fileName.endsWith("package.json"),
      namesMatch: (a, b) => a === b,
      findOffsets: (text, _file, name) => findDependencyOffsets(text, name),
      nameAtOffset: (text, _file, offset) => findDependencyNameAtOffset(text, offset),
    });
  }
}
