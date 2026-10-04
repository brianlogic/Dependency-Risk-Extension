import type { Ecosystem } from "../types";

export interface LockPackage {
  name: string;
  version: string;
  /** Dependency path key from lockfile (e.g. node_modules/lodash). */
  lockPath: string;
  ecosystem?: Ecosystem;
}
