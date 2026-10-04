// Map/cache keys. The ecosystem prefix keeps npm `foo` and PyPI `foo` apart.
/** Key for one exact version, e.g. `npm:lodash@4.17.21`. */
export function packageVersionKey(pkg: { ecosystem: string; name: string; version: string }): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

/** Key for a package regardless of version (registry metadata is per name). */
export function packageNameKey(pkg: { ecosystem: string; name: string }): string {
  return `${pkg.ecosystem}:${pkg.name}`;
}
