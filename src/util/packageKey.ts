export function packageVersionKey(pkg: { ecosystem: string; name: string; version: string }): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

export function packageNameKey(pkg: { ecosystem: string; name: string }): string {
  return `${pkg.ecosystem}:${pkg.name}`;
}
