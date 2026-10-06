// npm-side version math on top of the `semver` package (`coerce` tolerates ranges and prefixes).
import * as semver from "semver";

/** Major versions between `current` and `latest` (never negative); undefined if unparsable. */
export function majorsBehind(current: string, latest: string): number | undefined {
  const a = semver.coerce(current);
  const b = semver.coerce(latest);
  if (!a || !b) {
    return undefined;
  }
  return Math.max(0, b.major - a.major);
}

export function isDowngrade(from: string, to: string): boolean {
  const a = semver.coerce(from);
  const b = semver.coerce(to);
  return !!a && !!b && semver.lt(b, a);
}

export function isMajorBump(from: string, to: string): boolean {
  const a = semver.coerce(from);
  const b = semver.coerce(to);
  if (!a || !b) {
    return false;
  }
  return b.major > a.major;
}

/**
 * Choose a target that clears every advisory with a known fix.
 *
 * A flattened list is unsafe: when advisory A is fixed in 1.2.4 and B in
 * 1.3.2, choosing the lowest value (1.2.4) leaves B unresolved. Select the
 * nearest fix for each advisory, then take the highest required target.
 * Return undefined if any advisory has no published fix; in that case the UI
 * must not claim that an upgrade clears all findings.
 */
export function pickSafeBumpForAdvisories(
  current: string,
  fixedVersionsByAdvisory: string[][]
): string | undefined {
  const cur = semver.coerce(current);
  if (!cur || fixedVersionsByAdvisory.length === 0) {
    return undefined;
  }

  const required: string[] = [];
  for (const fixes of fixedVersionsByAdvisory) {
    const candidates = fixes
      .map((version) => semver.coerce(version)?.version)
      .filter((version): version is string => !!version && semver.gt(version, cur))
      .sort(semver.compare);

    if (candidates.length === 0) {
      return undefined;
    }

    const sameMajor = candidates.filter((version) => semver.major(version) === cur.major);
    required.push(sameMajor[0] ?? candidates[0]);
  }

  return required.sort(semver.rcompare)[0];
}

export function nextPatchAfter(version: string): string | undefined {
  const coerced = semver.coerce(version);
  if (!coerced) {
    return undefined;
  }
  return semver.inc(coerced, "patch") ?? undefined;
}

/** True when a lockfile version is a concrete registry semver OSV can query. */
/** True for plain registry versions; git/file/link/workspace specs can't be looked up in OSV. */
export function isQueryableNpmVersion(version: string): boolean {
  if (!version) {
    return false;
  }
  if (/^(git\+?|git@|http:|https:|file:|link:|workspace:|npm:|github:|gitlab:)/i.test(version)) {
    return false;
  }
  if (/^[<>=~^]/.test(version)) {
    return false;
  }
  if (version.includes("://") || version.includes("/")) {
    return false;
  }
  return semver.valid(semver.coerce(version)) != null;
}

export function monthsBetween(fromIso: string, to = new Date()): number {
  const from = new Date(fromIso);
  if (Number.isNaN(from.getTime())) {
    return Number.POSITIVE_INFINITY;
  }
  const ms = to.getTime() - from.getTime();
  return ms / (1000 * 60 * 60 * 24 * 30.437);
}
