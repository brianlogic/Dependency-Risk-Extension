import * as semver from "semver";

export function coerceVersion(version: string): string | null {
  const cleaned = version.replace(/^[=v]/, "").trim();
  const coerced = semver.coerce(cleaned);
  return coerced ? coerced.version : null;
}

export function majorsBehind(current: string, latest: string): number | undefined {
  const a = semver.coerce(current);
  const b = semver.coerce(latest);
  if (!a || !b) {
    return undefined;
  }
  return Math.max(0, b.major - a.major);
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
 * Pick the lowest version >= current that satisfies "fixed" — prefer same major,
 * then same minor ladder, else the lowest overall fixed version newer than current.
 */
export function pickSafeBump(
  current: string,
  latest: string | undefined,
  fixedVersions: string[]
): string | undefined {
  const cur = semver.coerce(current);
  if (!cur) {
    return latest;
  }

  const candidates = new Set<string>();
  for (const f of fixedVersions) {
    const c = semver.coerce(f);
    if (c && semver.gt(c, cur)) {
      candidates.add(c.version);
    }
  }
  if (latest) {
    const l = semver.coerce(latest);
    if (l && semver.gt(l, cur)) {
      candidates.add(l.version);
    }
  }

  const sorted = [...candidates].sort(semver.compare);
  if (sorted.length === 0) {
    return undefined;
  }

  const sameMajor = sorted.filter((v) => semver.major(v) === cur.major);
  if (sameMajor.length) {
    const sameMinor = sameMajor.filter((v) => semver.minor(v) === cur.minor);
    return sameMinor[0] ?? sameMajor[0];
  }

  // Unavoidable major — still pick the lowest major jump that appears in fixed set
  const fixedOnly = fixedVersions
    .map((f) => semver.coerce(f)?.version)
    .filter((v): v is string => !!v && semver.gt(v, cur))
    .sort(semver.compare);
  if (fixedOnly.length) {
    return fixedOnly[0];
  }

  return sorted[0];
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

/** Extract introduced/fixed pairs from OSV events for a package name. */
export function fixedVersionsFromOsvEvents(
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>
): string[] {
  const fixed: string[] = [];
  for (const e of events) {
    if (e.fixed) {
      fixed.push(e.fixed);
    }
  }
  return fixed;
}

export function monthsBetween(fromIso: string, to = new Date()): number {
  const from = new Date(fromIso);
  if (Number.isNaN(from.getTime())) {
    return Number.POSITIVE_INFINITY;
  }
  const ms = to.getTime() - from.getTime();
  return ms / (1000 * 60 * 60 * 24 * 30.437);
}
