// Ecosystem dispatcher: picks semver (npm) or PEP 440 (PyPI) logic so callers don't branch.
import type { Ecosystem, RiskResult } from "../types";
import {
  isDowngrade as npmIsDowngrade,
  isMajorBump as npmIsMajorBump,
  isQueryableNpmVersion,
  majorsBehind as npmMajorsBehind,
  nextPatchAfter as npmNextPatchAfter,
  pickSafeBumpForAdvisories as npmPickSafeBump,
} from "./semver";
import {
  isQueryablePypiVersion,
  pep440IsDowngrade,
  pep440IsMajorBump,
  pep440MajorsBehind,
  pep440NextPatch,
  pickPep440SafeBumpForAdvisories,
} from "./pep440";

export function isQueryableVersion(version: string, ecosystem: Ecosystem = "npm"): boolean {
  return ecosystem === "pypi" ? isQueryablePypiVersion(version) : isQueryableNpmVersion(version);
}

export function majorsBehind(
  current: string,
  latest: string,
  ecosystem: Ecosystem = "npm"
): number | undefined {
  return ecosystem === "pypi"
    ? pep440MajorsBehind(current, latest)
    : npmMajorsBehind(current, latest);
}

export function isMajorBump(from: string, to: string, ecosystem: Ecosystem = "npm"): boolean {
  return ecosystem === "pypi" ? pep440IsMajorBump(from, to) : npmIsMajorBump(from, to);
}

/** True when the recommended target is older than the installed version. */
/** True when the recommended bump is older than the installed version (advisory fixed only in an earlier branch). */
export function isDowngrade(risk: RiskResult): boolean {
  const { version, ecosystem } = risk.signals.pkg;
  const to = risk.recommendedBump;
  if (!to) {
    return false;
  }
  return ecosystem === "pypi" ? pep440IsDowngrade(version, to) : npmIsDowngrade(version, to);
}

export function pickSafeBumpForAdvisories(
  current: string,
  fixedVersionsByAdvisory: string[][],
  ecosystem: Ecosystem = "npm"
): string | undefined {
  return ecosystem === "pypi"
    ? pickPep440SafeBumpForAdvisories(current, fixedVersionsByAdvisory)
    : npmPickSafeBump(current, fixedVersionsByAdvisory);
}

export function nextPatchAfter(version: string, ecosystem: Ecosystem = "npm"): string | undefined {
  return ecosystem === "pypi" ? pep440NextPatch(version) : npmNextPatchAfter(version);
}

/** PEP 503 normalization: lowercase, runs of `-_.` collapse to `-`. */
export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[._]/g, "-");
}

/** PyPI name equality after normalization. */
export function namesMatch(left: string, right: string): boolean {
  return normalizePyName(left) === normalizePyName(right);
}
