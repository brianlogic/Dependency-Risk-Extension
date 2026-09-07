import type { Ecosystem } from "../types";
import {
  isMajorBump as npmIsMajorBump,
  isQueryableNpmVersion,
  majorsBehind as npmMajorsBehind,
  nextPatchAfter as npmNextPatchAfter,
  pickSafeBumpForAdvisories as npmPickSafeBump,
} from "./semver";
import {
  isQueryablePypiVersion,
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

export function normalizePyName(name: string): string {
  return name.toLowerCase().replace(/[._]/g, "-");
}

export function namesMatch(left: string, right: string): boolean {
  return normalizePyName(left) === normalizePyName(right);
}
