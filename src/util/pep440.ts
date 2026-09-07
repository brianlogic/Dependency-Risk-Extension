export interface Pep440Version {
  epoch: number;
  release: number[];
  pre?: { letter: number; num: number };
  post?: number;
  dev?: number;
}

const PRE: Record<string, number> = {
  a: 0,
  alpha: 0,
  b: 1,
  beta: 1,
  c: 2,
  rc: 2,
  pre: 2,
  preview: 2,
};

const PEP440_RE =
  /^(?:v)?(?:(?<epoch>\d+)!)?(?<release>\d+(?:\.\d+)*)(?:[-._]?(?<preLetter>a|b|c|rc|alpha|beta|pre|preview)[-._]?(?<preNum>\d*))?(?:(?:[-._]?(?:post|rev|r)[-._]?(?<post>\d*))|(?<postImplicit>-(?<postDash>\d+)))?(?:[-._]?dev[-._]?(?<dev>\d*))?(?:\+[a-z0-9]+(?:[.][a-z0-9]+)*)?$/i;

export function parsePep440(version: string): Pep440Version | undefined {
  const trimmed = version.trim();
  if (!trimmed) {
    return undefined;
  }
  const match = trimmed.match(PEP440_RE);
  if (!match?.groups) {
    return undefined;
  }
  const release = match.groups.release.split(".").map((part) => Number(part));
  const parsed: Pep440Version = {
    epoch: match.groups.epoch ? Number(match.groups.epoch) : 0,
    release,
  };
  if (match.groups.preLetter) {
    parsed.pre = {
      letter: PRE[match.groups.preLetter.toLowerCase()] ?? 2,
      num: match.groups.preNum ? Number(match.groups.preNum) : 0,
    };
  }
  if (match.groups.post != null && match.groups.post !== "") {
    parsed.post = Number(match.groups.post);
  } else if (match.groups.postDash) {
    parsed.post = Number(match.groups.postDash);
  }
  if (match.groups.dev != null) {
    parsed.dev = match.groups.dev === "" ? 0 : Number(match.groups.dev);
  }
  return parsed;
}

export function comparePep440(left: string, right: string): number | undefined {
  const a = parsePep440(left);
  const b = parsePep440(right);
  if (!a || !b) {
    return undefined;
  }
  return compareParsed(a, b);
}

export function pep440Gt(left: string, right: string): boolean {
  return (comparePep440(left, right) ?? 0) > 0;
}

export function pep440MajorsBehind(current: string, latest: string): number | undefined {
  const a = parsePep440(current);
  const b = parsePep440(latest);
  if (!a || !b) {
    return undefined;
  }
  return Math.max(0, (b.release[0] ?? 0) - (a.release[0] ?? 0));
}

export function pep440IsMajorBump(from: string, to: string): boolean {
  const a = parsePep440(from);
  const b = parsePep440(to);
  if (!a || !b) {
    return false;
  }
  return (b.release[0] ?? 0) > (a.release[0] ?? 0);
}

export function pep440NextPatch(version: string): string | undefined {
  const parsed = parsePep440(version);
  if (!parsed) {
    return undefined;
  }
  const release = [...parsed.release];
  if (release.length < 3) {
    while (release.length < 3) {
      release.push(0);
    }
  }
  release[release.length - 1] += 1;
  const epoch = parsed.epoch ? `${parsed.epoch}!` : "";
  return `${epoch}${release.join(".")}`;
}

export function isQueryablePypiVersion(version: string): boolean {
  if (!version) {
    return false;
  }
  if (/^(git\+?|git@|http:|https:|file:|path:|url:)/i.test(version)) {
    return false;
  }
  if (version.includes("://") || version.includes("/")) {
    return false;
  }
  return parsePep440(version) != null;
}

export function pickPep440SafeBumpForAdvisories(
  current: string,
  fixedVersionsByAdvisory: string[][]
): string | undefined {
  if (!parsePep440(current) || fixedVersionsByAdvisory.length === 0) {
    return undefined;
  }

  const required: string[] = [];
  for (const fixes of fixedVersionsByAdvisory) {
    const candidates = fixes
      .filter((version) => pep440Gt(version, current))
      .sort((a, b) => comparePep440(a, b) ?? 0);
    if (candidates.length === 0) {
      return undefined;
    }
    const currentMajor = parsePep440(current)?.release[0];
    const sameMajor = candidates.filter((version) => parsePep440(version)?.release[0] === currentMajor);
    required.push(sameMajor[0] ?? candidates[0]);
  }

  return required.sort((a, b) => comparePep440(b, a) ?? 0)[0];
}

function compareParsed(a: Pep440Version, b: Pep440Version): number {
  if (a.epoch !== b.epoch) {
    return a.epoch - b.epoch;
  }
  const length = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < length; i++) {
    const delta = (a.release[i] ?? 0) - (b.release[i] ?? 0);
    if (delta) {
      return delta;
    }
  }

  const aKey = cmpKey(a);
  const bKey = cmpKey(b);
  for (let i = 0; i < aKey.length; i++) {
    const delta = aKey[i] - bKey[i];
    if (delta) {
      return delta;
    }
  }
  return 0;
}

function cmpKey(version: Pep440Version): number[] {
  const NEG = Number.NEGATIVE_INFINITY;
  const POS = Number.POSITIVE_INFINITY;
  let preLetter = POS;
  let preNum = POS;
  if (!version.pre && version.post == null && version.dev != null) {
    preLetter = NEG;
    preNum = NEG;
  } else if (version.pre) {
    preLetter = version.pre.letter;
    preNum = version.pre.num;
  }
  const post = version.post ?? NEG;
  const dev = version.dev ?? POS;
  return [preLetter, preNum, post, dev];
}
