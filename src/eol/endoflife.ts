import { fetchJson } from "../util/http";
import type { RiskCache } from "../cache/store";
import type { RuntimeEolInfo } from "../types";

const EOL_API = "https://endoflife.date/api/v1/products";
const EOL_TTL_MS = 24 * 60 * 60 * 1000;

interface EolRelease {
  name: string;
  isEol?: boolean;
  eolFrom?: string | null;
}

interface EolProductResponse {
  result?: {
    releases?: EolRelease[];
  };
}

export function parseDeclaredNodeMajor(enginesNode?: string): string | undefined {
  if (!enginesNode) {
    return undefined;
  }

  // engines ranges such as ">=18" are compatibility declarations, not the
  // runtime actually used by the project. Only evaluate an unambiguous line.
  const trimmed = enginesNode.trim();
  if (trimmed.includes("||") || /^[<>]=?/.test(trimmed)) {
    return undefined;
  }
  const m = trimmed.match(/^(?:[=v^~]\s*)?(\d+)(?:\.\d+|\.x){0,2}$/);
  return m?.[1];
}

export class EolClient {
  constructor(private readonly cache: RiskCache) {}

  async nodeRuntimeEol(enginesNode?: string): Promise<RuntimeEolInfo | undefined> {
    const major = parseDeclaredNodeMajor(enginesNode);
    if (!major) {
      return undefined;
    }

    const cycles = await this.getProductCycles("nodejs");
    const cycle =
      cycles.find((c) => String(c.name) === major) ??
      cycles.find((c) => String(c.name).startsWith(`${major}.`));

    if (!cycle) {
      return {
        product: "nodejs",
        current: major,
        alreadyEol: false,
      };
    }

    const eolDate = cycle.eolFrom ?? undefined;
    const alreadyEol =
      cycle.isEol === true || (eolDate ? new Date(eolDate).getTime() < Date.now() : false);
    let monthsToEol: number | undefined;
    if (eolDate) {
      const eol = new Date(eolDate);
      monthsToEol = (eol.getTime() - Date.now()) / (1000 * 60 * 60 * 24 * 30.437);
    }

    return {
      product: "nodejs",
      current: String(cycle.name),
      eolDate,
      monthsUntilEol: monthsToEol,
      alreadyEol,
    };
  }

  private async getProductCycles(product: string): Promise<EolRelease[]> {
    const cacheKey = `v1:${product}`;
    const cached = this.cache.getEol(cacheKey, EOL_TTL_MS);
    if (cached) {
      return cached as EolRelease[];
    }

    const response = await fetchJson<EolProductResponse>(`${EOL_API}/${product}`, {
      timeoutMs: 20_000,
    });
    const releases = response.result?.releases ?? [];
    this.cache.setEol(cacheKey, releases);
    return releases;
  }
}
