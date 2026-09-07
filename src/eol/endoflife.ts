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

export function parseDeclaredPythonRelease(requiresPython?: string): string | undefined {
  if (!requiresPython) {
    return undefined;
  }
  const trimmed = requiresPython.trim();
  if (trimmed.includes("||") || /[<>]/.test(trimmed)) {
    return undefined;
  }
  const match = trimmed.match(/^(?:python-)?(?:[=v^~]\s*)?(\d+\.\d+)(?:\.\d+)?$/i);
  return match?.[1];
}

export class EolClient {
  constructor(private readonly cache: RiskCache) {}

  async pythonRuntimeEol(requiresPython?: string): Promise<RuntimeEolInfo | undefined> {
    const release = parseDeclaredPythonRelease(requiresPython);
    if (!release) {
      return undefined;
    }
    return this.runtimeEol("python", release);
  }

  async nodeRuntimeEol(enginesNode?: string): Promise<RuntimeEolInfo | undefined> {
    const major = parseDeclaredNodeMajor(enginesNode);
    if (!major) {
      return undefined;
    }
    return this.runtimeEol("nodejs", major);
  }

  private async runtimeEol(product: string, declared: string): Promise<RuntimeEolInfo | undefined> {
    const cycles = await this.getProductCycles(product);
    const cycle =
      cycles.find((c) => String(c.name) === declared) ??
      cycles.find((c) => String(c.name).startsWith(`${declared}.`));

    if (!cycle) {
      return {
        product,
        current: declared,
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
      product,
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
