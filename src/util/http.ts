export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: string
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export async function fetchJson<T>(
  url: string,
  init?: RequestInit & { timeoutMs?: number; retries?: number }
): Promise<T> {
  const timeoutMs = init?.timeoutMs ?? 30_000;
  const retries = init?.retries ?? 2;
  const { timeoutMs: _timeout, retries: _retries, ...requestInit } = init ?? {};
  void _timeout;
  void _retries;

  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        ...requestInit,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "User-Agent": "dependency-version-risk-extension/0.2",
          ...(requestInit.headers ?? {}),
        },
      });
      const text = await res.text();
      if (!res.ok) {
        const error = new HttpError(
          `HTTP ${res.status} for ${url}`,
          res.status,
          text.slice(0, 500)
        );
        if (attempt < retries && (res.status === 429 || res.status >= 500)) {
          await delay(retryDelayMs(attempt, res.headers.get("retry-after")));
          continue;
        }
        throw error;
      }
      if (!text) {
        return {} as T;
      }
      return JSON.parse(text) as T;
    } catch (error) {
      if (
        attempt < retries &&
        !(error instanceof HttpError && error.status < 500 && error.status !== 429)
      ) {
        await delay(retryDelayMs(attempt));
        continue;
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(`Request failed after ${retries + 1} attempts: ${url}`);
}

function retryDelayMs(attempt: number, retryAfter?: string | null): number {
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds)) {
      return Math.min(seconds * 1000, 10_000);
    }
  }
  return Math.min(500 * 2 ** attempt, 4_000);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function mapPool<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;

  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
