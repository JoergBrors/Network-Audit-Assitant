/** Cache for discovery results. Holds resource data only — never tokens or headers. */
export interface DiscoveryCache {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttlMs: number): Promise<void>;
  clear(): Promise<void>;
}

export class MemoryCache implements DiscoveryCache {
  private readonly entries = new Map<string, { value: unknown; expiresAt: number }>();

  constructor(private readonly now: () => number = Date.now) {}

  get(key: string): Promise<unknown> {
    const entry = this.entries.get(key);
    if (!entry) return Promise.resolve(undefined);
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return Promise.resolve(undefined);
    }
    return Promise.resolve(entry.value);
  }

  set(key: string, value: unknown, ttlMs: number): Promise<void> {
    this.entries.set(key, { value, expiresAt: this.now() + ttlMs });
    return Promise.resolve();
  }

  clear(): Promise<void> {
    this.entries.clear();
    return Promise.resolve();
  }
}

export const DEFAULT_CACHE_TTL_MS = 15 * 60_000;

/** SHA-256 hex via Web Crypto (available in browsers and Node >= 20). */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
