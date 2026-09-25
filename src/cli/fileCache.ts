import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { DiscoveryCache } from "../azure/cache.js";

/** File-based discovery cache for the CLI. Stores resource data only (no tokens). */
export class FileCache implements DiscoveryCache {
  constructor(
    private readonly dir: string,
    private readonly now: () => number = Date.now,
  ) {}

  private path(key: string): string {
    return join(this.dir, `${key.replace(/[^a-z0-9-]/gi, "_")}.json`);
  }

  async get(key: string): Promise<unknown> {
    try {
      const entry = JSON.parse(await readFile(this.path(key), "utf8")) as {
        expiresAt: number;
        value: unknown;
      };
      return entry.expiresAt > this.now() ? entry.value : undefined;
    } catch {
      return undefined;
    }
  }

  async set(key: string, value: unknown, ttlMs: number): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    await writeFile(this.path(key), JSON.stringify({ expiresAt: this.now() + ttlMs, value }), "utf8");
  }

  async clear(): Promise<void> {
    await rm(this.dir, { recursive: true, force: true });
  }
}
