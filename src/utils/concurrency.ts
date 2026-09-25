export type Limiter = <T>(task: () => Promise<T>) => Promise<T>;

/** Minimal promise-based concurrency limiter (FIFO). */
export function createLimiter(maxConcurrency: number): Limiter {
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new RangeError(`maxConcurrency must be a positive integer, got ${maxConcurrency}`);
  }
  let active = 0;
  const queue: (() => void)[] = [];

  const release = (): void => {
    active--;
    queue.shift()?.();
  };

  return <T>(task: () => Promise<T>): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      const run = (): void => {
        active++;
        task().then(resolve, reject).finally(release);
      };
      if (active < maxConcurrency) run();
      else queue.push(run);
    });
}

export function chunk<T>(items: readonly T[], size: number): T[][] {
  if (size < 1) throw new RangeError("chunk size must be >= 1");
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
