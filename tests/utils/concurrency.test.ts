import { describe, expect, it } from "vitest";
import { chunk, createLimiter } from "../../src/utils/concurrency.js";

describe("createLimiter", () => {
  it("never exceeds the configured concurrency and propagates errors", async () => {
    const limit = createLimiter(2);
    let active = 0;
    let max = 0;
    const task = (fail: boolean) => async () => {
      active++;
      max = Math.max(max, active);
      await new Promise((r) => setTimeout(r, 2));
      active--;
      if (fail) throw new Error("x");
      return 1;
    };
    const results = await Promise.allSettled([1, 2, 3, 4, 5].map((i) => limit(task(i === 3))));
    expect(max).toBe(2);
    expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
  });

  it("validates arguments", () => {
    expect(() => createLimiter(0)).toThrow(RangeError);
    expect(chunk([1, 2, 3], 2)).toEqual([[1, 2], [3]]);
  });
});
