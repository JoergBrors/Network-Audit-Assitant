import { describe, expect, it } from "vitest";
import { createHttpHeaders, createPipelineRequest } from "@azure/core-rest-pipeline";
import { argQuotaPolicy, parseQuotaReset } from "../../src/azure/http/argQuotaPolicy.js";

describe("parseQuotaReset", () => {
  it("parses hh:mm:ss", () => {
    expect(parseQuotaReset("00:00:04")).toBe(4000);
    expect(parseQuotaReset("01:02:03")).toBe(3_723_000);
    expect(parseQuotaReset("garbage")).toBeUndefined();
    expect(parseQuotaReset(undefined)).toBeUndefined();
  });
});

describe("argQuotaPolicy", () => {
  it("waits for the quota reset when the quota is exhausted", async () => {
    let clock = 1_000;
    const waits: number[] = [];
    const { policy } = argQuotaPolicy({
      now: () => clock,
      wait: (ms) => (waits.push(ms), Promise.resolve()),
    });
    const request = createPipelineRequest({
      url: "https://management.azure.com/providers/Microsoft.ResourceGraph/resources",
    });
    const respond = (remaining: string) => (r: typeof request) =>
      Promise.resolve({
        request: r,
        status: 200,
        headers: createHttpHeaders({
          "x-ms-user-quota-remaining": remaining,
          "x-ms-user-quota-resets-after": "00:00:05",
        }),
      });

    await policy.sendRequest(request, respond("10"));
    await policy.sendRequest(request, respond("1"));
    expect(waits).toEqual([]);
    clock += 2_000;
    await policy.sendRequest(request, respond("15"));
    expect(waits).toEqual([3_000]);
  });
});
