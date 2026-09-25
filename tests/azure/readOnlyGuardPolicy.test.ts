import { describe, expect, it } from "vitest";
import { createHttpHeaders, createPipelineRequest, type PipelineResponse } from "@azure/core-rest-pipeline";
import {
  isRequestAllowed,
  readOnlyGuardPolicy,
  ReadOnlyViolationError,
} from "../../src/azure/http/readOnlyGuardPolicy.js";

const ARM = "https://management.azure.com";
const NIC = `${ARM}/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1`;

describe("isRequestAllowed", () => {
  it.each(["GET", "get", "HEAD"])("allows %s", (method) => {
    expect(isRequestAllowed(method, `${ARM}/subscriptions?api-version=2022-12-01`)).toBe(true);
  });

  it.each(["PUT", "PATCH", "DELETE", "OPTIONS", "MERGE"])("blocks %s", (method) => {
    expect(isRequestAllowed(method, `${ARM}/subscriptions/s1/resourceGroups/rg?api-version=2021-04-01`)).toBe(
      false,
    );
  });

  it("allows the Resource Graph query POST", () => {
    expect(
      isRequestAllowed("POST", `${ARM}/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01`),
    ).toBe(true);
  });

  it("blocks other POST actions", () => {
    expect(
      isRequestAllowed("POST", `${ARM}/subscriptions/s1/providers/Microsoft.Resources/checkResourceName`),
    ).toBe(false);
    expect(isRequestAllowed("POST", `${NIC}/start`)).toBe(false);
    expect(isRequestAllowed("POST", `${ARM}/providers/Microsoft.ResourceGraph/resources/extra`)).toBe(false);
  });

  it("allows effective routes only when explicitly enabled", () => {
    const url = `${NIC}/effectiveRouteTable?api-version=2026-01-01`;
    expect(isRequestAllowed("POST", url)).toBe(false);
    expect(isRequestAllowed("POST", url, { allowEffectiveRoutes: true })).toBe(true);
    expect(
      isRequestAllowed("POST", `${NIC}/effectiveNetworkSecurityGroups`, { allowEffectiveRoutes: true }),
    ).toBe(true);
  });

  it("blocks malformed URLs", () => {
    expect(isRequestAllowed("POST", "not a url")).toBe(false);
  });
});

describe("readOnlyGuardPolicy", () => {
  const ok = (request: ReturnType<typeof createPipelineRequest>): Promise<PipelineResponse> =>
    Promise.resolve({ request, status: 200, headers: createHttpHeaders() });

  it("rejects mutating requests before they are sent", async () => {
    let sent = false;
    const policy = readOnlyGuardPolicy();
    const request = createPipelineRequest({
      url: `${ARM}/subscriptions/s1/resourceGroups/rg`,
      method: "DELETE",
    });
    await expect(
      policy.sendRequest(request, (r) => {
        sent = true;
        return ok(r);
      }),
    ).rejects.toBeInstanceOf(ReadOnlyViolationError);
    expect(sent).toBe(false);
  });

  it("passes read requests through", async () => {
    const policy = readOnlyGuardPolicy();
    const request = createPipelineRequest({ url: `${ARM}/subscriptions`, method: "GET" });
    await expect(policy.sendRequest(request, ok)).resolves.toMatchObject({ status: 200 });
  });
});
