import { describe, expect, it } from "vitest";
import { MemoryCache } from "../../src/azure/cache.js";
import { ORG_MANAGEMENT_GROUPS, NETWORK_QUERIES } from "../../src/azure/resourceGraph/queries.js";
import { runArgQuery } from "../../src/azure/resourceGraph/runQuery.js";
import { createLimiter } from "../../src/utils/concurrency.js";
import { fakeArg, memoryLogger, page, resource, restError, SUB, TENANT_A } from "../helpers/fakes.js";

const VNET_QUERY = NETWORK_QUERIES.find((q) => q.id === "Q-NET-VNET")!;
const base = () => ({
  query: VNET_QUERY,
  tenantId: TENANT_A,
  limiter: createLimiter(2),
  logger: memoryLogger().logger,
});

describe("runArgQuery", () => {
  it("follows skipToken paging and keeps scope and query stable", async () => {
    const { executor, requests } = fakeArg((req) => {
      if (!req.options?.skipToken) return page([resource(`/subscriptions/${SUB(1)}/a`)], "t1");
      if (req.options.skipToken === "t1") return page([resource(`/subscriptions/${SUB(1)}/b`)], "t2");
      return page([resource(`/subscriptions/${SUB(1)}/c`)]);
    });
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1)] });
    expect(result.rows.map((r) => r.id.slice(-1))).toEqual(["a", "b", "c"]);
    expect(result.stats).toMatchObject({ pages: 3, rows: 3, batches: 1, failedBatches: 0 });
    expect(
      requests.every((r) => r.query === VNET_QUERY.kql && r.options?.resultFormat === "objectArray"),
    ).toBe(true);
    expect(requests[0]!.options?.top).toBe(1000);
  });

  it("batches subscriptions", async () => {
    const { executor, requests } = fakeArg(() => page([]));
    const subs = Array.from({ length: 5 }, (_, i) => SUB(i));
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: subs, batchSize: 2 });
    expect(requests.map((r) => r.subscriptions?.length)).toEqual([2, 2, 1]);
    expect(result.stats.batches).toBe(3);
  });

  it("isolates a subscription without permissions by splitting the batch", async () => {
    const denied = SUB(3);
    const { executor } = fakeArg((req) => {
      if (req.subscriptions?.includes(denied)) throw restError(403, "AuthorizationFailed");
      return page(req.subscriptions!.map((s) => resource(`/subscriptions/${s}/vnet`)));
    });
    const subs = [SUB(1), SUB(2), SUB(3), SUB(4)];
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: subs });
    expect(result.rows).toHaveLength(3);
    expect(result.warnings).toEqual([
      {
        scope: `/subscriptions/${denied}`,
        operation: "ARG:Q-NET-VNET",
        reason: "InsufficientPermissions",
        detail: "AuthorizationFailed",
      },
    ]);
    expect(result.stats.failedBatches).toBe(1);
  });

  it("discards partial pages of a failed attempt (no duplicates after split)", async () => {
    const { executor } = fakeArg((req) => {
      const subs = req.subscriptions!;
      if (subs.length > 1 && req.options?.skipToken) throw restError(403, "AuthorizationFailed");
      if (subs.length > 1) return page([resource(`/subscriptions/${subs[0]}/first`)], "next");
      return page([resource(`/subscriptions/${subs[0]}/vnet`)]);
    });
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1), SUB(2)] });
    expect(result.rows.map((r) => r.id).sort()).toEqual([
      `/subscriptions/${SUB(1)}/vnet`,
      `/subscriptions/${SUB(2)}/vnet`,
    ]);
  });

  it("splits truncated results and warns when a single subscription is still truncated", async () => {
    const { executor } = fakeArg((req) =>
      page([resource(`/subscriptions/${req.subscriptions![0]}/x`)], undefined, true),
    );
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1), SUB(2)] });
    expect(result.stats.truncated).toBe(2);
    expect(result.warnings.map((w) => w.reason)).toEqual(["Truncated", "Truncated"]);
    expect(result.stats.failedBatches).toBe(0);
  });

  it("halves the page size when the payload is too large", async () => {
    const { executor, requests } = fakeArg((req) => {
      if ((req.options?.top ?? 0) > 250) throw restError(400, "ResponsePayloadTooLarge");
      return page([resource(`/subscriptions/${SUB(1)}/x`)]);
    });
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1)] });
    expect(requests.map((r) => r.options?.top)).toEqual([1000, 500, 250]);
    expect(result.rows).toHaveLength(1);
  });

  it("reports non-scope errors without retrying the scope", async () => {
    const { executor, requests } = fakeArg(() => {
      throw restError(500, "InternalServerError");
    });
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1), SUB(2)] });
    expect(requests).toHaveLength(1);
    expect(result.warnings[0]).toMatchObject({ reason: "Error", detail: "InternalServerError" });
  });

  it("uses the management group scope for Q-ORG-02", async () => {
    const { executor, requests } = fakeArg(() => page([]));
    await runArgQuery({ ...base(), query: ORG_MANAGEMENT_GROUPS, executor, subscriptionIds: [SUB(1)] });
    expect(requests[0]).toMatchObject({ managementGroups: [TENANT_A] });
    expect(requests[0]!.subscriptions).toBeUndefined();
  });

  it("serves complete results from cache and does not cache failures", async () => {
    const cache = new MemoryCache();
    let fail = true;
    const { executor, requests } = fakeArg(() => {
      if (fail) throw restError(500, "Boom");
      return page([resource(`/subscriptions/${SUB(1)}/x`)]);
    });
    await runArgQuery({ ...base(), executor, cache, subscriptionIds: [SUB(1)] });
    fail = false;
    await runArgQuery({ ...base(), executor, cache, subscriptionIds: [SUB(1)] });
    const cached = await runArgQuery({ ...base(), executor, cache, subscriptionIds: [SUB(1)] });
    expect(requests).toHaveLength(2);
    expect(cached.stats.fromCache).toBe(1);
    expect(cached.rows).toHaveLength(1);
  });

  it("skips rows that are not resources", async () => {
    const { executor } = fakeArg(() => page([{ foo: 1 }, resource(`/subscriptions/${SUB(1)}/ok`)]));
    const result = await runArgQuery({ ...base(), executor, subscriptionIds: [SUB(1)] });
    expect(result.rows).toHaveLength(1);
  });
});
