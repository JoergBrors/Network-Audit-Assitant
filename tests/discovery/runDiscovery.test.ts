import { describe, expect, it } from "vitest";
import type { QueryRequest } from "@azure/arm-resourcegraph";
import { NETWORK_QUERIES, ORG_MANAGEMENT_GROUPS } from "../../src/azure/resourceGraph/queries.js";
import type { SubscriptionApi } from "../../src/azure/subscriptions/discoverSubscriptions.js";
import { runDiscovery } from "../../src/discovery/runDiscovery.js";
import {
  fakeArg,
  memoryLogger,
  page,
  resource,
  restError,
  SUB,
  TENANT_A,
  TENANT_B,
} from "../helpers/fakes.js";

const credential = { getToken: () => Promise.reject(new Error("must not be used with fakes")) };
const VNET = NETWORK_QUERIES.find((q) => q.id === "Q-NET-VNET")!;
const NIC = NETWORK_QUERIES.find((q) => q.id === "Q-NET-NIC")!;

const subscriptionApi: SubscriptionApi = {
  listTenants: () => Promise.resolve([{ tenantId: TENANT_A }, { tenantId: TENANT_B }]),
  listSubscriptions: (tenantId) =>
    tenantId === TENANT_A
      ? Promise.resolve([
          {
            subscriptionId: SUB(1),
            displayName: "conn",
            tenantId: TENANT_A,
            state: "Enabled",
            managedByTenantIds: [],
          },
          {
            subscriptionId: SUB(2),
            displayName: "app",
            tenantId: TENANT_A,
            state: "Enabled",
            managedByTenantIds: [],
          },
        ])
      : Promise.reject(restError(400, "AADSTS65001")),
};

function handler(req: QueryRequest) {
  if (req.managementGroups) throw restError(403, "AuthorizationFailed");
  // Subscription 2 may read VNets but not NICs: the NIC batch must be split and only SUB(2) reported.
  if (req.subscriptions!.includes(SUB(2)) && req.query === NIC.kql)
    throw restError(403, "AuthorizationFailed");
  if (req.query === VNET.kql) {
    return page(
      req.subscriptions!.map((s) =>
        resource(`/subscriptions/${s}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet`),
      ),
    );
  }
  return page([]);
}

describe("runDiscovery", () => {
  it("produces a raw inventory with isolated failures, warnings and quality", async () => {
    const { executor, requests } = fakeArg(handler);
    const factoryTenants: string[] = [];
    const progress: string[] = [];
    const inventory = await runDiscovery({
      credential,
      logger: memoryLogger("info").logger,
      subscriptionApi,
      argExecutorFactory: (tenantId) => (factoryTenants.push(tenantId), executor),
      queries: [VNET, NIC],
      now: () => new Date("2026-09-25T10:00:00Z"),
      onProgress: (p) => progress.push(p.phase),
    });

    expect(factoryTenants).toEqual([TENANT_A]);
    expect(inventory.generatedAt).toBe("2026-09-25T10:00:00.000Z");
    expect(inventory.resources["Q-NET-VNET"]).toHaveLength(2);
    expect(inventory.warnings.map((w) => `${w.reason}:${w.operation}`).sort()).toEqual([
      "InsufficientPermissions:ARG:Q-NET-NIC",
      `InsufficientPermissions:ARG:${ORG_MANAGEMENT_GROUPS.id}`,
      "TenantTokenUnavailable:ListSubscriptions",
    ]);
    expect(inventory.quality).toMatchObject({
      tenants: { total: 2, readable: 1 },
      subscriptions: { total: 2, readable: 1 },
      networkResources: 2,
      argQueries: { executed: 2, failed: 1 },
      overallConfidence: "LOW",
    });
    expect(requests.some((r) => r.managementGroups?.[0] === TENANT_A)).toBe(true);
    expect(progress.at(0)).toBe("subscriptions");
    expect(progress.at(-1)).toBe("complete");
  });

  it("reports HIGH confidence when everything is readable", async () => {
    const { executor } = fakeArg((req) =>
      req.query === VNET.kql ? page([resource(`/subscriptions/${SUB(1)}/v`)]) : page([]),
    );
    const inventory = await runDiscovery({
      credential,
      logger: memoryLogger("info").logger,
      subscriptionApi: {
        listTenants: () => Promise.resolve([{ tenantId: TENANT_A }]),
        listSubscriptions: () =>
          Promise.resolve([
            {
              subscriptionId: SUB(1),
              displayName: "s",
              tenantId: TENANT_A,
              state: "Enabled",
              managedByTenantIds: [],
            },
          ]),
      },
      argExecutorFactory: () => executor,
      queries: [VNET],
    });
    expect(inventory.warnings).toEqual([]);
    expect(inventory.quality.overallConfidence).toBe("HIGH");
  });
});
