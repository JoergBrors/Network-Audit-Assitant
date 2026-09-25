import { describe, expect, it } from "vitest";
import {
  discoverSubscriptions,
  type SubscriptionApi,
  type SubscriptionRecord,
} from "../../src/azure/subscriptions/discoverSubscriptions.js";
import { memoryLogger, restError, SUB, TENANT_A, TENANT_B } from "../helpers/fakes.js";

const sub = (n: number, tenantId: string, state = "Enabled"): SubscriptionRecord => ({
  subscriptionId: SUB(n),
  displayName: `sub-${n}`,
  tenantId,
  state,
  managedByTenantIds: [],
});

function api(tenants: string[], subs: Record<string, SubscriptionRecord[] | Error>): SubscriptionApi {
  return {
    listTenants: () => Promise.resolve(tenants.map((tenantId) => ({ tenantId }))),
    listSubscriptions: (tenantId) => {
      const v = subs[tenantId];
      return v instanceof Error ? Promise.reject(v) : Promise.resolve(v ?? []);
    },
  };
}

describe("discoverSubscriptions", () => {
  it("continues when a tenant token cannot be obtained", async () => {
    const result = await discoverSubscriptions(
      api([TENANT_A, TENANT_B], {
        [TENANT_A]: [sub(1, TENANT_A)],
        [TENANT_B]: restError(401, "InteractionRequired"),
      }),
      memoryLogger().logger,
    );
    expect(result.subscriptions.map((s) => s.subscriptionId)).toEqual([SUB(1)]);
    expect(result.tenants).toEqual([
      { tenantId: TENANT_A, accessible: true },
      { tenantId: TENANT_B, accessible: false },
    ]);
    expect(result.warnings).toEqual([
      {
        scope: `/tenants/${TENANT_B}`,
        operation: "ListSubscriptions",
        reason: "TenantTokenUnavailable",
        detail: "InteractionRequired",
      },
    ]);
  });

  it("de-duplicates Lighthouse subscriptions, preferring the owning tenant", async () => {
    const delegated = { ...sub(2, TENANT_B), managedByTenantIds: [TENANT_A] };
    const result = await discoverSubscriptions(
      api([TENANT_A, TENANT_B], { [TENANT_A]: [sub(1, TENANT_A), delegated], [TENANT_B]: [delegated] }),
      memoryLogger().logger,
    );
    expect(result.subscriptions.find((s) => s.subscriptionId === SUB(2))).toMatchObject({
      tenantId: TENANT_B,
      accessTenantId: TENANT_B,
    });
  });

  it("keeps Lighthouse access when the owning tenant is not accessible", async () => {
    const delegated = sub(2, TENANT_B);
    const result = await discoverSubscriptions(
      api([TENANT_A], { [TENANT_A]: [delegated] }),
      memoryLogger().logger,
    );
    expect(result.subscriptions[0]).toMatchObject({ tenantId: TENANT_B, accessTenantId: TENANT_A });
  });

  it("warns about disabled subscriptions and applies filters", async () => {
    const result = await discoverSubscriptions(
      api([TENANT_A, TENANT_B], { [TENANT_A]: [sub(1, TENANT_A), sub(3, TENANT_A, "Disabled")] }),
      memoryLogger().logger,
      { tenantIds: [TENANT_A.toUpperCase()] },
    );
    expect(result.tenants.map((t) => t.tenantId)).toEqual([TENANT_A]);
    expect(result.warnings).toEqual([
      {
        scope: `/subscriptions/${SUB(3)}`,
        operation: "SubscriptionState",
        reason: "SubscriptionDisabled",
        detail: "Disabled",
      },
    ]);

    const filtered = await discoverSubscriptions(
      api([TENANT_A], { [TENANT_A]: [sub(1, TENANT_A), sub(2, TENANT_A)] }),
      memoryLogger().logger,
      { subscriptionIds: [SUB(2)] },
    );
    expect(filtered.subscriptions.map((s) => s.subscriptionId)).toEqual([SUB(2)]);
  });
});
