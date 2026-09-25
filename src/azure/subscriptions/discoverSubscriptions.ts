import type { TokenCredential } from "@azure/core-auth";
import { SubscriptionClient } from "@azure/arm-resources-subscriptions";
import type { DiscoveryWarning, SubscriptionInfo, TenantInfo } from "../../models/discovery.js";
import type { Logger } from "../../logging/logger.js";
import { tenantBoundCredential } from "../../auth/tenantCredential.js";
import { readOnlyClientOptions } from "../http/clientOptions.js";
import { classifyAzureError } from "../errors.js";

export interface TenantRecord {
  tenantId: string;
  displayName?: string | undefined;
  defaultDomain?: string | undefined;
}

export interface SubscriptionRecord {
  subscriptionId: string;
  displayName: string;
  tenantId: string;
  state: string;
  managedByTenantIds: string[];
  tags?: Record<string, string> | undefined;
}

/** Abstraction over the ARM subscription API (fakeable in tests). */
export interface SubscriptionApi {
  listTenants(): Promise<TenantRecord[]>;
  /** Lists the subscriptions visible with a token issued by `accessTenantId`. */
  listSubscriptions(accessTenantId: string): Promise<SubscriptionRecord[]>;
}

export function createSubscriptionApi(credential: TokenCredential): SubscriptionApi {
  const options = readOnlyClientOptions();
  return {
    async listTenants() {
      const client = new SubscriptionClient(credential, options);
      const out: TenantRecord[] = [];
      for await (const t of client.tenants.list()) {
        if (t.tenantId)
          out.push({ tenantId: t.tenantId, displayName: t.displayName, defaultDomain: t.defaultDomain });
      }
      return out;
    },
    async listSubscriptions(accessTenantId) {
      const client = new SubscriptionClient(tenantBoundCredential(credential, accessTenantId), options);
      const out: SubscriptionRecord[] = [];
      for await (const s of client.subscriptions.list()) {
        if (!s.subscriptionId) continue;
        out.push({
          subscriptionId: s.subscriptionId,
          displayName: s.displayName ?? s.subscriptionId,
          tenantId: s.tenantId ?? accessTenantId,
          state: s.state ?? "Unknown",
          managedByTenantIds: (s.managedByTenants ?? []).flatMap((m) => (m.tenantId ? [m.tenantId] : [])),
          tags: s.tags,
        });
      }
      return out;
    },
  };
}

export interface SubscriptionDiscoveryResult {
  tenants: TenantInfo[];
  subscriptions: SubscriptionInfo[];
  warnings: DiscoveryWarning[];
}

const READABLE_STATES = new Set(["enabled", "warned", "pastdue"]);

export function isReadableState(state: string): boolean {
  return READABLE_STATES.has(state.toLowerCase());
}

/**
 * Discovers all tenants of the signed-in identity and all subscriptions per tenant.
 * A tenant whose token cannot be obtained (consent, MFA, Conditional Access) produces a warning
 * and does not abort discovery. Subscriptions visible from several tenants (Azure Lighthouse)
 * are de-duplicated, preferring access through the owning tenant.
 */
export async function discoverSubscriptions(
  api: SubscriptionApi,
  logger: Logger,
  filter: { tenantIds?: readonly string[]; subscriptionIds?: readonly string[] } = {},
): Promise<SubscriptionDiscoveryResult> {
  const warnings: DiscoveryWarning[] = [];
  let tenants = await api.listTenants();
  if (filter.tenantIds?.length) {
    const wanted = new Set(filter.tenantIds.map((t) => t.toLowerCase()));
    tenants = tenants.filter((t) => wanted.has(t.tenantId.toLowerCase()));
  }
  logger.info("tenants.discovered", { count: tenants.length });

  const tenantInfos: TenantInfo[] = [];
  const bySubscription = new Map<string, SubscriptionInfo>();

  for (const tenant of tenants) {
    let subs: SubscriptionRecord[];
    try {
      subs = await api.listSubscriptions(tenant.tenantId);
      tenantInfos.push({ ...definedTenantFields(tenant), accessible: true });
    } catch (error) {
      const classified = classifyAzureError(error);
      tenantInfos.push({ ...definedTenantFields(tenant), accessible: false });
      warnings.push({
        scope: `/tenants/${tenant.tenantId}`,
        operation: "ListSubscriptions",
        reason: "TenantTokenUnavailable",
        detail: classified.code ?? classified.message,
      });
      continue;
    }
    for (const s of subs) {
      const key = s.subscriptionId.toLowerCase();
      const existing = bySubscription.get(key);
      const candidate: SubscriptionInfo = {
        subscriptionId: s.subscriptionId,
        displayName: s.displayName,
        tenantId: s.tenantId,
        accessTenantId: tenant.tenantId,
        state: s.state,
        managedByTenantIds: s.managedByTenantIds,
        ...(s.tags ? { tags: s.tags } : {}),
      };
      if (
        !existing ||
        (existing.accessTenantId !== existing.tenantId && candidate.accessTenantId === candidate.tenantId)
      ) {
        bySubscription.set(key, candidate);
      }
    }
  }

  let subscriptions = [...bySubscription.values()].sort((a, b) =>
    a.subscriptionId.localeCompare(b.subscriptionId),
  );
  if (filter.subscriptionIds?.length) {
    const wanted = new Set(filter.subscriptionIds.map((s) => s.toLowerCase()));
    subscriptions = subscriptions.filter((s) => wanted.has(s.subscriptionId.toLowerCase()));
  }
  for (const s of subscriptions) {
    if (!isReadableState(s.state)) {
      warnings.push({
        scope: `/subscriptions/${s.subscriptionId}`,
        operation: "SubscriptionState",
        reason: "SubscriptionDisabled",
        detail: s.state,
      });
    }
  }
  logger.info("subscriptions.discovered", {
    count: subscriptions.length,
    readable: subscriptions.filter((s) => isReadableState(s.state)).length,
  });
  return { tenants: tenantInfos, subscriptions, warnings };
}

function definedTenantFields(t: TenantRecord): Omit<TenantInfo, "accessible"> {
  return {
    tenantId: t.tenantId,
    ...(t.displayName ? { displayName: t.displayName } : {}),
    ...(t.defaultDomain ? { defaultDomain: t.defaultDomain } : {}),
  };
}
