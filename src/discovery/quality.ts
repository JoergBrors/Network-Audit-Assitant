import type {
  DiscoveryQuality,
  DiscoveryWarning,
  QueryStats,
  RawResource,
  SubscriptionInfo,
  TenantInfo,
} from "../models/discovery.js";
import { isReadableState } from "../azure/subscriptions/discoverSubscriptions.js";
import { ORG_MANAGEMENT_GROUPS } from "../azure/resourceGraph/queries.js";

export interface EnrichmentCounts {
  attempted: number;
  successful: number;
  unavailable: number;
}

const SUBSCRIPTION_IN_SCOPE = /\/subscriptions\/([0-9a-f-]{36})/gi;

export function isNetworkResource(resource: RawResource): boolean {
  const type = resource.type.toLowerCase();
  return (
    type.startsWith("microsoft.network/") ||
    type === "microsoft.compute/virtualmachinescalesets/virtualmachines/networkinterfaces"
  );
}

/** Documented in AZURE-DISCOVERY.md § 7. */
export function computeDiscoveryQuality(input: {
  tenants: readonly TenantInfo[];
  subscriptions: readonly SubscriptionInfo[];
  resources: readonly RawResource[];
  queryStats: readonly QueryStats[];
  warnings: readonly DiscoveryWarning[];
  enrichment?: EnrichmentCounts;
}): DiscoveryQuality {
  const unreadable = new Set<string>();
  for (const w of input.warnings) {
    if (w.reason !== "InsufficientPermissions" && w.reason !== "SubscriptionDisabled") continue;
    for (const match of (w.scope ?? "").matchAll(SUBSCRIPTION_IN_SCOPE))
      unreadable.add(match[1]!.toLowerCase());
  }
  const inaccessibleTenants = new Set(input.tenants.filter((t) => !t.accessible).map((t) => t.tenantId));
  const readableSubs = input.subscriptions.filter(
    (s) =>
      isReadableState(s.state) &&
      !unreadable.has(s.subscriptionId.toLowerCase()) &&
      !inaccessibleTenants.has(s.accessTenantId),
  ).length;

  // Management-group visibility is optional and does not reduce assessment quality.
  const relevantStats = input.queryStats.filter((q) => q.queryId !== ORG_MANAGEMENT_GROUPS.id);
  const argQueries = {
    executed: relevantStats.length,
    pages: relevantStats.reduce((a, q) => a + q.pages, 0),
    truncated: relevantStats.reduce((a, q) => a + q.truncated, 0),
    failed: relevantStats.reduce((a, q) => a + q.failedBatches, 0),
  };
  const armEnrichment = input.enrichment ?? { attempted: 0, successful: 0, unavailable: 0 };
  const tenants = { total: input.tenants.length, readable: input.tenants.length - inaccessibleTenants.size };
  const subscriptions = { total: input.subscriptions.length, readable: readableSubs };

  const subRatio = subscriptions.total === 0 ? 0 : subscriptions.readable / subscriptions.total;
  const enrichRatio = armEnrichment.attempted === 0 ? 1 : armEnrichment.successful / armEnrichment.attempted;
  const tenantsOk = tenants.readable === tenants.total;

  let overallConfidence: DiscoveryQuality["overallConfidence"] = "LOW";
  if (
    subRatio === 1 &&
    tenantsOk &&
    argQueries.failed === 0 &&
    argQueries.truncated === 0 &&
    enrichRatio >= 0.98
  ) {
    overallConfidence = "HIGH";
  } else if (subRatio >= 0.9 && enrichRatio >= 0.9) {
    overallConfidence = "MEDIUM";
  }

  return {
    tenants,
    subscriptions,
    networkResources: input.resources.filter(isNetworkResource).length,
    argQueries,
    armEnrichment,
    overallConfidence,
  };
}
