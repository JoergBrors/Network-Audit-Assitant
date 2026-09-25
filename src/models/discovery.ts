import { z } from "zod";

export const WarningReasonSchema = z.enum([
  "InsufficientPermissions",
  "Throttled",
  "NotFound",
  "Truncated",
  "TenantTokenUnavailable",
  "SubscriptionDisabled",
  "Error",
]);
export type WarningReason = z.infer<typeof WarningReasonSchema>;

export const DiscoveryWarningSchema = z.object({
  resource: z.string().optional(),
  scope: z.string().optional(),
  operation: z.string(),
  reason: WarningReasonSchema,
  detail: z.string().optional(),
  /** Optional data (e.g. management groups): shown as a notice, does not reduce assessment quality. */
  optional: z.boolean().optional(),
});
export type DiscoveryWarning = z.infer<typeof DiscoveryWarningSchema>;

export const TenantInfoSchema = z.object({
  tenantId: z.string(),
  displayName: z.string().optional(),
  defaultDomain: z.string().optional(),
  accessible: z.boolean(),
});
export type TenantInfo = z.infer<typeof TenantInfoSchema>;

export const SubscriptionInfoSchema = z.object({
  subscriptionId: z.string(),
  displayName: z.string(),
  /** Tenant that owns the subscription. */
  tenantId: z.string(),
  /** Tenant whose token is used to read the subscription (differs for Azure Lighthouse delegations). */
  accessTenantId: z.string(),
  state: z.string(),
  managedByTenantIds: z.array(z.string()),
  tags: z.record(z.string(), z.string()).optional(),
});
export type SubscriptionInfo = z.infer<typeof SubscriptionInfoSchema>;

/** One row returned by Azure Resource Graph. Only the base columns are guaranteed. */
export const RawResourceSchema = z.looseObject({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  tenantId: z.string().optional(),
  subscriptionId: z.string().optional(),
  resourceGroup: z.string().optional(),
  location: z.string().optional(),
  properties: z.record(z.string(), z.unknown()).optional(),
});
export type RawResource = z.infer<typeof RawResourceSchema>;

export const QueryStatsSchema = z.object({
  queryId: z.string(),
  tenantId: z.string(),
  batches: z.number(),
  pages: z.number(),
  rows: z.number(),
  truncated: z.number(),
  failedBatches: z.number(),
  fromCache: z.number(),
  durationMs: z.number(),
});
export type QueryStats = z.infer<typeof QueryStatsSchema>;

export const DiscoveryQualitySchema = z.object({
  tenants: z.object({ total: z.number(), readable: z.number() }),
  subscriptions: z.object({ total: z.number(), readable: z.number() }),
  networkResources: z.number(),
  argQueries: z.object({
    executed: z.number(),
    pages: z.number(),
    truncated: z.number(),
    failed: z.number(),
  }),
  armEnrichment: z.object({ attempted: z.number(), successful: z.number(), unavailable: z.number() }),
  overallConfidence: z.enum(["HIGH", "MEDIUM", "LOW"]),
});
export type DiscoveryQuality = z.infer<typeof DiscoveryQualitySchema>;

export const RawInventorySchema = z.object({
  generatedAt: z.string(),
  tenants: z.array(TenantInfoSchema),
  subscriptions: z.array(SubscriptionInfoSchema),
  /** Keyed by query id (e.g. "Q-NET-VNET"). */
  resources: z.record(z.string(), z.array(RawResourceSchema)),
  queryStats: z.array(QueryStatsSchema),
  warnings: z.array(DiscoveryWarningSchema),
  quality: DiscoveryQualitySchema,
});
export type RawInventory = z.infer<typeof RawInventorySchema>;
