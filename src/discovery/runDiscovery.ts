import type { TokenCredential } from "@azure/core-auth";
import type { DiscoveryWarning, QueryStats, RawInventory, RawResource } from "../models/discovery.js";
import type { Logger } from "../logging/logger.js";
import { createLimiter } from "../utils/concurrency.js";
import type { DiscoveryCache } from "../azure/cache.js";
import { createArgExecutor } from "../azure/resourceGraph/argClient.js";
import {
  DISCOVERY_QUERIES,
  ORG_MANAGEMENT_GROUPS,
  type ArgQueryDefinition,
} from "../azure/resourceGraph/queries.js";
import { runArgQuery, type ArgExecutor } from "../azure/resourceGraph/runQuery.js";
import {
  createSubscriptionApi,
  discoverSubscriptions,
  isReadableState,
  type SubscriptionApi,
} from "../azure/subscriptions/discoverSubscriptions.js";
import { computeDiscoveryQuality } from "./quality.js";
import { runEnrichment } from "../azure/arm/enrichment.js";
import type { ArmReader } from "../azure/arm/armReader.js";

export interface DiscoveryOptions {
  credential: TokenCredential;
  logger: Logger;
  cache?: DiscoveryCache | undefined;
  tenantIds?: readonly string[];
  subscriptionIds?: readonly string[];
  includeManagementGroups?: boolean;
  argConcurrency?: number;
  batchSize?: number;
  /** Phase 5 ARM enrichment (Virtual WAN, service tags). Default: true. */
  enrich?: boolean;
  onProgress?: (progress: DiscoveryProgress) => void;
  /** Test seams; production code uses the Azure SDK implementations. */
  subscriptionApi?: SubscriptionApi;
  argExecutorFactory?: (tenantId: string) => ArgExecutor;
  armReaderFactory?: (tenantId: string) => ArmReader;
  queries?: readonly ArgQueryDefinition[];
  now?: () => Date;
}

export interface DiscoveryProgress {
  phase: "subscriptions" | "resourceGraph" | "enrichment" | "complete";
  completedQueries: number;
  totalQueries: number;
}

/**
 * Discovery pipeline steps 1–5 (AZURE-DISCOVERY.md): tenants → subscriptions → ARG queries →
 * RawInventory. Errors are isolated per tenant/batch/subscription and surface as warnings.
 */
export async function runDiscovery(options: DiscoveryOptions): Promise<RawInventory> {
  const { logger, credential } = options;
  const now = options.now ?? (() => new Date());
  const queries = options.queries ?? DISCOVERY_QUERIES;
  const limiter = createLimiter(options.argConcurrency ?? 4);
  const executorFactory =
    options.argExecutorFactory ?? ((tenantId: string) => createArgExecutor(credential, tenantId));

  logger.info("discovery.start", {
    tenantFilter: options.tenantIds?.length ?? 0,
    subscriptionFilter: options.subscriptionIds?.length ?? 0,
  });
  options.onProgress?.({ phase: "subscriptions", completedQueries: 0, totalQueries: 0 });

  const subs = await discoverSubscriptions(
    options.subscriptionApi ?? createSubscriptionApi(credential),
    logger,
    {
      ...(options.tenantIds ? { tenantIds: options.tenantIds } : {}),
      ...(options.subscriptionIds ? { subscriptionIds: options.subscriptionIds } : {}),
    },
  );

  const warnings: DiscoveryWarning[] = [...subs.warnings];
  const queryStats: QueryStats[] = [];
  const resources: Record<string, RawResource[]> = {};

  const jobs: { tenantId: string; query: ArgQueryDefinition; subscriptionIds: string[] }[] = [];
  for (const tenant of subs.tenants.filter((t) => t.accessible)) {
    const subscriptionIds = subs.subscriptions
      .filter((s) => s.accessTenantId === tenant.tenantId && isReadableState(s.state))
      .map((s) => s.subscriptionId);
    if (subscriptionIds.length > 0) {
      for (const query of queries) jobs.push({ tenantId: tenant.tenantId, query, subscriptionIds });
    }
    if (options.includeManagementGroups !== false) {
      jobs.push({ tenantId: tenant.tenantId, query: ORG_MANAGEMENT_GROUPS, subscriptionIds: [] });
    }
  }

  let completed = 0;
  const executors = new Map<string, ArgExecutor>();
  const executorFor = (tenantId: string): ArgExecutor => {
    let executor = executors.get(tenantId);
    if (!executor) {
      executor = executorFactory(tenantId);
      executors.set(tenantId, executor);
    }
    return executor;
  };

  await Promise.all(
    jobs.map(async (job) => {
      const result = await runArgQuery({
        executor: executorFor(job.tenantId),
        query: job.query,
        tenantId: job.tenantId,
        subscriptionIds: job.subscriptionIds,
        limiter,
        logger,
        cache: options.cache,
        optional: job.query.id === ORG_MANAGEMENT_GROUPS.id,
        ...(options.batchSize ? { batchSize: options.batchSize } : {}),
      });
      (resources[job.query.id] ??= []).push(...result.rows);
      queryStats.push(result.stats);
      warnings.push(...result.warnings);
      completed++;
      options.onProgress?.({
        phase: "resourceGraph",
        completedQueries: completed,
        totalQueries: jobs.length,
      });
    }),
  );

  for (const [queryId, rows] of Object.entries(resources)) resources[queryId] = dedupeById(rows);
  queryStats.sort((a, b) => a.queryId.localeCompare(b.queryId) || a.tenantId.localeCompare(b.tenantId));

  const allRows = Object.values(resources).flat();
  const partial: RawInventory = {
    generatedAt: now().toISOString(),
    tenants: subs.tenants,
    subscriptions: subs.subscriptions,
    resources,
    queryStats,
    warnings,
    quality: computeDiscoveryQuality({
      tenants: subs.tenants,
      subscriptions: subs.subscriptions,
      resources: allRows,
      queryStats,
      warnings,
    }),
  };

  let enrichment: RawInventory["enrichment"];
  if (options.enrich !== false) {
    options.onProgress?.({ phase: "enrichment", completedQueries: completed, totalQueries: jobs.length });
    const result = await runEnrichment({
      raw: partial,
      credential,
      logger,
      ...(options.armReaderFactory ? { readerFactory: options.armReaderFactory } : {}),
    });
    enrichment = result.enrichment;
    warnings.push(...result.warnings);
  }
  const quality = computeDiscoveryQuality({
    tenants: subs.tenants,
    subscriptions: subs.subscriptions,
    resources: allRows,
    queryStats,
    warnings,
    ...(enrichment
      ? {
          enrichment: {
            attempted: enrichment.results.length,
            successful: enrichment.results.filter((r) => r.status === "ok" || r.status === "notFound").length,
            unavailable: enrichment.results.filter((r) => r.status === "forbidden" || r.status === "error")
              .length,
          },
        }
      : {}),
  });
  logger.info("discovery.complete", { resources: allRows.length, warnings: warnings.length, ...quality });
  options.onProgress?.({ phase: "complete", completedQueries: completed, totalQueries: jobs.length });

  return {
    generatedAt: now().toISOString(),
    tenants: subs.tenants,
    subscriptions: subs.subscriptions,
    resources,
    queryStats,
    warnings,
    quality,
    ...(enrichment ? { enrichment } : {}),
  };
}

function dedupeById(rows: RawResource[]): RawResource[] {
  const seen = new Map<string, RawResource>();
  for (const row of rows) {
    const key = row.id.toLowerCase();
    if (!seen.has(key)) seen.set(key, row);
  }
  return [...seen.values()].sort((a, b) => a.id.toLowerCase().localeCompare(b.id.toLowerCase()));
}
