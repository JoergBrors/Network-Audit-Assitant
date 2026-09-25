import type { QueryRequest, QueryResponse } from "@azure/arm-resourcegraph";
import type { DiscoveryWarning, QueryStats, RawResource } from "../../models/discovery.js";
import { RawResourceSchema } from "../../models/discovery.js";
import type { Logger } from "../../logging/logger.js";
import { chunk, type Limiter } from "../../utils/concurrency.js";
import { DEFAULT_CACHE_TTL_MS, sha256Hex, type DiscoveryCache } from "../cache.js";
import { classifyAzureError } from "../errors.js";
import type { ArgQueryDefinition } from "./queries.js";

/** The subset of ResourceGraphClient used here (enables fakes in tests). */
export interface ArgExecutor {
  resources(query: QueryRequest): Promise<QueryResponse>;
}

export interface RunArgQueryParams {
  executor: ArgExecutor;
  query: ArgQueryDefinition;
  tenantId: string;
  /** Subscription ids for subscription-scoped queries. Ignored for management-group scope. */
  subscriptionIds: readonly string[];
  limiter: Limiter;
  logger: Logger;
  cache?: DiscoveryCache | undefined;
  cacheTtlMs?: number;
  batchSize?: number;
  pageSize?: number;
  minPageSize?: number;
  /** Failures of optional queries are reported as notices (warning.optional = true). */
  optional?: boolean;
}

export interface ArgQueryResult {
  rows: RawResource[];
  stats: QueryStats;
  warnings: DiscoveryWarning[];
}

interface Scope {
  subscriptions?: string[];
  managementGroups?: string[];
}

interface BatchOutcome {
  rows: RawResource[];
  pages: number;
  truncated: number;
  failed: number;
  fromCache: number;
  warnings: DiscoveryWarning[];
}

export const DEFAULT_BATCH_SIZE = 200;
export const DEFAULT_PAGE_SIZE = 1000;

export async function runArgQuery(params: RunArgQueryParams): Promise<ArgQueryResult> {
  const started = Date.now();
  const { query, tenantId, batchSize = DEFAULT_BATCH_SIZE, logger } = params;

  const scopes: Scope[] =
    query.scope === "tenantRootManagementGroup"
      ? [{ managementGroups: [tenantId] }]
      : chunk([...params.subscriptionIds].sort(), batchSize).map((subscriptions) => ({ subscriptions }));

  const outcomes = await Promise.all(scopes.map((scope) => runScope(params, scope)));

  const rows = outcomes.flatMap((o) => o.rows);
  const stats: QueryStats = {
    queryId: query.id,
    tenantId,
    batches: scopes.length,
    pages: sum(outcomes, "pages"),
    rows: rows.length,
    truncated: sum(outcomes, "truncated"),
    failedBatches: sum(outcomes, "failed"),
    fromCache: sum(outcomes, "fromCache"),
    durationMs: Date.now() - started,
  };
  logger.info("arg.query", { ...stats });
  const warnings = outcomes.flatMap((o) => o.warnings);
  return {
    rows,
    stats,
    warnings: params.optional ? warnings.map((w) => ({ ...w, optional: true })) : warnings,
  };
}

async function runScope(params: RunArgQueryParams, scope: Scope): Promise<BatchOutcome> {
  const { query, tenantId, cache, cacheTtlMs = DEFAULT_CACHE_TTL_MS } = params;
  const cacheKey = cache ? await scopeCacheKey(tenantId, query, scope) : undefined;
  if (cache && cacheKey) {
    const cached = await cache.get(cacheKey);
    if (Array.isArray(cached)) {
      return { rows: cached as RawResource[], pages: 0, truncated: 0, failed: 0, fromCache: 1, warnings: [] };
    }
  }

  const outcome = await fetchScope(params, scope, params.pageSize ?? DEFAULT_PAGE_SIZE);
  if (cache && cacheKey && outcome.failed === 0 && outcome.truncated === 0) {
    await cache.set(cacheKey, outcome.rows, cacheTtlMs);
  }
  return outcome;
}

/** Fetches all pages of one scope. Splits the scope when a subset of subscriptions fails or truncates. */
async function fetchScope(params: RunArgQueryParams, scope: Scope, pageSize: number): Promise<BatchOutcome> {
  const { executor, query, limiter, logger, minPageSize = 50 } = params;
  const rows: RawResource[] = [];
  let pages = 0;
  let skipToken: string | undefined;

  try {
    do {
      const request: QueryRequest = {
        query: query.kql,
        ...(scope.subscriptions ? { subscriptions: scope.subscriptions } : {}),
        ...(scope.managementGroups ? { managementGroups: scope.managementGroups } : {}),
        options: { resultFormat: "objectArray", top: pageSize, ...(skipToken ? { skipToken } : {}) },
      };
      const response = await limiter(() => executor.resources(request));
      pages++;
      rows.push(...parseRows(response.data, query.id, params.tenantId, logger));
      logger.debug("arg.page", {
        queryId: query.id,
        page: pages,
        count: response.count,
        total: response.totalRecords,
      });

      if (response.resultTruncated === "true" && !response.skipToken) {
        return splitOrWarn(
          params,
          scope,
          pageSize,
          "Truncated",
          "Result truncated without continuation token",
        );
      }
      skipToken = response.skipToken;
    } while (skipToken);
  } catch (error) {
    const classified = classifyAzureError(error);
    if (classified.payloadTooLarge && pageSize > minPageSize) {
      logger.warn("arg.page.reduce", { queryId: query.id, pageSize: Math.floor(pageSize / 2) });
      return fetchScope(params, scope, Math.max(minPageSize, Math.floor(pageSize / 2)));
    }
    if (classified.scopeRelated) {
      return splitOrWarn(params, scope, pageSize, classified.reason, classified.code ?? classified.message);
    }
    return failed(scope, query.id, classified.reason, classified.code ?? classified.message);
  }
  return { rows, pages, truncated: 0, failed: 0, fromCache: 0, warnings: [] };
}

async function splitOrWarn(
  params: RunArgQueryParams,
  scope: Scope,
  pageSize: number,
  reason: DiscoveryWarning["reason"],
  detail: string,
): Promise<BatchOutcome> {
  const subs = scope.subscriptions;
  if (subs && subs.length > 1) {
    const mid = Math.ceil(subs.length / 2);
    const parts = await Promise.all([
      fetchScope(params, { subscriptions: subs.slice(0, mid) }, pageSize),
      fetchScope(params, { subscriptions: subs.slice(mid) }, pageSize),
    ]);
    return {
      rows: parts.flatMap((p) => p.rows),
      pages: sum(parts, "pages"),
      truncated: sum(parts, "truncated"),
      failed: sum(parts, "failed"),
      fromCache: 0,
      warnings: parts.flatMap((p) => p.warnings),
    };
  }
  const outcome = failed(scope, params.query.id, reason, detail);
  if (reason === "Truncated") return { ...outcome, failed: 0, truncated: 1 };
  return outcome;
}

function failed(
  scope: Scope,
  queryId: string,
  reason: DiscoveryWarning["reason"],
  detail: string,
): BatchOutcome {
  const scopeLabel = scope.managementGroups
    ? `/providers/Microsoft.Management/managementGroups/${scope.managementGroups.join(",")}`
    : (scope.subscriptions ?? []).map((s) => `/subscriptions/${s}`).join(",");
  return {
    rows: [],
    pages: 0,
    truncated: 0,
    failed: 1,
    fromCache: 0,
    warnings: [{ scope: scopeLabel, operation: `ARG:${queryId}`, reason, detail }],
  };
}

function parseRows(data: unknown, queryId: string, tenantId: string, logger: Logger): RawResource[] {
  if (!Array.isArray(data)) {
    logger.warn("arg.unexpectedFormat", { queryId, tenantId });
    return [];
  }
  const rows: RawResource[] = [];
  for (const item of data) {
    const parsed = RawResourceSchema.safeParse(item);
    if (parsed.success) rows.push(parsed.data);
    else logger.warn("arg.invalidRow", { queryId, issues: parsed.error.issues.length });
  }
  return rows;
}

async function scopeCacheKey(tenantId: string, query: ArgQueryDefinition, scope: Scope): Promise<string> {
  const scopeIds = [...(scope.subscriptions ?? scope.managementGroups ?? [])].sort().join(",");
  return `arg:${await sha256Hex(`${tenantId}|${query.id}|v${query.version}|${query.kql}|${scopeIds}`)}`;
}

function sum<T extends Record<K, number>, K extends string>(items: readonly T[], key: K): number {
  return items.reduce((acc, item) => acc + item[key], 0);
}
