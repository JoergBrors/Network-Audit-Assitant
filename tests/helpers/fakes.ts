import { RestError } from "@azure/core-rest-pipeline";
import type { QueryRequest, QueryResponse } from "@azure/arm-resourcegraph";
import type { ArgExecutor } from "../../src/azure/resourceGraph/runQuery.js";
import { createLogger, type LogRecord } from "../../src/logging/logger.js";

export function memoryLogger(level: "debug" | "info" = "debug") {
  const records: LogRecord[] = [];
  return { logger: createLogger({ sink: (r) => records.push(r), level }), records };
}

export function restError(statusCode: number, code: string, message = code): RestError {
  return new RestError(message, { statusCode, code });
}

export function resource(id: string, extra: Record<string, unknown> = {}) {
  const sub = /\/subscriptions\/([^/]+)/i.exec(id)?.[1];
  return {
    id,
    name: id.split("/").pop() ?? id,
    type: "microsoft.network/virtualnetworks",
    subscriptionId: sub,
    properties: {},
    ...extra,
  };
}

export function page(data: unknown[], skipToken?: string, truncated = false): QueryResponse {
  return {
    totalRecords: data.length,
    count: data.length,
    resultTruncated: truncated ? "true" : "false",
    ...(skipToken ? { skipToken } : {}),
    data,
  };
}

/** ARG fake driven by a handler; records every request. */
export function fakeArg(handler: (req: QueryRequest) => QueryResponse | Promise<QueryResponse>) {
  const requests: QueryRequest[] = [];
  const executor: ArgExecutor = {
    async resources(req) {
      requests.push(structuredClone(req));
      return handler(req);
    },
  };
  return { executor, requests };
}

export const SUB = (n: number): string => `00000000-0000-0000-0000-${String(n).padStart(12, "0")}`;
export const TENANT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
export const TENANT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
