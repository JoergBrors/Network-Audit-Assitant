import type { TokenCredential } from "@azure/core-auth";
import {
  bearerTokenAuthenticationPolicy,
  createDefaultHttpClient,
  createPipelineFromOptions,
  createPipelineRequest,
  RestError,
  type HttpClient,
} from "@azure/core-rest-pipeline";
import { tenantBoundCredential } from "../../auth/tenantCredential.js";
import { readOnlyClientOptions } from "../http/clientOptions.js";

export const ARM_ENDPOINT = "https://management.azure.com";
/** API version of @azure/arm-network@39 (ARCHITECTURE.md § 1.1). */
export const NETWORK_API_VERSION = "2026-01-01";

/** Read-only ARM access for enrichment: GET only, paging via nextLink. */
export interface ArmReader {
  /** Lists all items of a collection (`itemsKey`, default `value`), following `nextLink`. */
  list(path: string, apiVersion: string, itemsKey?: string): Promise<unknown[]>;
}

/**
 * Creates an ARM reader with the same read-only guard, retry and user agent as the SDK clients.
 * Every request is a GET; the guard rejects anything else before it is sent.
 */
export function createArmReader(
  credential: TokenCredential,
  tenantId: string,
  httpClient: HttpClient = createDefaultHttpClient(),
): ArmReader {
  const options = readOnlyClientOptions();
  const pipeline = createPipelineFromOptions({
    retryOptions: options.retryOptions,
    userAgentOptions: options.userAgentOptions,
  });
  for (const p of options.additionalPolicies)
    pipeline.addPolicy(p.policy, p.position === "perRetry" ? { phase: "Retry" } : {});
  pipeline.addPolicy(
    bearerTokenAuthenticationPolicy({
      credential: tenantBoundCredential(credential, tenantId),
      scopes: `${ARM_ENDPOINT}/.default`,
    }),
  );

  const get = async (url: string): Promise<Record<string, unknown>> => {
    const request = createPipelineRequest({ url, method: "GET" });
    const response = await pipeline.sendRequest(httpClient, request);
    if (response.status >= 400) {
      let code = `HTTP${response.status}`;
      try {
        code = (JSON.parse(response.bodyAsText ?? "{}") as { error?: { code?: string } }).error?.code ?? code;
      } catch {
        // keep status code
      }
      throw new RestError(code, { statusCode: response.status, code, request, response });
    }
    return JSON.parse(response.bodyAsText ?? "{}") as Record<string, unknown>;
  };

  return {
    async list(path, apiVersion, itemsKey = "value") {
      const out: unknown[] = [];
      let url: string | undefined =
        `${ARM_ENDPOINT}${path}${path.includes("?") ? "&" : "?"}api-version=${apiVersion}`;
      for (let page = 0; url && page < 100; page++) {
        const body = await get(url);
        const items = body[itemsKey];
        if (Array.isArray(items)) out.push(...(items as unknown[]));
        url = typeof body["nextLink"] === "string" ? body["nextLink"] : undefined;
      }
      return out;
    },
  };
}
