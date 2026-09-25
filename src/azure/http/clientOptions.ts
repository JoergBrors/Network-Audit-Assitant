import type { PipelinePolicy } from "@azure/core-rest-pipeline";
import { readOnlyGuardPolicy, type ReadOnlyGuardOptions } from "./readOnlyGuardPolicy.js";

export const TOOL_USER_AGENT = "azure-network-audit-assistant";

export interface ReadOnlyClientOptions {
  additionalPolicies: { policy: PipelinePolicy; position: "perCall" | "perRetry" }[];
  retryOptions: { maxRetries: number; retryDelayInMs: number; maxRetryDelayInMs: number };
  userAgentOptions: { userAgentPrefix: string };
}

/**
 * Options for every Azure SDK client used by this tool. The SDK's built-in retry policy handles
 * 429/5xx with exponential backoff and honours `Retry-After`; the read-only guard runs per retry
 * so that no attempt can ever send a mutating request.
 */
export function readOnlyClientOptions(
  options: ReadOnlyGuardOptions & { extraPolicies?: PipelinePolicy[] } = {},
): ReadOnlyClientOptions {
  return {
    additionalPolicies: [
      { policy: readOnlyGuardPolicy(options), position: "perRetry" },
      ...(options.extraPolicies ?? []).map((policy) => ({ policy, position: "perCall" as const })),
    ],
    retryOptions: { maxRetries: 5, retryDelayInMs: 500, maxRetryDelayInMs: 30_000 },
    userAgentOptions: { userAgentPrefix: TOOL_USER_AGENT },
  };
}
