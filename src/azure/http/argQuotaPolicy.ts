import type { PipelinePolicy } from "@azure/core-rest-pipeline";
import { sleep } from "../../utils/concurrency.js";

export const ARG_QUOTA_POLICY_NAME = "argQuotaPolicy";

/** Parses ARG's `x-ms-user-quota-resets-after` header (format `hh:mm:ss`) into milliseconds. */
export function parseQuotaReset(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const match = /^(\d+):(\d{2}):(\d{2})(?:\.\d+)?$/.exec(value.trim());
  if (!match) return undefined;
  const [, h, m, s] = match;
  return ((Number(h) * 60 + Number(m)) * 60 + Number(s)) * 1000;
}

export interface QuotaState {
  remaining: number | undefined;
  resetAt: number | undefined;
}

/**
 * Proactive ARG throttling: when the per-user quota is (nearly) exhausted, following requests
 * wait until the quota window resets instead of provoking HTTP 429.
 */
export function argQuotaPolicy(options: { now?: () => number; wait?: (ms: number) => Promise<void> } = {}): {
  policy: PipelinePolicy;
  state: QuotaState;
} {
  const now = options.now ?? Date.now;
  const wait = options.wait ?? sleep;
  const state: QuotaState = { remaining: undefined, resetAt: undefined };

  const policy: PipelinePolicy = {
    name: ARG_QUOTA_POLICY_NAME,
    async sendRequest(request, next) {
      if (state.remaining !== undefined && state.remaining <= 1 && state.resetAt !== undefined) {
        const delay = state.resetAt - now();
        if (delay > 0) await wait(delay);
        state.remaining = undefined;
      }
      const response = await next(request);
      const remaining = response.headers.get("x-ms-user-quota-remaining");
      const resetMs = parseQuotaReset(response.headers.get("x-ms-user-quota-resets-after"));
      if (remaining !== undefined) state.remaining = Number(remaining);
      if (resetMs !== undefined) state.resetAt = now() + resetMs;
      return response;
    },
  };
  return { policy, state };
}
