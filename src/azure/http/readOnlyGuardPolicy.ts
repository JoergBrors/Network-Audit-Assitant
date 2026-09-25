import type { PipelinePolicy, PipelineRequest } from "@azure/core-rest-pipeline";

export const READ_ONLY_GUARD_POLICY_NAME = "readOnlyGuardPolicy";

/** Thrown before a request leaves the process when it could modify Azure state. */
export class ReadOnlyViolationError extends Error {
  override readonly name = "ReadOnlyViolationError";
  constructor(
    readonly method: string,
    readonly url: string,
  ) {
    super(`Blocked ${method} ${url}: this tool is strictly read-only.`);
  }
}

export interface ReadOnlyGuardOptions {
  /** Allow the POST actions that read effective routes / effective NSGs (requires a custom role). */
  allowEffectiveRoutes?: boolean;
}

const ALWAYS_ALLOWED_POST: RegExp[] = [
  // Azure Resource Graph query (read-only by definition).
  /^\/providers\/microsoft\.resourcegraph\/resources$/i,
];

const EFFECTIVE_ROUTES_POST: RegExp[] = [
  /^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networkinterfaces\/[^/]+\/effectiveroutetable$/i,
  /^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.network\/networkinterfaces\/[^/]+\/effectivenetworksecuritygroups$/i,
];

/** Pure decision function, exported for tests. */
export function isRequestAllowed(method: string, url: string, options: ReadOnlyGuardOptions = {}): boolean {
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD") return true;
  if (m !== "POST") return false;
  let path: string;
  try {
    path = new URL(url).pathname.replace(/\/+$/, "");
  } catch {
    return false;
  }
  if (ALWAYS_ALLOWED_POST.some((re) => re.test(path))) return true;
  return options.allowEffectiveRoutes === true && EFFECTIVE_ROUTES_POST.some((re) => re.test(path));
}

/**
 * Pipeline policy that rejects every request which could change Azure resources.
 * Installed on every Azure SDK client created by this tool (see clientOptions.ts).
 */
export function readOnlyGuardPolicy(options: ReadOnlyGuardOptions = {}): PipelinePolicy {
  return {
    name: READ_ONLY_GUARD_POLICY_NAME,
    sendRequest(request: PipelineRequest, next) {
      if (!isRequestAllowed(request.method, request.url, options)) {
        return Promise.reject(new ReadOnlyViolationError(request.method, request.url));
      }
      return next(request);
    },
  };
}
