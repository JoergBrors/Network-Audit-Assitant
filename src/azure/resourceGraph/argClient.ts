import type { TokenCredential } from "@azure/core-auth";
import { ResourceGraphClient } from "@azure/arm-resourcegraph";
import { tenantBoundCredential } from "../../auth/tenantCredential.js";
import { argQuotaPolicy } from "../http/argQuotaPolicy.js";
import { readOnlyClientOptions } from "../http/clientOptions.js";
import type { ArgExecutor } from "./runQuery.js";

/** Creates a read-only ARG client whose token is issued by the given tenant. */
export function createArgExecutor(credential: TokenCredential, tenantId: string): ArgExecutor {
  const { policy } = argQuotaPolicy();
  const client = new ResourceGraphClient(
    tenantBoundCredential(credential, tenantId),
    readOnlyClientOptions({ extraPolicies: [policy] }),
  );
  return { resources: (query) => client.resources(query) };
}
