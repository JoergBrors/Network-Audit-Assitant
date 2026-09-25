/**
 * Development diagnostic (RESOURCE-GRAPH-QUERIES.md § 10): reports which property keys Azure
 * Resource Graph returns per network resource type. Only aggregates are printed — no resource
 * names, IDs or values. Read-only.
 *
 *   npm run verify:arg -- [--credential cli] [--tenant <id>]
 */
import { parseArgs } from "node:util";
import { createNodeCredential, isCredentialKind } from "../src/auth/node/credential.js";
import { createArgExecutor } from "../src/azure/resourceGraph/argClient.js";
import {
  createSubscriptionApi,
  discoverSubscriptions,
  isReadableState,
} from "../src/azure/subscriptions/discoverSubscriptions.js";
import { createLogger, jsonLinesSink } from "../src/logging/logger.js";
import { chunk } from "../src/utils/concurrency.js";

const { values } = parseArgs({
  options: { credential: { type: "string", default: "default" }, tenant: { type: "string" } },
});
if (!isCredentialKind(values.credential)) throw new Error(`unknown credential kind: ${values.credential}`);

const credential = createNodeCredential(values.credential);
const logger = createLogger({ sink: jsonLinesSink((l) => process.stderr.write(`${l}\n`)), level: "warn" });
const subs = await discoverSubscriptions(createSubscriptionApi(credential), logger, {
  ...(values.tenant ? { tenantIds: [values.tenant] } : {}),
});

const TABLES = ["resources", "networkresources", "dnsresources", "computeresources"] as const;
const report = new Map<string, Map<string, number>>();

for (const tenant of subs.tenants.filter((t) => t.accessible)) {
  const ids = subs.subscriptions
    .filter((s) => s.accessTenantId === tenant.tenantId && isReadableState(s.state))
    .map((s) => s.subscriptionId);
  if (ids.length === 0) continue;
  const arg = createArgExecutor(credential, tenant.tenantId);
  for (const table of TABLES) {
    const kql = `${table}
| where type startswith 'microsoft.network/' or type startswith 'microsoft.compute/virtualmachinescalesets/virtualmachines/networkinterfaces'
| summarize arg_max(id, properties) by type
| mv-expand key = bag_keys(properties)
| summarize samples = count() by type, key = tostring(key)`;
    for (const batch of chunk(ids, 200)) {
      const response = await arg.resources({
        query: kql,
        subscriptions: batch,
        options: { resultFormat: "objectArray", top: 1000 },
      });
      for (const row of response.data as { type: string; key: string }[]) {
        const keys = report.get(`${table}:${row.type}`) ?? new Map<string, number>();
        keys.set(row.key, (keys.get(row.key) ?? 0) + 1);
        report.set(`${table}:${row.type}`, keys);
      }
    }
  }
}

for (const [type, keys] of [...report.entries()].sort(([a], [b]) => a.localeCompare(b))) {
  process.stdout.write(`${type}\n  ${[...keys.keys()].sort().join(", ")}\n`);
}
