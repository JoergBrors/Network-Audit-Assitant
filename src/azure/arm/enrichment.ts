import type { TokenCredential } from "@azure/core-auth";
import { ipFamilyOf } from "../../addressing/ip.js";
import type {
  DiscoveryWarning,
  Enrichment,
  EnrichmentResult,
  RawInventory,
  RawResource,
} from "../../models/discovery.js";
import type { Logger } from "../../logging/logger.js";
import { createLimiter } from "../../utils/concurrency.js";
import { classifyAzureError } from "../errors.js";
import { createArmReader, NETWORK_API_VERSION, type ArmReader } from "./armReader.js";

/** Service tags that NSGs/firewalls/UDRs evaluate natively without prefix lists. */
const BUILTIN_TAGS = new Set(["*", "any", "internet", "virtualnetwork", "azureloadbalancer"]);

export interface EnrichmentOptions {
  raw: RawInventory;
  credential: TokenCredential;
  logger: Logger;
  concurrency?: number;
  /** Test seam. */
  readerFactory?: (tenantId: string) => ArmReader;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

/** Collects service tag names referenced in NSG rules, UDRs, firewall rules and AVNM admin rules. */
export function referencedServiceTags(raw: RawInventory): string[] {
  const tags = new Set<string>();
  const consider = (value: unknown) => {
    if (typeof value !== "string") return;
    const v = value.trim();
    if (!v || ipFamilyOf(v.split("/")[0]) || BUILTIN_TAGS.has(v.toLowerCase())) return;
    if (/^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)?$/.test(v)) tags.add(v);
  };
  const walk = (value: unknown, key = "", depth = 0) => {
    if (depth > 8) return;
    if (Array.isArray(value)) for (const v of value) walk(v, key, depth + 1);
    else if (isObj(value)) for (const [k, v] of Object.entries(value)) walk(v, k, depth + 1);
    else if (
      /^(source|destination)AddressPrefix(es)?$|^addressPrefix$|^destinationAddresses$|^sourceAddresses$|^destinationAddress$/i.test(
        key,
      )
    )
      consider(value);
  };
  for (const q of ["Q-NET-NSG", "Q-NET-RT", "Q-SEC-FWRCG", "Q-SEC-AVNM"])
    for (const r of raw.resources[q] ?? []) walk(r.properties);
  return [...tags].sort();
}

/**
 * Phase 5: targeted ARM enrichment for data Resource Graph does not provide:
 * Virtual WAN hub connections, routing intent and hub route tables (E-VWAN-01…03) and the
 * address prefixes of referenced service tags. Failures are isolated and reported as warnings.
 */
export async function runEnrichment(
  options: EnrichmentOptions,
): Promise<{ enrichment: Enrichment; warnings: DiscoveryWarning[] }> {
  const { raw, logger } = options;
  const limit = createLimiter(options.concurrency ?? 8);
  const readers = new Map<string, ArmReader>();
  const readerFor = (tenantId: string) => {
    let r = readers.get(tenantId);
    if (!r) {
      r = options.readerFactory
        ? options.readerFactory(tenantId)
        : createArmReader(options.credential, tenantId);
      readers.set(tenantId, r);
    }
    return r;
  };
  const accessTenant = new Map(
    raw.subscriptions.map((s) => [s.subscriptionId.toLowerCase(), s.accessTenantId]),
  );
  const tenantOf = (r: RawResource) =>
    accessTenant.get((r.subscriptionId ?? "").toLowerCase()) ?? r.tenantId ?? raw.tenants[0]?.tenantId ?? "";
  const results: EnrichmentResult[] = [];
  const warnings: DiscoveryWarning[] = [];
  const enrichment: Enrichment = { virtualHubs: {}, results };

  const call = async (
    operation: string,
    resourceId: string | undefined,
    tenantId: string,
    path: string,
    itemsKey = "value",
  ) => {
    try {
      const value = await limit(() => readerFor(tenantId).list(path, NETWORK_API_VERSION, itemsKey));
      results.push({ operation, ...(resourceId ? { resourceId } : {}), status: "ok" });
      return value;
    } catch (error) {
      const c = classifyAzureError(error);
      const status =
        c.reason === "InsufficientPermissions" ? "forbidden" : c.reason === "NotFound" ? "notFound" : "error";
      results.push({ operation, ...(resourceId ? { resourceId } : {}), status, detail: c.code ?? c.message });
      if (status !== "notFound") {
        warnings.push({
          resource: resourceId,
          operation: `ARM:${operation}`,
          reason: c.reason === "NotFound" ? "NotFound" : c.reason,
          detail: c.code ?? c.message,
        });
      }
      return undefined;
    }
  };

  // Virtual WAN hubs (virtualHubs with a virtualWan reference; Route Servers have none).
  const hubs = (raw.resources["Q-VWAN"] ?? []).filter(
    (r) => r.type.toLowerCase() === "microsoft.network/virtualhubs" && isObj(r.properties?.["virtualWan"]),
  );
  const hubJobs = hubs.map(async (hub) => {
    const tenantId = tenantOf(hub);
    const [connections, routingIntents, routeTables] = await Promise.all([
      call("HubVirtualNetworkConnections.list", hub.id, tenantId, `${hub.id}/hubVirtualNetworkConnections`),
      call("RoutingIntent.list", hub.id, tenantId, `${hub.id}/routingIntent`),
      call("HubRouteTables.list", hub.id, tenantId, `${hub.id}/hubRouteTables`),
    ]);
    const got = [connections, routingIntents, routeTables].filter((x) => x !== undefined).length;
    enrichment.virtualHubs[hub.id.toLowerCase()] = {
      connections: connections ?? [],
      routingIntents: routingIntents ?? [],
      routeTables: routeTables ?? [],
      status: got === 3 ? "ok" : got === 0 ? "not-accessible" : "partial",
    };
  });

  // Service tags (one call per cloud; the location only selects the cloud/version, not a filter).
  const tagNames = referencedServiceTags(raw);
  const tagJob = (async () => {
    if (tagNames.length === 0) return;
    const sub = raw.subscriptions.find((s) => s.state.toLowerCase() === "enabled") ?? raw.subscriptions[0];
    if (!sub) return;
    const location =
      (raw.resources["Q-NET-VNET"] ?? []).find(
        (v) => v.subscriptionId?.toLowerCase() === sub.subscriptionId.toLowerCase(),
      )?.location ??
      (raw.resources["Q-NET-VNET"] ?? [])[0]?.location ??
      "westeurope";
    const value = await call(
      "ServiceTags.list",
      `/subscriptions/${sub.subscriptionId}`,
      sub.accessTenantId,
      `/subscriptions/${sub.subscriptionId}/providers/Microsoft.Network/locations/${location}/serviceTags`,
      "values",
    );
    if (!value) return;
    const wanted = new Set(tagNames.map((t) => t.toLowerCase()));
    const values = value;
    enrichment.serviceTags = {
      location,
      tags: values
        .filter(
          (v): v is Record<string, unknown> =>
            isObj(v) && typeof v["name"] === "string" && wanted.has(v["name"].toLowerCase()),
        )
        .map((v) => ({
          name: v["name"] as string,
          prefixes: (isObj(v["properties"]) && Array.isArray(v["properties"]["addressPrefixes"])
            ? (v["properties"]["addressPrefixes"] as unknown[])
            : []
          ).filter((p): p is string => typeof p === "string"),
        })),
    };
  })();

  await Promise.all([...hubJobs, tagJob]);
  logger.info("arm.enrichment", {
    hubs: hubs.length,
    serviceTags: enrichment.serviceTags?.tags.length ?? 0,
    calls: results.length,
    failed: results.filter((r) => r.status !== "ok").length,
  });
  return { enrichment, warnings };
}
