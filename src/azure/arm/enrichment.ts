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

/** ARM collections with PaaS network rules (RESOURCE-GRAPH-QUERIES.md § 11, E-PAAS-01…03). */
interface PaasArmCall {
  /** firewallRules / virtualNetworkRules / siteConfig, else stored under `extra[key]`. */
  key: string;
  /** Path below the resource ID. */
  path: string;
  version: string;
  /** Items key of a list response; "" reads a single resource. */
  itemsKey?: string;
}

/**
 * ARM sub-resources with network settings Resource Graph does not return (Microsoft REST API
 * reference per provider). `publicOnly`: only read while the public endpoint is enabled (rules
 * that only filter public traffic).
 */
const PAAS_ARM_CALLS: Record<string, { label: string; publicOnly?: boolean; calls: PaasArmCall[] }> = {
  "microsoft.sql/servers": {
    label: "SqlServers",
    publicOnly: true,
    calls: [
      { key: "firewallRules", path: "/firewallRules", version: "2021-11-01" },
      { key: "virtualNetworkRules", path: "/virtualNetworkRules", version: "2021-11-01" },
    ],
  },
  "microsoft.dbforpostgresql/flexibleservers": {
    label: "PostgreSqlFlexibleServers",
    publicOnly: true,
    calls: [{ key: "firewallRules", path: "/firewallRules", version: "2022-12-01" }],
  },
  "microsoft.dbformysql/flexibleservers": {
    label: "MySqlFlexibleServers",
    publicOnly: true,
    calls: [{ key: "firewallRules", path: "/firewallRules", version: "2023-06-30" }],
  },
  // Access restrictions (main + SCM) and outbound routing live in the site configuration.
  "microsoft.web/sites": {
    label: "WebApps",
    calls: [{ key: "siteConfig", path: "/config/web", version: "2023-12-01", itemsKey: "" }],
  },
  "microsoft.servicebus/namespaces": {
    label: "ServiceBusNamespaces",
    publicOnly: true,
    calls: [
      {
        key: "networkRuleSet",
        path: "/networkRuleSets/default",
        version: "2022-10-01-preview",
        itemsKey: "",
      },
    ],
  },
  "microsoft.eventhub/namespaces": {
    label: "EventHubsNamespaces",
    publicOnly: true,
    calls: [{ key: "networkRuleSet", path: "/networkRuleSets/default", version: "2024-01-01", itemsKey: "" }],
  },
  "microsoft.cache/redis": {
    label: "Redis",
    publicOnly: true,
    calls: [{ key: "firewallRules", path: "/firewallRules", version: "2024-03-01" }],
  },
  "microsoft.synapse/workspaces": {
    label: "SynapseWorkspaces",
    publicOnly: true,
    calls: [{ key: "firewallRules", path: "/firewallRules", version: "2021-06-01" }],
  },
  "microsoft.datafactory/factories": {
    label: "DataFactories",
    calls: [
      { key: "managedVirtualNetworks", path: "/managedVirtualNetworks", version: "2018-06-01" },
      { key: "integrationRuntimes", path: "/integrationRuntimes", version: "2018-06-01" },
    ],
  },
  // Session hosts link the host pool to its VMs (and so to their subnets and egress path).
  "microsoft.desktopvirtualization/hostpools": {
    label: "HostPools",
    calls: [{ key: "sessionHosts", path: "/sessionHosts", version: "2024-04-03" }],
  },
  "microsoft.web/hostingenvironments": {
    label: "AppServiceEnvironments",
    calls: [{ key: "networking", path: "/configurations/networking", version: "2023-12-01", itemsKey: "" }],
  },
};

const RULE_FIELDS = new Set(["firewallRules", "virtualNetworkRules", "siteConfig"]);

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
 * Virtual WAN hub connections, routing intent and hub route tables (E-VWAN-01…03), the
 * address prefixes of referenced service tags and PaaS network rules (E-PAAS-01…03). Failures are isolated and reported as warnings.
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
    apiVersion = NETWORK_API_VERSION,
  ) => {
    try {
      const value = await limit(() => readerFor(tenantId).list(path, apiVersion, itemsKey));
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

  // PaaS network settings that Resource Graph does not return.
  const paasRows = (raw.resources["Q-PAAS"] ?? []).filter((r) => {
    const api = PAAS_ARM_CALLS[r.type.toLowerCase()];
    if (!api) return false;
    if (!api.publicOnly) return true;
    const props = isObj(r.properties) ? r.properties : {};
    const network = isObj(props["network"]) ? props["network"] : {};
    const value = props["publicNetworkAccess"] ?? network["publicNetworkAccess"];
    const access = typeof value === "string" ? value.toLowerCase() : "";
    return access !== "disabled";
  });
  const paasRules: NonNullable<Enrichment["paasNetworkRules"]> = {};
  const paasJobs = paasRows.map(async (r) => {
    const api = PAAS_ARM_CALLS[r.type.toLowerCase()]!;
    const tenantId = tenantOf(r);
    const values = await Promise.all(
      api.calls.map((c) =>
        call(`${api.label}.${c.key}`, r.id, tenantId, `${r.id}${c.path}`, c.itemsKey ?? "value", c.version),
      ),
    );
    const entry: NonNullable<Enrichment["paasNetworkRules"]>[string] = {
      firewallRules: [],
      virtualNetworkRules: [],
      siteConfig: [],
      status: "ok",
    };
    const extra: Record<string, unknown[]> = {};
    api.calls.forEach((c, i) => {
      const v = values[i] ?? [];
      if (RULE_FIELDS.has(c.key)) entry[c.key as "firewallRules" | "virtualNetworkRules" | "siteConfig"] = v;
      else extra[c.key] = v;
    });
    if (Object.keys(extra).length) entry.extra = extra;
    const failed = values.filter((v) => v === undefined).length;
    entry.status = failed === 0 ? "ok" : failed === api.calls.length ? "not-accessible" : "partial";
    paasRules[r.id.toLowerCase()] = entry;
  });

  await Promise.all([...hubJobs, tagJob, ...paasJobs]);
  if (paasRows.length > 0) enrichment.paasNetworkRules = paasRules;
  logger.info("arm.enrichment", {
    hubs: hubs.length,
    serviceTags: enrichment.serviceTags?.tags.length ?? 0,
    paasServices: paasRows.length,
    calls: results.length,
    failed: results.filter((r) => r.status !== "ok").length,
  });
  return { enrichment, warnings };
}
