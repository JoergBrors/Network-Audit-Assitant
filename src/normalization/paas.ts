import type { Enrichment, RawResource } from "../models/discovery.js";
import type { BaseEntity, PaasExposure, PaasServiceEntity, PublicNetworkAccess } from "../models/network.js";
import { PAAS_TYPE_INFO } from "../models/paasCatalog.js";
import { normalizeId, refId } from "../utils/ids.js";
import { arr, bool, obj, str, strings, type Obj } from "./access.js";

type PaasRules = NonNullable<Enrichment["paasNetworkRules"]>[string];

/** Case-insensitive property lookup (resource providers differ in casing, e.g. vnetSubnetID). */
function ci(o: Obj, key: string): unknown {
  const lower = key.toLowerCase();
  for (const [k, v] of Object.entries(o)) if (k.toLowerCase() === lower) return v;
  return undefined;
}

function access(value: unknown): PublicNetworkAccess | undefined {
  switch (str(value)?.toLowerCase()) {
    case "enabled":
      return "Enabled";
    case "disabled":
      return "Disabled";
    case "securedbyperimeter":
      return "SecuredByPerimeter";
    default:
      return undefined;
  }
}

function action(value: unknown): "Allow" | "Deny" | undefined {
  const v = str(value)?.toLowerCase();
  return v === "allow" ? "Allow" : v === "deny" ? "Deny" : undefined;
}

/** Hostname of a URL or FQDN string. */
function hostOf(value: string): string | undefined {
  const v = value.trim();
  if (!v) return undefined;
  try {
    return new URL(v.includes("://") ? v : `https://${v}`).hostname.toLowerCase() || undefined;
  } catch {
    return undefined;
  }
}

const ENDPOINT_KEYS = [
  "fullyQualifiedDomainName",
  "documentEndpoint",
  "vaultUri",
  "defaultHostName",
  "defaultHostname",
  "loginServer",
  "endpoint",
  "serviceBusEndpoint",
  "hostName",
  "fqdn",
  "privateFQDN",
  "gatewayUrl",
  "defaultDomain",
  "workspaceUrl",
];
const ENDPOINT_MAPS = ["primaryEndpoints", "secondaryEndpoints", "connectivityEndpoints", "endpoints"];

function endpointsOf(p: Obj): string[] {
  const values: string[] = [];
  for (const key of ENDPOINT_KEYS) {
    const v = str(ci(p, key));
    if (v) values.push(v);
  }
  values.push(...strings(p["hostNames"]));
  for (const key of ENDPOINT_MAPS) {
    const map = obj(ci(p, key));
    for (const v of Object.values(map)) if (typeof v === "string") values.push(v);
  }
  const ingress = obj(obj(p["configuration"])["ingress"]);
  if (str(ingress["fqdn"])) values.push(str(ingress["fqdn"])!);
  return [...new Set(values.flatMap((v) => (hostOf(v) ? [hostOf(v)!] : [])))].sort();
}

function privateEndpointConnections(p: Obj): { privateEndpointId: string; status: string }[] {
  return arr(p["privateEndpointConnections"]).flatMap((c) => {
    const co = obj(c);
    const cp = obj(co["properties"]);
    const pe = obj(cp["privateEndpoint"] ?? co["privateEndpoint"]);
    const id = normalizeId(str(pe["id"]));
    if (!id) return [];
    const state = obj(cp["privateLinkServiceConnectionState"] ?? co["privateLinkServiceConnectionState"]);
    return [{ privateEndpointId: id, status: str(state["status"]) ?? "Unknown" }];
  });
}

/** Firewall rule lists as ARM returns them (`properties.startIpAddress`/`endIpAddress`). */
function rangeRules(rules: unknown[]): string[] {
  return rules.flatMap((r) => {
    const rp = obj(obj(r)["properties"]);
    const start = str(rp["startIpAddress"]);
    const end = str(rp["endIpAddress"]);
    if (!start) return [];
    return [end && end !== start ? `${start}-${end}` : start];
  });
}

/** SQL "Allow Azure services" rule and the open-to-all range. */
const AZURE_SERVICES_RULE = "0.0.0.0";
const OPEN_RANGES = new Set(["0.0.0.0-255.255.255.255", "0.0.0.0/0", "any", "*"]);

function firewallOf(type: string, p: Obj, rules: PaasRules | undefined): PaasServiceEntity["firewall"] {
  const acl = obj(p["networkAcls"] ?? p["networkRuleSet"]);
  const ipValues = (list: unknown) =>
    arr(list).flatMap((r) => strings([obj(r)["value"] ?? obj(r)["ipAddressOrRange"] ?? obj(r)["ipMask"]]));
  const subnetValues = (list: unknown) =>
    arr(list).flatMap((r) => {
      const id = normalizeId(str(obj(r)["id"]) ?? str(obj(r)["subnetId"]));
      return id ? [id] : [];
    });

  if (Object.keys(acl).length > 0 && type !== "microsoft.search/searchservices") {
    return {
      defaultAction: action(acl["defaultAction"]),
      ipRules: ipValues(acl["ipRules"]),
      subnetIds: subnetValues(acl["virtualNetworkRules"]),
      bypass: str(acl["bypass"]),
      source: "arg",
    };
  }
  switch (type) {
    case "microsoft.search/searchservices": {
      const ipRules = ipValues(acl["ipRules"]);
      return {
        defaultAction: ipRules.length > 0 ? "Deny" : "Allow",
        ipRules,
        subnetIds: [],
        bypass: str(acl["bypass"]),
        source: "arg",
      };
    }
    case "microsoft.documentdb/databaseaccounts": {
      const ipRules = ipValues(p["ipRules"]);
      const subnetIds = subnetValues(p["virtualNetworkRules"]);
      const filtered = ipRules.length > 0 || bool(p["isVirtualNetworkFilterEnabled"]) === true;
      return { defaultAction: filtered ? "Deny" : "Allow", ipRules, subnetIds, source: "arg" };
    }
    case "microsoft.appconfiguration/configurationstores":
    case "microsoft.eventgrid/topics":
    case "microsoft.eventgrid/domains": {
      const ipRules = ipValues(p["inboundIpRules"]);
      return { defaultAction: ipRules.length > 0 ? "Deny" : "Allow", ipRules, subnetIds: [], source: "arg" };
    }
    case "microsoft.containerservice/managedclusters": {
      const ranges = strings(obj(p["apiServerAccessProfile"])["authorizedIPRanges"]);
      return {
        defaultAction: ranges.length > 0 ? "Deny" : "Allow",
        ipRules: ranges,
        subnetIds: [],
        source: "arg",
      };
    }
    case "microsoft.sql/servers":
    case "microsoft.dbforpostgresql/flexibleservers":
    case "microsoft.dbformysql/flexibleservers": {
      if (!rules || rules.status === "not-accessible") return { ipRules: [], subnetIds: [], source: "none" };
      const ranges = rangeRules(rules.firewallRules);
      const azure = ranges.includes(AZURE_SERVICES_RULE) || ranges.includes("0.0.0.0-0.0.0.0");
      return {
        // Database firewalls deny everything not covered by a rule.
        defaultAction: ranges.some((r) => OPEN_RANGES.has(r)) ? "Allow" : "Deny",
        ipRules: ranges.filter((r) => r !== AZURE_SERVICES_RULE && r !== "0.0.0.0-0.0.0.0"),
        subnetIds: rules.virtualNetworkRules.flatMap((r) => {
          const id = normalizeId(str(obj(obj(r)["properties"])["virtualNetworkSubnetId"]));
          return id ? [id] : [];
        }),
        ...(azure ? { bypass: "AzureServices" } : {}),
        source: "arm",
      };
    }
    case "microsoft.web/sites": {
      const web = rules?.siteConfig.map((c) => obj(c)).find((c) => str(c["name"])?.toLowerCase() === "web");
      const config = web ? obj(web["properties"]) : obj(p["siteConfig"]);
      const restrictions = arr(config["ipSecurityRestrictions"]).map((r) => obj(r));
      if (!web && restrictions.length === 0) return { ipRules: [], subnetIds: [], source: "none" };
      const allows = restrictions.filter((r) => (str(r["action"]) ?? "Allow").toLowerCase() === "allow");
      const ipRules = allows
        .flatMap((r) => strings([r["ipAddress"]]))
        .filter((ip) => ip.toLowerCase() !== "any");
      const tags = allows.flatMap((r) =>
        str(r["tag"])?.toLowerCase() === "servicetag" ? strings([r["ipAddress"]]) : [],
      );
      const allowAll = allows.some((r) => str(r["ipAddress"])?.toLowerCase() === "any");
      const explicitDefault = action(config["ipSecurityRestrictionsDefaultAction"]);
      return {
        defaultAction: allowAll || restrictions.length === 0 ? "Allow" : (explicitDefault ?? "Deny"),
        ipRules: ipRules.filter((ip) => !tags.includes(ip)),
        subnetIds: allows.flatMap((r) => {
          const id = normalizeId(str(r["vnetSubnetResourceId"]));
          return id ? [id] : [];
        }),
        ...(tags.length ? { bypass: tags.join(", ") } : {}),
        source: web ? "arm" : "arg",
      };
    }
    // No ACL object on these providers means "allow all networks".
    case "microsoft.storage/storageaccounts":
    case "microsoft.keyvault/vaults":
    case "microsoft.containerregistry/registries":
    case "microsoft.cognitiveservices/accounts":
      return { defaultAction: "Allow", ipRules: [], subnetIds: [], source: "arg" };
    default:
      return { ipRules: [], subnetIds: [], source: "none" };
  }
}

function publicAccessOf(type: string, p: Obj): PublicNetworkAccess {
  const network = obj(p["network"]);
  switch (type) {
    case "microsoft.sql/managedinstances":
      return bool(p["publicDataEndpointEnabled"]) ? "Enabled" : "Disabled";
    case "microsoft.dbforpostgresql/flexibleservers":
    case "microsoft.dbformysql/flexibleservers":
      return (
        access(network["publicNetworkAccess"]) ??
        (str(network["delegatedSubnetResourceId"]) ? "Disabled" : "Enabled")
      );
    case "microsoft.containerservice/managedclusters":
      return bool(obj(p["apiServerAccessProfile"])["enablePrivateCluster"])
        ? "Disabled"
        : (access(p["publicNetworkAccess"]) ?? "Enabled");
    case "microsoft.app/managedenvironments":
      return (
        access(p["publicNetworkAccess"]) ??
        (bool(obj(p["vnetConfiguration"])["internal"]) ? "Disabled" : "Enabled")
      );
    case "microsoft.app/containerapps": {
      const ingress = obj(obj(p["configuration"])["ingress"]);
      if (Object.keys(ingress).length === 0) return "Disabled";
      return bool(ingress["external"]) ? "Enabled" : "Disabled";
    }
    case "microsoft.apimanagement/service":
      if (str(p["virtualNetworkType"])?.toLowerCase() === "internal") return "Disabled";
      return access(p["publicNetworkAccess"]) ?? "Enabled";
    // Storage accounts and Key Vaults are public unless explicitly disabled.
    case "microsoft.storage/storageaccounts":
    case "microsoft.keyvault/vaults":
    case "microsoft.containerregistry/registries":
    case "microsoft.cognitiveservices/accounts":
    case "microsoft.search/searchservices":
    case "microsoft.documentdb/databaseaccounts":
      return access(p["publicNetworkAccess"]) ?? "Enabled";
    default:
      return access(p["publicNetworkAccess"]) ?? "Unknown";
  }
}

function vnetIntegrationOf(type: string, p: Obj): PaasServiceEntity["vnetIntegration"] {
  const ids = (...values: unknown[]) => [
    ...new Set(values.flatMap((v) => (normalizeId(str(v)) ? [normalizeId(str(v))!] : []))),
  ];
  switch (type) {
    case "microsoft.web/sites": {
      const subnets = ids(p["virtualNetworkSubnetId"]);
      const routeAll =
        bool(p["vnetRouteAllEnabled"]) ??
        bool(obj(p["siteConfig"])["vnetRouteAllEnabled"]) ??
        bool(obj(p["outboundVnetRouting"])["allTraffic"]);
      return subnets.length ? { subnetIds: subnets, mode: "integration", routeAll } : { subnetIds: [] };
    }
    case "microsoft.dbforpostgresql/flexibleservers":
    case "microsoft.dbformysql/flexibleservers":
      return { subnetIds: ids(obj(p["network"])["delegatedSubnetResourceId"]), mode: "injection" };
    case "microsoft.sql/managedinstances":
    case "microsoft.cache/redis":
      return { subnetIds: ids(p["subnetId"]), mode: "injection" };
    case "microsoft.containerservice/managedclusters":
      return {
        subnetIds: ids(
          ...arr(p["agentPoolProfiles"]).flatMap((a) => [
            ci(obj(a), "vnetSubnetID"),
            ci(obj(a), "podSubnetID"),
          ]),
          obj(p["apiServerAccessProfile"])["subnetId"],
        ),
        mode: "injection",
      };
    case "microsoft.apimanagement/service":
      return { subnetIds: ids(obj(p["virtualNetworkConfiguration"])["subnetResourceId"]), mode: "injection" };
    case "microsoft.app/managedenvironments":
      return { subnetIds: ids(obj(p["vnetConfiguration"])["infrastructureSubnetId"]), mode: "injection" };
    case "microsoft.databricks/workspaces": {
      const params = obj(p["parameters"]);
      const vnet = str(obj(params["customVirtualNetworkId"])["value"]);
      const names = [
        obj(params["customPrivateSubnetName"])["value"],
        obj(params["customPublicSubnetName"])["value"],
      ];
      return {
        subnetIds: vnet ? ids(...names.flatMap((n) => (str(n) ? [`${vnet}/subnets/${str(n)}`] : []))) : [],
        mode: "injection",
      };
    }
    default:
      return { subnetIds: [] };
  }
}

/** Exposure from public access and firewall (Private Link counterpart is added later). */
export function classifyExposure(
  e: Pick<PaasServiceEntity, "publicNetworkAccess" | "firewall" | "privateEndpointIds" | "vnetIntegration">,
): {
  exposure: PaasExposure;
  reasons: string[];
} {
  const privateWays = [
    e.privateEndpointIds.length ? `${e.privateEndpointIds.length} Private Endpoint(s)` : "",
    e.vnetIntegration.mode === "injection" && e.vnetIntegration.subnetIds.length ? "in VNet injiziert" : "",
  ].filter(Boolean);
  switch (e.publicNetworkAccess) {
    case "Disabled":
      return {
        exposure: "private",
        reasons: ["Öffentlicher Zugriff deaktiviert", ...privateWays],
      };
    case "SecuredByPerimeter":
      return {
        exposure: "restricted",
        reasons: ["Öffentlicher Zugriff nur über Network Security Perimeter", ...privateWays],
      };
    case "Unknown":
      if (e.firewall.source === "none")
        return {
          exposure: "unknown",
          reasons: ["Öffentlicher Zugriff nicht aus der Konfiguration ablesbar", ...privateWays],
        };
  }
  const fw = e.firewall;
  if (fw.source === "none") {
    return {
      exposure: "unknown",
      reasons: ["Öffentlicher Endpunkt aktiv, Firewall-Regeln nicht lesbar", ...privateWays],
    };
  }
  if (fw.defaultAction === "Deny") {
    const rules = [
      fw.ipRules.length ? `${fw.ipRules.length} IP-Regel(n)` : "",
      fw.subnetIds.length ? `${fw.subnetIds.length} Subnet-Regel(n)` : "",
      fw.bypass ? `Ausnahme: ${fw.bypass}` : "",
    ].filter(Boolean);
    return {
      exposure: "restricted",
      reasons: [
        `Öffentlicher Endpunkt nur für erlaubte Quellen${rules.length ? ` (${rules.join(", ")})` : " (keine Regel: faktisch gesperrt)"}`,
        ...privateWays,
      ],
    };
  }
  return {
    exposure: "public",
    reasons: ["Öffentlicher Endpunkt ohne Einschränkung (Standardaktion: Allow)", ...privateWays],
  };
}

export function normalizePaasService(
  r: RawResource,
  baseEntity: BaseEntity,
  rules: PaasRules | undefined,
): PaasServiceEntity {
  const type = r.type.toLowerCase();
  const info = PAAS_TYPE_INFO.get(type);
  const p = obj(r.properties);
  const sku = obj(r["sku"]);
  const connections = privateEndpointConnections(p);
  const entity: PaasServiceEntity = {
    ...baseEntity,
    service: info?.label ?? type,
    category: info?.category ?? "other",
    kind: str(r["kind"]),
    sku: str(sku["name"]) ?? str(sku["tier"]) ?? str(obj(p["sku"])["name"]),
    endpoints: endpointsOf(p),
    publicNetworkAccess: publicAccessOf(type, p),
    firewall: firewallOf(type, p, rules),
    privateEndpointIds: [...new Set(connections.map((c) => c.privateEndpointId))],
    privateEndpointConnectionStates: connections.filter((c) => c.status.toLowerCase() !== "approved"),
    vnetIntegration: vnetIntegrationOf(type, p),
    outboundIps: [
      ...new Set(
        (str(p["possibleOutboundIpAddresses"]) ?? str(p["outboundIpAddresses"]) ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    ],
    minimumTlsVersion:
      str(p["minimumTlsVersion"]) ??
      str(p["minimalTlsVersion"]) ??
      str(obj(p["siteConfig"])["minTlsVersion"]),
    exposure: "unknown",
    exposureReasons: [],
  };
  // App Service: an absent setting means enabled, unless a private endpoint switches it off.
  if (
    type === "microsoft.web/sites" &&
    entity.publicNetworkAccess === "Unknown" &&
    entity.privateEndpointIds.length === 0
  )
    entity.publicNetworkAccess = "Enabled";
  const { exposure, reasons } = classifyExposure(entity);
  entity.exposure = exposure;
  entity.exposureReasons = reasons;
  if (refId(p["subnet"]) && entity.vnetIntegration.subnetIds.length === 0)
    entity.vnetIntegration = { subnetIds: [refId(p["subnet"])!], mode: "injection" };
  return entity;
}
