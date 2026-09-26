import type { EdgeType, GraphNode, NodeType } from "../../models/graph.js";
import { PAAS_SERVICE_TYPES, PAAS_TYPE_INFO, type PaasCategory } from "../../models/paasCatalog.js";

export type NodeCategory =
  | "org"
  | "network"
  | "security"
  | "routing"
  | "compute"
  | "edge"
  | "dns"
  | "hybrid"
  | "external"
  | "app"
  | "data"
  | "integration"
  | "analytics"
  | "vdi"
  | "monitoring";

const CATEGORY: Partial<Record<NodeType, NodeCategory>> = {
  tenant: "org",
  subscription: "org",
  region: "org",
  vnet: "network",
  subnet: "network",
  publicIp: "edge",
  publicIpPrefix: "edge",
  natGateway: "edge",
  loadBalancer: "edge",
  applicationGateway: "edge",
  bastion: "edge",
  azureFirewall: "security",
  firewallPolicy: "security",
  ruleCollectionGroup: "security",
  ipGroup: "security",
  nsg: "security",
  wafPolicy: "security",
  nva: "security",
  routeTable: "routing",
  route: "routing",
  routeServer: "routing",
  virtualHub: "routing",
  virtualWan: "routing",
  nic: "compute",
  vm: "compute",
  vmss: "compute",
  privateEndpoint: "dns",
  privateLinkService: "dns",
  paasService: "external",
  privateDnsZone: "dns",
  dnsResolver: "dns",
  dnsForwardingRuleset: "dns",
  vpnGateway: "hybrid",
  expressRouteGateway: "hybrid",
  expressRouteCircuit: "hybrid",
  localNetworkGateway: "hybrid",
  gatewayConnection: "hybrid",
  internet: "external",
  externalResource: "external",
};

export function categoryOf(type: NodeType): NodeCategory {
  return CATEGORY[type] ?? "network";
}

const ABBREVIATION: Partial<Record<NodeType, string>> = {
  tenant: "TEN",
  subscription: "SUB",
  region: "REG",
  vnet: "VNET",
  subnet: "SNET",
  routeTable: "UDR",
  route: "RT",
  nsg: "NSG",
  nic: "NIC",
  vm: "VM",
  vmss: "VMSS",
  publicIp: "PIP",
  publicIpPrefix: "PIPP",
  natGateway: "NAT",
  azureFirewall: "AFW",
  firewallPolicy: "AFWP",
  ruleCollectionGroup: "RCG",
  ipGroup: "IPG",
  loadBalancer: "LB",
  applicationGateway: "AGW",
  vpnGateway: "VPN",
  expressRouteGateway: "ERGW",
  localNetworkGateway: "LNG",
  gatewayConnection: "CONN",
  expressRouteCircuit: "ER",
  virtualWan: "VWAN",
  virtualHub: "HUB",
  routeServer: "ARS",
  nva: "NVA",
  bastion: "BAS",
  privateEndpoint: "PE",
  privateLinkService: "PLS",
  paasService: "PAAS",
  privateDnsZone: "DNS",
  dnsResolver: "DNSR",
  dnsForwardingRuleset: "FWDR",
  wafPolicy: "WAF",
  networkWatcher: "NW",
  flowLog: "FLOG",
  internet: "NET",
  externalResource: "EXT",
};

export function abbreviationOf(type: NodeType): string {
  return ABBREVIATION[type] ?? "RES";
}

/** Service-specific abbreviation per ARM type (PaaS nodes). */
const PAAS_ABBREVIATION: Record<string, string> = {
  "microsoft.storage/storageaccounts": "ST",
  "microsoft.sql/servers": "SQL",
  "microsoft.sql/managedinstances": "SQLMI",
  "microsoft.dbforpostgresql/flexibleservers": "PG",
  "microsoft.dbformysql/flexibleservers": "MYSQL",
  "microsoft.documentdb/databaseaccounts": "COSMOS",
  "microsoft.cache/redis": "REDIS",
  "microsoft.keyvault/vaults": "KV",
  "microsoft.web/sites": "APP",
  "microsoft.web/staticsites": "SWA",
  "microsoft.web/serverfarms": "ASP",
  "microsoft.web/hostingenvironments": "ASE",
  "microsoft.apimanagement/service": "APIM",
  "microsoft.servicebus/namespaces": "SB",
  "microsoft.eventhub/namespaces": "EH",
  "microsoft.eventgrid/topics": "EGT",
  "microsoft.eventgrid/domains": "EGD",
  "microsoft.signalrservice/signalr": "SIGR",
  "microsoft.signalrservice/webpubsub": "WPS",
  "microsoft.appconfiguration/configurationstores": "APPC",
  "microsoft.automation/automationaccounts": "AUTO",
  "microsoft.logic/workflows": "LOGIC",
  "microsoft.devices/iothubs": "IOT",
  "microsoft.cognitiveservices/accounts": "AI",
  "microsoft.search/searchservices": "SRCH",
  "microsoft.machinelearningservices/workspaces": "AML",
  "microsoft.containerregistry/registries": "ACR",
  "microsoft.containerservice/managedclusters": "AKS",
  "microsoft.app/managedenvironments": "ACAE",
  "microsoft.app/containerapps": "ACA",
  "microsoft.app/jobs": "ACAJ",
  "microsoft.containerinstance/containergroups": "ACI",
  "microsoft.datafactory/factories": "ADF",
  "microsoft.synapse/workspaces": "SYN",
  "microsoft.databricks/workspaces": "DBX",
  "microsoft.purview/accounts": "PVW",
  "microsoft.kusto/clusters": "ADX",
  "microsoft.fabric/capacities": "FAB",
  "microsoft.fabric/privatelinkservicesforfabric": "FABPL",
  "microsoft.powerbi/privatelinkservicesforpowerbi": "PBIPL",
  "microsoft.powerbidedicated/capacities": "PBIE",
  "microsoft.batch/batchaccounts": "BATCH",
  "microsoft.recoveryservices/vaults": "RSV",
  "microsoft.desktopvirtualization/hostpools": "AVDHP",
  "microsoft.desktopvirtualization/workspaces": "AVDWS",
  "microsoft.cdn/profiles": "AFD",
  "microsoft.servicenetworking/trafficcontrollers": "AGC",
  "microsoft.devopsinfrastructure/pools": "MDP",
  "microsoft.dashboard/grafana": "GRAF",
  "microsoft.insights/components": "APPI",
  "microsoft.operationalinsights/workspaces": "LAW",
  "microsoft.insights/privatelinkscopes": "AMPLS",
};

const PAAS_GROUP: Record<PaasCategory, NodeCategory> = {
  storage: "data",
  database: "data",
  web: "app",
  containers: "app",
  security: "security",
  integration: "integration",
  ai: "analytics",
  analytics: "analytics",
  vdi: "vdi",
  edge: "edge",
  monitoring: "monitoring",
  other: "app",
};

const TYPE_BY_LABEL = new Map(PAAS_SERVICE_TYPES.map((t) => [t.label, t.type]));

/** ARM type of a PaaS node (older exports only carry the service label). */
function paasTypeOf(node: GraphNode): string | undefined {
  const azureType = node.properties["azureType"];
  if (typeof azureType === "string") return azureType;
  const service = node.properties["service"];
  return typeof service === "string" ? TYPE_BY_LABEL.get(service) : undefined;
}

/** Abbreviation of a graph node: service-specific for PaaS (FUNC for function apps, AOAI for OpenAI). */
export function nodeAbbreviation(node: GraphNode): string {
  if (node.type !== "paasService") return abbreviationOf(node.type);
  const type = paasTypeOf(node);
  const kind = typeof node.properties["kind"] === "string" ? node.properties["kind"].toLowerCase() : "";
  if (type === "microsoft.web/sites") {
    if (kind.includes("workflowapp")) return "LOGIC";
    if (kind.includes("functionapp")) return "FUNC";
  }
  if (type === "microsoft.cognitiveservices/accounts" && kind === "openai") return "AOAI";
  return (type && PAAS_ABBREVIATION[type]) ?? "PAAS";
}

/** Colour group of a graph node: PaaS nodes by service group, others by resource type. */
export function nodeCategory(node: GraphNode): NodeCategory {
  if (node.type !== "paasService") return categoryOf(node.type);
  const type = paasTypeOf(node);
  const group = type ? PAAS_TYPE_INFO.get(type)?.category : undefined;
  return group ? PAAS_GROUP[group] : "app";
}

/** Short addressing summary, e.g. "10.0.0.0/16 · fd00::/48 +2". */
export function addressSummary(node: GraphNode): string {
  const all = [...node.addressing.ipv4, ...node.addressing.ipv6];
  if (all.length === 0) return "";
  const first = [node.addressing.ipv4[0], node.addressing.ipv6[0]].filter(Boolean).join(" · ");
  const shown = (node.addressing.ipv4[0] ? 1 : 0) + (node.addressing.ipv6[0] ? 1 : 0);
  return all.length > shown ? `${first} +${all.length - shown}` : first;
}

export const EDGE_CLASS: Record<EdgeType, string> = {
  contains: "edge-contains",
  peering: "edge-peering",
  route: "edge-route",
  attached: "edge-attached",
  securedBy: "edge-security",
  natThrough: "edge-nat",
  connectedTo: "edge-attached",
  privateEndpoint: "edge-pe",
  gatewayConnection: "edge-gateway",
  dnsLink: "edge-dns",
  internetEgress: "edge-internet",
  backendOf: "edge-attached",
  policyOf: "edge-security",
  monitoredBy: "edge-attached",
};

/** Edges drawn with an arrow (directional semantics). */
export const DIRECTED: ReadonlySet<EdgeType> = new Set([
  "route",
  "securedBy",
  "natThrough",
  "privateEndpoint",
  "internetEgress",
  "policyOf",
]);
