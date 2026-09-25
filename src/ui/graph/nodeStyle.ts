import type { EdgeType, GraphNode, NodeType } from "../../models/graph.js";

export type NodeCategory =
  "org" | "network" | "security" | "routing" | "compute" | "edge" | "dns" | "hybrid" | "external";

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
