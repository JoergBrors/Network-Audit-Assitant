import { z } from "zod";

export const NODE_TYPES = [
  "tenant",
  "subscription",
  "region",
  "vnet",
  "subnet",
  "routeTable",
  "route",
  "nsg",
  "nic",
  "vm",
  "vmss",
  "publicIp",
  "publicIpPrefix",
  "natGateway",
  "azureFirewall",
  "firewallPolicy",
  "ruleCollectionGroup",
  "ipGroup",
  "loadBalancer",
  "applicationGateway",
  "vpnGateway",
  "expressRouteGateway",
  "localNetworkGateway",
  "gatewayConnection",
  "expressRouteCircuit",
  "virtualWan",
  "virtualHub",
  "routeServer",
  "nva",
  "bastion",
  "privateEndpoint",
  "privateLinkService",
  "privateDnsZone",
  "dnsResolver",
  "dnsForwardingRuleset",
  "wafPolicy",
  "networkWatcher",
  "flowLog",
  "internet",
  "externalResource",
  "other",
  "unclassified",
] as const;
export type NodeType = (typeof NODE_TYPES)[number];

export const EDGE_TYPES = [
  "contains",
  "peering",
  "route",
  "attached",
  "securedBy",
  "natThrough",
  "connectedTo",
  "privateEndpoint",
  "gatewayConnection",
  "dnsLink",
  "internetEgress",
  "backendOf",
  "policyOf",
  "monitoredBy",
] as const;
export type EdgeType = (typeof EDGE_TYPES)[number];

export const IpClassificationSchema = z.enum(["ipv4-only", "ipv6-only", "dual-stack", "no-ip", "unknown"]);

export const GraphNodeSchema = z.object({
  id: z.string(),
  type: z.enum(NODE_TYPES),
  name: z.string(),
  tenantId: z.string().optional(),
  subscriptionId: z.string().optional(),
  subscriptionName: z.string().optional(),
  resourceGroup: z.string().optional(),
  region: z.string().optional(),
  parentId: z.string().optional(),
  /** Level of detail 1–5 (ARCHITECTURE.md § 18). */
  lod: z.number().int().min(1).max(5),
  addressing: z.object({
    ipv4: z.array(z.string()),
    ipv6: z.array(z.string()),
    classification: IpClassificationSchema,
  }),
  /** Short, type-specific key facts (full details live in the inventory sections). */
  properties: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.string())])),
  topology: z
    .object({
      classification: z.enum(["hub", "spoke", "shared-services", "standalone", "unknown"]),
      confidence: z.number(),
      reasons: z.array(z.string()),
      hubIds: z.array(z.string()),
    })
    .optional(),
  nva: z
    .object({ potentialNva: z.boolean(), confidence: z.number(), reasons: z.array(z.string()) })
    .optional(),
});
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  type: z.enum(EDGE_TYPES),
  family: z.enum(["ipv4", "ipv6", "both"]).optional(),
  label: z.string().optional(),
  properties: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.string())])),
});
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

export const NetworkGraphSchema = z.object({
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
});
export type NetworkGraph = z.infer<typeof NetworkGraphSchema>;

export const NODE_TYPE_LABELS: Record<NodeType, string> = {
  tenant: "Tenant",
  subscription: "Subscription",
  region: "Region",
  vnet: "VNet",
  subnet: "Subnet",
  routeTable: "Route Table",
  route: "Route",
  nsg: "NSG",
  nic: "NIC",
  vm: "VM",
  vmss: "VM Scale Set",
  publicIp: "Public IP",
  publicIpPrefix: "Public IP Prefix",
  natGateway: "NAT Gateway",
  azureFirewall: "Azure Firewall",
  firewallPolicy: "Firewall Policy",
  ruleCollectionGroup: "Rule Collection Group",
  ipGroup: "IP Group",
  loadBalancer: "Load Balancer",
  applicationGateway: "Application Gateway",
  vpnGateway: "VPN Gateway",
  expressRouteGateway: "ExpressRoute Gateway",
  localNetworkGateway: "Local Network Gateway",
  gatewayConnection: "Connection",
  expressRouteCircuit: "ExpressRoute Circuit",
  virtualWan: "Virtual WAN",
  virtualHub: "Virtual Hub",
  routeServer: "Route Server",
  nva: "NVA",
  bastion: "Bastion",
  privateEndpoint: "Private Endpoint",
  privateLinkService: "Private Link Service",
  privateDnsZone: "Private DNS Zone",
  dnsResolver: "DNS Resolver",
  dnsForwardingRuleset: "DNS Forwarding Ruleset",
  wafPolicy: "WAF Policy",
  networkWatcher: "Network Watcher",
  flowLog: "Flow Log",
  internet: "Internet",
  externalResource: "Externe Ressource",
  other: "Netzwerkressource",
  unclassified: "Nicht klassifiziert",
};

export const EDGE_TYPE_LABELS: Record<EdgeType, string> = {
  contains: "enthält",
  peering: "Peering",
  route: "Route",
  attached: "zugeordnet",
  securedBy: "gesichert durch",
  natThrough: "NAT über",
  connectedTo: "verbunden mit",
  privateEndpoint: "Private Endpoint zu",
  gatewayConnection: "Gateway-Verbindung",
  dnsLink: "DNS-Link",
  internetEgress: "Internet-Egress",
  backendOf: "Backend von",
  policyOf: "Policy von",
  monitoredBy: "überwacht durch",
};
