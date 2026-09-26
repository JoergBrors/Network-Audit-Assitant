import type { PaasCategory } from "./paasCatalog.js";
import type { FamilySplit, IpClassification, IpFamily } from "../addressing/ip.js";

/**
 * Normalized network inventory (NETWORK-GRAPH-MODEL.md). All IDs are lowercase ARM resource IDs.
 * Only normalized, security-relevant fields are kept — no raw ARM payloads, no secrets.
 */

export interface BaseEntity {
  id: string;
  name: string;
  /** Lowercase ARM resource type, e.g. microsoft.network/virtualnetworks */
  azureType: string;
  tenantId?: string | undefined;
  subscriptionId?: string | undefined;
  resourceGroup?: string | undefined;
  location?: string | undefined;
  tags?: Record<string, string> | undefined;
}

export interface TopologyClassification {
  classification: "hub" | "spoke" | "shared-services" | "standalone" | "unknown";
  confidence: number;
  reasons: string[];
  /** Hubs this spoke is attached to. */
  hubIds: string[];
}

export interface NvaClassification {
  potentialNva: boolean;
  confidence: number;
  reasons: string[];
}

export interface SubscriptionEntity {
  id: string;
  subscriptionId: string;
  name: string;
  tenantId: string;
  accessTenantId: string;
  state: string;
  managementGroupPath: string[];
  managedByTenantIds: string[];
  tags?: Record<string, string> | undefined;
}

export interface VNetEntity extends BaseEntity {
  addressSpace: FamilySplit;
  ipClassification: IpClassification;
  dnsServers: string[];
  ddosProtectionEnabled: boolean;
  ddosProtectionPlanId?: string | undefined;
  encryption?: { enabled: boolean; enforcement?: string | undefined } | undefined;
  flowTimeoutInMinutes?: number | undefined;
  subnetIds: string[];
  peeringIds: string[];
  topology?: TopologyClassification | undefined;
}

export interface SubnetEntity {
  id: string;
  name: string;
  vnetId: string;
  subscriptionId?: string | undefined;
  resourceGroup?: string | undefined;
  location?: string | undefined;
  prefixes: FamilySplit;
  ipClassification: IpClassification;
  nsgId?: string | undefined;
  routeTableId?: string | undefined;
  natGatewayId?: string | undefined;
  delegations: string[];
  serviceEndpoints: string[];
  privateEndpointNetworkPolicies?: string | undefined;
  privateLinkServiceNetworkPolicies?: string | undefined;
  /** `false` = private subnet (no default outbound access). Undefined = not set explicitly. */
  defaultOutboundAccess?: boolean | undefined;
  /** Resources with an IP configuration in this subnet (NICs rolled up to VM scale sets). */
  connectedResourceIds: string[];
  /** Number of IP configurations in the subnet (incl. rolled-up scale set instances). */
  ipConfigurationCount: number;
  /**
   * Service association / resource navigation links: the resource that uses a delegated subnet
   * (App Service plan, Container Apps environment, flexible server, …) as the platform records it.
   */
  serviceLinks?: SubnetServiceLink[] | undefined;
}

export interface SubnetServiceLink {
  kind: "serviceAssociation" | "resourceNavigation";
  name?: string | undefined;
  linkedResourceType?: string | undefined;
  /** Linked resource ID (lowercase) when the link is a resource ID. */
  linkId?: string | undefined;
}

export interface PeeringEntity {
  id: string;
  name: string;
  vnetId: string;
  remoteVnetId?: string | undefined;
  remoteAddressSpace: FamilySplit;
  peeringState?: string | undefined;
  peeringSyncLevel?: string | undefined;
  allowVirtualNetworkAccess: boolean;
  allowForwardedTraffic: boolean;
  allowGatewayTransit: boolean;
  useRemoteGateways: boolean;
  peerCompleteVnets?: boolean | undefined;
  localSubnetNames?: string[] | undefined;
  remoteSubnetNames?: string[] | undefined;
  enableOnlyIPv6Peering?: boolean | undefined;
}

export interface RouteEntity {
  id: string;
  name: string;
  routeTableId: string;
  addressPrefix: string;
  /** ipv4/ipv6 for CIDR prefixes, "serviceTag" for service tags. */
  ipVersion: IpFamily | "serviceTag";
  nextHopType: string;
  nextHopIpAddress?: string | undefined;
  /** VirtualApplianceEcmp: all next hop IPs (equal-cost multipath). */
  nextHopIpAddresses?: string[] | undefined;
  defaultRoute: boolean;
  /** Resolved resource behind nextHopIpAddress, if known. */
  nextHopResourceId?: string | undefined;
}

export interface RouteTableEntity extends BaseEntity {
  routeIds: string[];
  subnetIds: string[];
  disableBgpRoutePropagation: boolean;
}

export interface NsgRuleEntity {
  name: string;
  /** "Inbound" or "Outbound" */
  direction: string;
  /** "Allow" or "Deny" */
  access: string;
  priority: number;
  protocol: string;
  sources: string[];
  destinations: string[];
  sourcePorts: string[];
  destinationPorts: string[];
  sourceAsgIds: string[];
  destinationAsgIds: string[];
  /** Families referenced by explicit prefixes; `any` when `*`, `Internet` or service tags are used. */
  ipFamilies: (IpFamily | "any")[];
  isDefault: boolean;
}

export interface NsgEntity extends BaseEntity {
  rules: NsgRuleEntity[];
  defaultRules: NsgRuleEntity[];
  subnetIds: string[];
  nicIds: string[];
}

export interface IpConfigurationEntity {
  name: string;
  privateIpAddress?: string | undefined;
  privateIpVersion?: IpFamily | undefined;
  subnetId?: string | undefined;
  publicIpId?: string | undefined;
  primary: boolean;
  loadBalancerBackendPoolIds: string[];
  applicationSecurityGroupIds?: string[] | undefined;
}

export interface NicEntity extends BaseEntity {
  ipConfigurations: IpConfigurationEntity[];
  addressing: FamilySplit;
  ipClassification: IpClassification;
  subnetIds: string[];
  vmId?: string | undefined;
  nsgId?: string | undefined;
  ipForwarding: boolean;
  acceleratedNetworking: boolean;
  defaultOutboundConnectivityEnabled?: boolean | undefined;
  /** Set for VM scale set instance NICs (rolled up into the scale set in the graph). */
  scaleSetId?: string | undefined;
}

export interface PublicIpEntity extends BaseEntity {
  ipAddress?: string | undefined;
  ipVersion: IpFamily;
  sku?: string | undefined;
  tier?: string | undefined;
  allocationMethod?: string | undefined;
  /** Resource the IP is attached to (NIC → rolled up to VM scale set, firewall, LB, gateway, …). */
  attachedToId?: string | undefined;
  publicIpPrefixId?: string | undefined;
  natGatewayId?: string | undefined;
  zones: string[];
}

export interface PublicIpPrefixEntity extends BaseEntity {
  prefix?: string | undefined;
  ipVersion: IpFamily;
  prefixLength?: number | undefined;
  natGatewayId?: string | undefined;
  publicIpIds: string[];
  sku?: string | undefined;
}

export interface NatGatewayEntity extends BaseEntity {
  sku: string;
  zones: string[];
  subnetIds: string[];
  publicIpIds: string[];
  publicIpPrefixIds: string[];
  idleTimeoutInMinutes?: number | undefined;
  ipv4EgressConfigured: boolean;
  ipv6EgressConfigured: boolean;
  dualStackEgressConfigured: boolean;
}

export interface FirewallEntity extends BaseEntity {
  skuName?: string | undefined;
  skuTier?: string | undefined;
  zones: string[];
  firewallPolicyId?: string | undefined;
  ipConfigurations: IpConfigurationEntity[];
  managementIpConfiguration?: IpConfigurationEntity | undefined;
  privateIps: FamilySplit;
  publicIpIds: string[];
  threatIntelMode?: string | undefined;
  virtualHubId?: string | undefined;
  /** Secured virtual hub firewall: public IPs from hubIPAddresses. */
  hubPublicIps: string[];
  dnsProxyEnabled?: boolean | undefined;
  classicRuleCollections: { application: number; network: number; nat: number };
}

export interface FirewallRuleEntity {
  name: string;
  ruleType: string;
  sources: string[];
  destinations: string[];
  sourceIpGroupIds: string[];
  destinationIpGroupIds: string[];
  destinationPorts: string[];
  protocols: string[];
  destinationFqdns: string[];
  targetFqdns: string[];
  translatedAddress?: string | undefined;
  translatedPort?: string | undefined;
  ipv6Rule?: boolean | undefined;
}

export interface RuleCollectionEntity {
  name: string;
  collectionType: string;
  priority?: number | undefined;
  action?: string | undefined;
  rules: FirewallRuleEntity[];
}

export interface RuleCollectionGroupEntity {
  id: string;
  name: string;
  firewallPolicyId: string;
  priority?: number | undefined;
  ruleCollections: RuleCollectionEntity[];
}

export interface FirewallPolicyEntity extends BaseEntity {
  skuTier?: string | undefined;
  basePolicyId?: string | undefined;
  childPolicyIds: string[];
  firewallIds: string[];
  ruleCollectionGroupIds: string[];
  threatIntelMode?: string | undefined;
  dnsProxyEnabled?: boolean | undefined;
  dnsServers: string[];
  intrusionDetectionMode?: string | undefined;
}

export interface IpGroupEntity extends BaseEntity {
  ipAddresses: string[];
}

export interface LoadBalancerEntity extends BaseEntity {
  sku?: string | undefined;
  frontends: (IpConfigurationEntity & { publicIpPrefixId?: string | undefined })[];
  backendPools: { name: string; memberIds: string[] }[];
  loadBalancingRules: number;
  inboundNatRules: number;
  rules: {
    name: string;
    protocol: string;
    frontendPort?: number | undefined;
    backendPort?: number | undefined;
    frontendName?: string | undefined;
    backendPool?: string | undefined;
  }[];
  natRules: {
    name: string;
    protocol: string;
    frontendPort?: number | undefined;
    backendPort?: number | undefined;
    frontendName?: string | undefined;
    targetId?: string | undefined;
  }[];
  outboundRules: { name: string; frontendNames: string[]; backendPool?: string | undefined }[];
  probes: number;
  isPublic: boolean;
}

export interface ApplicationGatewayEntity extends BaseEntity {
  sku?: string | undefined;
  tier?: string | undefined;
  frontends: IpConfigurationEntity[];
  gatewaySubnetIds: string[];
  listeners: {
    name: string;
    protocol?: string | undefined;
    hostNames: string[];
    frontendPort?: string | undefined;
  }[];
  backendPools: { name: string; addresses: string[]; memberIds: string[] }[];
  routingRules: number;
  /** listener → backend pool mapping of request routing rules. */
  routes: { name: string; listener?: string | undefined; backendPool?: string | undefined }[];
  wafPolicyId?: string | undefined;
  wafEnabled?: boolean | undefined;
}

export interface VirtualNetworkGatewayEntity extends BaseEntity {
  gatewayType?: string | undefined;
  vpnType?: string | undefined;
  sku?: string | undefined;
  activeActive: boolean;
  bgpEnabled: boolean;
  bgpAsn?: number | undefined;
  ipConfigurations: IpConfigurationEntity[];
  vnetId?: string | undefined;
  publicIpIds: string[];
}

export interface LocalNetworkGatewayEntity extends BaseEntity {
  addressPrefixes: FamilySplit;
  gatewayIpAddress?: string | undefined;
  fqdn?: string | undefined;
  bgpAsn?: number | undefined;
  bgpPeeringAddress?: string | undefined;
}

export interface ConnectionEntity extends BaseEntity {
  connectionType?: string | undefined;
  virtualNetworkGatewayId?: string | undefined;
  remoteVirtualNetworkGatewayId?: string | undefined;
  localNetworkGatewayId?: string | undefined;
  expressRouteCircuitId?: string | undefined;
  connectionStatus?: string | undefined;
  bgpEnabled: boolean;
}

export interface PrivateEndpointEntity extends BaseEntity {
  subnetId?: string | undefined;
  nicIds: string[];
  addressing: FamilySplit;
  ipClassification: IpClassification;
  targets: { resourceId: string; groupIds: string[]; status?: string | undefined; manual: boolean }[];
  customDnsConfigs: { fqdn?: string | undefined; ipAddresses: string[] }[];
}

export interface DnsRecordEntity {
  id: string;
  name: string;
  recordType: string;
  values: string[];
  ttl?: number | undefined;
}

export interface PrivateDnsZoneEntity extends BaseEntity {
  vnetLinks: {
    id: string;
    vnetId?: string | undefined;
    registrationEnabled: boolean;
    state?: string | undefined;
  }[];
  records: DnsRecordEntity[];
  aaaaRecordCount: number;
  aRecordCount: number;
}

export interface DnsResolverEntity extends BaseEntity {
  kind: "resolver" | "inboundEndpoint" | "outboundEndpoint" | "forwardingRuleset";
  vnetId?: string | undefined;
  subnetIds: string[];
  privateIps: string[];
  resolverId?: string | undefined;
  linkedVnetIds: string[];
  outboundEndpointIds: string[];
  forwardingRules: {
    name: string;
    domainName?: string | undefined;
    targets: string[];
    state?: string | undefined;
  }[];
}

/** Public network access setting of a PaaS service (normalized across resource providers). */
/** `NotApplicable`: the resource has no network endpoint of its own (App Service plan, DevOps pool). */
export type PublicNetworkAccess = "Enabled" | "Disabled" | "SecuredByPerimeter" | "NotApplicable" | "Unknown";

/**
 * Network exposure of a PaaS endpoint: `private` = reachable only via Private Link / VNet,
 * `restricted` = public endpoint limited by firewall rules, `public` = open to the Internet.
 */
export type PaasExposure = "private" | "restricted" | "public" | "none" | "unknown";

/** One inbound access rule of a PaaS service (IP restriction, firewall rule, authorized range). */
export interface PaasAccessRule {
  name?: string | undefined;
  /** IP, CIDR, range, service tag or subnet ID. */
  source: string;
  action: "Allow" | "Deny";
  priority?: number | undefined;
  /** Endpoint the rule applies to when a service has several (e.g. "SCM/Kudu", "API-Server"). */
  scope?: string | undefined;
}

/**
 * How a PaaS service is reached (Microsoft terms): `internet` = public endpoint open,
 * `internet-restricted` = public endpoint with IP/subnet rules, `vnet` = only from the VNet
 * (internal load balancer / internal environment), `private-endpoint` = only via Private Link,
 * `none` = no inbound endpoint (e.g. container app without ingress).
 */
export type PaasIngressMode =
  "internet" | "internet-restricted" | "vnet" | "private-endpoint" | "none" | "unknown";

/**
 * How a PaaS service reaches other networks: `azure-default` = platform outbound (shared public IPs,
 * not controllable), `vnet` = all traffic through a customer subnet (UDR/NAT/firewall apply),
 * `vnet-partial` = only private (RFC 1918) traffic through the subnet, `managed-vnet` = Microsoft
 * managed VNet (managed private endpoints / outbound rules), `load-balancer` / `nat-gateway` / `udr`
 * = AKS outbound types, `none` = the service does not initiate customer traffic.
 */
export type PaasEgressMode =
  | "azure-default"
  | "vnet"
  | "vnet-partial"
  | "managed-vnet"
  | "load-balancer"
  | "nat-gateway"
  | "udr"
  | "none"
  | "unknown";

export interface PaasIngress {
  mode: PaasIngressMode;
  summary: string;
  rules: PaasAccessRule[];
  /** Inbound IPs (environment static IP, load balancer frontends). */
  ips: string[];
  /** Service-specific settings (label → value), e.g. "Transport", "Client-Zertifikat". */
  details: Record<string, string>;
}

export interface PaasEgress {
  mode: PaasEgressMode;
  summary: string;
  /** Customer subnets outbound traffic leaves through (UDR / NAT gateway / NSG apply there). */
  subnetIds: string[];
  /** Public source IPs of outbound traffic. */
  outboundIps: string[];
  /** Outbound restricted to these targets (FQDN allow list, approved outbound rules). */
  allowedTargets?: string[] | undefined;
  details: Record<string, string>;
}

/** Resource related to a PaaS service's network path (environment, load balancer, session host, …). */
export interface PaasLink {
  id: string;
  label: string;
  direction: "ingress" | "egress" | "other";
}

export interface PaasServiceEntity extends BaseEntity {
  /** Human-readable service, e.g. "Storage Account". */
  service: string;
  category: PaasCategory;
  /** Raw kind (e.g. "functionapp,linux", "StorageV2", "OpenAI"). */
  kind?: string | undefined;
  sku?: string | undefined;
  /** Hostnames / FQDNs the service is reached by. */
  endpoints: string[];
  publicNetworkAccess: PublicNetworkAccess;
  firewall: {
    /** Action for traffic not matching a rule; `Allow` means open. */
    defaultAction?: "Allow" | "Deny" | undefined;
    /** Allowed public IPs / CIDR ranges. */
    ipRules: string[];
    /** Subnets allowed via service endpoint / VNet rule. */
    subnetIds: string[];
    /** e.g. "AzureServices", "Logging, Metrics". */
    bypass?: string | undefined;
    /** Where the rules come from: Resource Graph, ARM enrichment or not readable. */
    source: "arg" | "arm" | "none";
  };
  /** Private endpoints connected to the service (from its connections and from the endpoints). */
  privateEndpointIds: string[];
  /** Pending/rejected Private Link connections. */
  privateEndpointConnectionStates: { privateEndpointId: string; status: string }[];
  /** Subnets the service is injected into or integrated with (outbound VNet integration). */
  vnetIntegration: {
    subnetIds: string[];
    mode?: "injection" | "integration" | undefined;
    /** App Service: all outbound traffic routed through the VNet. */
    routeAll?: boolean | undefined;
  };
  /** Public outbound IPs (App Service). */
  outboundIps: string[];
  minimumTlsVersion?: string | undefined;
  exposure: PaasExposure;
  exposureReasons: string[];
  /** Inbound configuration (optional: exports before schema 0.7 do not carry it). */
  ingress?: PaasIngress | undefined;
  /** Outbound configuration. */
  egress?: PaasEgress | undefined;
  links?: PaasLink[] | undefined;
}

export interface VirtualMachineEntity extends BaseEntity {
  nicIds: string[];
  vmSize?: string | undefined;
  image?: string | undefined;
  powerState?: string | undefined;
  nva?: NvaClassification | undefined;
}

export interface ScaleSetEntity extends BaseEntity {
  orchestrationMode?: string | undefined;
  instanceNicIds: string[];
  subnetIds: string[];
  ipForwarding: boolean;
}

export interface GenericNetworkEntity extends BaseEntity {
  /** Normalized kind, e.g. bastion, expressRouteCircuit, virtualWan, virtualHub, flowLog, ... */
  kind: string;
  subnetIds: string[];
  referencedIds: string[];
  properties: Record<string, string | number | boolean | string[]>;
}

export interface ServiceTagEntity {
  name: string;
  prefixes: string[];
}

export interface HubConnectionEntity {
  id: string;
  name: string;
  hubId: string;
  remoteVnetId?: string | undefined;
  enableInternetSecurity: boolean;
  associatedRouteTableId?: string | undefined;
  propagatedRouteTableIds: string[];
  propagatedLabels: string[];
  staticRoutes: { name: string; addressPrefixes: string[]; nextHopIpAddress?: string | undefined }[];
}

export interface HubRouteTableEntity {
  id: string;
  name: string;
  labels: string[];
  routes: {
    name: string;
    destinationType: string;
    destinations: string[];
    nextHopType: string;
    nextHop: string;
  }[];
}

export interface VirtualHubEntity extends BaseEntity {
  virtualWanId?: string | undefined;
  addressPrefix?: string | undefined;
  addressPrefixV6?: string | undefined;
  firewallId?: string | undefined;
  sku?: string | undefined;
  /** Routing intent: next hop resource per policy. */
  routingIntent?: { internetNextHop?: string | undefined; privateNextHop?: string | undefined } | undefined;
  connections: HubConnectionEntity[];
  routeTables: HubRouteTableEntity[];
  /** ARM enrichment status of connections/route tables/routing intent. */
  detailStatus: "ok" | "partial" | "not-accessible" | "not-run";
}

export interface AvnmAdminRuleEntity {
  id: string;
  name: string;
  /** Configuration (without snapshot suffix) the rule belongs to. */
  configurationId: string;
  priority: number;
  access: "Allow" | "Deny" | "AlwaysAllow";
  direction: "Inbound" | "Outbound";
  protocol: string;
  sources: string[];
  destinations: string[];
  sourcePorts: string[];
  destinationPorts: string[];
}

export interface AvnmModel {
  adminRules: AvnmAdminRuleEntity[];
  /** VNet → effective security admin configuration IDs (without snapshot suffix). */
  vnetAdminConfigurations: Record<string, string[]>;
  /** Mesh / direct connectivity groups: VNets sharing an effective connectivity configuration. */
  connectedGroups: { configurationId: string; topology: string; vnetIds: string[] }[];
}

export interface NormalizedInventory {
  generatedAt: string;
  tenants: { tenantId: string; displayName?: string | undefined; accessible: boolean }[];
  subscriptions: SubscriptionEntity[];
  managementGroups: {
    id: string;
    name: string;
    displayName?: string | undefined;
    parentId?: string | undefined;
  }[];
  vnets: VNetEntity[];
  subnets: SubnetEntity[];
  peerings: PeeringEntity[];
  routeTables: RouteTableEntity[];
  routes: RouteEntity[];
  nsgs: NsgEntity[];
  networkInterfaces: NicEntity[];
  publicIps: PublicIpEntity[];
  publicIpPrefixes: PublicIpPrefixEntity[];
  natGateways: NatGatewayEntity[];
  firewalls: FirewallEntity[];
  firewallPolicies: FirewallPolicyEntity[];
  ruleCollectionGroups: RuleCollectionGroupEntity[];
  ipGroups: IpGroupEntity[];
  loadBalancers: LoadBalancerEntity[];
  applicationGateways: ApplicationGatewayEntity[];
  vpnGateways: VirtualNetworkGatewayEntity[];
  localNetworkGateways: LocalNetworkGatewayEntity[];
  connections: ConnectionEntity[];
  privateEndpoints: PrivateEndpointEntity[];
  privateDnsZones: PrivateDnsZoneEntity[];
  dnsResolvers: DnsResolverEntity[];
  /** PaaS services with network endpoints (storage, databases, Key Vault, App Service, …). */
  paasServices: PaasServiceEntity[];
  virtualMachines: VirtualMachineEntity[];
  scaleSets: ScaleSetEntity[];
  /** Supported, but modelled generically (bastion, ExpressRoute, vWAN, WAF, flow logs, …). */
  otherNetworkResources: GenericNetworkEntity[];
  unclassifiedNetworkResources: GenericNetworkEntity[];
  virtualHubs: VirtualHubEntity[];
  serviceTags: ServiceTagEntity[];
  avnm: AvnmModel;
}
