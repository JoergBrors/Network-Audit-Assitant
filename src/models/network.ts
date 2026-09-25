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
  virtualMachines: VirtualMachineEntity[];
  scaleSets: ScaleSetEntity[];
  /** Supported, but modelled generically (bastion, ExpressRoute, vWAN, WAF, flow logs, …). */
  otherNetworkResources: GenericNetworkEntity[];
  unclassifiedNetworkResources: GenericNetworkEntity[];
}
