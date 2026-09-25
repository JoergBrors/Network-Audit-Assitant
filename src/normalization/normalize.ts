import {
  classifyAddressing,
  ipFamilyOf,
  isDefaultRoutePrefix,
  splitByFamily,
  type IpFamily,
} from "../addressing/ip.js";
import type { RawInventory, RawResource } from "../models/discovery.js";
import type {
  ApplicationGatewayEntity,
  BaseEntity,
  ConnectionEntity,
  DnsRecordEntity,
  DnsResolverEntity,
  FirewallEntity,
  FirewallPolicyEntity,
  FirewallRuleEntity,
  GenericNetworkEntity,
  IpConfigurationEntity,
  IpGroupEntity,
  LoadBalancerEntity,
  LocalNetworkGatewayEntity,
  NatGatewayEntity,
  NicEntity,
  NormalizedInventory,
  NsgEntity,
  NsgRuleEntity,
  PeeringEntity,
  PrivateDnsZoneEntity,
  PrivateEndpointEntity,
  PublicIpEntity,
  PublicIpPrefixEntity,
  RouteEntity,
  RouteTableEntity,
  RuleCollectionGroupEntity,
  ScaleSetEntity,
  SubnetEntity,
  SubscriptionEntity,
  VirtualMachineEntity,
  VirtualNetworkGatewayEntity,
  VNetEntity,
} from "../models/network.js";
import {
  lastSegment,
  normalizeId,
  ownerOfIpConfiguration,
  parentId,
  refId,
  refIds,
  resourceGroupOf,
  rollUpScaleSet,
  subscriptionOf,
} from "../utils/ids.js";
import {
  arr,
  bool,
  collectReferencedIds,
  num,
  obj,
  singleOrMany,
  str,
  strings,
  tagsOf,
  type Obj,
} from "./access.js";

const T = {
  vnet: "microsoft.network/virtualnetworks",
  routeTable: "microsoft.network/routetables",
  nsg: "microsoft.network/networksecuritygroups",
  nic: "microsoft.network/networkinterfaces",
  vmssNic: "microsoft.compute/virtualmachinescalesets/virtualmachines/networkinterfaces",
  pip: "microsoft.network/publicipaddresses",
  pipPrefix: "microsoft.network/publicipprefixes",
  nat: "microsoft.network/natgateways",
  firewall: "microsoft.network/azurefirewalls",
  firewallPolicy: "microsoft.network/firewallpolicies",
  rcg: "microsoft.network/firewallpolicies/rulecollectiongroups",
  ipGroup: "microsoft.network/ipgroups",
  lb: "microsoft.network/loadbalancers",
  appGw: "microsoft.network/applicationgateways",
  vng: "microsoft.network/virtualnetworkgateways",
  lng: "microsoft.network/localnetworkgateways",
  connection: "microsoft.network/connections",
  pe: "microsoft.network/privateendpoints",
  pdnsZone: "microsoft.network/privatednszones",
  pdnsLink: "microsoft.network/privatednszones/virtualnetworklinks",
  resolver: "microsoft.network/dnsresolvers",
  resolverIn: "microsoft.network/dnsresolvers/inboundendpoints",
  resolverOut: "microsoft.network/dnsresolvers/outboundendpoints",
  ruleset: "microsoft.network/dnsforwardingrulesets",
  rulesetRule: "microsoft.network/dnsforwardingrulesets/forwardingrules",
  rulesetLink: "microsoft.network/dnsforwardingrulesets/virtualnetworklinks",
  vm: "microsoft.compute/virtualmachines",
  vmss: "microsoft.compute/virtualmachinescalesets",
  subscription: "microsoft.resources/subscriptions",
  managementGroup: "microsoft.management/managementgroups",
} as const;

/** Types modelled generically: normalized kind + subnets + references. */
const GENERIC_KINDS: Record<string, string> = {
  "microsoft.network/bastionhosts": "bastion",
  "microsoft.network/expressroutecircuits": "expressRouteCircuit",
  "microsoft.network/expressroutegateways": "expressRouteGateway",
  "microsoft.network/expressrouteports": "expressRoutePort",
  "microsoft.network/expressroutecrossconnections": "expressRouteCrossConnection",
  "microsoft.network/routefilters": "routeFilter",
  "microsoft.network/virtualwans": "virtualWan",
  "microsoft.network/virtualhubs": "virtualHub",
  "microsoft.network/virtualhubs/bgpconnections": "bgpConnection",
  "microsoft.network/virtualhubs/ipconfigurations": "virtualHubIpConfiguration",
  "microsoft.network/vpngateways": "vpnGatewayVwan",
  "microsoft.network/vpnsites": "vpnSite",
  "microsoft.network/p2svpngateways": "p2sVpnGateway",
  "microsoft.network/vpnserverconfigurations": "vpnServerConfiguration",
  "microsoft.network/virtualrouters": "virtualRouter",
  "microsoft.network/securitypartnerproviders": "securityPartnerProvider",
  "microsoft.network/networkvirtualappliances": "nva",
  "microsoft.network/privatelinkservices": "privateLinkService",
  "microsoft.network/applicationsecuritygroups": "applicationSecurityGroup",
  "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": "wafPolicy",
  "microsoft.network/frontdoorwebapplicationfirewallpolicies": "wafPolicy",
  "microsoft.cdn/cdnwebapplicationfirewallpolicies": "wafPolicy",
  "microsoft.network/ddosprotectionplans": "ddosProtectionPlan",
  "microsoft.cdn/profiles": "frontDoorProfile",
  "microsoft.cdn/profiles/afdendpoints": "frontDoorEndpoint",
  "microsoft.network/frontdoors": "frontDoorClassic",
  "microsoft.network/trafficmanagerprofiles": "trafficManager",
  "microsoft.network/networkwatchers": "networkWatcher",
  "microsoft.network/networkwatchers/flowlogs": "flowLog",
  "microsoft.network/networkwatchers/connectionmonitors": "connectionMonitor",
  "microsoft.network/dnszones": "publicDnsZone",
  "microsoft.network/dnsresolverpolicies": "dnsResolverPolicy",
  "microsoft.network/dnsresolverpolicies/virtualnetworklinks": "dnsResolverPolicyLink",
  "microsoft.network/dnssecuritypolicies": "dnsSecurityPolicy",
  "microsoft.network/servicegateways": "serviceGateway",
  "microsoft.network/customipprefixes": "customIpPrefix",
};

/** Query ids whose rows are organisation data, not network resources. */
const ORG_QUERIES = new Set(["Q-ORG-01", "Q-ORG-02"]);
const UNCLASSIFIED_QUERIES = new Set(["Q-NET-ALL", "Q-NET-ALL-NR"]);

/** Property keys that may contain secrets; never copied into the normalized model. */
const SECRET_KEY =
  /sharedkey|secret|password|certificate|certdata|privatekey|connectionstring|sas|token|authorizationkey|psk/i;

export function normalizeInventory(raw: RawInventory): NormalizedInventory {
  const rows = Object.entries(raw.resources).flatMap(([queryId, list]) => list.map((r) => ({ queryId, r })));
  const byType = new Map<string, RawResource[]>();
  const unclassifiedRows: RawResource[] = [];
  const orgRows: RawResource[] = [];
  for (const { queryId, r } of rows) {
    if (ORG_QUERIES.has(queryId)) orgRows.push(r);
    else if (UNCLASSIFIED_QUERIES.has(queryId)) unclassifiedRows.push(r);
    else {
      const type = r.type.toLowerCase();
      const list = byType.get(type) ?? [];
      list.push(r);
      byType.set(type, list);
    }
  }
  const of = (type: string): RawResource[] => byType.get(type) ?? [];

  const inv: NormalizedInventory = {
    generatedAt: raw.generatedAt,
    tenants: raw.tenants.map((t) => ({
      tenantId: t.tenantId,
      displayName: t.displayName,
      accessible: t.accessible,
    })),
    subscriptions: normalizeSubscriptions(raw, orgRows),
    managementGroups: orgRows
      .filter((r) => r.type.toLowerCase() === T.managementGroup)
      .map((r) => ({
        id: normalizeId(r.id),
        name: r.name,
        displayName: str(r["displayName"]),
        parentId: normalizeId(str(r["parent"])),
      })),
    vnets: [],
    subnets: [],
    peerings: [],
    routeTables: [],
    routes: [],
    nsgs: [],
    networkInterfaces: [],
    publicIps: [],
    publicIpPrefixes: [],
    natGateways: [],
    firewalls: [],
    firewallPolicies: [],
    ruleCollectionGroups: [],
    ipGroups: [],
    loadBalancers: [],
    applicationGateways: [],
    vpnGateways: [],
    localNetworkGateways: [],
    connections: [],
    privateEndpoints: [],
    privateDnsZones: [],
    dnsResolvers: [],
    virtualMachines: [],
    scaleSets: [],
    otherNetworkResources: [],
    unclassifiedNetworkResources: [],
  };

  for (const r of of(T.vnet)) normalizeVnet(r, inv);
  for (const r of of(T.routeTable)) normalizeRouteTable(r, inv);
  for (const r of of(T.nsg)) inv.nsgs.push(normalizeNsg(r));
  for (const r of [...of(T.nic), ...of(T.vmssNic)]) inv.networkInterfaces.push(normalizeNic(r));
  for (const r of of(T.pip)) inv.publicIps.push(normalizePublicIp(r));
  for (const r of of(T.pipPrefix)) inv.publicIpPrefixes.push(normalizePublicIpPrefix(r));
  for (const r of of(T.nat)) inv.natGateways.push(normalizeNatGateway(r));
  for (const r of of(T.firewall)) inv.firewalls.push(normalizeFirewall(r));
  for (const r of of(T.firewallPolicy)) inv.firewallPolicies.push(normalizeFirewallPolicy(r));
  for (const r of of(T.rcg)) inv.ruleCollectionGroups.push(normalizeRuleCollectionGroup(r));
  for (const r of of(T.ipGroup)) inv.ipGroups.push(normalizeIpGroup(r));
  for (const r of of(T.lb)) inv.loadBalancers.push(normalizeLoadBalancer(r));
  for (const r of of(T.appGw)) inv.applicationGateways.push(normalizeAppGateway(r));
  for (const r of of(T.vng)) inv.vpnGateways.push(normalizeVng(r));
  for (const r of of(T.lng)) inv.localNetworkGateways.push(normalizeLng(r));
  for (const r of of(T.connection)) inv.connections.push(normalizeConnection(r));
  for (const r of of(T.pe)) inv.privateEndpoints.push(normalizePrivateEndpoint(r));
  normalizePrivateDns(of(T.pdnsZone), of(T.pdnsLink), recordRows(byType), inv);
  normalizeDnsResolvers(byType, inv);
  for (const r of of(T.vm)) inv.virtualMachines.push(normalizeVm(r));
  for (const r of of(T.vmss)) inv.scaleSets.push(normalizeScaleSet(r));

  for (const [type, kind] of Object.entries(GENERIC_KINDS)) {
    for (const r of of(type)) inv.otherNetworkResources.push(normalizeGeneric(r, kind));
  }
  for (const r of unclassifiedRows)
    inv.unclassifiedNetworkResources.push(normalizeGeneric(r, "unclassified"));

  resolveCrossReferences(inv);
  sortInventory(inv);
  return inv;
}

// ---------------------------------------------------------------------------------------------
// Organisation

function normalizeSubscriptions(raw: RawInventory, orgRows: RawResource[]): SubscriptionEntity[] {
  const chains = new Map<string, string[]>();
  for (const r of orgRows) {
    if (r.type.toLowerCase() !== T.subscription) continue;
    const chain = arr(r["mgChain"]).map((m) => str(obj(m)["displayName"]) ?? str(obj(m)["name"]) ?? "?");
    if (r.subscriptionId) chains.set(r.subscriptionId.toLowerCase(), chain.reverse());
  }
  return raw.subscriptions.map((s) => ({
    id: `/subscriptions/${s.subscriptionId.toLowerCase()}`,
    subscriptionId: s.subscriptionId.toLowerCase(),
    name: s.displayName,
    tenantId: s.tenantId,
    accessTenantId: s.accessTenantId,
    state: s.state,
    managementGroupPath: chains.get(s.subscriptionId.toLowerCase()) ?? [],
    managedByTenantIds: s.managedByTenantIds,
    tags: s.tags,
  }));
}

function base(r: RawResource): BaseEntity {
  const id = normalizeId(r.id);
  return {
    id,
    name: r.name,
    azureType: r.type.toLowerCase(),
    tenantId: r.tenantId,
    subscriptionId: r.subscriptionId?.toLowerCase() ?? subscriptionOf(id),
    resourceGroup: r.resourceGroup?.toLowerCase() ?? resourceGroupOf(id),
    location: str(r.location)?.toLowerCase(),
    tags: tagsOf(r["tags"]),
  };
}

const propsOf = (r: RawResource): Obj => obj(r.properties);
const skuOf = (r: RawResource): Obj => obj(r["sku"]);
const zonesOf = (r: RawResource): string[] => strings(r["zones"]);

// ---------------------------------------------------------------------------------------------
// VNets, subnets, peerings

function normalizeVnet(r: RawResource, inv: NormalizedInventory): void {
  const b = base(r);
  const p = propsOf(r);
  const addressSpace = splitByFamily(strings(obj(p["addressSpace"])["addressPrefixes"]));
  const encryption = obj(p["encryption"]);
  const vnet: VNetEntity = {
    ...b,
    addressSpace,
    ipClassification: classifyAddressing(addressSpace),
    dnsServers: strings(obj(p["dhcpOptions"])["dnsServers"]),
    ddosProtectionEnabled: bool(p["enableDdosProtection"]) ?? false,
    ddosProtectionPlanId: refId(p["ddosProtectionPlan"]),
    encryption:
      bool(encryption["enabled"]) !== undefined
        ? { enabled: bool(encryption["enabled"]) ?? false, enforcement: str(encryption["enforcement"]) }
        : undefined,
    flowTimeoutInMinutes: num(p["flowTimeoutInMinutes"]),
    subnetIds: [],
    peeringIds: [],
  };

  for (const s of arr(p["subnets"])) {
    const so = obj(s);
    const sp = obj(so["properties"]);
    const id = normalizeId(str(so["id"]));
    if (!id) continue;
    const prefixes = splitByFamily(singleOrMany(sp["addressPrefix"], sp["addressPrefixes"]));
    const ipConfigIds = refIds(sp["ipConfigurations"]);
    const connected = new Set(ipConfigIds.map(ownerOfIpConfiguration));
    for (const pe of refIds(sp["privateEndpoints"])) connected.add(pe);
    for (const agw of refIds(sp["applicationGatewayIPConfigurations"])) connected.add(parentId(agw));
    const subnet: SubnetEntity = {
      id,
      name: str(so["name"]) ?? lastSegment(id),
      vnetId: b.id,
      subscriptionId: b.subscriptionId,
      resourceGroup: b.resourceGroup,
      location: b.location,
      prefixes,
      ipClassification: classifyAddressing(prefixes),
      nsgId: refId(sp["networkSecurityGroup"]),
      routeTableId: refId(sp["routeTable"]),
      natGatewayId: refId(sp["natGateway"]),
      delegations: arr(sp["delegations"]).flatMap((d) => {
        const name = str(obj(obj(d)["properties"])["serviceName"]);
        return name ? [name] : [];
      }),
      serviceEndpoints: arr(sp["serviceEndpoints"]).flatMap((e) => {
        const svc = str(obj(obj(e)["properties"])["service"]);
        return svc ? [svc] : [];
      }),
      privateEndpointNetworkPolicies: str(sp["privateEndpointNetworkPolicies"]),
      privateLinkServiceNetworkPolicies: str(sp["privateLinkServiceNetworkPolicies"]),
      defaultOutboundAccess: bool(sp["defaultOutboundAccess"]),
      connectedResourceIds: [...connected].sort(),
      ipConfigurationCount: ipConfigIds.length,
    };
    inv.subnets.push(subnet);
    vnet.subnetIds.push(id);
  }

  for (const pe of arr(p["virtualNetworkPeerings"])) {
    const po = obj(pe);
    const pp = obj(po["properties"]);
    const id = normalizeId(str(po["id"]));
    if (!id) continue;
    const remoteSpace = strings(obj(pp["remoteVirtualNetworkAddressSpace"])["addressPrefixes"]);
    const peering: PeeringEntity = {
      id,
      name: str(po["name"]) ?? lastSegment(id),
      vnetId: b.id,
      remoteVnetId: refId(pp["remoteVirtualNetwork"]),
      remoteAddressSpace: splitByFamily(
        remoteSpace.length > 0 ? remoteSpace : strings(obj(pp["remoteAddressSpace"])["addressPrefixes"]),
      ),
      peeringState: str(pp["peeringState"]),
      peeringSyncLevel: str(pp["peeringSyncLevel"]),
      allowVirtualNetworkAccess: bool(pp["allowVirtualNetworkAccess"]) ?? false,
      allowForwardedTraffic: bool(pp["allowForwardedTraffic"]) ?? false,
      allowGatewayTransit: bool(pp["allowGatewayTransit"]) ?? false,
      useRemoteGateways: bool(pp["useRemoteGateways"]) ?? false,
      peerCompleteVnets: bool(pp["peerCompleteVnets"]),
      localSubnetNames: pp["localSubnetNames"] !== undefined ? strings(pp["localSubnetNames"]) : undefined,
      remoteSubnetNames: pp["remoteSubnetNames"] !== undefined ? strings(pp["remoteSubnetNames"]) : undefined,
      enableOnlyIPv6Peering: bool(pp["enableOnlyIPv6Peering"]),
    };
    inv.peerings.push(peering);
    vnet.peeringIds.push(id);
  }
  inv.vnets.push(vnet);
}

// ---------------------------------------------------------------------------------------------
// Routing & security

function normalizeRouteTable(r: RawResource, inv: NormalizedInventory): void {
  const b = base(r);
  const p = propsOf(r);
  const rt: RouteTableEntity = {
    ...b,
    routeIds: [],
    subnetIds: refIds(p["subnets"]),
    disableBgpRoutePropagation: bool(p["disableBgpRoutePropagation"]) ?? false,
  };
  for (const route of arr(p["routes"])) {
    const ro = obj(route);
    const rp = obj(ro["properties"]);
    const name = str(ro["name"]) ?? "route";
    const id = normalizeId(str(ro["id"])) ?? `${b.id}/routes/${name.toLowerCase()}`;
    const prefix = str(rp["addressPrefix"]) ?? "";
    const family = ipFamilyOf(prefix);
    const entity: RouteEntity = {
      id,
      name,
      routeTableId: b.id,
      addressPrefix: prefix,
      ipVersion: family ?? "serviceTag",
      nextHopType: str(rp["nextHopType"]) ?? "Unknown",
      nextHopIpAddress: str(rp["nextHopIpAddress"]),
      defaultRoute: isDefaultRoutePrefix(prefix) !== undefined,
    };
    inv.routes.push(entity);
    rt.routeIds.push(id);
  }
  inv.routeTables.push(rt);
}

function familiesOf(values: string[]): (IpFamily | "any")[] {
  const set = new Set<IpFamily | "any">();
  for (const v of values) set.add(ipFamilyOf(v) ?? "any");
  return [...set].sort();
}

function normalizeNsgRule(rule: unknown, isDefault: boolean): NsgRuleEntity {
  const ro = obj(rule);
  const rp = obj(ro["properties"]);
  const sources = singleOrMany(rp["sourceAddressPrefix"], rp["sourceAddressPrefixes"]);
  const destinations = singleOrMany(rp["destinationAddressPrefix"], rp["destinationAddressPrefixes"]);
  const sourceAsgIds = refIds(rp["sourceApplicationSecurityGroups"]);
  const destinationAsgIds = refIds(rp["destinationApplicationSecurityGroups"]);
  return {
    name: str(ro["name"]) ?? "rule",
    direction: str(rp["direction"]) ?? "Inbound",
    access: str(rp["access"]) ?? "Allow",
    priority: num(rp["priority"]) ?? 0,
    protocol: str(rp["protocol"]) ?? "*",
    sources,
    destinations,
    sourcePorts: singleOrMany(rp["sourcePortRange"], rp["sourcePortRanges"]),
    destinationPorts: singleOrMany(rp["destinationPortRange"], rp["destinationPortRanges"]),
    sourceAsgIds,
    destinationAsgIds,
    ipFamilies: familiesOf([...sources, ...destinations].filter((v) => v.length > 0)),
    isDefault,
  };
}

function normalizeNsg(r: RawResource): NsgEntity {
  const p = propsOf(r);
  const byPriority = (a: NsgRuleEntity, b: NsgRuleEntity) =>
    a.direction.localeCompare(b.direction) || a.priority - b.priority;
  return {
    ...base(r),
    rules: arr(p["securityRules"])
      .map((x) => normalizeNsgRule(x, false))
      .sort(byPriority),
    defaultRules: arr(p["defaultSecurityRules"])
      .map((x) => normalizeNsgRule(x, true))
      .sort(byPriority),
    subnetIds: refIds(p["subnets"]),
    nicIds: refIds(p["networkInterfaces"]),
  };
}

// ---------------------------------------------------------------------------------------------
// Compute attachment: NICs, public IPs, NAT

function ipConfiguration(value: unknown): IpConfigurationEntity {
  const o = obj(value);
  const p = obj(o["properties"]);
  const ip = str(p["privateIPAddress"]);
  const version = str(p["privateIPAddressVersion"])?.toLowerCase();
  return {
    name: str(o["name"]) ?? "ipconfig",
    privateIpAddress: ip,
    privateIpVersion: version === "ipv6" ? "ipv6" : version === "ipv4" ? "ipv4" : ipFamilyOf(ip),
    subnetId: refId(p["subnet"]),
    publicIpId: refId(p["publicIPAddress"]),
    primary: bool(p["primary"]) ?? false,
    loadBalancerBackendPoolIds: refIds(p["loadBalancerBackendAddressPools"]),
  };
}

function normalizeNic(r: RawResource): NicEntity {
  const b = base(r);
  const p = propsOf(r);
  const ipConfigurations = arr(p["ipConfigurations"]).map(ipConfiguration);
  const addressing = splitByFamily(ipConfigurations.map((c) => c.privateIpAddress));
  const scaleSetId = rollUpScaleSet(b.id) !== b.id ? rollUpScaleSet(b.id) : undefined;
  return {
    ...b,
    ipConfigurations,
    addressing,
    ipClassification: classifyAddressing(addressing),
    subnetIds: [...new Set(ipConfigurations.flatMap((c) => (c.subnetId ? [c.subnetId] : [])))],
    vmId: refId(p["virtualMachine"]),
    nsgId: refId(p["networkSecurityGroup"]),
    ipForwarding: bool(p["enableIPForwarding"]) ?? false,
    acceleratedNetworking: bool(p["enableAcceleratedNetworking"]) ?? false,
    defaultOutboundConnectivityEnabled: bool(p["defaultOutboundConnectivityEnabled"]),
    scaleSetId,
  };
}

function versionOf(p: Obj, address?: string): IpFamily {
  const v = str(p["publicIPAddressVersion"])?.toLowerCase();
  if (v === "ipv6") return "ipv6";
  if (v === "ipv4") return "ipv4";
  return ipFamilyOf(address) ?? "ipv4";
}

function normalizePublicIp(r: RawResource): PublicIpEntity {
  const p = propsOf(r);
  const ipConfig = refId(p["ipConfiguration"]);
  const ipAddress = str(p["ipAddress"]);
  return {
    ...base(r),
    ipAddress,
    ipVersion: versionOf(p, ipAddress),
    sku: str(skuOf(r)["name"]),
    tier: str(skuOf(r)["tier"]),
    allocationMethod: str(p["publicIPAllocationMethod"]),
    attachedToId: ipConfig ? ownerOfIpConfiguration(ipConfig) : refId(p["natGateway"]),
    publicIpPrefixId: refId(p["publicIPPrefix"]),
    natGatewayId: refId(p["natGateway"]),
    zones: zonesOf(r),
  };
}

function normalizePublicIpPrefix(r: RawResource): PublicIpPrefixEntity {
  const p = propsOf(r);
  const prefix = str(p["ipPrefix"]);
  return {
    ...base(r),
    prefix,
    ipVersion: versionOf(p, prefix),
    prefixLength: num(p["prefixLength"]),
    natGatewayId: refId(p["natGateway"]),
    publicIpIds: refIds(p["publicIPAddresses"]),
    sku: str(skuOf(r)["name"]),
  };
}

function normalizeNatGateway(r: RawResource): NatGatewayEntity {
  const p = propsOf(r);
  return {
    ...base(r),
    sku: str(skuOf(r)["name"]) ?? "Standard",
    zones: zonesOf(r),
    subnetIds: refIds(p["subnets"]),
    publicIpIds: refIds(p["publicIpAddresses"]),
    publicIpPrefixIds: refIds(p["publicIpPrefixes"]),
    idleTimeoutInMinutes: num(p["idleTimeoutInMinutes"]),
    // Computed in resolveCrossReferences once public IP families are known.
    ipv4EgressConfigured: false,
    ipv6EgressConfigured: false,
    dualStackEgressConfigured: false,
  };
}

// ---------------------------------------------------------------------------------------------
// Firewall

function normalizeFirewall(r: RawResource): FirewallEntity {
  const p = propsOf(r);
  const ipConfigurations = arr(p["ipConfigurations"]).map(ipConfiguration);
  const mgmt = p["managementIpConfiguration"] ? ipConfiguration(p["managementIpConfiguration"]) : undefined;
  const hub = obj(p["hubIPAddresses"]);
  const hubPrivate = str(hub["privateIPAddress"]);
  const extra = obj(p["additionalProperties"]);
  const privateIps = splitByFamily([...ipConfigurations.map((c) => c.privateIpAddress), hubPrivate]);
  const sku = obj(p["sku"]);
  return {
    ...base(r),
    skuName: str(sku["name"]),
    skuTier: str(sku["tier"]),
    zones: zonesOf(r),
    firewallPolicyId: refId(p["firewallPolicy"]),
    ipConfigurations,
    managementIpConfiguration: mgmt,
    privateIps,
    publicIpIds: [
      ...ipConfigurations.flatMap((c) => (c.publicIpId ? [c.publicIpId] : [])),
      ...(mgmt?.publicIpId ? [mgmt.publicIpId] : []),
    ],
    threatIntelMode: str(p["threatIntelMode"]),
    virtualHubId: refId(p["virtualHub"]),
    dnsProxyEnabled: bool(extra["Network.DNS.EnableProxy"]),
    classicRuleCollections: {
      application: arr(p["applicationRuleCollections"]).length,
      network: arr(p["networkRuleCollections"]).length,
      nat: arr(p["natRuleCollections"]).length,
    },
  };
}

function normalizeFirewallPolicy(r: RawResource): FirewallPolicyEntity {
  const p = propsOf(r);
  const dns = obj(p["dnsSettings"]);
  return {
    ...base(r),
    skuTier: str(obj(p["sku"])["tier"]),
    basePolicyId: refId(p["basePolicy"]),
    childPolicyIds: refIds(p["childPolicies"]),
    firewallIds: refIds(p["firewalls"]),
    ruleCollectionGroupIds: refIds(p["ruleCollectionGroups"]),
    threatIntelMode: str(p["threatIntelMode"]),
    dnsProxyEnabled: bool(dns["enableProxy"]),
    dnsServers: strings(dns["servers"]),
    intrusionDetectionMode: str(obj(p["intrusionDetection"])["mode"]),
  };
}

function normalizeFirewallRule(rule: unknown): FirewallRuleEntity {
  const o = obj(rule);
  const protocols = arr(o["ipProtocols"]).length
    ? strings(o["ipProtocols"])
    : arr(o["protocols"]).map((x) => {
        const po = obj(x);
        return `${str(po["protocolType"]) ?? "?"}:${num(po["port"]) ?? "*"}`;
      });
  return {
    name: str(o["name"]) ?? "rule",
    ruleType: str(o["ruleType"]) ?? "Unknown",
    sources: strings(o["sourceAddresses"]),
    destinations: strings(o["destinationAddresses"]),
    sourceIpGroupIds: strings(o["sourceIpGroups"]).map((x) => x.toLowerCase()),
    destinationIpGroupIds: strings(o["destinationIpGroups"]).map((x) => x.toLowerCase()),
    destinationPorts: strings(o["destinationPorts"]),
    protocols,
    destinationFqdns: strings(o["destinationFqdns"]),
    targetFqdns: strings(o["targetFqdns"]),
    translatedAddress: str(o["translatedAddress"]) ?? str(o["translatedFqdn"]),
    translatedPort: str(o["translatedPort"]),
    ipv6Rule: bool(o["ipv6Rule"]),
  };
}

function normalizeRuleCollectionGroup(r: RawResource): RuleCollectionGroupEntity {
  const id = normalizeId(r.id);
  const p = propsOf(r);
  return {
    id,
    name: r.name,
    firewallPolicyId: parentId(id),
    priority: num(p["priority"]),
    ruleCollections: arr(p["ruleCollections"]).map((c) => {
      const co = obj(c);
      return {
        name: str(co["name"]) ?? "collection",
        collectionType: str(co["ruleCollectionType"]) ?? "Unknown",
        priority: num(co["priority"]),
        action: str(obj(co["action"])["type"]),
        rules: arr(co["rules"]).map(normalizeFirewallRule),
      };
    }),
  };
}

function normalizeIpGroup(r: RawResource): IpGroupEntity {
  return { ...base(r), ipAddresses: strings(propsOf(r)["ipAddresses"]) };
}

// ---------------------------------------------------------------------------------------------
// Load balancing

function normalizeLoadBalancer(r: RawResource): LoadBalancerEntity {
  const p = propsOf(r);
  const frontends = arr(p["frontendIPConfigurations"]).map((f) => ({
    ...ipConfiguration(f),
    publicIpPrefixId: refId(obj(obj(f)["properties"])["publicIPPrefix"]),
  }));
  const nameOf = (v: unknown) => str(obj(v)["name"]) ?? "?";
  return {
    ...base(r),
    sku: str(skuOf(r)["name"]),
    frontends,
    backendPools: arr(p["backendAddressPools"]).map((bp) => ({
      name: nameOf(bp),
      memberIds: [
        ...new Set(refIds(obj(obj(bp)["properties"])["backendIPConfigurations"]).map(ownerOfIpConfiguration)),
      ].sort(),
    })),
    loadBalancingRules: arr(p["loadBalancingRules"]).length,
    inboundNatRules: arr(p["inboundNatRules"]).length,
    outboundRules: arr(p["outboundRules"]).map((o) => {
      const op = obj(obj(o)["properties"]);
      const pool = refId(op["backendAddressPool"]);
      return {
        name: nameOf(o),
        frontendNames: refIds(op["frontendIPConfigurations"]).map(lastSegment),
        backendPool: pool ? lastSegment(pool) : undefined,
      };
    }),
    probes: arr(p["probes"]).length,
    isPublic: frontends.some((f) => f.publicIpId !== undefined || f.publicIpPrefixId !== undefined),
  };
}

function normalizeAppGateway(r: RawResource): ApplicationGatewayEntity {
  const p = propsOf(r);
  const sku = obj(p["sku"]);
  const ports = new Map(
    arr(p["frontendPorts"]).map((fp) => [
      normalizeId(str(obj(fp)["id"])) ?? "",
      String(num(obj(obj(fp)["properties"])["port"]) ?? ""),
    ]),
  );
  return {
    ...base(r),
    sku: str(sku["name"]),
    tier: str(sku["tier"]),
    frontends: arr(p["frontendIPConfigurations"]).map(ipConfiguration),
    gatewaySubnetIds: arr(p["gatewayIPConfigurations"]).flatMap((g) => {
      const id = refId(obj(obj(g)["properties"])["subnet"]);
      return id ? [id] : [];
    }),
    listeners: arr(p["httpListeners"]).map((l) => {
      const lp = obj(obj(l)["properties"]);
      const port = refId(lp["frontendPort"]);
      return {
        name: str(obj(l)["name"]) ?? "listener",
        protocol: str(lp["protocol"]),
        hostNames: singleOrMany(lp["hostName"], lp["hostNames"]),
        frontendPort: port ? ports.get(port) : undefined,
      };
    }),
    backendPools: arr(p["backendAddressPools"]).map((bp) => {
      const bpp = obj(obj(bp)["properties"]);
      return {
        name: str(obj(bp)["name"]) ?? "pool",
        addresses: arr(bpp["backendAddresses"]).flatMap((a) => {
          const v = str(obj(a)["fqdn"]) ?? str(obj(a)["ipAddress"]);
          return v ? [v] : [];
        }),
        memberIds: [...new Set(refIds(bpp["backendIPConfigurations"]).map(ownerOfIpConfiguration))],
      };
    }),
    routingRules: arr(p["requestRoutingRules"]).length,
    wafPolicyId: refId(p["firewallPolicy"]),
    wafEnabled: bool(obj(p["webApplicationFirewallConfiguration"])["enabled"]),
  };
}

// ---------------------------------------------------------------------------------------------
// Hybrid connectivity

function normalizeVng(r: RawResource): VirtualNetworkGatewayEntity {
  const p = propsOf(r);
  const ipConfigurations = arr(p["ipConfigurations"]).map(ipConfiguration);
  const subnet = ipConfigurations.find((c) => c.subnetId)?.subnetId;
  return {
    ...base(r),
    gatewayType: str(p["gatewayType"]),
    vpnType: str(p["vpnType"]),
    sku: str(obj(p["sku"])["name"]),
    activeActive: bool(p["activeActive"]) ?? false,
    bgpEnabled: bool(p["enableBgp"]) ?? false,
    bgpAsn: num(obj(p["bgpSettings"])["asn"]),
    ipConfigurations,
    vnetId: subnet ? parentId(subnet) : undefined,
    publicIpIds: ipConfigurations.flatMap((c) => (c.publicIpId ? [c.publicIpId] : [])),
  };
}

function normalizeLng(r: RawResource): LocalNetworkGatewayEntity {
  const p = propsOf(r);
  const bgp = obj(p["bgpSettings"]);
  return {
    ...base(r),
    addressPrefixes: splitByFamily(strings(obj(p["localNetworkAddressSpace"])["addressPrefixes"])),
    gatewayIpAddress: str(p["gatewayIpAddress"]),
    fqdn: str(p["fqdn"]),
    bgpAsn: num(bgp["asn"]),
    bgpPeeringAddress: str(bgp["bgpPeeringAddress"]),
  };
}

function normalizeConnection(r: RawResource): ConnectionEntity {
  const p = propsOf(r);
  return {
    ...base(r),
    connectionType: str(p["connectionType"]),
    virtualNetworkGatewayId: refId(p["virtualNetworkGateway1"]),
    remoteVirtualNetworkGatewayId: refId(p["virtualNetworkGateway2"]),
    localNetworkGatewayId: refId(p["localNetworkGateway2"]),
    expressRouteCircuitId: refId(p["peer"]),
    connectionStatus: str(p["connectionStatus"]),
    bgpEnabled: bool(p["enableBgp"]) ?? false,
  };
}

// ---------------------------------------------------------------------------------------------
// Private endpoints & DNS

function normalizePrivateEndpoint(r: RawResource): PrivateEndpointEntity {
  const p = propsOf(r);
  const targets = (manual: boolean) => (c: unknown) => {
    const cp = obj(obj(c)["properties"]);
    return {
      resourceId: normalizeId(str(cp["privateLinkServiceId"])) ?? "",
      groupIds: strings(cp["groupIds"]),
      status: str(obj(cp["privateLinkServiceConnectionState"])["status"]),
      manual,
    };
  };
  const customDnsConfigs = arr(p["customDnsConfigs"]).map((c) => ({
    fqdn: str(obj(c)["fqdn"]),
    ipAddresses: strings(obj(c)["ipAddresses"]),
  }));
  const ipConfigs = arr(p["ipConfigurations"]).map((c) => str(obj(obj(c)["properties"])["privateIPAddress"]));
  const addressing = splitByFamily([...ipConfigs, ...customDnsConfigs.flatMap((c) => c.ipAddresses)]);
  return {
    ...base(r),
    subnetId: refId(p["subnet"]),
    nicIds: refIds(p["networkInterfaces"]),
    addressing,
    ipClassification: classifyAddressing(addressing),
    targets: [
      ...arr(p["privateLinkServiceConnections"]).map(targets(false)),
      ...arr(p["manualPrivateLinkServiceConnections"]).map(targets(true)),
    ].filter((t) => t.resourceId !== ""),
    customDnsConfigs,
  };
}

function recordRows(byType: Map<string, RawResource[]>): RawResource[] {
  return [...byType.entries()]
    .filter(([type]) => /^microsoft\.network\/privatednszones\/(a|aaaa|cname|ptr|srv|txt|mx)$/.test(type))
    .flatMap(([, rows]) => rows);
}

function recordValues(type: string, p: Obj): string[] {
  const records = arr(p["records"]);
  const pick = (key: string) => records.flatMap((x) => (str(obj(x)[key]) ? [str(obj(x)[key])!] : []));
  switch (type) {
    case "a":
      return [...pick("ipv4Address"), ...arr(p["aRecords"]).flatMap((x) => strings([obj(x)["ipv4Address"]]))];
    case "aaaa":
      return [
        ...pick("ipv6Address"),
        ...arr(p["aaaaRecords"]).flatMap((x) => strings([obj(x)["ipv6Address"]])),
      ];
    case "cname":
      return [...pick("cname"), ...strings([obj(p["cnameRecord"])["cname"]])];
    case "ptr":
      return pick("ptrdname");
    default:
      return [];
  }
}

function normalizePrivateDns(
  zones: RawResource[],
  links: RawResource[],
  records: RawResource[],
  inv: NormalizedInventory,
): void {
  const map = new Map<string, PrivateDnsZoneEntity>();
  for (const r of zones) {
    const zone: PrivateDnsZoneEntity = {
      ...base(r),
      vnetLinks: [],
      records: [],
      aaaaRecordCount: 0,
      aRecordCount: 0,
    };
    map.set(zone.id, zone);
    inv.privateDnsZones.push(zone);
  }
  for (const r of links) {
    const id = normalizeId(r.id);
    const p = propsOf(r);
    map.get(parentId(id))?.vnetLinks.push({
      id,
      vnetId: refId(p["virtualNetwork"]),
      registrationEnabled: bool(p["registrationEnabled"]) ?? false,
      state: str(p["virtualNetworkLinkState"]),
    });
  }
  for (const r of records) {
    const id = normalizeId(r.id);
    const recordType = r.type.toLowerCase().split("/").pop() ?? "?";
    const zone = map.get(parentId(id));
    if (!zone || recordType === "soa") continue;
    const p = propsOf(r);
    const record: DnsRecordEntity = {
      id,
      name: r.name,
      recordType: recordType.toUpperCase(),
      values: recordValues(recordType, p),
      ttl: num(p["ttl"]),
    };
    zone.records.push(record);
    if (recordType === "a") zone.aRecordCount++;
    if (recordType === "aaaa") zone.aaaaRecordCount++;
  }
  for (const zone of inv.privateDnsZones) zone.records.sort((a, b) => a.name.localeCompare(b.name));
}

function normalizeDnsResolvers(byType: Map<string, RawResource[]>, inv: NormalizedInventory): void {
  const make = (r: RawResource, kind: DnsResolverEntity["kind"]): DnsResolverEntity => {
    const p = propsOf(r);
    const ipConfigs = arr(p["ipConfigurations"]).map((c) => obj(c));
    return {
      ...base(r),
      kind,
      vnetId: refId(p["virtualNetwork"]),
      subnetIds: [
        ...refIds([p["subnet"]].filter(Boolean)),
        ...ipConfigs.flatMap((c) => (refId(c["subnet"]) ? [refId(c["subnet"])!] : [])),
      ],
      privateIps: ipConfigs.flatMap((c) => strings([c["privateIpAddress"]])),
      resolverId:
        kind === "inboundEndpoint" || kind === "outboundEndpoint" ? parentId(normalizeId(r.id)) : undefined,
      linkedVnetIds: [],
      outboundEndpointIds: refIds(p["dnsResolverOutboundEndpoints"]),
      forwardingRules: [],
    };
  };
  const all = new Map<string, DnsResolverEntity>();
  const add = (rows: RawResource[] | undefined, kind: DnsResolverEntity["kind"]) => {
    for (const r of rows ?? []) {
      const e = make(r, kind);
      all.set(e.id, e);
      inv.dnsResolvers.push(e);
    }
  };
  add(byType.get(T.resolver), "resolver");
  add(byType.get(T.resolverIn), "inboundEndpoint");
  add(byType.get(T.resolverOut), "outboundEndpoint");
  add(byType.get(T.ruleset), "forwardingRuleset");
  for (const r of byType.get(T.rulesetRule) ?? []) {
    const p = propsOf(r);
    all.get(parentId(normalizeId(r.id)))?.forwardingRules.push({
      name: r.name,
      domainName: str(p["domainName"]),
      targets: arr(p["targetDnsServers"]).map(
        (t) => `${str(obj(t)["ipAddress"]) ?? "?"}:${num(obj(t)["port"]) ?? 53}`,
      ),
      state: str(p["forwardingRuleState"]),
    });
  }
  for (const r of byType.get(T.rulesetLink) ?? []) {
    const vnet = refId(propsOf(r)["virtualNetwork"]);
    if (vnet) all.get(parentId(normalizeId(r.id)))?.linkedVnetIds.push(vnet);
  }
}

// ---------------------------------------------------------------------------------------------
// Compute

function normalizeVm(r: RawResource): VirtualMachineEntity {
  const image = obj(r["imageReference"]);
  const imageName = [str(image["publisher"]), str(image["offer"]), str(image["sku"])]
    .filter(Boolean)
    .join(":");
  return {
    ...base(r),
    nicIds: refIds(r["nics"]),
    vmSize: str(r["vmSize"]),
    image: imageName || (refId(image["id"]) ? "custom image" : undefined),
    powerState: str(r["powerState"])?.replace(/^PowerState\//i, ""),
  };
}

function normalizeScaleSet(r: RawResource): ScaleSetEntity {
  const nicTemplates = arr(obj(r["networkProfile"])["networkInterfaceConfigurations"]).map((n) =>
    obj(obj(n)["properties"]),
  );
  return {
    ...base(r),
    orchestrationMode: str(r["orchestrationMode"]),
    instanceNicIds: [],
    subnetIds: [
      ...new Set(
        nicTemplates.flatMap((n) =>
          arr(n["ipConfigurations"]).flatMap((c) => {
            const id = refId(obj(obj(c)["properties"])["subnet"]);
            return id ? [id] : [];
          }),
        ),
      ),
    ],
    ipForwarding: nicTemplates.some((n) => bool(n["enableIPForwarding"]) === true),
  };
}

// ---------------------------------------------------------------------------------------------
// Generic

function flatProperties(p: Obj): Record<string, string | number | boolean | string[]> {
  const out: Record<string, string | number | boolean | string[]> = {};
  for (const [key, value] of Object.entries(p)) {
    if (SECRET_KEY.test(key) || key === "provisioningState" || key === "resourceGuid" || key === "etag")
      continue;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
      out[key] = value;
    else if (Array.isArray(value) && value.every((v) => typeof v === "string")) out[key] = value;
    else {
      const id = refId(value);
      if (id) out[key] = id;
    }
  }
  return out;
}

function normalizeGeneric(r: RawResource, kind: string): GenericNetworkEntity {
  const b = base(r);
  const p = propsOf(r);
  const referenced = collectReferencedIds(p);
  referenced.delete(b.id);
  const subnetIds = [...referenced].filter((id) => /\/virtualnetworks\/[^/]+\/subnets\/[^/]+$/.test(id));
  // IP configurations of generic resources (e.g. bastion) point to subnets via ipConfigurations[].properties.subnet
  return {
    ...b,
    kind,
    subnetIds,
    referencedIds: [...referenced]
      .map((id) => (/\/ipconfigurations\//.test(id) ? ownerOfIpConfiguration(id) : id))
      .filter((id, i, a) => a.indexOf(id) === i)
      .sort(),
    properties: flatProperties({ ...p, ...(r["sku"] ? { sku: str(skuOf(r)["name"]) ?? "" } : {}) }),
  };
}

// ---------------------------------------------------------------------------------------------
// Cross references

function resolveCrossReferences(inv: NormalizedInventory): void {
  const pips = new Map(inv.publicIps.map((p) => [p.id, p]));
  const prefixes = new Map(inv.publicIpPrefixes.map((p) => [p.id, p]));

  // NAT gateway egress families (StandardV2 is required for IPv6; the SKU check is an assessment concern).
  for (const nat of inv.natGateways) {
    const families = new Set<IpFamily>([
      ...nat.publicIpIds.flatMap((id) => (pips.get(id) ? [pips.get(id)!.ipVersion] : [])),
      ...nat.publicIpPrefixIds.flatMap((id) => (prefixes.get(id) ? [prefixes.get(id)!.ipVersion] : [])),
    ]);
    nat.ipv4EgressConfigured = families.has("ipv4");
    nat.ipv6EgressConfigured = families.has("ipv6");
    nat.dualStackEgressConfigured = nat.ipv4EgressConfigured && nat.ipv6EgressConfigured;
  }

  // Private endpoint NICs carry the private IPs.
  const nics = new Map(inv.networkInterfaces.map((n) => [n.id, n]));
  for (const pe of inv.privateEndpoints) {
    const ips = pe.nicIds.flatMap(
      (id) => nics.get(id)?.ipConfigurations.map((c) => c.privateIpAddress) ?? [],
    );
    const merged = splitByFamily([...pe.addressing.ipv4, ...pe.addressing.ipv6, ...ips]);
    pe.addressing = merged;
    pe.ipClassification = classifyAddressing(merged);
  }

  // VM scale set instance NICs.
  const scaleSets = new Map(inv.scaleSets.map((s) => [s.id, s]));
  for (const nic of inv.networkInterfaces) {
    if (!nic.scaleSetId) continue;
    const ss = scaleSets.get(nic.scaleSetId);
    if (!ss) continue;
    ss.instanceNicIds.push(nic.id);
    for (const s of nic.subnetIds) if (!ss.subnetIds.includes(s)) ss.subnetIds.push(s);
    if (nic.ipForwarding) ss.ipForwarding = true;
  }

  // UDR next hop IP → resource (firewall, NIC → VM, LB frontend, gateway).
  const ipOwner = new Map<string, string>();
  for (const fw of inv.firewalls)
    for (const ip of [...fw.privateIps.ipv4, ...fw.privateIps.ipv6]) ipOwner.set(ip, fw.id);
  for (const lb of inv.loadBalancers)
    for (const f of lb.frontends) if (f.privateIpAddress) ipOwner.set(f.privateIpAddress, lb.id);
  for (const nic of inv.networkInterfaces) {
    const owner = nic.vmId ?? nic.scaleSetId ?? nic.id;
    for (const c of nic.ipConfigurations)
      if (c.privateIpAddress && !ipOwner.has(c.privateIpAddress)) ipOwner.set(c.privateIpAddress, owner);
  }
  for (const route of inv.routes) {
    if (route.nextHopIpAddress) route.nextHopResourceId = ipOwner.get(route.nextHopIpAddress);
  }
}

function sortInventory(inv: NormalizedInventory): void {
  const byId = (a: { id: string }, b: { id: string }) => a.id.localeCompare(b.id);
  for (const value of Object.values(inv)) {
    if (Array.isArray(value) && value.length > 0 && typeof (value[0] as { id?: unknown }).id === "string") {
      (value as { id: string }[]).sort(byId);
    }
  }
}
