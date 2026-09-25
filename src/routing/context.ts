import { cidrContains, ipFamilyOf, type IpFamily } from "../addressing/ip.js";
import type {
  ConnectionEntity,
  FirewallEntity,
  FirewallPolicyEntity,
  IpGroupEntity,
  LoadBalancerEntity,
  LocalNetworkGatewayEntity,
  NatGatewayEntity,
  NicEntity,
  NormalizedInventory,
  NsgEntity,
  PeeringEntity,
  PrivateEndpointEntity,
  PublicIpEntity,
  PublicIpPrefixEntity,
  RouteEntity,
  RouteTableEntity,
  RuleCollectionGroupEntity,
  SubnetEntity,
  VirtualMachineEntity,
  VirtualNetworkGatewayEntity,
  VNetEntity,
  AvnmAdminRuleEntity,
  HubConnectionEntity,
  VirtualHubEntity,
} from "../models/network.js";

export type IpOwnerKind = "firewall" | "nic" | "loadBalancer" | "privateEndpoint" | "gateway";

export interface IpOwner {
  kind: IpOwnerKind;
  id: string;
  /** VM or scale set behind a NIC. */
  computeId?: string | undefined;
  subnetId?: string | undefined;
}

/** Indexes over the normalized inventory used by route synthesis, NSG/firewall evaluation and tracing. */
export interface RoutingContext {
  inv: NormalizedInventory;
  vnets: Map<string, VNetEntity>;
  subnets: Map<string, SubnetEntity>;
  routeTables: Map<string, RouteTableEntity>;
  routesByTable: Map<string, RouteEntity[]>;
  peeringsByVnet: Map<string, PeeringEntity[]>;
  nsgs: Map<string, NsgEntity>;
  nics: Map<string, NicEntity>;
  nicsByCompute: Map<string, NicEntity[]>;
  vms: Map<string, VirtualMachineEntity>;
  privateEndpoints: Map<string, PrivateEndpointEntity>;
  firewalls: Map<string, FirewallEntity>;
  firewallPolicies: Map<string, FirewallPolicyEntity>;
  ruleCollectionGroups: Map<string, RuleCollectionGroupEntity>;
  ipGroups: Map<string, IpGroupEntity>;
  natGateways: Map<string, NatGatewayEntity>;
  publicIps: Map<string, PublicIpEntity>;
  publicIpPrefixes: Map<string, PublicIpPrefixEntity>;
  loadBalancers: Map<string, LoadBalancerEntity>;
  gatewaysByVnet: Map<string, VirtualNetworkGatewayEntity[]>;
  connectionsByGateway: Map<string, ConnectionEntity[]>;
  localNetworkGateways: Map<string, LocalNetworkGatewayEntity>;
  ipOwners: Map<string, IpOwner>;
  /** Scale set / VM / NIC → potential NVA flag from the topology heuristic. */
  nvaIds: Set<string>;
  /** Service tag (lowercase) → prefixes (Service Tag Discovery API, referenced tags only). */
  serviceTags: Map<string, string[]>;
  virtualHubs: Map<string, VirtualHubEntity>;
  /** Spoke VNet → its Virtual WAN hub connection. */
  hubConnectionByVnet: Map<string, { hub: VirtualHubEntity; connection: HubConnectionEntity }>;
  /** VNet → AVNM security admin rules in effect (sorted by priority). */
  adminRulesByVnet: Map<string, AvnmAdminRuleEntity[]>;
  /** VNet → other VNets of the same AVNM connected group (mesh / direct connectivity). */
  connectedGroupPeers: Map<string, string[]>;
}

const group = <T, K>(items: T[], key: (t: T) => K | undefined): Map<K, T[]> => {
  const map = new Map<K, T[]>();
  for (const item of items) {
    const k = key(item);
    if (k === undefined) continue;
    const list = map.get(k) ?? [];
    list.push(item);
    map.set(k, list);
  }
  return map;
};
const byId = <T extends { id: string }>(items: T[]): Map<string, T> => new Map(items.map((i) => [i.id, i]));

export function buildRoutingContext(inv: NormalizedInventory): RoutingContext {
  const ipOwners = new Map<string, IpOwner>();
  const setOwner = (ip: string | undefined, owner: IpOwner) => {
    if (ip && !ipOwners.has(ip.toLowerCase())) ipOwners.set(ip.toLowerCase(), owner);
  };
  for (const fw of inv.firewalls) {
    for (const c of fw.ipConfigurations)
      setOwner(c.privateIpAddress, { kind: "firewall", id: fw.id, subnetId: c.subnetId });
    for (const ip of [...fw.privateIps.ipv4, ...fw.privateIps.ipv6])
      setOwner(ip, { kind: "firewall", id: fw.id });
  }
  for (const lb of inv.loadBalancers) {
    for (const f of lb.frontends)
      setOwner(f.privateIpAddress, { kind: "loadBalancer", id: lb.id, subnetId: f.subnetId });
  }
  const peByNic = new Map(inv.privateEndpoints.flatMap((pe) => pe.nicIds.map((n) => [n, pe.id] as const)));
  for (const nic of inv.networkInterfaces) {
    const pe = peByNic.get(nic.id);
    for (const c of nic.ipConfigurations) {
      setOwner(
        c.privateIpAddress,
        pe
          ? { kind: "privateEndpoint", id: pe, subnetId: c.subnetId }
          : { kind: "nic", id: nic.id, computeId: nic.vmId ?? nic.scaleSetId, subnetId: c.subnetId },
      );
    }
  }
  for (const g of inv.vpnGateways)
    for (const c of g.ipConfigurations)
      setOwner(c.privateIpAddress, { kind: "gateway", id: g.id, subnetId: c.subnetId });

  const hubConnectionByVnet = new Map<string, { hub: VirtualHubEntity; connection: HubConnectionEntity }>();
  for (const hub of inv.virtualHubs ?? []) {
    for (const c of hub.connections)
      if (c.remoteVnetId) hubConnectionByVnet.set(c.remoteVnetId, { hub, connection: c });
  }
  const avnm = inv.avnm ?? { adminRules: [], vnetAdminConfigurations: {}, connectedGroups: [] };
  const adminRulesByVnet = new Map<string, AvnmAdminRuleEntity[]>();
  for (const [vnetId, configs] of Object.entries(avnm.vnetAdminConfigurations)) {
    const rules = avnm.adminRules.filter((r) => configs.includes(r.configurationId));
    adminRulesByVnet.set(vnetId, rules);
  }
  const connectedGroupPeers = new Map<string, string[]>();
  for (const g of avnm.connectedGroups) {
    for (const v of g.vnetIds) {
      connectedGroupPeers.set(v, [
        ...new Set([...(connectedGroupPeers.get(v) ?? []), ...g.vnetIds.filter((x) => x !== v)]),
      ]);
    }
  }

  const nvaIds = new Set(inv.virtualMachines.filter((v) => v.nva?.potentialNva).map((v) => v.id));
  for (const ss of inv.scaleSets) if (ss.ipForwarding) nvaIds.add(ss.id);

  return {
    inv,
    vnets: byId(inv.vnets),
    subnets: byId(inv.subnets),
    routeTables: byId(inv.routeTables),
    routesByTable: group(inv.routes, (r) => r.routeTableId),
    peeringsByVnet: group(inv.peerings, (p) => p.vnetId),
    nsgs: byId(inv.nsgs),
    nics: byId(inv.networkInterfaces),
    nicsByCompute: group(inv.networkInterfaces, (n) => n.vmId ?? n.scaleSetId),
    vms: byId(inv.virtualMachines),
    privateEndpoints: byId(inv.privateEndpoints),
    firewalls: byId(inv.firewalls),
    firewallPolicies: byId(inv.firewallPolicies),
    ruleCollectionGroups: byId(inv.ruleCollectionGroups),
    ipGroups: byId(inv.ipGroups),
    natGateways: byId(inv.natGateways),
    publicIps: byId(inv.publicIps),
    publicIpPrefixes: byId(inv.publicIpPrefixes),
    loadBalancers: byId(inv.loadBalancers),
    gatewaysByVnet: group(inv.vpnGateways, (g) => g.vnetId),
    connectionsByGateway: group(inv.connections, (c) => c.virtualNetworkGatewayId),
    localNetworkGateways: byId(inv.localNetworkGateways),
    ipOwners,
    nvaIds,
    serviceTags: new Map((inv.serviceTags ?? []).map((t) => [t.name.toLowerCase(), t.prefixes])),
    virtualHubs: byId(inv.virtualHubs ?? []),
    hubConnectionByVnet,
    adminRulesByVnet,
    connectedGroupPeers,
  };
}

/** Service tag resolver for NSG/firewall/UDR evaluation; undefined when the tag was not loaded. */
export function tagResolver(ctx: RoutingContext): (tag: string) => string[] | undefined {
  return (tag) => ctx.serviceTags.get(tag.toLowerCase());
}

export function ownerOfIp(ctx: RoutingContext, ip: string): IpOwner | undefined {
  return ctx.ipOwners.get(ip.toLowerCase());
}

/** Subnet (from any VNet in the inventory) whose prefix contains the address. */
export function subnetContaining(ctx: RoutingContext, ip: string, vnetId?: string): SubnetEntity | undefined {
  const family = ipFamilyOf(ip);
  if (!family) return undefined;
  for (const s of ctx.subnets.values()) {
    if (vnetId && s.vnetId !== vnetId) continue;
    if (s.prefixes[family].some((p) => cidrContains(p, ip))) return s;
  }
  return undefined;
}

export function vnetContaining(ctx: RoutingContext, ip: string): VNetEntity | undefined {
  const family = ipFamilyOf(ip);
  if (!family) return undefined;
  for (const v of ctx.vnets.values()) if (v.addressSpace[family].some((p) => cidrContains(p, ip))) return v;
  return undefined;
}

/** First address of a family on a NIC / VM / scale set / private endpoint / firewall. */
export function addressOf(ctx: RoutingContext, id: string, family: IpFamily): string | undefined {
  const nic = ctx.nics.get(id);
  if (nic) return nic.addressing[family][0];
  const nics = ctx.nicsByCompute.get(id);
  if (nics) return nics.flatMap((n) => n.addressing[family])[0];
  const pe = ctx.privateEndpoints.get(id);
  if (pe) return pe.addressing[family][0];
  const fw = ctx.firewalls.get(id);
  if (fw) return fw.privateIps[family][0];
  const lb = ctx.loadBalancers.get(id);
  if (lb) return lb.frontends.find((f) => f.privateIpVersion === family)?.privateIpAddress;
  return undefined;
}

/** Representative public destinations used for "Internet" traces (well-known public resolvers). */
export const INTERNET_PROBE: Record<IpFamily, string> = { ipv4: "8.8.8.8", ipv6: "2001:4860:4860::8888" };
