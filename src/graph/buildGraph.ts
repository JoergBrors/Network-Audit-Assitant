import {
  classifyAddressing,
  isDefaultRoutePrefix,
  splitByFamily,
  type FamilySplit,
  type IpFamily,
} from "../addressing/ip.js";
import type { EdgeType, GraphEdge, GraphNode, NetworkGraph, NodeType } from "../models/graph.js";
import type {
  BaseEntity,
  GenericNetworkEntity,
  NatGatewayEntity,
  NormalizedInventory,
} from "../models/network.js";
import { lastSegment } from "../utils/ids.js";

type Props = GraphNode["properties"];
type NodeInput = Omit<GraphNode, "addressing" | "properties" | "lod"> & {
  lod?: GraphNode["lod"] | undefined;
  addressing?: FamilySplit | undefined;
  properties?: Props | undefined;
};

const LOD: Partial<Record<NodeType, GraphNode["lod"]>> = {
  tenant: 1,
  subscription: 1,
  region: 1,
  vnet: 2,
  subnet: 3,
  azureFirewall: 3,
  natGateway: 3,
  vpnGateway: 3,
  expressRouteGateway: 3,
  routeServer: 3,
  virtualHub: 3,
  virtualWan: 3,
  routeTable: 3,
  applicationGateway: 3,
  loadBalancer: 3,
  bastion: 3,
  localNetworkGateway: 3,
  gatewayConnection: 3,
  expressRouteCircuit: 3,
  firewallPolicy: 3,
  nva: 3,
  internet: 2,
  dnsResolver: 3,
  nic: 4,
  vm: 4,
  vmss: 4,
  privateEndpoint: 4,
  nsg: 4,
  publicIp: 4,
  publicIpPrefix: 4,
  privateDnsZone: 4,
  dnsForwardingRuleset: 4,
  privateLinkService: 4,
  paasService: 3,
  wafPolicy: 4,
  ipGroup: 5,
  externalResource: 4,
  route: 5,
  ruleCollectionGroup: 5,
  networkWatcher: 5,
  flowLog: 5,
  other: 4,
  unclassified: 4,
};

const GENERIC_NODE_TYPE: Record<string, NodeType> = {
  bastion: "bastion",
  expressRouteCircuit: "expressRouteCircuit",
  expressRouteGateway: "expressRouteGateway",
  virtualWan: "virtualWan",
  virtualHub: "virtualHub",
  nva: "nva",
  privateLinkService: "privateLinkService",
  wafPolicy: "wafPolicy",
  networkWatcher: "networkWatcher",
  flowLog: "flowLog",
  unclassified: "unclassified",
};

export const EXTERNAL_ROOT_ID = "external";
export const internetNodeId = (family: IpFamily) => `internet:${family}`;

/**
 * Builds the NetworkGraph (NETWORK-GRAPH-MODEL.md) from the normalized inventory.
 * - Hierarchy: tenant → subscription → region → VNet → subnet → attached resources (`parentId`, `contains`).
 * - Relationships: peering, attached, natThrough, route, securedBy, privateEndpoint, gatewayConnection,
 *   dnsLink, backendOf, policyOf, monitoredBy, connectedTo.
 * - Private endpoint NICs are merged into the private endpoint; VM scale set instance NICs into the scale set.
 */
export function buildGraph(inv: NormalizedInventory): NetworkGraph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const subscriptionNames = new Map(inv.subscriptions.map((s) => [s.subscriptionId, s.name]));
  /** Resource IDs that are represented by another node (PE NICs, VMSS instance NICs). */
  const alias = new Map<string, string>();

  const addNode = (n: NodeInput): GraphNode => {
    const addressing = n.addressing ?? { ipv4: [], ipv6: [] };
    const { lod, parentId, ...rest } = n;
    const node: GraphNode = {
      ...rest,
      ...(parentId ? { parentId } : {}),
      lod: lod ?? LOD[n.type] ?? 4,
      addressing: { ...addressing, classification: classifyAddressing(addressing) },
      properties: n.properties ?? {},
    };
    if (node.subscriptionId && !node.subscriptionName) {
      const name = subscriptionNames.get(node.subscriptionId);
      if (name) node.subscriptionName = name;
    }
    nodes.set(node.id, node);
    return node;
  };
  const resolve = (id: string | undefined): string | undefined => (id ? (alias.get(id) ?? id) : undefined);
  const addEdge = (
    type: EdgeType,
    source: string | undefined,
    target: string | undefined,
    extra: { family?: GraphEdge["family"]; label?: string; properties?: Props; qualifier?: string } = {},
  ): void => {
    const s = resolve(source);
    const t = resolve(target);
    if (!s || !t || s === t) return;
    const id = `${type}:${s}->${t}${extra.qualifier ? `#${extra.qualifier}` : ""}`;
    if (edges.has(id)) return;
    edges.set(id, {
      id,
      source: s,
      target: t,
      type,
      ...(extra.family ? { family: extra.family } : {}),
      ...(extra.label ? { label: extra.label } : {}),
      properties: extra.properties ?? {},
    });
  };
  const common = (e: BaseEntity) => ({
    ...(e.tenantId ? { tenantId: e.tenantId } : {}),
    ...(e.subscriptionId ? { subscriptionId: e.subscriptionId } : {}),
    ...(e.resourceGroup ? { resourceGroup: e.resourceGroup } : {}),
    ...(e.location ? { region: e.location } : {}),
  });

  // --- Organisation ---------------------------------------------------------------------------
  const tenantName = new Map(inv.tenants.map((t) => [t.tenantId, t.displayName ?? t.tenantId]));
  for (const s of inv.subscriptions) {
    const tenantNode = `tenant:${s.tenantId}`;
    if (!nodes.has(tenantNode)) {
      addNode({
        id: tenantNode,
        type: "tenant",
        name: tenantName.get(s.tenantId) ?? s.tenantId,
        tenantId: s.tenantId,
      });
    }
    addNode({
      id: s.id,
      type: "subscription",
      name: s.name,
      tenantId: s.tenantId,
      subscriptionId: s.subscriptionId,
      subscriptionName: s.name,
      parentId: tenantNode,
      properties: {
        subscriptionId: s.subscriptionId,
        state: s.state,
        ...(s.managementGroupPath.length ? { managementGroups: s.managementGroupPath } : {}),
        ...(s.accessTenantId !== s.tenantId ? { lighthouseAccessTenant: s.accessTenantId } : {}),
      },
    });
  }
  const regionOf = (e: {
    subscriptionId?: string | undefined;
    location?: string | undefined;
  }): string | undefined => {
    if (!e.subscriptionId) return undefined;
    const sub = `/subscriptions/${e.subscriptionId}`;
    if (!nodes.has(sub)) return undefined;
    const location = e.location ?? "global";
    const id = `${sub}/locations/${location}`;
    if (!nodes.has(id)) {
      addNode({
        id,
        type: "region",
        name: location,
        subscriptionId: e.subscriptionId,
        region: location,
        parentId: sub,
      });
    }
    return id;
  };
  const containerOf = (e: BaseEntity): string | undefined =>
    regionOf(e) ?? (e.subscriptionId ? `/subscriptions/${e.subscriptionId}` : undefined);

  // --- Subnet placement of attached resources -------------------------------------------------
  const subnetOfResource = new Map<string, string>();
  for (const s of inv.subnets)
    for (const r of s.connectedResourceIds) if (!subnetOfResource.has(r)) subnetOfResource.set(r, s.id);

  for (const pe of inv.privateEndpoints) for (const nic of pe.nicIds) alias.set(nic, pe.id);
  for (const nic of inv.networkInterfaces) if (nic.scaleSetId) alias.set(nic.id, nic.scaleSetId);

  // --- Networks -------------------------------------------------------------------------------
  for (const v of inv.vnets) {
    const hubOrSpoke = v.topology?.classification === "hub" || v.topology?.classification === "spoke";
    addNode({
      id: v.id,
      type: "vnet",
      name: v.name,
      ...common(v),
      parentId: containerOf(v),
      lod: hubOrSpoke ? 1 : 2,
      addressing: v.addressSpace,
      properties: {
        subnets: v.subnetIds.length,
        peerings: v.peeringIds.length,
        ...(v.dnsServers.length ? { dnsServers: v.dnsServers } : { dnsServers: "Azure-provided" }),
        ddosProtection: v.ddosProtectionEnabled,
      },
      ...(v.topology ? { topology: v.topology } : {}),
    });
    if (v.ddosProtectionPlanId) addEdge("attached", v.id, v.ddosProtectionPlanId);
  }
  // Internet endpoints for every IP family in use (targets of routes and path traces).
  if (inv.vnets.some((v) => v.addressSpace.ipv4.length > 0)) ensureInternet("ipv4");
  if (inv.vnets.some((v) => v.addressSpace.ipv6.length > 0)) ensureInternet("ipv6");

  for (const s of inv.subnets) {
    addNode({
      id: s.id,
      type: "subnet",
      name: s.name,
      ...(s.subscriptionId ? { subscriptionId: s.subscriptionId } : {}),
      ...(s.resourceGroup ? { resourceGroup: s.resourceGroup } : {}),
      ...(s.location ? { region: s.location } : {}),
      parentId: s.vnetId,
      addressing: s.prefixes,
      properties: {
        connectedResources: s.connectedResourceIds.length,
        ipConfigurations: s.ipConfigurationCount,
        ...(s.delegations.length ? { delegations: s.delegations } : {}),
        ...(s.serviceEndpoints.length ? { serviceEndpoints: s.serviceEndpoints } : {}),
        ...(s.defaultOutboundAccess !== undefined ? { defaultOutboundAccess: s.defaultOutboundAccess } : {}),
      },
    });
  }

  // --- Routing & security resources -----------------------------------------------------------
  for (const rt of inv.routeTables) {
    addNode({
      id: rt.id,
      type: "routeTable",
      name: rt.name,
      ...common(rt),
      parentId: containerOf(rt),
      // Families the table routes (IP mode filter); service tag routes carry no family.
      addressing: splitByFamily(
        inv.routes
          .filter((r) => r.routeTableId === rt.id && r.ipVersion !== "serviceTag")
          .map((r) => r.addressPrefix),
      ),
      properties: {
        routes: rt.routeIds.length,
        subnets: rt.subnetIds.length,
        bgpPropagationDisabled: rt.disableBgpRoutePropagation,
      },
    });
  }
  for (const r of inv.routes) {
    const family = r.ipVersion === "serviceTag" ? undefined : r.ipVersion;
    addNode({
      id: r.id,
      type: "route",
      name: `${r.name} (${r.addressPrefix})`,
      ...common(
        inv.routeTables.find((t) => t.id === r.routeTableId) ?? {
          id: r.routeTableId,
          name: "",
          azureType: "",
        },
      ),
      parentId: r.routeTableId,
      addressing: family
        ? {
            ipv4: family === "ipv4" ? [r.addressPrefix] : [],
            ipv6: family === "ipv6" ? [r.addressPrefix] : [],
          }
        : undefined,
      properties: {
        addressPrefix: r.addressPrefix,
        nextHopType: r.nextHopType,
        ...(r.nextHopIpAddress ? { nextHopIpAddress: r.nextHopIpAddress } : {}),
        defaultRoute: r.defaultRoute,
      },
    });
  }
  for (const nsg of inv.nsgs) {
    addNode({
      id: nsg.id,
      type: "nsg",
      name: nsg.name,
      ...common(nsg),
      parentId: containerOf(nsg),
      properties: {
        rules: nsg.rules.length,
        inboundAllowRules: nsg.rules.filter((r) => r.direction === "Inbound" && r.access === "Allow").length,
        subnets: nsg.subnetIds.length,
        nics: nsg.nicIds.length,
      },
    });
  }

  // --- Public IPs & NAT (before attachments so edges resolve) --------------------------------------
  for (const pip of inv.publicIps) {
    addNode({
      id: pip.id,
      type: "publicIp",
      name: pip.name,
      ...common(pip),
      parentId: containerOf(pip),
      addressing: pip.ipAddress ? splitByFamily([pip.ipAddress]) : undefined,
      properties: {
        ipVersion: pip.ipVersion,
        ...(pip.ipAddress ? { ipAddress: pip.ipAddress } : {}),
        ...(pip.sku ? { sku: pip.sku } : {}),
        ...(pip.allocationMethod ? { allocation: pip.allocationMethod } : {}),
        attached: pip.attachedToId !== undefined,
      },
    });
  }
  for (const p of inv.publicIpPrefixes) {
    addNode({
      id: p.id,
      type: "publicIpPrefix",
      name: p.name,
      ...common(p),
      parentId: containerOf(p),
      addressing: p.prefix ? splitByFamily([p.prefix]) : undefined,
      properties: { ipVersion: p.ipVersion, ...(p.prefix ? { prefix: p.prefix } : {}) },
    });
  }
  for (const nat of inv.natGateways) {
    addNode({
      id: nat.id,
      type: "natGateway",
      name: nat.name,
      ...common(nat),
      parentId: containerOf(nat),
      // Egress addresses (public IPs / prefixes) – decides IPv4/IPv6/dual stack in the IP mode filter.
      addressing: natEgressAddressing(inv, nat),
      properties: {
        sku: nat.sku,
        subnets: nat.subnetIds.length,
        ipv4Egress: nat.ipv4EgressConfigured,
        ipv6Egress: nat.ipv6EgressConfigured,
        dualStackEgress: nat.dualStackEgressConfigured,
      },
    });
    for (const s of nat.subnetIds) addEdge("natThrough", s, nat.id);
    for (const pip of nat.publicIpIds) addEdge("natThrough", nat.id, pip);
    for (const pfx of nat.publicIpPrefixIds) addEdge("natThrough", nat.id, pfx);
  }

  // --- Firewalls ---------------------------------------------------------------------------------
  for (const fw of inv.firewalls) {
    addNode({
      id: fw.id,
      type: "azureFirewall",
      name: fw.name,
      ...common(fw),
      parentId: subnetOfResource.get(fw.id) ?? containerOf(fw),
      addressing: fw.privateIps,
      properties: {
        ...(fw.skuName ? { sku: fw.skuName } : {}),
        ...(fw.skuTier ? { tier: fw.skuTier } : {}),
        ...(fw.threatIntelMode ? { threatIntel: fw.threatIntelMode } : {}),
        zones: fw.zones,
        forcedTunneling: fw.managementIpConfiguration !== undefined,
      },
    });
    for (const pip of fw.publicIpIds) addEdge("attached", fw.id, pip);
  }
  for (const pol of inv.firewallPolicies) {
    addNode({
      id: pol.id,
      type: "firewallPolicy",
      name: pol.name,
      ...common(pol),
      parentId: containerOf(pol),
      properties: {
        ...(pol.skuTier ? { tier: pol.skuTier } : {}),
        ruleCollectionGroups: pol.ruleCollectionGroupIds.length,
        ...(pol.threatIntelMode ? { threatIntel: pol.threatIntelMode } : {}),
        ...(pol.dnsProxyEnabled !== undefined ? { dnsProxy: pol.dnsProxyEnabled } : {}),
        ...(pol.intrusionDetectionMode ? { idps: pol.intrusionDetectionMode } : {}),
      },
    });
    for (const fw of pol.firewallIds) addEdge("policyOf", pol.id, fw);
    if (pol.basePolicyId) addEdge("policyOf", pol.basePolicyId, pol.id, { label: "Parent Policy" });
  }
  for (const fw of inv.firewalls) if (fw.firewallPolicyId) addEdge("policyOf", fw.firewallPolicyId, fw.id);
  for (const rcg of inv.ruleCollectionGroups) {
    const policy = inv.firewallPolicies.find((p) => p.id === rcg.firewallPolicyId);
    addNode({
      id: rcg.id,
      type: "ruleCollectionGroup",
      name: rcg.name,
      ...(policy ? common(policy) : {}),
      parentId: rcg.firewallPolicyId,
      properties: {
        ...(rcg.priority !== undefined ? { priority: rcg.priority } : {}),
        ruleCollections: rcg.ruleCollections.length,
        rules: rcg.ruleCollections.reduce((n, c) => n + c.rules.length, 0),
      },
    });
  }
  for (const g of inv.ipGroups) {
    addNode({
      id: g.id,
      type: "ipGroup",
      name: g.name,
      ...common(g),
      parentId: containerOf(g),
      properties: { entries: g.ipAddresses.length },
    });
  }

  // --- Compute ------------------------------------------------------------------------------------
  const nicsByVm = new Map<string, typeof inv.networkInterfaces>();
  for (const nic of inv.networkInterfaces)
    if (nic.vmId) nicsByVm.set(nic.vmId, [...(nicsByVm.get(nic.vmId) ?? []), nic]);
  for (const vm of inv.virtualMachines) {
    const nics = nicsByVm.get(vm.id) ?? [];
    const primary = nics.find((n) => n.ipConfigurations.some((c) => c.primary)) ?? nics[0];
    const addressing = splitByFamily(nics.flatMap((n) => [...n.addressing.ipv4, ...n.addressing.ipv6]));
    addNode({
      id: vm.id,
      type: "vm",
      name: vm.name,
      ...common(vm),
      parentId: primary?.subnetIds[0] ?? containerOf(vm),
      addressing,
      properties: {
        ...(vm.vmSize ? { size: vm.vmSize } : {}),
        ...(vm.powerState ? { powerState: vm.powerState } : {}),
        ...(vm.image ? { image: vm.image } : {}),
        nics: nics.length,
      },
      ...(vm.nva ? { nva: vm.nva } : {}),
    });
  }
  for (const ss of inv.scaleSets) {
    const nics = inv.networkInterfaces.filter((n) => n.scaleSetId === ss.id);
    addNode({
      id: ss.id,
      type: "vmss",
      name: ss.name,
      ...common(ss),
      parentId: ss.subnetIds[0] ?? containerOf(ss),
      addressing: {
        ipv4: nics.some((n) => n.addressing.ipv4.length)
          ? [`${nics.reduce((a, n) => a + n.addressing.ipv4.length, 0)} IPv4-Adressen`]
          : [],
        ipv6: nics.some((n) => n.addressing.ipv6.length)
          ? [`${nics.reduce((a, n) => a + n.addressing.ipv6.length, 0)} IPv6-Adressen`]
          : [],
      },
      properties: {
        instances: nics.length,
        ...(ss.orchestrationMode ? { orchestrationMode: ss.orchestrationMode } : {}),
        ipForwarding: ss.ipForwarding,
      },
    });
    for (const s of ss.subnetIds.slice(1)) addEdge("attached", s, ss.id, { label: "weiteres Subnet" });
  }
  for (const nic of inv.networkInterfaces) {
    if (alias.has(nic.id)) continue;
    addNode({
      id: nic.id,
      type: "nic",
      name: nic.name,
      ...common(nic),
      parentId: nic.vmId && nodes.has(nic.vmId) ? nic.vmId : (nic.subnetIds[0] ?? containerOf(nic)),
      addressing: nic.addressing,
      properties: {
        ipForwarding: nic.ipForwarding,
        acceleratedNetworking: nic.acceleratedNetworking,
        ...(nic.defaultOutboundConnectivityEnabled !== undefined
          ? { defaultOutboundConnectivity: nic.defaultOutboundConnectivityEnabled }
          : {}),
        ipConfigurations: nic.ipConfigurations.length,
      },
    });
    if (nic.vmId && !nodes.has(nic.vmId)) addEdge("attached", nic.id, nic.vmId);
    for (const s of nic.subnetIds.slice(nic.vmId && nodes.has(nic.vmId) ? 0 : 1))
      addEdge("attached", nic.id, s, { label: "Subnet" });
  }
  for (const nic of inv.networkInterfaces) {
    if (nic.nsgId) addEdge("attached", nic.id, nic.nsgId, { label: "NSG" });
    for (const c of nic.ipConfigurations)
      for (const pool of c.loadBalancerBackendPoolIds) {
        addEdge("backendOf", nic.id, pool.split("/backendaddresspools/")[0], { label: lastSegment(pool) });
      }
  }

  // --- Load balancing ------------------------------------------------------------------------------
  for (const lb of inv.loadBalancers) {
    const subnet = lb.frontends.find((f) => f.subnetId)?.subnetId;
    addNode({
      id: lb.id,
      type: "loadBalancer",
      name: lb.name,
      ...common(lb),
      parentId: subnet ?? containerOf(lb),
      addressing: splitByFamily(lb.frontends.map((f) => f.privateIpAddress)),
      properties: {
        ...(lb.sku ? { sku: lb.sku } : {}),
        public: lb.isPublic,
        frontends: lb.frontends.length,
        rules: lb.loadBalancingRules,
        outboundRules: lb.outboundRules.length,
      },
    });
    for (const f of lb.frontends) {
      if (f.publicIpId) addEdge("attached", lb.id, f.publicIpId, { label: f.name });
      if (f.publicIpPrefixId) addEdge("attached", lb.id, f.publicIpPrefixId, { label: f.name });
    }
  }
  for (const agw of inv.applicationGateways) {
    addNode({
      id: agw.id,
      type: "applicationGateway",
      name: agw.name,
      ...common(agw),
      parentId: agw.gatewaySubnetIds[0] ?? subnetOfResource.get(agw.id) ?? containerOf(agw),
      addressing: splitByFamily(agw.frontends.map((f) => f.privateIpAddress)),
      properties: {
        ...(agw.sku ? { sku: agw.sku } : {}),
        ...(agw.tier ? { tier: agw.tier } : {}),
        listeners: agw.listeners.length,
        backendPools: agw.backendPools.length,
        ...(agw.wafEnabled !== undefined ? { wafEnabled: agw.wafEnabled } : {}),
      },
    });
    for (const f of agw.frontends)
      if (f.publicIpId) addEdge("attached", agw.id, f.publicIpId, { label: f.name });
    if (agw.wafPolicyId) addEdge("attached", agw.id, agw.wafPolicyId, { label: "WAF Policy" });
    for (const pool of agw.backendPools)
      for (const m of pool.memberIds) addEdge("backendOf", m, agw.id, { label: pool.name });
  }

  // --- Hybrid ----------------------------------------------------------------------------------------
  for (const g of inv.vpnGateways) {
    const isEr = g.gatewayType?.toLowerCase() === "expressroute";
    addNode({
      id: g.id,
      type: isEr ? "expressRouteGateway" : "vpnGateway",
      name: g.name,
      ...common(g),
      parentId: g.ipConfigurations.find((c) => c.subnetId)?.subnetId ?? containerOf(g),
      addressing: splitByFamily(g.ipConfigurations.map((c) => c.privateIpAddress)),
      properties: {
        ...(g.gatewayType ? { gatewayType: g.gatewayType } : {}),
        ...(g.vpnType ? { vpnType: g.vpnType } : {}),
        ...(g.sku ? { sku: g.sku } : {}),
        activeActive: g.activeActive,
        bgp: g.bgpEnabled,
        ...(g.bgpAsn !== undefined ? { asn: g.bgpAsn } : {}),
      },
    });
    for (const pip of g.publicIpIds) addEdge("attached", g.id, pip);
  }
  for (const l of inv.localNetworkGateways) {
    addNode({
      id: l.id,
      type: "localNetworkGateway",
      name: l.name,
      ...common(l),
      parentId: containerOf(l),
      addressing: l.addressPrefixes,
      properties: {
        ...(l.gatewayIpAddress ? { gatewayIp: l.gatewayIpAddress } : {}),
        ...(l.fqdn ? { fqdn: l.fqdn } : {}),
        ...(l.bgpAsn !== undefined ? { asn: l.bgpAsn } : {}),
      },
    });
  }
  for (const c of inv.connections) {
    addNode({
      id: c.id,
      type: "gatewayConnection",
      name: c.name,
      ...common(c),
      parentId: containerOf(c),
      properties: {
        ...(c.connectionType ? { connectionType: c.connectionType } : {}),
        ...(c.connectionStatus ? { status: c.connectionStatus } : {}),
        bgp: c.bgpEnabled,
      },
    });
    addEdge("gatewayConnection", c.virtualNetworkGatewayId, c.id);
    addEdge("gatewayConnection", c.id, c.localNetworkGatewayId);
    addEdge("gatewayConnection", c.id, c.remoteVirtualNetworkGatewayId);
    addEdge("gatewayConnection", c.id, c.expressRouteCircuitId);
  }

  // --- Private endpoints & DNS ----------------------------------------------------------------------
  for (const pe of inv.privateEndpoints) {
    addNode({
      id: pe.id,
      type: "privateEndpoint",
      name: pe.name,
      ...common(pe),
      parentId: pe.subnetId ?? containerOf(pe),
      addressing: pe.addressing,
      properties: {
        targets: pe.targets.map((t) => `${lastSegment(t.resourceId)} (${t.groupIds.join(",")})`),
        status: pe.targets.map((t) => t.status ?? "?"),
      },
    });
  }
  for (const z of inv.privateDnsZones) {
    addNode({
      id: z.id,
      type: "privateDnsZone",
      name: z.name,
      ...common(z),
      parentId: containerOf(z),
      properties: {
        vnetLinks: z.vnetLinks.length,
        aRecords: z.aRecordCount,
        aaaaRecords: z.aaaaRecordCount,
        records: z.records.length,
      },
    });
    for (const link of z.vnetLinks) {
      addEdge("dnsLink", z.id, link.vnetId, {
        label: link.registrationEnabled ? "Auto-Registrierung" : "Link",
      });
    }
  }
  for (const d of inv.dnsResolvers) {
    const type: NodeType = d.kind === "forwardingRuleset" ? "dnsForwardingRuleset" : "dnsResolver";
    const parent =
      d.kind === "resolver"
        ? d.vnetId
        : d.kind === "forwardingRuleset"
          ? undefined
          : (d.subnetIds[0] ?? d.resolverId);
    addNode({
      id: d.id,
      type,
      name: d.kind === "resolver" ? d.name : `${d.name} (${d.kind})`,
      ...common(d),
      parentId: parent ?? containerOf(d),
      addressing: splitByFamily(d.privateIps),
      properties: {
        kind: d.kind,
        ...(d.forwardingRules.length
          ? {
              forwardingRules: d.forwardingRules.map(
                (r) => `${r.domainName ?? r.name} → ${r.targets.join(", ")}`,
              ),
            }
          : {}),
      },
    });
    if (d.resolverId) addEdge("connectedTo", d.id, d.resolverId, { label: "Endpoint von" });
    for (const v of d.linkedVnetIds) addEdge("dnsLink", d.id, v, { label: "Ruleset-Link" });
    for (const o of d.outboundEndpointIds) addEdge("connectedTo", d.id, o, { label: "Outbound Endpoint" });
  }

  // --- PaaS services ---------------------------------------------------------------------------------
  for (const p of inv.paasServices) {
    addNode({
      id: p.id,
      type: "paasService",
      name: p.name,
      ...common(p),
      parentId: containerOf(p),
      properties: {
        service: p.service,
        exposure: p.exposure,
        publicNetworkAccess: p.publicNetworkAccess,
        ...(p.firewall.defaultAction ? { firewallDefaultAction: p.firewall.defaultAction } : {}),
        ...(p.firewall.ipRules.length ? { ipRules: p.firewall.ipRules } : {}),
        privateEndpoints: p.privateEndpointIds.length,
        ...(p.endpoints.length ? { endpoints: p.endpoints } : {}),
      },
    });
    const label = p.vnetIntegration.mode === "injection" ? "VNet-Injection" : "VNet-Integration";
    // Only subnets in the discovered inventory (rules may name subnets of other tenants).
    for (const s of p.vnetIntegration.subnetIds) if (nodes.has(s)) addEdge("attached", p.id, s, { label });
    for (const s of p.firewall.subnetIds)
      if (nodes.has(s)) addEdge("connectedTo", s, p.id, { label: "erlaubtes Subnet" });
  }

  // --- Generic network resources --------------------------------------------------------------------
  const addGeneric = (g: GenericNetworkEntity) => {
    const routeServer = g.kind === "virtualHub" && !g.properties["virtualWan"];
    const type: NodeType = routeServer
      ? "routeServer"
      : (GENERIC_NODE_TYPE[g.kind] ?? (g.kind === "unclassified" ? "unclassified" : "other"));
    addNode({
      id: g.id,
      type,
      name: g.name,
      ...common(g),
      parentId: g.subnetIds[0] ?? subnetOfResource.get(g.id) ?? containerOf(g),
      properties: { kind: g.kind, azureType: g.azureType, ...pickScalar(g.properties) },
    });
  };
  for (const g of inv.otherNetworkResources) addGeneric(g);
  for (const g of inv.unclassifiedNetworkResources) addGeneric(g);

  // --- Relationships ----------------------------------------------------------------------------------
  for (const s of inv.subnets) {
    if (s.nsgId) addEdge("attached", s.id, s.nsgId, { label: "NSG" });
    if (s.routeTableId) addEdge("attached", s.id, s.routeTableId, { label: "Route Table" });
  }
  for (const p of inv.peerings) {
    if (!p.remoteVnetId) continue;
    ensureExternal(p.remoteVnetId, "vnet");
    addEdge("peering", p.vnetId, p.remoteVnetId, {
      label: p.peeringState ?? "Peering",
      properties: {
        state: p.peeringState ?? "Unknown",
        ...(p.peeringSyncLevel ? { syncLevel: p.peeringSyncLevel } : {}),
        allowVirtualNetworkAccess: p.allowVirtualNetworkAccess,
        allowForwardedTraffic: p.allowForwardedTraffic,
        allowGatewayTransit: p.allowGatewayTransit,
        useRemoteGateways: p.useRemoteGateways,
        remoteIpv4: p.remoteAddressSpace.ipv4,
        remoteIpv6: p.remoteAddressSpace.ipv6,
      },
    });
  }
  for (const pip of inv.publicIps)
    if (pip.attachedToId && !pip.natGatewayId)
      addEdge("attached", pip.attachedToId, pip.id, { label: "Public IP" });
  for (const pe of inv.privateEndpoints) {
    for (const t of pe.targets) {
      ensureExternal(t.resourceId, "externalResource");
      addEdge("privateEndpoint", pe.id, t.resourceId, {
        label: t.groupIds.join(", "),
        properties: { groupIds: t.groupIds, status: t.status ?? "Unknown", manual: t.manual },
      });
    }
  }

  // Routes → next hop, and securedBy for default routes via a firewall/NVA.
  const routeTableOfSubnet = new Map(
    inv.subnets.flatMap((s) => (s.routeTableId ? [[s.id, s.routeTableId] as const] : [])),
  );
  const routesByTable = new Map<string, typeof inv.routes>();
  for (const r of inv.routes)
    routesByTable.set(r.routeTableId, [...(routesByTable.get(r.routeTableId) ?? []), r]);
  for (const r of inv.routes) {
    const family = r.ipVersion === "serviceTag" ? undefined : r.ipVersion;
    let target = r.nextHopResourceId;
    if (!target && r.nextHopType === "Internet" && family) target = ensureInternet(family);
    if (!target) continue;
    addEdge("route", r.id, target, {
      ...(family ? { family } : {}),
      label: `${r.addressPrefix} → ${r.nextHopType}`,
      properties: {
        addressPrefix: r.addressPrefix,
        nextHopType: r.nextHopType,
        ...(r.nextHopIpAddress ? { nextHopIpAddress: r.nextHopIpAddress } : {}),
      },
    });
  }
  for (const [subnet, table] of routeTableOfSubnet) {
    for (const r of routesByTable.get(table) ?? []) {
      const family = isDefaultRoutePrefix(r.addressPrefix);
      if (!family || !r.nextHopResourceId) continue;
      const target = resolve(r.nextHopResourceId);
      const t = target ? nodes.get(target) : undefined;
      if (
        t &&
        (t.type === "azureFirewall" || t.type === "nva" || t.nva?.potentialNva || t.type === "loadBalancer")
      ) {
        addEdge("securedBy", subnet, t.id, {
          family,
          qualifier: family,
          label: `${r.addressPrefix} via ${t.name}`,
        });
      }
    }
  }

  // Generic references (flow logs, bastion, vWAN, …) → typed where known.
  for (const g of [...inv.otherNetworkResources, ...inv.unclassifiedNetworkResources]) {
    for (const ref of g.referencedIds) {
      if (!nodes.has(resolve(ref) ?? "") || nodes.get(g.id)?.parentId === ref) continue;
      if (g.kind === "flowLog") addEdge("monitoredBy", ref, g.id);
      else if (/\/publicipaddresses\//.test(ref)) addEdge("attached", g.id, ref);
      else if (!/\/subnets\//.test(ref)) addEdge("connectedTo", g.id, ref);
    }
  }

  // Targets outside the readable scope (other tenants, missing permissions) stay visible as external nodes.
  for (const e of [...edges.values()]) {
    for (const end of [e.source, e.target]) {
      if (!nodes.has(end))
        ensureExternal(end, /\/virtualnetworks\/[^/]+$/.test(end) ? "vnet" : "externalResource");
    }
  }

  // --- Hierarchy edges ---------------------------------------------------------------------------------
  for (const n of nodes.values()) {
    if (n.parentId && !nodes.has(n.parentId)) delete n.parentId;
    if (n.parentId) addEdge("contains", n.parentId, n.id);
  }

  return {
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)),
  };

  function ensureExternal(id: string, type: NodeType): void {
    if (nodes.has(resolve(id) ?? id)) return;
    if (!nodes.has(EXTERNAL_ROOT_ID)) {
      addNode({
        id: EXTERNAL_ROOT_ID,
        type: "externalResource",
        name: "Externe / nicht lesbare Ressourcen",
        lod: 2,
      });
    }
    addNode({
      id,
      type: type === "vnet" ? "externalResource" : type,
      name: lastSegment(id),
      parentId: EXTERNAL_ROOT_ID,
      lod: type === "vnet" ? 2 : 4,
      properties: { azureType: azureTypeOf(id), inventory: "nicht im Scope oder nicht lesbar" },
    });
  }

  function ensureInternet(family: IpFamily): string {
    const id = internetNodeId(family);
    if (!nodes.has(id))
      addNode({
        id,
        type: "internet",
        name: family === "ipv4" ? "Internet (IPv4)" : "Internet (IPv6)",
        lod: 2,
      });
    return id;
  }
}

function azureTypeOf(id: string): string {
  const m = /\/providers\/([^/]+\/[^/]+)/.exec(id);
  return m?.[1] ?? "unknown";
}

function pickScalar(p: GenericNetworkEntity["properties"]): Props {
  const out: Props = {};
  for (const [k, v] of Object.entries(p).slice(0, 12)) {
    if (typeof v === "string" && /^\/subscriptions\//.test(v)) continue;
    out[k] = v;
  }
  return out;
}

function natEgressAddressing(inv: NormalizedInventory, nat: NatGatewayEntity): FamilySplit {
  const out: FamilySplit = { ipv4: [], ipv6: [] };
  for (const pip of inv.publicIps.filter((p) => nat.publicIpIds.includes(p.id)))
    out[pip.ipVersion].push(pip.ipAddress ?? `${pip.name} (nicht zugewiesen)`);
  for (const pfx of inv.publicIpPrefixes.filter((p) => nat.publicIpPrefixIds.includes(p.id)))
    out[pfx.ipVersion].push(pfx.prefix ?? pfx.name);
  return out;
}
