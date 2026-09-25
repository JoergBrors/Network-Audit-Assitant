import { cidrContains, ipFamilyOf, parseCidr, type IpFamily } from "../addressing/ip.js";
import type { EffectiveRoute, RouteSource } from "../models/path.js";
import type { RoutingContext } from "./context.js";

/** IPv4 prefixes with a system route to "None" (Microsoft Learn: virtual-networks-udr-overview, default system routes). */
export const IPV4_NONE_PREFIXES = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "157.59.0.0/16",
  "127.0.0.0/8",
  "104.147.0.0/16",
  "104.146.0.0/17",
];
const RFC_OVERRIDABLE = new Set(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]);

const overlaps = (a: string, b: string) => cidrContains(a, b) || cidrContains(b, a);

/**
 * Configuration-based reconstruction of a subnet's effective routes for one IP family
 * (ARCHITECTURE.md § 12.1). BGP-learned routes are not visible in the configuration; routes derived
 * from local network gateways are therefore marked POSSIBLE.
 */
export function synthesizeRoutes(ctx: RoutingContext, subnetId: string, family: IpFamily): EffectiveRoute[] {
  const subnet = ctx.subnets.get(subnetId);
  if (!subnet) return [];
  const vnet = ctx.vnets.get(subnet.vnetId);
  const routes: EffectiveRoute[] = [];
  const table = subnet.routeTableId ? ctx.routeTables.get(subnet.routeTableId) : undefined;
  const allUdrs = subnet.routeTableId ? (ctx.routesByTable.get(subnet.routeTableId) ?? []) : [];
  const udrs = allUdrs.filter((r) => r.ipVersion === family);
  const tagUdrs = allUdrs.filter((r) => r.ipVersion === "serviceTag");

  // 1. Own address space.
  for (const prefix of vnet?.addressSpace[family] ?? []) {
    routes.push({
      prefix,
      family,
      nextHopType: "VnetLocal",
      nextHopResourceId: vnet?.id,
      source: "system",
      confidence: "CONFIRMED",
    });
  }

  // 2. VNet peerings (non-transitive): remote address space of connected peerings.
  for (const p of ctx.peeringsByVnet.get(subnet.vnetId) ?? []) {
    if (!p.allowVirtualNetworkAccess || (p.peeringState && p.peeringState !== "Connected")) continue;
    let prefixes = p.remoteAddressSpace[family];
    let note: string | undefined;
    if (p.peerCompleteVnets === false && p.remoteSubnetNames?.length && p.remoteVnetId) {
      const remoteSubnets = [...ctx.subnets.values()].filter(
        (s) =>
          s.vnetId === p.remoteVnetId &&
          p.remoteSubnetNames!.some((n) => n.toLowerCase() === s.name.toLowerCase()),
      );
      if (remoteSubnets.length > 0) prefixes = remoteSubnets.flatMap((s) => s.prefixes[family]);
      note = "Subnet-Peering";
    }
    for (const prefix of prefixes) {
      routes.push({
        prefix,
        family,
        nextHopType: "VNetPeering",
        nextHopResourceId: p.remoteVnetId,
        source: "peering",
        originId: p.id,
        confidence: "CONFIRMED",
        note,
      });
    }
  }

  // 3. Gateway routes (local gateway or remote gateway via useRemoteGateways), unless propagation is disabled.
  if (!table?.disableBgpRoutePropagation) {
    for (const gw of gatewaysReachableFrom(ctx, subnet.vnetId)) {
      for (const conn of ctx.connectionsByGateway.get(gw.id) ?? []) {
        const lng = conn.localNetworkGatewayId
          ? ctx.localNetworkGateways.get(conn.localNetworkGatewayId)
          : undefined;
        for (const prefix of lng?.addressPrefixes[family] ?? []) {
          routes.push({
            prefix,
            family,
            nextHopType: "VirtualNetworkGateway",
            nextHopResourceId: gw.id,
            source: "gateway",
            originId: conn.id,
            confidence: "POSSIBLE",
            note: "aus Local Network Gateway abgeleitet; per BGP gelernte Routen sind in der Konfiguration nicht sichtbar",
          });
        }
      }
    }
  }

  // 4. Default system routes. If the subnet can learn routes via BGP, an on-premises default route
  //    (forced tunneling) could override the system default route – not visible in the configuration.
  const hasGatewayDefault = udrs.some((r) => r.defaultRoute && r.nextHopType === "VirtualNetworkGateway");
  const bgpGateways = table?.disableBgpRoutePropagation
    ? []
    : gatewaysReachableFrom(ctx, subnet.vnetId).filter(
        (g) => g.bgpEnabled || g.gatewayType?.toLowerCase() === "expressroute",
      );
  const defaultConfidence = bgpGateways.length > 0 ? "POSSIBLE" : undefined;
  const bgpNote =
    bgpGateways.length > 0
      ? `BGP über ${bgpGateways.map((g) => g.name).join(", ")}: eine per BGP gelernte Default-Route (Forced Tunneling) hätte Vorrang und ist nicht einsehbar`
      : undefined;
  if (family === "ipv4") {
    routes.push({
      prefix: "0.0.0.0/0",
      family,
      nextHopType: "Internet",
      source: "system",
      confidence: defaultConfidence ?? "CONFIRMED",
      note: bgpNote,
    });
    if (!hasGatewayDefault) {
      const own = vnet?.addressSpace.ipv4 ?? [];
      for (const prefix of IPV4_NONE_PREFIXES) {
        // Azure removes the reserved None route when the VNet address space overlaps it.
        if (RFC_OVERRIDABLE.has(prefix) && own.some((o) => overlaps(o, prefix))) continue;
        routes.push({
          prefix,
          family,
          nextHopType: "None",
          source: "system",
          confidence: "LIKELY",
          note: "reservierter Bereich",
        });
      }
    }
  } else {
    routes.push({
      prefix: "::/0",
      family,
      nextHopType: "Internet",
      source: "system",
      confidence: defaultConfidence ?? "LIKELY",
      note: ["IPv6-Default-Systemroute (in der Azure-Doku für IPv6 nicht explizit tabelliert)", bgpNote]
        .filter(Boolean)
        .join("; "),
    });
  }

  // 5. User-defined routes (incl. ECMP next hops).
  for (const r of udrs) {
    routes.push({
      prefix: r.addressPrefix,
      family,
      nextHopType: normalizeNextHop(r.nextHopType),
      nextHopIpAddress: r.nextHopIpAddress,
      ...(r.nextHopIpAddresses && r.nextHopIpAddresses.length > 1
        ? { nextHopIpAddresses: r.nextHopIpAddresses }
        : {}),
      nextHopResourceId: r.nextHopResourceId,
      source: "udr",
      originId: r.id,
      confidence: "CONFIRMED",
    });
  }

  // 6. UDRs with service tags, expanded to the tag's prefixes of this family.
  for (const r of tagUdrs) {
    const prefixes = ctx.serviceTags.get(r.addressPrefix.toLowerCase());
    if (!prefixes) continue; // reported via unresolvedServiceTagRoutes()
    for (const prefix of prefixes) {
      if (ipFamilyOf(prefix.split("/")[0]) !== family) continue;
      routes.push({
        prefix,
        family,
        nextHopType: normalizeNextHop(r.nextHopType),
        nextHopIpAddress: r.nextHopIpAddress,
        nextHopResourceId: r.nextHopResourceId,
        source: "udr",
        originId: r.id,
        serviceTag: r.addressPrefix,
        confidence: "CONFIRMED",
        note: `aus Service Tag ${r.addressPrefix}`,
      });
    }
  }

  // 7. Azure Virtual Network Manager connected groups (mesh / direct connectivity).
  for (const peer of ctx.connectedGroupPeers.get(subnet.vnetId) ?? []) {
    for (const prefix of ctx.vnets.get(peer)?.addressSpace[family] ?? []) {
      routes.push({
        prefix,
        family,
        nextHopType: "ConnectedGroup",
        nextHopResourceId: peer,
        source: "system",
        confidence: "LIKELY",
        note: "AVNM Connected Group (Mesh), keine sichtbare Peering-Ressource",
      });
    }
  }

  // 8. Virtual WAN (hub connection of this VNet).
  routes.push(...virtualWanRoutes(ctx, subnet.vnetId, family));
  return routes;
}

const RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/**
 * Routes a spoke VNet learns from its Virtual WAN hub (Microsoft Learn: virtual hub routing,
 * routing intent). Reconstructed from hub route tables, associations/propagations and routing
 * policies; LIKELY at best, POSSIBLE when hub details could not be read.
 */
function virtualWanRoutes(ctx: RoutingContext, vnetId: string, family: IpFamily): EffectiveRoute[] {
  const link = ctx.hubConnectionByVnet.get(vnetId);
  if (!link) return [];
  const { hub, connection } = link;
  const confidence = hub.detailStatus === "ok" ? "LIKELY" : "POSSIBLE";
  const out: EffectiveRoute[] = [];
  const hubPrefix = family === "ipv4" ? hub.addressPrefix : hub.addressPrefixV6;
  const add = (prefix: string, nextHop: string | undefined, note: string, originId?: string) =>
    out.push({
      prefix,
      family,
      nextHopType: "VirtualHub",
      nextHopResourceId: nextHop ?? hub.id,
      source: "vwan",
      originId: originId ?? connection.id,
      confidence,
      note,
    });
  if (hubPrefix) add(hubPrefix, hub.id, `Hub-Adressraum ${hub.name}`);
  if (family === "ipv6") return out; // Virtual WAN routes IPv4 only (Microsoft Learn: IPv6 hub-spoke limitations)

  const sameWan = [...ctx.virtualHubs.values()].filter((h) => h.virtualWanId === hub.virtualWanId);
  const otherConnections = sameWan
    .flatMap((h) => h.connections.map((c) => ({ hub: h, c })))
    .filter((x) => x.c.id !== connection.id);

  if (hub.routingIntent) {
    const { privateNextHop, internetNextHop } = hub.routingIntent;
    if (privateNextHop) {
      for (const p of RFC1918) add(p, privateNextHop, "Routing Intent: Private Traffic");
      for (const x of otherConnections) {
        for (const p of (x.c.remoteVnetId && ctx.vnets.get(x.c.remoteVnetId)?.addressSpace.ipv4) || []) {
          if (!RFC1918.some((r) => cidrContains(r, p)))
            add(p, privateNextHop, "Routing Intent: Private Traffic");
        }
      }
    } else {
      for (const x of otherConnections)
        for (const p of (x.c.remoteVnetId && ctx.vnets.get(x.c.remoteVnetId)?.addressSpace.ipv4) || [])
          add(p, x.c.remoteVnetId, `über Hub zu ${x.c.name}`);
    }
    if (internetNextHop && connection.enableInternetSecurity)
      add("0.0.0.0/0", internetNextHop, "Routing Intent: Internet Traffic");
    return out;
  }

  // Without routing intent: associated route table + propagations.
  const table =
    hub.routeTables.find((t) => t.id === connection.associatedRouteTableId) ??
    hub.routeTables.find((t) => t.name.toLowerCase() === "defaultroutetable");
  if (!table) {
    if (hub.detailStatus !== "ok")
      out.forEach((r) => (r.note = `${r.note ?? ""}; Hub-Routing-Details nicht verfügbar`));
    return out;
  }
  for (const x of otherConnections) {
    const propagates =
      x.c.propagatedRouteTableIds.includes(table.id) ||
      x.c.propagatedLabels.some((l) => table.labels.includes(l)) ||
      (x.c.propagatedRouteTableIds.length === 0 &&
        x.c.propagatedLabels.length === 0 &&
        table.name.toLowerCase() === "defaultroutetable");
    if (!propagates || !x.c.remoteVnetId) continue;
    for (const p of ctx.vnets.get(x.c.remoteVnetId)?.addressSpace.ipv4 ?? [])
      add(p, x.c.remoteVnetId, `propagiert von ${x.c.name}`);
  }
  for (const route of table.routes) {
    if (route.destinationType.toUpperCase() !== "CIDR") continue;
    for (const d of route.destinations) {
      if (ipFamilyOf(d.split("/")[0]) !== "ipv4") continue;
      if (d === "0.0.0.0/0" && !connection.enableInternetSecurity) continue;
      add(d, route.nextHop, `Hub-Route ${route.name} (${table.name})`, table.id);
    }
  }
  return out;
}

function normalizeNextHop(type: string): EffectiveRoute["nextHopType"] {
  switch (type.toLowerCase()) {
    case "vnetlocal":
      return "VnetLocal";
    case "virtualnetworkgateway":
      return "VirtualNetworkGateway";
    case "internet":
      return "Internet";
    case "virtualappliance":
    case "virtualapplianceecmp":
      return "VirtualAppliance";
    default:
      return "None";
  }
}

/** Gateways usable from a VNet: its own, or the peered hub's gateway when useRemoteGateways is set. */
export function gatewaysReachableFrom(ctx: RoutingContext, vnetId: string) {
  const own = ctx.gatewaysByVnet.get(vnetId) ?? [];
  const remote = (ctx.peeringsByVnet.get(vnetId) ?? [])
    .filter((p) => p.useRemoteGateways && p.remoteVnetId)
    .flatMap((p) => ctx.gatewaysByVnet.get(p.remoteVnetId!) ?? []);
  return [...own, ...remote];
}

const SOURCE_RANK: Record<RouteSource, number> = { udr: 0, gateway: 1, vwan: 1, peering: 2, system: 2 };

/** Service tag precedence for equal prefixes (Microsoft Learn: UDR service tags, exact match). */
function tagRank(r: EffectiveRoute): number {
  if (!r.serviceTag) return 0;
  const t = r.serviceTag.toLowerCase();
  if (t === "azurecloud") return 4;
  if (t.startsWith("azurecloud.")) return 3;
  return t.includes(".") ? 1 : 2;
}

/**
 * Azure route selection: longest prefix match; for equal prefixes UDR > BGP > system.
 * System routes for the VNet and peerings win over (even more specific) gateway/BGP routes.
 */
export function selectRoute(routes: EffectiveRoute[], address: string): EffectiveRoute | undefined {
  const family = ipFamilyOf(address);
  const matching = routes.filter((r) => r.family === family && cidrContains(r.prefix, address));
  if (matching.length === 0) return undefined;
  const vnetSystem = matching.filter(
    (r) =>
      r.nextHopType === "VnetLocal" || r.nextHopType === "VNetPeering" || r.nextHopType === "ConnectedGroup",
  );
  const candidates = vnetSystem.length > 0 ? matching.filter((r) => r.source !== "gateway") : matching;
  return [...candidates].sort((a, b) => {
    const la = parseCidr(a.prefix)?.length ?? 0;
    const lb = parseCidr(b.prefix)?.length ?? 0;
    return lb - la || SOURCE_RANK[a.source] - SOURCE_RANK[b.source] || tagRank(a) - tagRank(b);
  })[0];
}

export function describeRoute(r: EffectiveRoute): string {
  const origin =
    r.source === "udr"
      ? "UDR"
      : r.source === "peering"
        ? "Peering-Route"
        : r.source === "gateway"
          ? "Gateway-Route"
          : r.source === "vwan"
            ? "Virtual-WAN-Route"
            : "Systemroute";
  const ecmp =
    r.nextHopIpAddresses && r.nextHopIpAddresses.length > 1
      ? ` (ECMP: ${r.nextHopIpAddresses.join(", ")})`
      : r.nextHopIpAddress
        ? ` ${r.nextHopIpAddress}`
        : "";
  return `${origin} ${r.prefix}${r.serviceTag ? ` [${r.serviceTag}]` : ""} → ${r.nextHopType}${ecmp}`;
}

/** UDRs with service tags whose prefixes are unknown (no Service Tag Discovery data). */
export function unresolvedServiceTagRoutes(ctx: RoutingContext, subnetId: string): string[] {
  const table = ctx.subnets.get(subnetId)?.routeTableId;
  if (!table) return [];
  return (ctx.routesByTable.get(table) ?? [])
    .filter((r) => r.ipVersion === "serviceTag" && !ctx.serviceTags.has(r.addressPrefix.toLowerCase()))
    .map((r) => r.addressPrefix);
}
