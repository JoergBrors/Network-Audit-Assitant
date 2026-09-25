import { cidrContains } from "../addressing/ip.js";
import type {
  NormalizedInventory,
  NvaClassification,
  TopologyClassification,
  VNetEntity,
} from "../models/network.js";
import { rollUpScaleSet } from "../utils/ids.js";

/** Marketplace publishers of common firewall / routing appliances (NVA heuristic). */
const NVA_PUBLISHERS =
  /paloaltonetworks|fortinet|checkpoint|cisco|barracuda|sophos|juniper|f5-networks|citrix|versa-networks|aviatrix|vmware-inc|netgate|forcepoint|arista|zscaler|opnsense|pfsense|vyos/i;

const round = (n: number) => Math.round(Math.min(1, n) * 100) / 100;

/**
 * Explainable heuristics (ARCHITECTURE.md § 11). Mutates `inv`: sets `vnet.topology` and `vm.nva`.
 * Every contributing signal is recorded as a human-readable reason.
 */
export function classifyTopology(inv: NormalizedInventory): void {
  const subnetVnet = new Map(inv.subnets.map((s) => [s.id, s.vnetId]));
  const resourceVnet = new Map<string, string>();
  for (const s of inv.subnets) for (const r of s.connectedResourceIds) resourceVnet.set(r, s.vnetId);
  for (const nic of inv.networkInterfaces) {
    const vnet = nic.subnetIds.map((id) => subnetVnet.get(id)).find(Boolean);
    if (vnet && nic.vmId) resourceVnet.set(nic.vmId, vnet);
  }
  const vnetById = new Map(inv.vnets.map((v) => [v.id, v]));
  const peeringsByVnet = new Map<string, typeof inv.peerings>();
  for (const p of inv.peerings) peeringsByVnet.set(p.vnetId, [...(peeringsByVnet.get(p.vnetId) ?? []), p]);

  // --- NVA heuristic for VMs -----------------------------------------------------------------
  const udrTargets = new Map<string, number>();
  for (const r of inv.routes) {
    if (r.nextHopResourceId)
      udrTargets.set(r.nextHopResourceId, (udrTargets.get(r.nextHopResourceId) ?? 0) + 1);
  }
  const nicsByVm = new Map<string, typeof inv.networkInterfaces>();
  for (const nic of inv.networkInterfaces) {
    if (nic.vmId) nicsByVm.set(nic.vmId, [...(nicsByVm.get(nic.vmId) ?? []), nic]);
  }
  for (const vm of inv.virtualMachines) {
    const nics = nicsByVm.get(vm.id) ?? [];
    const nva: NvaClassification = { potentialNva: false, confidence: 0, reasons: [] };
    let score = 0;
    if (nics.some((n) => n.ipForwarding)) {
      score += 0.35;
      nva.reasons.push("IP forwarding enabled");
    }
    const udr = udrTargets.get(vm.id);
    if (udr) {
      score += 0.4;
      nva.reasons.push(`Referenced as UDR next hop (${udr} route${udr > 1 ? "s" : ""})`);
    }
    const subnets = new Set(nics.flatMap((n) => n.subnetIds));
    if (nics.length > 1 && subnets.size > 1) {
      score += 0.15;
      nva.reasons.push(`Multiple network interfaces in ${subnets.size} subnets`);
    }
    if (vm.image && NVA_PUBLISHERS.test(vm.image)) {
      score += 0.2;
      nva.reasons.push(`Network appliance image (${vm.image.split(":")[0]})`);
    }
    nva.confidence = round(score);
    nva.potentialNva = score >= 0.5;
    if (nva.reasons.length > 0) vm.nva = nva;
  }
  const nvaVms = new Set(inv.virtualMachines.filter((v) => v.nva?.potentialNva).map((v) => v.id));

  // --- Default routes pointing into other VNets ------------------------------------------------
  const routesByTable = new Map<string, typeof inv.routes>();
  for (const r of inv.routes)
    routesByTable.set(r.routeTableId, [...(routesByTable.get(r.routeTableId) ?? []), r]);
  const vnetOfIp = (ip: string): string | undefined =>
    inv.vnets.find((v) => [...v.addressSpace.ipv4, ...v.addressSpace.ipv6].some((c) => cidrContains(c, ip)))
      ?.id;
  /** subnet vnet → target vnet → number of subnets whose default route points there */
  const defaultRouteTargets = new Map<string, Map<string, number>>();
  for (const s of inv.subnets) {
    if (!s.routeTableId) continue;
    for (const r of routesByTable.get(s.routeTableId) ?? []) {
      if (!r.defaultRoute || !r.nextHopType.startsWith("VirtualAppliance") || !r.nextHopIpAddress) continue;
      const owner = r.nextHopResourceId ? rollUpScaleSet(r.nextHopResourceId) : undefined;
      const target = (owner && resourceVnet.get(owner)) ?? vnetOfIp(r.nextHopIpAddress);
      if (!target || target === s.vnetId) continue;
      const m = defaultRouteTargets.get(s.vnetId) ?? new Map<string, number>();
      m.set(target, (m.get(target) ?? 0) + 1);
      defaultRouteTargets.set(s.vnetId, m);
    }
  }
  const inboundDefaultRoutes = new Map<string, { vnets: number; subnets: number }>();
  for (const targets of defaultRouteTargets.values()) {
    for (const [target, subnets] of targets) {
      const cur = inboundDefaultRoutes.get(target) ?? { vnets: 0, subnets: 0 };
      inboundDefaultRoutes.set(target, { vnets: cur.vnets + 1, subnets: cur.subnets + subnets });
    }
  }

  const resourcesInVnet = new Map<string, Set<string>>();
  for (const [res, vnet] of resourceVnet) {
    const set = resourcesInVnet.get(vnet) ?? new Set<string>();
    set.add(res);
    resourcesInVnet.set(vnet, set);
  }
  const count = (vnet: string, pattern: RegExp) =>
    [...(resourcesInVnet.get(vnet) ?? [])].filter((id) => pattern.test(id)).length;
  const routeServerVnets = new Set(
    inv.otherNetworkResources
      .filter((r) => r.kind === "virtualHub" && !r.properties["virtualWan"])
      .flatMap((r) => r.subnetIds.map((s) => subnetVnet.get(s)).filter((v): v is string => v !== undefined)),
  );

  // --- Hub scoring -----------------------------------------------------------------------------
  const hubScore = new Map<string, { score: number; reasons: string[] }>();
  for (const vnet of inv.vnets) {
    const reasons: string[] = [];
    let score = 0;
    const peerings = peeringsByVnet.get(vnet.id) ?? [];
    if (peerings.length >= 3) {
      score += peerings.length >= 10 ? 0.3 : 0.2;
      reasons.push(`${peerings.length} VNet peerings`);
    }
    const firewalls = count(vnet.id, /\/azurefirewalls\//);
    if (firewalls > 0) {
      score += 0.3;
      reasons.push("Azure Firewall present");
    }
    const nvas = [...(resourcesInVnet.get(vnet.id) ?? [])].filter((id) => nvaVms.has(id)).length;
    if (nvas > 0) {
      score += 0.25;
      reasons.push(`${nvas} potential NVA${nvas > 1 ? "s" : ""}`);
    }
    if (routeServerVnets.has(vnet.id)) {
      score += 0.2;
      reasons.push("Azure Route Server present");
    }
    const gateways = count(vnet.id, /\/virtualnetworkgateways\//);
    if (gateways > 0) {
      score += 0.2;
      reasons.push("VPN/ExpressRoute gateway present");
    }
    if (peerings.some((p) => p.allowGatewayTransit)) {
      score += 0.15;
      reasons.push("Gateway transit enabled");
    }
    const inbound = inboundDefaultRoutes.get(vnet.id);
    if (inbound) {
      score += 0.25;
      reasons.push(
        `Default route of ${inbound.subnets} subnet(s) in ${inbound.vnets} other VNet(s) points into this VNet`,
      );
    }
    hubScore.set(vnet.id, { score, reasons });
  }
  const isHub = (id: string) => (hubScore.get(id)?.score ?? 0) >= 0.5;

  // --- Final classification --------------------------------------------------------------------
  for (const vnet of inv.vnets) {
    const peerings = peeringsByVnet.get(vnet.id) ?? [];
    const hub = hubScore.get(vnet.id)!;
    const peeredHubs = [
      ...new Set(peerings.map((p) => p.remoteVnetId).filter((id): id is string => !!id && isHub(id))),
    ];

    if (isHub(vnet.id)) {
      vnet.topology = {
        classification: "hub",
        confidence: round(hub.score),
        reasons: hub.reasons,
        hubIds: [],
      };
      continue;
    }

    if (peerings.length === 0) {
      vnet.topology = {
        classification: "standalone",
        confidence: 0.9,
        reasons: ["No VNet peerings"],
        hubIds: [],
      };
      continue;
    }

    const spokeReasons: string[] = [];
    let spoke = 0;
    if (peerings.some((p) => p.useRemoteGateways)) {
      spoke += 0.35;
      spokeReasons.push("Uses remote gateways (useRemoteGateways)");
    }
    if (peeredHubs.length > 0) {
      spoke += 0.3;
      spokeReasons.push(`Peered with hub ${peeredHubs.map((h) => vnetById.get(h)?.name ?? h).join(", ")}`);
    }
    const routedTo = [...(defaultRouteTargets.get(vnet.id)?.keys() ?? [])];
    if (routedTo.some(isHub)) {
      spoke += 0.35;
      spokeReasons.push("Default route points to an appliance in a hub VNet");
    } else if (routedTo.length > 0) {
      spoke += 0.2;
      spokeReasons.push("Default route points to an appliance in another VNet");
    }
    if (peerings.length <= 2) {
      spoke += 0.1;
      spokeReasons.push(`${peerings.length} peering(s)`);
    }

    const sharedReasons: string[] = [];
    let shared = 0;
    const resolvers = inv.dnsResolvers.filter((r) => r.kind === "resolver" && r.vnetId === vnet.id).length;
    if (resolvers > 0) {
      shared += 0.35;
      sharedReasons.push("Private DNS Resolver present");
    }
    const bastions = count(vnet.id, /\/bastionhosts\//);
    if (bastions > 0) {
      shared += 0.15;
      sharedReasons.push("Azure Bastion present");
    }
    const pes = count(vnet.id, /\/privateendpoints\//);
    if (pes >= 10) {
      shared += 0.2;
      sharedReasons.push(`${pes} private endpoints`);
    }
    if (peerings.length >= 3 && hub.score < 0.5) {
      shared += 0.15;
      sharedReasons.push(`${peerings.length} peerings without central gateway or firewall`);
    }

    let result: TopologyClassification;
    if (shared >= 0.35 && shared >= spoke) {
      result = {
        classification: "shared-services",
        confidence: round(shared + 0.2),
        reasons: sharedReasons,
        hubIds: peeredHubs,
      };
    } else if (spoke >= 0.4) {
      result = {
        classification: "spoke",
        confidence: round(spoke),
        reasons: spokeReasons,
        hubIds: peeredHubs,
      };
    } else {
      result = {
        classification: "unknown",
        confidence: 0.3,
        reasons: [...hub.reasons, ...spokeReasons, "No conclusive hub or spoke signals"],
        hubIds: peeredHubs,
      };
    }
    vnet.topology = result;
  }
}

export function architectureType(
  vnets: readonly VNetEntity[],
): "hub-spoke" | "virtual-wan" | "flat" | "mixed" {
  const hubs = vnets.filter((v) => v.topology?.classification === "hub").length;
  const spokes = vnets.filter((v) => v.topology?.classification === "spoke").length;
  if (hubs > 0 && spokes > 0) return "hub-spoke";
  if (hubs === 0 && spokes === 0) return "flat";
  return "mixed";
}
