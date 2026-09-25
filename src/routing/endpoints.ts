import { cidrContains, ipFamilyOf, type IpFamily } from "../addressing/ip.js";
import { internetNodeId } from "../graph/buildGraph.js";
import type { NicEntity, SubnetEntity } from "../models/network.js";
import type { PathQuery } from "../models/path.js";
import { addressOf, INTERNET_PROBE, type RoutingContext } from "./context.js";
import { gatewaysReachableFrom } from "./routes.js";

export interface Endpoint {
  subnet: SubnetEntity;
  address: string;
  nic?: NicEntity | undefined;
  nodeId: string;
  label: string;
  asgIds?: string[] | undefined;
}

export const networkAddress = (prefix: string) => prefix.split("/")[0]!;
export const nameOf = (id: string | undefined) => (id ? (id.split("/").pop() ?? id) : "?");

/** Resolves a subnet / NIC / VM / scale set / private endpoint to a subnet and source address of the family. */
export function resolveEndpoint(ctx: RoutingContext, id: string, family: IpFamily): Endpoint | undefined {
  const subnet = ctx.subnets.get(id);
  if (subnet) {
    const prefix = subnet.prefixes[family][0];
    return prefix
      ? { subnet, address: networkAddress(prefix), nodeId: subnet.id, label: `Subnet ${subnet.name}` }
      : undefined;
  }
  const nics = ctx.nics.has(id) ? [ctx.nics.get(id)!] : (ctx.nicsByCompute.get(id) ?? []);
  for (const nic of nics) {
    const cfg = nic.ipConfigurations.find(
      (c) => c.privateIpVersion === family && c.subnetId && c.privateIpAddress,
    );
    const s = cfg?.subnetId ? ctx.subnets.get(cfg.subnetId) : undefined;
    if (cfg && s) {
      return {
        subnet: s,
        address: cfg.privateIpAddress!,
        nic,
        nodeId: id,
        label: nameOf(id),
        asgIds: cfg.applicationSecurityGroupIds,
      };
    }
  }
  const pe = ctx.privateEndpoints.get(id);
  const peSubnet = pe?.subnetId ? ctx.subnets.get(pe.subnetId) : undefined;
  if (pe && peSubnet && pe.addressing[family][0]) {
    return { subnet: peSubnet, address: pe.addressing[family][0], nodeId: pe.id, label: pe.name };
  }
  return undefined;
}

export function destinationAddress(
  ctx: RoutingContext,
  q: PathQuery,
): { address?: string | undefined; internet: boolean; label: string; nodeId?: string | undefined } {
  const d = q.destination;
  if (d.kind === "internet")
    return {
      address: INTERNET_PROBE[q.family],
      internet: true,
      label: `Internet (${q.family === "ipv4" ? "IPv4" : "IPv6"})`,
      nodeId: internetNodeId(q.family),
    };
  if (d.kind === "ip") {
    const address = d.address.split("/")[0]!;
    const inAzure = [...ctx.vnets.values()].some((v) =>
      v.addressSpace[q.family].some((p) => cidrContains(p, address)),
    );
    return {
      address: ipFamilyOf(address) === q.family ? address : undefined,
      internet: !inAzure && !isPrivateAddress(address),
      label: d.address,
    };
  }
  const subnet = ctx.subnets.get(d.id);
  const vnet = ctx.vnets.get(d.id);
  const address =
    addressOf(ctx, d.id, q.family) ??
    (subnet?.prefixes[q.family][0] ? networkAddress(subnet.prefixes[q.family][0]!) : undefined) ??
    (vnet?.addressSpace[q.family][0] ? networkAddress(vnet.addressSpace[q.family][0]!) : undefined);
  return { ...(address ? { address } : {}), internet: false, label: nameOf(d.id), nodeId: d.id };
}

export function isPrivateAddress(address: string): boolean {
  return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"].some((p) =>
    cidrContains(p, address),
  );
}

/** Address ranges the "VirtualNetwork" service tag covers for a subnet: own VNet, peerings, gateway prefixes. */
export function virtualNetworkPrefixes(ctx: RoutingContext, subnet: SubnetEntity): string[] {
  const vnet = ctx.vnets.get(subnet.vnetId);
  const own = vnet ? [...vnet.addressSpace.ipv4, ...vnet.addressSpace.ipv6] : [];
  const peered = (ctx.peeringsByVnet.get(subnet.vnetId) ?? []).flatMap((p) => [
    ...p.remoteAddressSpace.ipv4,
    ...p.remoteAddressSpace.ipv6,
  ]);
  const onPrem = gatewaysReachableFrom(ctx, subnet.vnetId).flatMap((g) =>
    (ctx.connectionsByGateway.get(g.id) ?? []).flatMap((c) => {
      const lng = c.localNetworkGatewayId ? ctx.localNetworkGateways.get(c.localNetworkGatewayId) : undefined;
      return lng ? [...lng.addressPrefixes.ipv4, ...lng.addressPrefixes.ipv6] : [];
    }),
  );
  return [...own, ...peered, ...onPrem];
}

/** Central security controls (firewalls/NVAs) of the hubs a VNet is attached to (or of the VNet itself if it is a hub). */
export function centralControlsFor(ctx: RoutingContext, vnetId: string): string[] {
  const vnet = ctx.vnets.get(vnetId);
  const hubs = vnet?.topology?.classification === "hub" ? [vnetId] : (vnet?.topology?.hubIds ?? []);
  const out: string[] = [];
  for (const hub of hubs) {
    for (const s of ctx.subnets.values()) {
      if (s.vnetId !== hub) continue;
      for (const r of s.connectedResourceIds) {
        if (ctx.firewalls.has(r) || ctx.nvaIds.has(r)) out.push(r);
      }
    }
    for (const vm of ctx.vms.values()) {
      if (!ctx.nvaIds.has(vm.id)) continue;
      const nic = (ctx.nicsByCompute.get(vm.id) ?? [])[0];
      if (nic?.subnetIds.some((sid) => ctx.subnets.get(sid)?.vnetId === hub)) out.push(vm.id);
    }
  }
  return [...new Set(out)];
}
