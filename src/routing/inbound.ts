import { cidrContains, ipFamilyOf, type IpFamily } from "../addressing/ip.js";
import { internetNodeId } from "../graph/buildGraph.js";
import type { NicEntity, NsgRuleEntity, SubnetEntity } from "../models/network.js";
import { weakest, type Confidence, type Evidence, type PathHop, type PathStatus } from "../models/path.js";
import { checkSecurity } from "../security/checks.js";
import { ownerOfIp, subnetContaining, tagResolver, type RoutingContext } from "./context.js";
import { nameOf, networkAddress, virtualNetworkPrefixes } from "./endpoints.js";
import { describeRoute, selectRoute, synthesizeRoutes } from "./routes.js";

/** Representative Internet client addresses (documentation ranges, outside every VNet). */
const INTERNET_CLIENT: Record<IpFamily, string> = { ipv4: "203.0.113.50", ipv6: "2001:db8:ffff::50" };

/** Ports checked for directly exposed instances (management, web, file, database). */
export const EXPOSURE_PORTS = [22, 3389, 80, 443, 445, 1433, 3306, 5432, 5985, 5986, 8080];

export type EntryKind =
  "publicIp" | "loadBalancer" | "loadBalancerNat" | "applicationGateway" | "firewallDnat";

export interface InboundExposure {
  id: string;
  family: IpFamily;
  entry: {
    kind: EntryKind;
    resourceId: string;
    name: string;
    publicAddress: string;
    frontendPort?: number | undefined;
    protocol: string;
  };
  targetId: string;
  targetName: string;
  targetAddress?: string | undefined;
  status: PathStatus;
  /** Reached through an inspecting control (Azure Firewall DNAT, Application Gateway with WAF). */
  controlled: boolean;
  /** Ports reachable from any Internet source. */
  openPorts: number[];
  /** Ports reachable only from specific public sources, with those sources. */
  restricted: { port: number; sources: string[] }[];
  asymmetricRouting: boolean;
  hops: PathHop[];
  summary: string;
  confidence: Confidence;
}

const PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];
const isPublicPrefix = (p: string) => {
  const family = ipFamilyOf(p.split("/")[0]);
  return family !== undefined && !PRIVATE.some((x) => cidrContains(x, p.split("/")[0]!));
};

interface Target {
  subnet: SubnetEntity;
  nic?: NicEntity | undefined;
  address: string;
  id: string;
}

function targetForAddress(ctx: RoutingContext, address: string): Target | undefined {
  const owner = ownerOfIp(ctx, address);
  const subnet = owner?.subnetId ? ctx.subnets.get(owner.subnetId) : subnetContaining(ctx, address);
  if (!subnet) return undefined;
  const nic = owner?.kind === "nic" ? ctx.nics.get(owner.id) : undefined;
  return { subnet, nic, address, id: owner ? (owner.computeId ?? owner.id) : subnet.id };
}

/** Allow-inbound NSG rules that open the port only for explicit public source ranges. */
function restrictedSources(ctx: RoutingContext, t: Target, port: number): string[] {
  const rules: NsgRuleEntity[] = [
    ...(t.subnet.nsgId ? (ctx.nsgs.get(t.subnet.nsgId)?.rules ?? []) : []),
    ...(t.nic?.nsgId ? (ctx.nsgs.get(t.nic.nsgId)?.rules ?? []) : []),
  ];
  return [
    ...new Set(
      rules
        .filter((r) => r.direction === "Inbound" && r.access === "Allow")
        .filter((r) =>
          r.destinationPorts.some((range) => {
            if (range === "*") return true;
            const [lo, hi] = range.split("-").map(Number);
            return hi === undefined ? lo === port : port >= lo! && port <= hi;
          }),
        )
        .flatMap((r) => r.sources.filter((s) => isPublicPrefix(s))),
    ),
  ];
}

/**
 * Return-path check: responses leave the target subnet by its effective route towards the client
 * (or the SNAT address). If that route points to an appliance, a stateful firewall drops them
 * (Microsoft Learn: Azure Firewall DNAT / AKS egress – asymmetric routing).
 */
function returnPathIssue(
  ctx: RoutingContext,
  subnet: SubnetEntity,
  peer: string,
  family: IpFamily,
): Evidence | undefined {
  const route = selectRoute(synthesizeRoutes(ctx, subnet.id, family), peer);
  const viaPeer = route?.nextHopIpAddresses?.includes(peer) || route?.nextHopIpAddress === peer;
  if (route && !viaPeer && (route.nextHopType === "VirtualAppliance" || route.nextHopType === "VirtualHub")) {
    return {
      kind: "route",
      resourceId: route.originId ?? subnet.routeTableId,
      description: `Asymmetrisches Routing: Antworten nehmen ${describeRoute(route)} statt des Eingangswegs – eine zustandsbehaftete Firewall verwirft sie`,
    };
  }
  return undefined;
}

function evaluate(
  ctx: RoutingContext,
  family: IpFamily,
  entry: InboundExposure["entry"],
  target: Target,
  options: {
    source: string;
    ports: number[];
    protocol: "Tcp" | "Udp" | "*";
    controlled: boolean;
    entryHops: Omit<PathHop, "index">[];
    returnPeer: string;
  },
): InboundExposure {
  const hops: PathHop[] = [];
  const add = (h: Omit<PathHop, "index">) => hops.push({ index: hops.length, ...h });
  add({
    type: "internet",
    nodeId: internetNodeId(family),
    label: `Internet (${family === "ipv4" ? "IPv4" : "IPv6"})`,
    reason: `Client ${options.source === INTERNET_CLIENT[family] ? "aus dem Internet" : options.source}`,
    confidence: "CONFIRMED",
    evidence: [],
  });
  for (const h of options.entryHops) add(h);

  const openPorts: number[] = [];
  const restricted: { port: number; sources: string[] }[] = [];
  let decisionHops: Omit<PathHop, "index">[] = [];
  let firstBlock: Omit<PathHop, "index"> | undefined;
  let uncertain = false;
  for (const port of options.ports) {
    const check = checkSecurity(ctx, "Inbound", target.subnet, target.nic, {
      source: options.source,
      destination: target.address,
      protocol: options.protocol,
      port,
      virtualNetworkPrefixes: virtualNetworkPrefixes(ctx, target.subnet),
      resolveTag: tagResolver(ctx),
      destinationAsgIds: target.nic?.ipConfigurations.find((c) => c.privateIpAddress === target.address)
        ?.applicationSecurityGroupIds,
    });
    if (check.uncertain) uncertain = true;
    if (!check.blocked) {
      openPorts.push(port);
      if (decisionHops.length === 0) decisionHops = check.hops;
    } else {
      firstBlock ??= check.blocked;
      const sources = options.source === INTERNET_CLIENT[family] ? restrictedSources(ctx, target, port) : [];
      if (sources.length) restricted.push({ port, sources });
    }
  }
  for (const h of decisionHops) add(h);

  const asymmetric = returnPathIssue(ctx, target.subnet, options.returnPeer, family);

  let status: PathStatus;
  let summary: string;
  if (openPorts.length > 0) {
    status = asymmetric ? "UNKNOWN" : uncertain ? "UNKNOWN" : "ALLOWED";
    summary = `Aus dem Internet erreichbar auf ${openPorts.join(", ")}${options.controlled ? " (über Firewall/WAF)" : " (ohne zentrale Kontrolle)"}`;
  } else if (restricted.length > 0) {
    status = asymmetric ? "UNKNOWN" : "ALLOWED";
    summary = `Nur für ausgewählte öffentliche Quellen offen (${restricted.map((r) => r.port).join(", ")})`;
  } else {
    status = "BLOCKED";
    summary = `Nicht erreichbar: ${firstBlock?.reason ?? "kein Zugang"}`;
  }
  if (asymmetric) summary += " – Rückweg asymmetrisch, Verbindung scheitert voraussichtlich";
  if (firstBlock && openPorts.length === 0 && restricted.length === 0) add(firstBlock);
  add({
    type: "destination",
    nodeId: target.id,
    label: nameOf(target.id),
    reason: `Ziel ${target.address} im Subnet ${target.subnet.name}`,
    confidence: asymmetric ? "POSSIBLE" : "CONFIRMED",
    evidence: asymmetric ? [asymmetric] : [],
  });
  return {
    id: `${entry.kind}:${entry.resourceId}:${entry.frontendPort ?? "*"}->${target.id}:${family}`,
    family,
    entry,
    targetId: target.id,
    targetName: nameOf(target.id),
    targetAddress: target.address,
    status,
    controlled: options.controlled,
    openPorts,
    restricted,
    asymmetricRouting: asymmetric !== undefined,
    hops,
    summary,
    confidence: weakest(...hops.map((h) => h.confidence)),
  };
}

/**
 * Internet → workload exposures (Lastenheft § 45 "Security Path", § 51 public IPv6): instance
 * public IPs, public load balancers (rules, inbound NAT), Application Gateways and Azure Firewall
 * DNAT. Configuration-based; FQDN backends and on-premises paths are out of scope.
 */
export function analyzeInbound(ctx: RoutingContext, filter?: { targetId?: string }): InboundExposure[] {
  const out: InboundExposure[] = [];
  const inv = ctx.inv;
  const pipFamily = (id: string | undefined) => (id ? ctx.publicIps.get(id) : undefined);

  // a) Public IPs directly on NICs.
  for (const nic of inv.networkInterfaces) {
    for (const cfg of nic.ipConfigurations) {
      const pip = pipFamily(cfg.publicIpId);
      if (!pip || !cfg.privateIpAddress || !cfg.subnetId) continue;
      const subnet = ctx.subnets.get(cfg.subnetId);
      if (!subnet) continue;
      const family = pip.ipVersion;
      if (ipFamilyOf(cfg.privateIpAddress) !== family) continue;
      const target: Target = {
        subnet,
        nic,
        address: cfg.privateIpAddress,
        id: nic.vmId ?? nic.scaleSetId ?? nic.id,
      };
      out.push(
        evaluate(
          ctx,
          family,
          {
            kind: "publicIp",
            resourceId: pip.id,
            name: pip.name,
            publicAddress: pip.ipAddress ?? pip.name,
            protocol: "Tcp",
          },
          target,
          {
            source: INTERNET_CLIENT[family],
            ports: EXPOSURE_PORTS,
            protocol: "Tcp",
            controlled: false,
            returnPeer: INTERNET_CLIENT[family],
            entryHops: [
              {
                type: "publicIp",
                nodeId: pip.id,
                label: pip.ipAddress ?? pip.name,
                reason: `Public IP ${pip.ipAddress ?? ""} direkt an der NIC ${nic.name}`,
                confidence: "CONFIRMED",
                evidence: [
                  {
                    kind: "property",
                    resourceId: pip.id,
                    description: `Instance-Level Public IP (${family})`,
                  },
                ],
              },
            ],
          },
        ),
      );
    }
  }

  // b) Public load balancers: load balancing rules and inbound NAT rules.
  for (const lb of inv.loadBalancers) {
    for (const fe of lb.frontends) {
      const pip = pipFamily(fe.publicIpId);
      if (!pip) continue;
      const family = pip.ipVersion;
      const lbHop = (port: number | undefined, what: string): Omit<PathHop, "index"> => ({
        type: "loadBalancer",
        nodeId: lb.id,
        label: lb.name,
        reason: `Public Load Balancer ${pip.ipAddress ?? ""}${port ? `:${port}` : ""} – ${what}`,
        confidence: "CONFIRMED",
        evidence: [],
      });
      for (const rule of lb.rules.filter((r) => r.frontendName === fe.name)) {
        const pool = lb.backendPools.find((p) => p.name === rule.backendPool);
        for (const member of pool?.memberIds ?? []) {
          const nic = ctx.nics.get(member);
          const cfg = nic?.ipConfigurations.find((c) => c.privateIpVersion === family && c.subnetId);
          const subnet = cfg?.subnetId ? ctx.subnets.get(cfg.subnetId) : undefined;
          if (!nic || !cfg?.privateIpAddress || !subnet) continue;
          const port = rule.backendPort ?? rule.frontendPort ?? 443;
          out.push(
            evaluate(
              ctx,
              family,
              {
                kind: "loadBalancer",
                resourceId: lb.id,
                name: lb.name,
                publicAddress: pip.ipAddress ?? pip.name,
                frontendPort: rule.frontendPort,
                protocol: rule.protocol,
              },
              { subnet, nic, address: cfg.privateIpAddress, id: nic.vmId ?? nic.scaleSetId ?? nic.id },
              {
                source: INTERNET_CLIENT[family],
                ports: [port],
                protocol:
                  rule.protocol.toLowerCase() === "udp"
                    ? "Udp"
                    : rule.protocol.toLowerCase() === "all"
                      ? "*"
                      : "Tcp",
                controlled: false,
                returnPeer: INTERNET_CLIENT[family],
                entryHops: [
                  lbHop(rule.frontendPort, `Regel ${rule.name} → Pool ${rule.backendPool ?? "?"}:${port}`),
                ],
              },
            ),
          );
        }
      }
      for (const nat of lb.natRules.filter((r) => r.frontendName === fe.name)) {
        const nic = nat.targetId ? ctx.nics.get(nat.targetId) : undefined;
        const cfg = nic?.ipConfigurations.find((c) => c.privateIpVersion === family && c.subnetId);
        const subnet = cfg?.subnetId ? ctx.subnets.get(cfg.subnetId) : undefined;
        if (!nic || !cfg?.privateIpAddress || !subnet) continue;
        const port = nat.backendPort ?? 22;
        out.push(
          evaluate(
            ctx,
            family,
            {
              kind: "loadBalancerNat",
              resourceId: lb.id,
              name: lb.name,
              publicAddress: pip.ipAddress ?? pip.name,
              frontendPort: nat.frontendPort,
              protocol: nat.protocol,
            },
            { subnet, nic, address: cfg.privateIpAddress, id: nic.vmId ?? nic.id },
            {
              source: INTERNET_CLIENT[family],
              ports: [port],
              protocol: nat.protocol.toLowerCase() === "udp" ? "Udp" : "Tcp",
              controlled: false,
              returnPeer: INTERNET_CLIENT[family],
              entryHops: [lbHop(nat.frontendPort, `Inbound NAT ${nat.name} → ${port}`)],
            },
          ),
        );
      }
    }
  }

  // c) Application Gateways with public frontends.
  for (const agw of inv.applicationGateways) {
    for (const fe of agw.frontends) {
      const pip = pipFamily(fe.publicIpId);
      if (!pip) continue;
      const family = pip.ipVersion;
      const agwSubnet = agw.gatewaySubnetIds[0] ? ctx.subnets.get(agw.gatewaySubnetIds[0]) : undefined;
      const agwSource = agwSubnet?.prefixes.ipv4[0] ? networkAddress(agwSubnet.prefixes.ipv4[0]) : undefined;
      if (!agwSource) continue;
      const waf = agw.wafEnabled === true || agw.wafPolicyId !== undefined;
      for (const route of agw.routes) {
        const listener = agw.listeners.find((l) => l.name === route.listener);
        const pool = agw.backendPools.find((p) => p.name === route.backendPool);
        const port =
          Number(listener?.frontendPort) || (listener?.protocol?.toLowerCase() === "http" ? 80 : 443);
        const targets: Target[] = [];
        for (const m of pool?.memberIds ?? []) {
          const nic = ctx.nics.get(m);
          const cfg = nic?.ipConfigurations.find((c) => c.privateIpVersion === "ipv4" && c.subnetId);
          const subnet = cfg?.subnetId ? ctx.subnets.get(cfg.subnetId) : undefined;
          if (nic && cfg?.privateIpAddress && subnet)
            targets.push({ subnet, nic, address: cfg.privateIpAddress, id: nic.vmId ?? nic.id });
        }
        for (const a of pool?.addresses ?? []) {
          if (ipFamilyOf(a) !== "ipv4") continue;
          const t = targetForAddress(ctx, a);
          if (t) targets.push(t);
        }
        for (const t of targets) {
          out.push(
            evaluate(
              ctx,
              family,
              {
                kind: "applicationGateway",
                resourceId: agw.id,
                name: agw.name,
                publicAddress: pip.ipAddress ?? pip.name,
                frontendPort: port,
                protocol: listener?.protocol ?? "Https",
              },
              t,
              {
                source: agwSource,
                ports: [port],
                protocol: "Tcp",
                controlled: waf,
                returnPeer: agwSource,
                entryHops: [
                  {
                    type: "loadBalancer",
                    nodeId: agw.id,
                    label: agw.name,
                    reason: `Application Gateway ${pip.ipAddress ?? ""}:${port} – Listener ${route.listener ?? "?"} → Pool ${route.backendPool ?? "?"}${waf ? " (WAF)" : " (ohne WAF)"}`,
                    confidence: "LIKELY",
                    evidence: [
                      {
                        kind: "property",
                        resourceId: agw.id,
                        description:
                          "Backend-Port aus HTTP-Settings nicht ausgewertet; Listener-Port als Näherung",
                      },
                    ],
                  },
                ],
              },
            ),
          );
        }
      }
    }
  }

  // d) Azure Firewall DNAT rules (IPv4; the firewall also SNATs the source to its private IP).
  for (const fw of inv.firewalls) {
    const policy = fw.firewallPolicyId;
    if (!policy) continue;
    const fwPrivate = fw.privateIps.ipv4[0];
    if (!fwPrivate) continue;
    for (const rcg of inv.ruleCollectionGroups.filter((g) => g.firewallPolicyId === policy)) {
      for (const coll of rcg.ruleCollections.filter((c) => c.collectionType.toLowerCase().includes("nat"))) {
        for (const r of coll.rules) {
          if (!r.translatedAddress || ipFamilyOf(r.translatedAddress) !== "ipv4") continue;
          const t = targetForAddress(ctx, r.translatedAddress);
          if (!t) continue;
          const port = Number(r.translatedPort) || Number(r.destinationPorts[0]) || 443;
          const openToAll = r.sources.some((s) => s === "*" || s === "0.0.0.0/0");
          out.push(
            evaluate(
              ctx,
              "ipv4",
              {
                kind: "firewallDnat",
                resourceId: fw.id,
                name: fw.name,
                publicAddress: r.destinations[0] ?? "Firewall-IP",
                frontendPort: Number(r.destinationPorts[0]) || undefined,
                protocol: r.protocols[0] ?? "TCP",
              },
              t,
              {
                source: fwPrivate,
                ports: [port],
                protocol: "Tcp",
                controlled: true,
                returnPeer: fwPrivate,
                entryHops: [
                  {
                    type: "firewall",
                    nodeId: fw.id,
                    label: fw.name,
                    reason: `DNAT ${r.destinations.join(", ")}:${r.destinationPorts.join(",")} → ${r.translatedAddress}:${port} (${rcg.name}/${coll.name}/${r.name})`,
                    decision: {
                      control: "firewall",
                      resourceId: fw.id,
                      access: "Allow",
                      rule: `${rcg.name}/${coll.name}/${r.name}`,
                    },
                    confidence: "CONFIRMED",
                    evidence: [
                      {
                        kind: "rule",
                        resourceId: policy,
                        description: `Quellen: ${r.sources.join(", ") || "–"}${openToAll ? " (beliebig)" : ""}`,
                      },
                      {
                        kind: "platform",
                        resourceId: fw.id,
                        description:
                          "Azure Firewall übersetzt bei DNAT auch die Quelle auf eine private Firewall-IP (NSG am Ziel sieht die Firewall)",
                      },
                    ],
                  },
                ],
              },
            ),
          );
        }
      }
    }
  }

  const id = filter?.targetId;
  const matches = (e: InboundExposure) => {
    if (!id) return true;
    if (e.targetId === id || e.targetId === ctx.nics.get(id)?.vmId) return true;
    return (
      ctx.subnets
        .get(id)
        ?.connectedResourceIds.some((r) => r === e.targetId || ctx.nics.get(r)?.vmId === e.targetId) ?? false
    );
  };
  const result = out.filter(matches);
  return result.sort((a, b) => a.targetName.localeCompare(b.targetName) || a.family.localeCompare(b.family));
}
