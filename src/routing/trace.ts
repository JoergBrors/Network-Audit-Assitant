import { ipFamilyOf } from "../addressing/ip.js";
import { internetNodeId } from "../graph/buildGraph.js";
import type { FirewallEntity, SubnetEntity } from "../models/network.js";
import {
  weakest,
  type Evidence,
  type PathComparison,
  type PathHop,
  type PathQuery,
  type PathResult,
  type PathStatus,
} from "../models/path.js";
import { checkSecurity } from "../security/checks.js";
import { evaluateFirewall } from "../security/firewall.js";
import type { FlowTuple } from "../security/nsg.js";
import { ownerOfIp, subnetContaining, tagResolver, vnetContaining, type RoutingContext } from "./context.js";
import { EGRESS_LABEL, egressHops, resolveEgress } from "./egress.js";
import {
  centralControlsFor,
  destinationAddress,
  nameOf,
  resolveEndpoint,
  virtualNetworkPrefixes,
} from "./endpoints.js";
import {
  describeRoute,
  gatewaysReachableFrom,
  selectRoute,
  synthesizeRoutes,
  unresolvedServiceTagRoutes,
} from "./routes.js";

export { EGRESS_LABEL, resolveEgress } from "./egress.js";
export { centralControlsFor, resolveEndpoint } from "./endpoints.js";

const MAX_HOPS = 16;

/**
 * Traces a flow hop by hop (ARCHITECTURE.md § 12.2): AVNM security admin rules and NSGs at source
 * and destination, effective route of every subnet on the way (UDR incl. service tags and ECMP,
 * peerings, AVNM connected groups, Virtual WAN, gateways), Azure Firewall/NVA as next hop and
 * Internet egress. Every hop carries its reason, confidence and evidence.
 */
export function tracePath(ctx: RoutingContext, q: PathQuery): PathResult {
  const hops: PathHop[] = [];
  const securityControls: string[] = [];
  const protocol = q.protocol ?? "Tcp";
  const port = q.port ?? 443;
  const familyLabel = q.family === "ipv4" ? "IPv4" : "IPv6";
  let uncertain = false;

  const add = (hop: Omit<PathHop, "index">): void => {
    hops.push({ index: hops.length, ...hop });
  };
  const finish = (status: PathStatus, summary: string, extra: Partial<PathResult> = {}): PathResult => ({
    query: q,
    status: status === "ALLOWED" && uncertain ? "UNKNOWN" : status,
    confidence: weakest(...hops.map((h) => h.confidence)),
    summary,
    hops,
    securityControls,
    ...extra,
  });

  const src = resolveEndpoint(ctx, q.sourceId, q.family);
  if (!src) {
    add({
      type: "source",
      nodeId: q.sourceId,
      label: nameOf(q.sourceId),
      reason: `Quelle hat keine ${familyLabel}-Adresse bzw. kein ${familyLabel}-Präfix`,
      confidence: "CONFIRMED",
      evidence: [
        { kind: "property", resourceId: q.sourceId, description: `keine ${familyLabel}-Konfiguration` },
      ],
    });
    return finish("BLOCKED", `Kein ${familyLabel} an der Quelle konfiguriert`, { notApplicable: true });
  }
  const dst = destinationAddress(ctx, q);
  if (!dst.address) {
    add({
      type: "source",
      nodeId: src.nodeId,
      label: src.label,
      reason: `Ziel hat keine ${familyLabel}-Adresse`,
      confidence: "CONFIRMED",
      evidence: [],
    });
    return finish("BLOCKED", `Kein ${familyLabel} am Ziel konfiguriert`, { notApplicable: true });
  }
  const destination = dst.address;
  add({
    type: "source",
    nodeId: src.nodeId,
    label: src.label,
    reason: `Quelle ${src.address} im Subnet ${src.subnet.name}`,
    confidence: "CONFIRMED",
    evidence: [
      { kind: "property", resourceId: src.nodeId, description: `${familyLabel}-Adresse ${src.address}` },
    ],
  });

  const flow = (s: SubnetEntity, source: string, extra: Partial<FlowTuple> = {}): FlowTuple => ({
    source,
    destination,
    protocol,
    port,
    virtualNetworkPrefixes: virtualNetworkPrefixes(ctx, s),
    resolveTag: tagResolver(ctx),
    ...extra,
  });

  // Source side: AVNM admin rules, then NSG (NIC → subnet).
  const out = checkSecurity(
    ctx,
    "Outbound",
    src.subnet,
    src.nic,
    flow(src.subnet, src.address, { sourceAsgIds: src.asgIds }),
  );
  for (const h of out.hops) add(h);
  if (out.uncertain) uncertain = true;
  if (out.blocked) {
    add(out.blocked);
    return finish("BLOCKED", `Ausgehend blockiert: ${out.blocked.reason}`);
  }

  let current = src.subnet;
  let sourceAddress = src.address;
  let afterFirewall: FirewallEntity | undefined;
  let afterNva: string | undefined;
  const visited = new Set<string>();

  /** Delivery into a VNet: destination subnet, inbound AVNM/NSG, destination hop. */
  const deliver = (targetVnet: string): PathResult => {
    if (!ctx.vnets.has(targetVnet)) {
      add({
        type: "destination",
        nodeId: targetVnet,
        label: nameOf(targetVnet),
        reason: "Ziel-VNet liegt außerhalb des lesbaren Bereichs",
        confidence: "UNKNOWN",
        evidence: [{ kind: "missing-data", resourceId: targetVnet, description: "VNet nicht im Inventar" }],
      });
      return finish("UNKNOWN", `Zustellung in ${nameOf(targetVnet)} nicht prüfbar`);
    }
    const destSubnet = subnetContaining(ctx, destination, targetVnet);
    if (!destSubnet) {
      add({
        type: "drop",
        nodeId: targetVnet,
        label: nameOf(targetVnet),
        reason: "Kein Subnet enthält die Zieladresse",
        confidence: "LIKELY",
        evidence: [],
      });
      return finish("BLOCKED", "Zieladresse in keinem Subnet");
    }
    const owner = ownerOfIp(ctx, destination);
    const destNic = owner?.kind === "nic" ? ctx.nics.get(owner.id) : undefined;
    const inbound = checkSecurity(
      ctx,
      "Inbound",
      destSubnet,
      destNic,
      flow(destSubnet, sourceAddress, {
        destinationAsgIds: destNic?.ipConfigurations.find((c) => c.privateIpAddress === destination)
          ?.applicationSecurityGroupIds,
      }),
    );
    for (const h of inbound.hops) add(h);
    if (inbound.uncertain) uncertain = true;
    if (inbound.blocked) {
      add(inbound.blocked);
      return finish("BLOCKED", `Eingehend blockiert: ${inbound.blocked.reason}`);
    }
    const nodeId = owner ? (owner.computeId ?? owner.id) : destSubnet.id;
    add({
      type: "destination",
      nodeId,
      label: nameOf(nodeId),
      reason: `Zustellung an ${destination} im Subnet ${destSubnet.name}`,
      confidence: "CONFIRMED",
      evidence: [],
    });
    return finish(
      "ALLOWED",
      `Zugestellt${securityControls.length ? ` über ${securityControls.map(nameOf).join(", ")}` : ""}`,
      { sourceAddress: src.address, destinationAddress: destination },
    );
  };

  /** Firewall as inspection point; returns the subnet to continue from (undefined = path ended). */
  const viaFirewall = (fw: FirewallEntity, reachedVia: string): { stop?: PathResult } => {
    if (securityControls.includes(fw.id)) {
      add({
        type: "drop",
        nodeId: fw.id,
        label: fw.name,
        reason: "Routing-Schleife: Verkehr wird erneut an dieselbe Firewall geleitet",
        confidence: "LIKELY",
        evidence: [],
      });
      return { stop: finish("UNKNOWN", "Routing-Schleife") };
    }
    if (fw.virtualHubId && q.family === "ipv6") {
      add({
        type: "firewall",
        nodeId: fw.id,
        label: fw.name,
        reason: "Azure Firewall im Virtual Hub unterstützt kein IPv6",
        confidence: "LIKELY",
        evidence: [
          {
            kind: "platform",
            resourceId: fw.id,
            description: "Microsoft Learn: vHub-Firewall ohne IPv6-Unterstützung",
          },
        ],
      });
      return { stop: finish("BLOCKED", "IPv6 über Virtual-Hub-Firewall nicht möglich") };
    }
    const verdict = evaluateFirewall(ctx, fw, {
      source: sourceAddress,
      destination,
      protocol,
      port,
      internet: dst.internet,
    });
    securityControls.push(fw.id);
    if (verdict.access === "Unknown") uncertain = true;
    add({
      type: "firewall",
      nodeId: fw.id,
      label: fw.name,
      reason: `Azure Firewall (${reachedVia})${verdict.rule ? ` – ${verdict.rule}` : ""}`,
      decision: { control: "firewall", resourceId: fw.id, access: verdict.access, rule: verdict.rule },
      confidence: verdict.confidence,
      evidence: verdict.evidence,
    });
    if (verdict.access === "Deny")
      return { stop: finish("BLOCKED", `Von Azure Firewall ${fw.name} verworfen`) };
    afterFirewall = fw;
    sourceAddress = fw.privateIps[q.family][0] ?? sourceAddress;
    return {};
  };

  const internetEgress = (subnet: SubnetEntity): PathResult => {
    const egress = resolveEgress(ctx, {
      subnet,
      nic: afterFirewall || afterNva ? undefined : src.nic,
      family: q.family,
      afterFirewall,
      afterNva,
    });
    for (const e of egressHops(ctx, egress)) add(e);
    if (egress.mechanism === "none") {
      add({
        type: "drop",
        label: "kein Egress",
        reason: "Kein ausgehender Internetzugang für diese Adressfamilie",
        confidence: egress.confidence,
        evidence: egress.evidence,
      });
      return finish("BLOCKED", `Kein ${familyLabel}-Internetzugang`, { egress });
    }
    if (egress.mechanism === "unknown") uncertain = true;
    add({
      type: "internet",
      nodeId: internetNodeId(q.family),
      label: `Internet (${familyLabel})`,
      reason: `Ausgang über ${EGRESS_LABEL[egress.mechanism]}`,
      confidence: egress.confidence,
      evidence: [],
    });
    const central = centralControlsFor(ctx, src.subnet.vnetId).filter((c) => !securityControls.includes(c));
    if (
      dst.internet &&
      securityControls.length === 0 &&
      central.length > 0 &&
      egress.mechanism !== "unknown"
    ) {
      return finish(
        "POTENTIAL_BYPASS",
        `${familyLabel}-Internetverkehr umgeht die zentrale Sicherheitskontrolle ${central.map(nameOf).join(", ")}`,
        { egress },
      );
    }
    return finish(
      "ALLOWED",
      `Internet über ${EGRESS_LABEL[egress.mechanism]}${securityControls.length ? ` (kontrolliert durch ${securityControls.map(nameOf).join(", ")})` : " (ohne zentrale Kontrolle)"}`,
      { egress },
    );
  };

  for (let step = 0; step < MAX_HOPS; step++) {
    if (visited.has(current.id)) {
      add({
        type: "drop",
        nodeId: current.id,
        label: `Subnet ${current.name}`,
        reason: "Routing-Schleife erkannt",
        confidence: "LIKELY",
        evidence: [
          {
            kind: "route",
            resourceId: current.id,
            description: "Pfad kehrt in ein bereits besuchtes Subnet zurück",
          },
        ],
      });
      return finish("UNKNOWN", "Routing-Schleife");
    }
    visited.add(current.id);
    const route = selectRoute(synthesizeRoutes(ctx, current.id, q.family), destination);
    const unresolvedTags = unresolvedServiceTagRoutes(ctx, current.id);
    const tagEvidence: Evidence[] = unresolvedTags.length
      ? [
          {
            kind: "missing-data",
            resourceId: current.routeTableId,
            description: `UDRs mit nicht aufgelösten Service Tags (${unresolvedTags.join(", ")}) könnten greifen`,
          },
        ]
      : [];
    // Service tag routes only concern traffic to that Azure service's addresses: they matter for a
    // concrete public destination IP, not for the generic "Internet" probe.
    if (unresolvedTags.length && dst.internet && q.destination.kind === "ip") uncertain = true;
    if (!route || route.nextHopType === "None") {
      add({
        type: "drop",
        nodeId: current.id,
        label: `Subnet ${current.name}`,
        reason: route ? `${describeRoute(route)} – Pakete werden verworfen` : "Keine passende Route",
        route,
        confidence: route?.confidence ?? "LIKELY",
        evidence: [
          {
            kind: "route",
            resourceId: route?.originId ?? current.routeTableId,
            description: route ? describeRoute(route) : "keine Route",
          },
          ...tagEvidence,
        ],
      });
      return finish("BLOCKED", route ? `Verworfen durch ${describeRoute(route)}` : "Keine Route zum Ziel");
    }
    add({
      type: "route",
      nodeId: current.id,
      label: `Subnet ${current.name}`,
      reason: describeRoute(route) + (route.note ? ` (${route.note})` : ""),
      route,
      confidence: route.confidence,
      evidence: [
        { kind: "route", resourceId: route.originId ?? current.id, description: describeRoute(route) },
        ...tagEvidence,
      ],
    });

    switch (route.nextHopType) {
      case "VnetLocal":
        return deliver(route.nextHopResourceId ?? current.vnetId);

      case "VNetPeering":
      case "ConnectedGroup": {
        const targetVnet = route.nextHopResourceId ?? current.vnetId;
        add({
          type: "peering",
          nodeId: targetVnet,
          label: nameOf(targetVnet),
          reason:
            route.nextHopType === "ConnectedGroup"
              ? `AVNM Connected Group zu ${nameOf(targetVnet)}`
              : `VNet-Peering zu ${nameOf(targetVnet)} (nicht transitiv)`,
          confidence: route.confidence,
          evidence: [
            {
              kind: "relationship",
              resourceId: route.originId ?? targetVnet,
              description:
                route.nextHopType === "ConnectedGroup"
                  ? "Mesh/Direct Connectivity des Virtual Network Managers"
                  : "Peering Connected, allowVirtualNetworkAccess",
            },
          ],
        });
        return deliver(targetVnet);
      }

      case "VirtualHub": {
        const link = ctx.hubConnectionByVnet.get(current.vnetId);
        const hubId = link?.hub.id ?? route.nextHopResourceId;
        add({
          type: "virtualHub",
          nodeId: hubId,
          label: nameOf(hubId),
          reason: `Virtual WAN Hub${route.note ? ` – ${route.note}` : ""}`,
          confidence: route.confidence,
          evidence: [{ kind: "route", resourceId: route.originId, description: describeRoute(route) }],
        });
        const target = route.nextHopResourceId;
        const fw = target ? ctx.firewalls.get(target) : undefined;
        if (fw) {
          const r = viaFirewall(fw, "Secured Virtual Hub");
          if (r.stop) return r.stop;
          if (dst.internet) return internetEgress(current);
          const destVnet = vnetContaining(ctx, destination);
          if (!destVnet) return finish("UNKNOWN", "Ziel hinter dem Virtual Hub nicht auflösbar (Branch/BGP)");
          return deliver(destVnet.id);
        }
        if (target && ctx.vnets.has(target)) return deliver(target);
        const destVnet = vnetContaining(ctx, destination);
        if (destVnet && ctx.hubConnectionByVnet.has(destVnet.id)) return deliver(destVnet.id);
        add({
          type: "onPremises",
          label: "Virtual WAN",
          reason: "Weiterleitung im Virtual WAN (Branch/Hub-zu-Hub, nicht vollständig einsehbar)",
          confidence: "POSSIBLE",
          evidence: [],
        });
        return finish("UNKNOWN", "Weiterleitung im Virtual WAN nicht vollständig prüfbar");
      }

      case "VirtualAppliance": {
        const nextIps =
          route.nextHopIpAddresses && route.nextHopIpAddresses.length > 1
            ? route.nextHopIpAddresses
            : route.nextHopIpAddress
              ? [route.nextHopIpAddress]
              : [];
        const nextIp = nextIps[0];
        if (!nextIp) {
          add({
            type: "drop",
            nodeId: current.id,
            label: "Next Hop",
            reason: "VirtualAppliance ohne Next-Hop-IP",
            confidence: "LIKELY",
            evidence: [],
          });
          return finish("BLOCKED", "Ungültige Route");
        }
        if (ipFamilyOf(nextIp) !== q.family) {
          add({
            type: "drop",
            nodeId: current.id,
            label: nextIp,
            reason: `Next-Hop-IP ${nextIp} passt nicht zur Adressfamilie ${familyLabel}`,
            confidence: "LIKELY",
            evidence: [],
          });
          return finish("BLOCKED", "Next Hop mit falscher Adressfamilie");
        }
        if (nextIps.length > 1) {
          const owners = nextIps.map((ip) => ({ ip, owner: ownerOfIp(ctx, ip) }));
          const kinds = new Set(owners.map((o) => o.owner?.kind ?? "unbekannt"));
          const unknown = owners.filter((o) => !o.owner).map((o) => o.ip);
          if (kinds.size > 1 || unknown.length) uncertain = true;
          add({
            type: "nva",
            nodeId: current.id,
            label: `ECMP (${nextIps.length} Next Hops)`,
            reason: `Equal-Cost Multipath über ${nextIps.join(", ")} – Flows werden verteilt; weiter mit ${nextIp}`,
            confidence: kinds.size > 1 || unknown.length ? "POSSIBLE" : "LIKELY",
            evidence: owners.map((o) => ({
              kind: "route" as const,
              resourceId: o.owner?.id,
              description: `${o.ip} → ${o.owner ? `${o.owner.kind} ${nameOf(o.owner.computeId ?? o.owner.id)}` : "nicht im Inventar"}`,
            })),
          });
          for (const o of owners) {
            const id = o.owner?.computeId ?? o.owner?.id;
            if (id && o.ip !== nextIp && !securityControls.includes(id)) securityControls.push(id);
          }
        }
        const owner = ownerOfIp(ctx, nextIp);
        const applianceId = owner ? (owner.computeId ?? owner.id) : undefined;
        if (applianceId && securityControls.includes(applianceId) && owner?.kind !== "firewall") {
          add({
            type: "drop",
            nodeId: applianceId,
            label: nameOf(applianceId),
            reason: "Routing-Schleife: Verkehr wird erneut an dieselbe Appliance geleitet",
            confidence: "LIKELY",
            evidence: [{ kind: "route", resourceId: route.originId, description: describeRoute(route) }],
          });
          return finish("UNKNOWN", "Routing-Schleife");
        }
        if (!owner) {
          add({
            type: "nva",
            label: nextIp,
            reason: `Next Hop ${nextIp} keiner bekannten Ressource zugeordnet`,
            confidence: "UNKNOWN",
            evidence: [{ kind: "missing-data", description: `IP ${nextIp} nicht im Inventar` }],
          });
          return finish("UNKNOWN", `Weiterleitung an unbekanntes Gerät ${nextIp}`);
        }
        if (owner.kind === "firewall") {
          const fw = ctx.firewalls.get(owner.id)!;
          const r = viaFirewall(fw, nextIp);
          if (r.stop) return r.stop;
          const fwSubnet = fw.ipConfigurations.find((c) => c.subnetId)?.subnetId;
          const next = fwSubnet ? ctx.subnets.get(fwSubnet) : undefined;
          if (!next) return finish("UNKNOWN", "Firewall-Subnet unbekannt");
          current = next;
          continue;
        }
        if (owner.kind === "nic" || owner.kind === "loadBalancer") {
          let nvaId = owner.computeId ?? owner.id;
          let nvaSubnet = owner.subnetId;
          const evidence: Evidence[] = [
            { kind: "heuristic", resourceId: nvaId, description: "Verhalten der NVA ist nicht einsehbar" },
          ];
          if (owner.kind === "loadBalancer") {
            const lb = ctx.loadBalancers.get(owner.id);
            add({
              type: "loadBalancer",
              nodeId: owner.id,
              label: nameOf(owner.id),
              reason: `Internal Load Balancer ${nextIp} (HA-NVA-Muster)`,
              confidence: "LIKELY",
              evidence: [],
            });
            const member = lb?.backendPools.flatMap((p) => p.memberIds)[0];
            if (!member) return finish("UNKNOWN", "Load Balancer ohne bekannte Backend-Mitglieder");
            const memberNic = ctx.nics.get(member);
            nvaId = memberNic?.vmId ?? member;
            nvaSubnet = memberNic?.subnetIds[0] ?? nvaSubnet;
          }
          const nic = ctx.nics.get(owner.id) ?? (ctx.nicsByCompute.get(nvaId) ?? [])[0];
          if (nic && !nic.ipForwarding && owner.kind === "nic") {
            add({
              type: "drop",
              nodeId: nvaId,
              label: nameOf(nvaId),
              reason: "IP-Forwarding an der NIC deaktiviert – weitergeleitete Pakete werden verworfen",
              confidence: "LIKELY",
              evidence: [{ kind: "property", resourceId: nic.id, description: "enableIPForwarding = false" }],
            });
            return finish("BLOCKED", `NVA ${nameOf(nvaId)} leitet nicht weiter (IP-Forwarding aus)`);
          }
          if (!securityControls.includes(nvaId)) securityControls.push(nvaId);
          uncertain = true;
          add({
            type: "nva",
            nodeId: nvaId,
            label: nameOf(nvaId),
            reason: `Network Virtual Appliance (${nextIp})`,
            confidence: "POSSIBLE",
            evidence,
          });
          const next = nvaSubnet ? ctx.subnets.get(nvaSubnet) : undefined;
          if (!next) return finish("UNKNOWN", "Subnet der NVA unbekannt");
          afterNva = nvaId;
          current = next;
          continue;
        }
        add({
          type: "nva",
          nodeId: owner.id,
          label: nameOf(owner.id),
          reason: `Next Hop ${nextIp} gehört zu ${owner.kind}`,
          confidence: "UNKNOWN",
          evidence: [],
        });
        return finish("UNKNOWN", "Unerwarteter Next Hop");
      }

      case "VirtualNetworkGateway": {
        const gw = route.nextHopResourceId ?? gatewaysReachableFrom(ctx, current.vnetId)[0]?.id;
        add({
          type: "gateway",
          nodeId: gw,
          label: nameOf(gw),
          reason: "Virtual Network Gateway (VPN/ExpressRoute)",
          confidence: route.confidence,
          evidence: [{ kind: "route", resourceId: route.originId, description: describeRoute(route) }],
        });
        if (dst.internet) {
          add({
            type: "onPremises",
            label: "On-Premises",
            reason: "Forced Tunneling: Internetverkehr wird ins On-Premises-Netz geleitet",
            confidence: "POSSIBLE",
            evidence: [],
          });
          return finish("UNKNOWN", "Internetverkehr per Forced Tunneling über das Gateway", {
            egress: {
              family: q.family,
              mechanism: "gateway",
              controlled: true,
              publicIps: [],
              resourceId: gw,
              confidence: "POSSIBLE",
              evidence: [],
            },
          });
        }
        add({
          type: "onPremises",
          label: "On-Premises",
          reason: "Weiterleitung über VPN/ExpressRoute (BGP nicht einsehbar)",
          confidence: "POSSIBLE",
          evidence: [],
        });
        return finish("UNKNOWN", "Weiterleitung ins On-Premises-Netz; Erreichbarkeit dort nicht prüfbar");
      }

      case "Internet":
        return internetEgress(current);
    }
  }
  return finish("UNKNOWN", "Maximale Hop-Anzahl erreicht");
}

/** IPv4 vs IPv6 for the same source/destination (Lastenheft § 53). */
export function compareFamilies(
  ctx: RoutingContext,
  sourceId: string,
  destination: PathQuery["destination"],
  options: { protocol?: PathQuery["protocol"]; port?: number } = {},
): PathComparison {
  const ipv4 = tracePath(ctx, { sourceId, destination, family: "ipv4", ...options });
  const ipv6 = tracePath(ctx, { sourceId, destination, family: "ipv6", ...options });
  const differences: string[] = [];
  let architectureGap: string | undefined;
  const na = (r: PathResult) => r.notApplicable === true;

  if (na(ipv6)) differences.push("Quelle oder Ziel hat kein IPv6 – nur IPv4-Pfad relevant.");
  else if (na(ipv4)) differences.push("Quelle oder Ziel hat kein IPv4 – nur IPv6-Pfad relevant.");
  else {
    if (ipv4.status !== ipv6.status) differences.push(`Status: IPv4 ${ipv4.status}, IPv6 ${ipv6.status}`);
    const fw4 = ipv4.securityControls.map(nameOf).join(", ") || "keine";
    const fw6 = ipv6.securityControls.map(nameOf).join(", ") || "keine";
    if (fw4 !== fw6) differences.push(`Sicherheitskontrollen: IPv4 ${fw4}, IPv6 ${fw6}`);
    if (ipv4.egress?.mechanism !== ipv6.egress?.mechanism && (ipv4.egress || ipv6.egress)) {
      differences.push(
        `Internet-Egress: IPv4 ${EGRESS_LABEL[ipv4.egress?.mechanism ?? "none"]}, IPv6 ${EGRESS_LABEL[ipv6.egress?.mechanism ?? "none"]}`,
      );
    }
    const v4Controlled = ipv4.securityControls.length > 0;
    const v6Open =
      ipv6.securityControls.length === 0 && (ipv6.status === "ALLOWED" || ipv6.status === "POTENTIAL_BYPASS");
    if (v4Controlled && v6Open) {
      architectureGap =
        "ARCHITECTURE GAP: IPv6 umgeht die zentralen Sicherheitskontrollen, die für IPv4 greifen.";
      if (ipv6.status === "ALLOWED") ipv6.status = "POTENTIAL_BYPASS";
    }
  }
  return { ipv4, ipv6, differences, ...(architectureGap ? { architectureGap } : {}) };
}
