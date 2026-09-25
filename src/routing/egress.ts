import type { IpFamily } from "../addressing/ip.js";
import type { FirewallEntity, NicEntity, SubnetEntity } from "../models/network.js";
import type { EgressInfo, Evidence, PathHop } from "../models/path.js";
import type { RoutingContext } from "./context.js";
import { nameOf } from "./endpoints.js";

export const EGRESS_LABEL: Record<EgressInfo["mechanism"], string> = {
  firewall: "Azure Firewall",
  nva: "NVA",
  natGateway: "NAT Gateway",
  instancePublicIp: "Public IP der Instanz",
  loadBalancerOutbound: "Load-Balancer-Outbound",
  defaultOutbound: "Default Outbound Access",
  gateway: "Gateway (Forced Tunneling)",
  none: "–",
  unknown: "unbekannt",
};

/**
 * Egress selection (Microsoft Learn, NAT Gateway overview): UDR to appliance/gateway > NAT Gateway >
 * instance-level public IP > load balancer outbound rules > default outbound access.
 */
export function resolveEgress(
  ctx: RoutingContext,
  s: {
    subnet: SubnetEntity;
    nic?: NicEntity | undefined;
    family: IpFamily;
    afterFirewall?: FirewallEntity | undefined;
    afterNva?: string | undefined;
  },
): EgressInfo {
  const { family } = s;
  const evidence: Evidence[] = [];
  const pipsOfFamily = (ids: string[]) =>
    ids.flatMap((id) => {
      const p = ctx.publicIps.get(id);
      return p && p.ipVersion === family ? [p.ipAddress ?? p.name] : [];
    });

  const nat = s.subnet.natGatewayId ? ctx.natGateways.get(s.subnet.natGatewayId) : undefined;
  const natSupports =
    nat &&
    (family === "ipv4"
      ? nat.ipv4EgressConfigured
      : nat.ipv6EgressConfigured && nat.sku.toLowerCase() === "standardv2");
  if (nat && !natSupports) {
    evidence.push({
      kind: "platform",
      resourceId: nat.id,
      description:
        family === "ipv6" && nat.sku.toLowerCase() !== "standardv2"
          ? `NAT Gateway ${nat.name} (SKU ${nat.sku}) unterstützt kein IPv6 – nur StandardV2`
          : `NAT Gateway ${nat.name} hat keine ${family}-Public-IP`,
    });
  }
  const natEgress = (): EgressInfo => ({
    family,
    mechanism: "natGateway",
    controlled: false,
    publicIps: [
      ...pipsOfFamily(nat!.publicIpIds),
      ...nat!.publicIpPrefixIds.flatMap((id) =>
        ctx.publicIpPrefixes.get(id)?.ipVersion === family
          ? [ctx.publicIpPrefixes.get(id)!.prefix ?? id]
          : [],
      ),
    ],
    resourceId: nat!.id,
    confidence: "CONFIRMED",
    evidence: [
      ...evidence,
      {
        kind: "property",
        resourceId: nat!.id,
        description: `NAT Gateway ${nat!.name} (SKU ${nat!.sku}) am Subnet`,
      },
    ],
  });

  if (s.afterFirewall) {
    const fw = s.afterFirewall;
    if (natSupports)
      return {
        ...natEgress(),
        mechanism: "firewall",
        controlled: true,
        resourceId: fw.id,
        evidence: [
          ...natEgress().evidence,
          {
            kind: "relationship",
            resourceId: fw.id,
            description: "Firewall-SNAT über den NAT Gateway des Firewall-Subnets",
          },
        ],
      };
    // Secured virtual hub firewall: public IPs come from hubIPAddresses (IPv4 only).
    const ips = fw.virtualHubId ? (family === "ipv4" ? fw.hubPublicIps : []) : pipsOfFamily(fw.publicIpIds);
    if (ips.length === 0) {
      return {
        family,
        mechanism: "none",
        controlled: true,
        publicIps: [],
        resourceId: fw.id,
        confidence: "LIKELY",
        evidence: [
          ...evidence,
          {
            kind: "property",
            resourceId: fw.id,
            description: `Firewall ${fw.name} hat keine ${family}-Public-IP`,
          },
        ],
      };
    }
    return {
      family,
      mechanism: "firewall",
      controlled: true,
      publicIps: ips,
      resourceId: fw.id,
      confidence: "CONFIRMED",
      evidence: [
        ...evidence,
        {
          kind: "property",
          resourceId: fw.id,
          description: `SNAT auf Firewall-Public-IP(s) ${ips.join(", ")}`,
        },
      ],
    };
  }
  if (s.afterNva) {
    return {
      family,
      mechanism: "nva",
      controlled: true,
      publicIps: [],
      resourceId: s.afterNva,
      confidence: "POSSIBLE",
      evidence: [
        ...evidence,
        {
          kind: "heuristic",
          resourceId: s.afterNva,
          description: "Egress über NVA; öffentliche Adresse der NVA nicht ausgewertet",
        },
      ],
    };
  }
  if (natSupports) return natEgress();

  const nic = s.nic;
  if (nic) {
    const ips = pipsOfFamily(nic.ipConfigurations.flatMap((c) => (c.publicIpId ? [c.publicIpId] : [])));
    if (ips.length > 0) {
      return {
        family,
        mechanism: "instancePublicIp",
        controlled: false,
        publicIps: ips,
        resourceId: nic.id,
        confidence: "CONFIRMED",
        evidence: [
          ...evidence,
          {
            kind: "property",
            resourceId: nic.id,
            description: `Öffentliche ${family}-Adresse direkt an der NIC: ${ips.join(", ")}`,
          },
        ],
      };
    }
    for (const c of nic.ipConfigurations) {
      for (const poolId of c.loadBalancerBackendPoolIds) {
        const lbId = poolId.split("/backendaddresspools/")[0]!;
        const lb = ctx.loadBalancers.get(lbId);
        if (!lb) continue;
        const pool = poolId.split("/").pop();
        const rule = lb.outboundRules.find((o) => o.backendPool === pool);
        const frontendIps = pipsOfFamily(
          lb.frontends
            .filter((f) => !rule || rule.frontendNames.includes(f.name))
            .flatMap((f) => (f.publicIpId ? [f.publicIpId] : [])),
        );
        if (rule && frontendIps.length > 0) {
          return {
            family,
            mechanism: "loadBalancerOutbound",
            controlled: false,
            publicIps: frontendIps,
            resourceId: lb.id,
            confidence: "CONFIRMED",
            evidence: [
              ...evidence,
              {
                kind: "property",
                resourceId: lb.id,
                description: `Outbound Rule ${rule.name} auf Load Balancer ${lb.name}`,
              },
            ],
          };
        }
      }
    }
  }

  if (family === "ipv4") {
    if (s.subnet.defaultOutboundAccess === false || nic?.defaultOutboundConnectivityEnabled === false) {
      return {
        family,
        mechanism: "none",
        controlled: false,
        publicIps: [],
        confidence: s.subnet.defaultOutboundAccess === false ? "CONFIRMED" : "LIKELY",
        evidence: [
          ...evidence,
          {
            kind: "property",
            resourceId: s.subnet.id,
            description:
              s.subnet.defaultOutboundAccess === false
                ? "Privates Subnet (defaultOutboundAccess = false), keine explizite Outbound-Methode"
                : "NIC nutzt keinen Default Outbound Access",
          },
        ],
      };
    }
    return {
      family,
      mechanism: "defaultOutbound",
      controlled: false,
      publicIps: [],
      confidence: s.subnet.defaultOutboundAccess === undefined ? "LIKELY" : "CONFIRMED",
      evidence: [
        ...evidence,
        {
          kind: "platform",
          resourceId: s.subnet.id,
          description:
            "Default Outbound Access (implizite, nicht kontrollierte Microsoft-IP; für neue VNets seit 31.03.2026 abgeschaltet)",
        },
      ],
    };
  }
  return {
    family,
    mechanism: "unknown",
    controlled: false,
    publicIps: [],
    confidence: "UNKNOWN",
    evidence: [
      ...evidence,
      {
        kind: "platform",
        description:
          "Keine explizite IPv6-Outbound-Methode (NAT StandardV2, Public IPv6, LB-Outbound). Default Outbound für IPv6 ist nicht dokumentiert – Internetzugang ungeklärt.",
      },
    ],
  };
}

export function egressHops(ctx: RoutingContext, e: EgressInfo): Omit<PathHop, "index">[] {
  if (
    e.mechanism === "natGateway" ||
    (e.mechanism === "firewall" && e.evidence.some((x) => x.description.includes("NAT Gateway")))
  ) {
    const natId = e.evidence.find((x) => x.resourceId && ctx.natGateways.has(x.resourceId))?.resourceId;
    return [
      {
        type: "natGateway",
        nodeId: natId,
        label: nameOf(natId),
        reason: `SNAT auf ${e.publicIps.join(", ") || "NAT-IPs"}`,
        confidence: e.confidence,
        evidence: e.evidence,
      },
    ];
  }
  if (
    e.mechanism === "instancePublicIp" ||
    e.mechanism === "firewall" ||
    e.mechanism === "loadBalancerOutbound"
  ) {
    return [
      {
        type: "publicIp",
        nodeId: e.resourceId,
        label: e.publicIps.join(", ") || "Public IP",
        reason: `Öffentliche Adresse (${EGRESS_LABEL[e.mechanism]})`,
        confidence: e.confidence,
        evidence: e.evidence,
      },
    ];
  }
  if (e.mechanism === "defaultOutbound") {
    return [
      {
        type: "publicIp",
        label: "Default Outbound IP",
        reason: "Implizite Microsoft-IP (nicht kontrolliert)",
        confidence: e.confidence,
        evidence: e.evidence,
      },
    ];
  }
  return [];
}
