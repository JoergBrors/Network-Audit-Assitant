import type { IpFamily } from "../addressing/ip.js";
import type { NormalizedInventory } from "../models/network.js";
import type { EgressMechanism, PathStatus } from "../models/path.js";
import { buildRoutingContext, type RoutingContext } from "./context.js";
import { tracePath } from "./trace.js";

/** Platform subnets whose traffic is not workload traffic. */
const PLATFORM_SUBNETS =
  /^(gatewaysubnet|azurefirewallsubnet|azurefirewallmanagementsubnet|azurebastionsubnet|routeserversubnet)$/i;

export interface DefaultPathSummary {
  subnetId: string;
  subnet: string;
  vnetId: string;
  vnet: string;
  family: IpFamily;
  status: PathStatus;
  egress: EgressMechanism;
  controlled: boolean;
  securityControls: string[];
  publicIps: string[];
  firstHop: string;
  summary: string;
  confidence: string;
}

/**
 * Internet default path of every workload subnet per IP family (configuration-based, ARCHITECTURE § 12).
 * Used for assessmentContext.ipv4DefaultPaths / ipv6DefaultPaths and the routing overview.
 */
export function analyzeDefaultPaths(
  inv: NormalizedInventory,
  ctx: RoutingContext = buildRoutingContext(inv),
): DefaultPathSummary[] {
  const out: DefaultPathSummary[] = [];
  for (const subnet of inv.subnets) {
    if (PLATFORM_SUBNETS.test(subnet.name)) continue;
    const vnet = ctx.vnets.get(subnet.vnetId);
    for (const family of ["ipv4", "ipv6"] as const) {
      if (subnet.prefixes[family].length === 0) continue;
      const r = tracePath(ctx, { sourceId: subnet.id, destination: { kind: "internet" }, family });
      const route = r.hops.find((h) => h.type === "route")?.route;
      out.push({
        subnetId: subnet.id,
        subnet: subnet.name,
        vnetId: subnet.vnetId,
        vnet: vnet?.name ?? subnet.vnetId,
        family,
        status: r.status,
        egress: r.egress?.mechanism ?? (r.status === "BLOCKED" ? "none" : "unknown"),
        controlled: r.securityControls.length > 0,
        securityControls: r.securityControls,
        publicIps: r.egress?.publicIps ?? [],
        firstHop: route
          ? `${route.prefix} → ${route.nextHopType}${route.nextHopIpAddress ? ` ${route.nextHopIpAddress}` : ""} (${route.source})`
          : "–",
        summary: r.summary,
        confidence: r.confidence,
      });
    }
  }
  return out;
}

export interface Ipv6BypassGap {
  resourceId: string;
  name: string;
  kind: "subnet" | "nic";
  ipv4: { status: PathStatus; egress: EgressMechanism; securityControls: string[] };
  ipv6: { status: PathStatus; egress: EgressMechanism };
  description: string;
}

/**
 * Subnets and NICs where IPv4 Internet traffic passes a central security control but IPv6 does not
 * (Lastenheft § 52, NET-IPV6-003 precursor until the assessment engine exists).
 */
export function findIpv6Bypasses(
  inv: NormalizedInventory,
  ctx: RoutingContext = buildRoutingContext(inv),
): Ipv6BypassGap[] {
  const out: Ipv6BypassGap[] = [];
  const check = (id: string, name: string, kind: Ipv6BypassGap["kind"]) => {
    const v4 = tracePath(ctx, { sourceId: id, destination: { kind: "internet" }, family: "ipv4" });
    const v6 = tracePath(ctx, { sourceId: id, destination: { kind: "internet" }, family: "ipv6" });
    if (v4.notApplicable || v6.notApplicable) return;
    const v6Reaches = v6.status === "ALLOWED" || v6.status === "POTENTIAL_BYPASS";
    if (v4.securityControls.length > 0 && v6.securityControls.length === 0 && v6Reaches) {
      out.push({
        resourceId: id,
        name,
        kind,
        ipv4: {
          status: v4.status,
          egress: v4.egress?.mechanism ?? "unknown",
          securityControls: v4.securityControls,
        },
        ipv6: { status: v6.status, egress: v6.egress?.mechanism ?? "unknown" },
        description: `IPv4 über ${v4.securityControls.map((c) => c.split("/").pop()).join(", ")}, IPv6 direkt über ${v6.egress?.mechanism ?? "unbekannt"} – IPv6 umgeht die zentrale Sicherheitskontrolle`,
      });
    }
  };
  for (const s of inv.subnets)
    if (s.prefixes.ipv4.length && s.prefixes.ipv6.length && !PLATFORM_SUBNETS.test(s.name))
      check(s.id, s.name, "subnet");
  for (const n of inv.networkInterfaces)
    if (n.addressing.ipv4.length && n.addressing.ipv6.length) check(n.id, n.name, "nic");
  return out;
}
