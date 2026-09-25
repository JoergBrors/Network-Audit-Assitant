import { z } from "zod";
import { DiscoveryQualitySchema, DiscoveryWarningSchema } from "../models/discovery.js";
import { buildGraph } from "../graph/buildGraph.js";
import { NetworkGraphSchema, type NetworkGraph } from "../models/graph.js";
import type { NormalizedInventory } from "../models/network.js";
import type { NetworkModel } from "../pipeline/analyze.js";
import { architectureType } from "../topology/classify.js";
import { buildRoutingContext } from "../routing/context.js";
import { analyzeDefaultPaths, findIpv6Bypasses } from "../routing/analysis.js";
import { analyzeInbound } from "../routing/inbound.js";

export const TOOL_NAME = "azure-network-audit-assistant";
export const TOOL_VERSION = "0.1.0";
/** 0.x until the assessment sections are implemented (IMPLEMENTATION_PLAN.md phases 9–14). */
export const EXPORT_SCHEMA_VERSION = "0.6.0";

/** Which analysis parts this export contains. Consumers (incl. AI tools) must not infer missing parts. */
export const EXPORT_COVERAGE = {
  inventory: "complete",
  graph: "complete",
  hubSpokeDetection: "complete",
  nvaDetection: "complete",
  routingAnalysis:
    "configuration-based (UDRs, system routes, peerings, gateway prefixes; BGP-learned routes not visible)",
  dualStackAnalysis: "not-yet-implemented",
  assessmentFindings: "not-yet-implemented",
} as const;

const pad = (n: number) => String(n).padStart(2, "0");

/** azure-network-assessment-YYYYMMDD-HHMM.json (local time). */
export function assessmentFileName(date: Date): string {
  return `azure-network-assessment-${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}.json`;
}

export function buildAssessmentExport(
  model: NetworkModel,
  options: { now?: Date; snapshotId?: string } = {},
) {
  const inv = model.inventory;
  const now = options.now ?? new Date();
  const vnets = inv.vnets;
  const hubs = vnets.filter((v) => v.topology?.classification === "hub");
  const spokes = vnets.filter((v) => v.topology?.classification === "spoke");
  const regions = [...new Set(vnets.flatMap((v) => (v.location ? [v.location] : [])))].sort();
  const count = (c: string) => vnets.filter((v) => v.ipClassification === c).length;
  const routing = buildRoutingContext(inv);
  const defaultPaths = analyzeDefaultPaths(inv, routing);
  const bypasses = findIpv6Bypasses(inv, routing);
  const inbound = analyzeInbound(routing);
  const reachable = inbound.filter((e) => e.status !== "BLOCKED");
  const compactPath = (p: (typeof defaultPaths)[number]) => ({
    subnetId: p.subnetId,
    subnet: p.subnet,
    vnet: p.vnet,
    status: p.status,
    firstHop: p.firstHop,
    egress: p.egress,
    centrallyControlled: p.controlled,
    securityControls: p.securityControls,
    publicIps: p.publicIps,
    confidence: p.confidence,
  });
  const egressSummary = (family: "ipv4" | "ipv6") => {
    const list = defaultPaths.filter((p) => p.family === family);
    const by: Record<string, number> = {};
    for (const p of list) {
      const key = `${p.egress}${p.controlled ? " (controlled)" : ""}`;
      by[key] = (by[key] ?? 0) + 1;
    }
    return {
      subnets: list.length,
      byEgress: by,
      potentialBypass: list.filter((p) => p.status === "POTENTIAL_BYPASS").length,
    };
  };

  return {
    metadata: {
      tool: TOOL_NAME,
      toolVersion: TOOL_VERSION,
      schemaVersion: EXPORT_SCHEMA_VERSION,
      exportedAt: now.toISOString(),
      discoveredAt: inv.generatedAt,
      readOnly: true,
      sanitized: false,
      coverage: EXPORT_COVERAGE,
      description:
        "Normalized Azure network inventory and relationship graph. IDs are lowercase ARM resource IDs. Hierarchy (tenant > subscription > region > VNet > subnet > resource) is expressed by graph.nodes[].parentId; graph.edges describe relationships (peering, attached, route, securedBy, natThrough, privateEndpoint, gatewayConnection, dnsLink, backendOf, policyOf, monitoredBy, connectedTo). Individual UDRs are listed in `routes`; route edges start at their route table.",
    },
    snapshotMetadata: {
      snapshotId: options.snapshotId ?? globalThis.crypto.randomUUID(),
      generatedAt: inv.generatedAt,
      tenantIds: [...new Set(inv.subscriptions.map((s) => s.tenantId))].sort(),
      subscriptionIds: inv.subscriptions.map((s) => s.subscriptionId),
      resourceCount: model.graph.nodes.length,
    },
    summary: {
      subscriptions: inv.subscriptions.length,
      vnets: vnets.length,
      subnets: inv.subnets.length,
      peerings: inv.peerings.length,
      ipv4OnlyVnets: count("ipv4-only"),
      ipv6OnlyVnets: count("ipv6-only"),
      dualStackVnets: count("dual-stack"),
      hubs: hubs.length,
      spokes: spokes.length,
      firewalls: inv.firewalls.length,
      natGateways: inv.natGateways.length,
      vpnGateways: inv.vpnGateways.filter((g) => g.gatewayType?.toLowerCase() !== "expressroute").length,
      expressRouteGateways: inv.vpnGateways.filter((g) => g.gatewayType?.toLowerCase() === "expressroute")
        .length,
      nsgs: inv.nsgs.length,
      routeTables: inv.routeTables.length,
      privateEndpoints: inv.privateEndpoints.length,
      publicIps: inv.publicIps.length,
      graphNodes: model.graph.nodes.length,
      graphEdges: model.graph.edges.length,
    },
    discovery: model.discovery,
    assessmentContext: {
      architectureType: architectureType(vnets),
      regions,
      networkCharacteristics: {
        ipv4: vnets.some((v) => v.addressSpace.ipv4.length > 0),
        ipv6: vnets.some((v) => v.addressSpace.ipv6.length > 0),
        dualStack: vnets.some((v) => v.ipClassification === "dual-stack"),
      },
      centralServices: {
        firewall: inv.firewalls.length > 0,
        natGateway: inv.natGateways.length > 0,
        vpnGateway: inv.vpnGateways.some((g) => g.gatewayType?.toLowerCase() === "vpn"),
        expressRoute: inv.vpnGateways.some((g) => g.gatewayType?.toLowerCase() === "expressroute"),
      },
      identifiedHubs: hubs.map((v) => ({
        id: v.id,
        name: v.name,
        confidence: v.topology?.confidence,
        reasons: v.topology?.reasons,
      })),
      identifiedSpokes: spokes.map((v) => ({
        id: v.id,
        name: v.name,
        hubIds: v.topology?.hubIds,
        confidence: v.topology?.confidence,
      })),
      internetEgressPaths: { ipv4: egressSummary("ipv4"), ipv6: egressSummary("ipv6") },
      ipv4DefaultPaths: defaultPaths.filter((p) => p.family === "ipv4").map(compactPath),
      ipv6DefaultPaths: defaultPaths.filter((p) => p.family === "ipv6").map(compactPath),
      internetIngressPaths: inbound.map((e) => ({
        family: e.family,
        entry: e.entry,
        targetId: e.targetId,
        target: e.targetName,
        targetAddress: e.targetAddress,
        status: e.status,
        centrallyControlled: e.controlled,
        openPorts: e.openPorts,
        restrictedPorts: e.restricted,
        asymmetricRouting: e.asymmetricRouting,
        confidence: e.confidence,
        summary: e.summary,
      })),
      knownArchitectureGaps: [
        ...bypasses.map((b) => ({ type: "IPV6_FIREWALL_BYPASS", ...b })),
        ...reachable
          .filter((e) => !e.controlled && e.openPorts.length > 0)
          .map((e) => ({
            type: e.family === "ipv6" ? "IPV6_INBOUND_EXPOSURE" : "UNCONTROLLED_INBOUND_EXPOSURE",
            targetId: e.targetId,
            entry: e.entry.kind,
            publicAddress: e.entry.publicAddress,
            openPorts: e.openPorts,
          })),
        ...reachable
          .filter((e) => e.asymmetricRouting)
          .map((e) => ({
            type: "ASYMMETRIC_INBOUND_ROUTING",
            targetId: e.targetId,
            entry: e.entry.kind,
            publicAddress: e.entry.publicAddress,
          })),
      ],
    },
    addressing: {
      ipv4: {
        vnetAddressSpaces: vnets.flatMap((v) =>
          v.addressSpace.ipv4.map((prefix) => ({ vnetId: v.id, vnet: v.name, prefix })),
        ),
        subnetPrefixes: inv.subnets.flatMap((s) =>
          s.prefixes.ipv4.map((prefix) => ({ subnetId: s.id, prefix })),
        ),
      },
      ipv6: {
        vnetAddressSpaces: vnets.flatMap((v) =>
          v.addressSpace.ipv6.map((prefix) => ({ vnetId: v.id, vnet: v.name, prefix })),
        ),
        subnetPrefixes: inv.subnets.flatMap((s) =>
          s.prefixes.ipv6.map((prefix) => ({ subnetId: s.id, prefix })),
        ),
      },
    },
    ...inventorySections(inv),
    graph: compactGraph(model.graph),
  };
}

/**
 * Export form of the graph: without `contains` edges (redundant with parentId) and without
 * per-route nodes (redundant with the `routes` section); route edges are re-anchored at their
 * route table. The full graph is rebuilt deterministically from the inventory on import.
 */
export function compactGraph(graph: NetworkGraph): NetworkGraph {
  const routeTableOf = new Map(graph.nodes.filter((n) => n.type === "route").map((n) => [n.id, n.parentId]));
  const edges = graph.edges.flatMap((e) => {
    if (e.type === "contains") return [];
    if (!routeTableOf.has(e.source)) return [e];
    const table = routeTableOf.get(e.source);
    if (!table) return [];
    const routeName = e.source.split("/").pop() ?? "";
    return [
      {
        ...e,
        id: `${e.type}:${table}->${e.target}#${routeName}`,
        source: table,
        properties: { ...e.properties, route: routeName },
      },
    ];
  });
  return { nodes: graph.nodes.filter((n) => n.type !== "route"), edges };
}

function inventorySections(inv: NormalizedInventory) {
  return {
    tenants: inv.tenants,
    managementGroups: inv.managementGroups,
    subscriptions: inv.subscriptions,
    vnets: inv.vnets,
    subnets: inv.subnets,
    peerings: inv.peerings,
    routeTables: inv.routeTables,
    routes: inv.routes,
    firewalls: inv.firewalls,
    firewallPolicies: inv.firewallPolicies,
    ruleCollectionGroups: inv.ruleCollectionGroups,
    ipGroups: inv.ipGroups,
    nsgs: inv.nsgs,
    natGateways: inv.natGateways,
    publicIps: inv.publicIps,
    publicIpPrefixes: inv.publicIpPrefixes,
    networkInterfaces: inv.networkInterfaces,
    virtualMachines: inv.virtualMachines,
    scaleSets: inv.scaleSets,
    loadBalancers: inv.loadBalancers,
    applicationGateways: inv.applicationGateways,
    vpnGateways: inv.vpnGateways,
    localNetworkGateways: inv.localNetworkGateways,
    connections: inv.connections,
    privateEndpoints: inv.privateEndpoints,
    privateDnsZones: inv.privateDnsZones,
    dnsResolvers: inv.dnsResolvers,
    otherNetworkResources: inv.otherNetworkResources,
    unclassifiedNetworkResources: inv.unclassifiedNetworkResources,
    virtualHubs: inv.virtualHubs,
    serviceTags: inv.serviceTags,
    avnm: inv.avnm,
  };
}

export type AssessmentExport = ReturnType<typeof buildAssessmentExport>;

const section = z.array(z.looseObject({}));
const ImportSchema = z.looseObject({
  metadata: z.looseObject({ tool: z.literal(TOOL_NAME), schemaVersion: z.string().regex(/^0\./) }),
  discovery: z.object({ quality: DiscoveryQualitySchema, warnings: z.array(DiscoveryWarningSchema) }),
  graph: NetworkGraphSchema,
  ...Object.fromEntries(
    Object.keys(inventorySections(emptyInventory()))
      .filter((k) => k !== "avnm")
      .map((k) => [k, k === "virtualHubs" || k === "serviceTags" ? section.optional() : section]),
  ),
  avnm: z.looseObject({}).optional(),
});

export class SnapshotImportError extends Error {
  override readonly name = "SnapshotImportError";
}

/** Parses an exported snapshot back into a NetworkModel (offline analysis). */
export function parseAssessmentExport(text: string): NetworkModel {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new SnapshotImportError("Die Datei ist kein gültiges JSON.");
  }
  const parsed = ImportSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new SnapshotImportError(
      `Kein gültiger Export dieses Tools (${issue ? `${issue.path.join(".")}: ${issue.message}` : "unbekannter Fehler"}).`,
    );
  }
  const doc = parsed.data as unknown as AssessmentExport;
  // Sections missing in older exports fall back to empty defaults.
  const sections = Object.fromEntries(
    Object.entries(inventorySections(doc as unknown as NormalizedInventory)).filter(
      ([, v]) => v !== undefined,
    ),
  );
  const inventory = {
    ...emptyInventory(),
    ...sections,
    generatedAt: doc.snapshotMetadata?.generatedAt ?? doc.metadata.exportedAt,
  };
  // The exported graph is compact; the UI works on the full graph rebuilt from the inventory.
  return { inventory, graph: buildGraph(inventory), discovery: doc.discovery };
}

function emptyInventory(): NormalizedInventory {
  return {
    generatedAt: "",
    tenants: [],
    subscriptions: [],
    managementGroups: [],
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
    virtualHubs: [],
    serviceTags: [],
    avnm: { adminRules: [], vnetAdminConfigurations: {}, connectedGroups: [] },
  };
}
