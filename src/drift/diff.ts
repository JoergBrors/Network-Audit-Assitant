import { ipFamilyOf, type IpFamily } from "../addressing/ip.js";
import type { EdgeType, GraphEdge, GraphNode, NetworkGraph, NodeType } from "../models/graph.js";
import { EDGE_TYPE_LABELS, NODE_TYPE_LABELS } from "../models/graph.js";
import type { NetworkModel } from "../pipeline/analyze.js";

/** SNAPSHOT-AND-DRIFT.md: drift categories (Lastenheft § 72). */
export type DriftCategory =
  "INFORMATIONAL" | "EXPECTED" | "SECURITY_RELEVANT" | "ARCHITECTURE_RELEVANT" | "POTENTIALLY_BREAKING";

export const CATEGORY_ORDER: DriftCategory[] = [
  "POTENTIALLY_BREAKING",
  "SECURITY_RELEVANT",
  "ARCHITECTURE_RELEVANT",
  "EXPECTED",
  "INFORMATIONAL",
];

export type ChangeKind = "added" | "removed" | "changed";

export interface FieldChange {
  /** Dotted path, e.g. `rules[allow-https]` or `addressSpace.ipv6`. */
  path: string;
  kind: ChangeKind;
  before?: unknown;
  after?: unknown;
}

export interface ResourceChange {
  id: string;
  kind: ChangeKind;
  nodeType: NodeType;
  name: string;
  subscriptionId?: string | undefined;
  category: DriftCategory;
  families: IpFamily[];
  summary: string;
  fields: FieldChange[];
}

export interface RelationshipChange {
  id: string;
  kind: "added" | "removed";
  type: EdgeType;
  source: string;
  target: string;
  family?: GraphEdge["family"];
  category: DriftCategory;
  summary: string;
}

export interface SnapshotDiff {
  baseline: { generatedAt: string };
  current: { generatedAt: string };
  resources: ResourceChange[];
  relationships: RelationshipChange[];
  summary: {
    added: number;
    removed: number;
    changed: number;
    relationshipsAdded: number;
    relationshipsRemoved: number;
    byCategory: Record<DriftCategory, number>;
    ipv4Changes: number;
    ipv6Changes: number;
  };
}

/** Synthetic / structural nodes that are not compared as resources. */
const SKIPPED_NODE_TYPES = new Set<NodeType>(["tenant", "region", "internet", "externalResource"]);
const SKIPPED_EDGE_TYPES = new Set<EdgeType>(["contains"]);

const ARCHITECTURE_TYPES = new Set<NodeType>([
  "vnet",
  "subnet",
  "azureFirewall",
  "natGateway",
  "vpnGateway",
  "expressRouteGateway",
  "expressRouteCircuit",
  "localNetworkGateway",
  "gatewayConnection",
  "virtualHub",
  "virtualWan",
  "routeServer",
  "loadBalancer",
  "applicationGateway",
  "privateDnsZone",
  "dnsResolver",
  "dnsForwardingRuleset",
  "subscription",
]);
const SECURITY_TYPES = new Set<NodeType>([
  "nsg",
  "azureFirewall",
  "firewallPolicy",
  "ruleCollectionGroup",
  "ipGroup",
  "wafPolicy",
  "publicIp",
  "publicIpPrefix",
  "privateEndpoint",
  "paasService",
  "bastion",
]);
const ROUTING_TYPES = new Set<NodeType>(["route", "routeTable"]);

const OPEN_SOURCES = new Set(["*", "internet", "0.0.0.0/0", "::/0", "any"]);

/**
 * Semantic diff between a baseline snapshot and the current state (not a JSON diff): resources are
 * matched by normalized resource ID, compared field by field on the normalized model, and every
 * change is classified (drift category, IPv4/IPv6 involvement).
 */
export function diffModels(baseline: NetworkModel, current: NetworkModel): SnapshotDiff {
  const before = entityIndex(baseline);
  const after = entityIndex(current);
  const beforeNodes = new Map(baseline.graph.nodes.map((n) => [n.id, n]));
  const afterNodes = new Map(current.graph.nodes.map((n) => [n.id, n]));

  const resources: ResourceChange[] = [];
  const ids = new Set([...beforeNodes.keys(), ...afterNodes.keys()]);
  for (const id of [...ids].sort()) {
    // A resource that is only referenced (external placeholder) no longer exists in the inventory.
    const real = (n: GraphNode | undefined) => (n && !SKIPPED_NODE_TYPES.has(n.type) ? n : undefined);
    const oldNode = real(beforeNodes.get(id));
    const newNode = real(afterNodes.get(id));
    if (!oldNode && !newNode) continue;
    const node = (newNode ?? oldNode)!;
    if (!oldNode) {
      resources.push(resourceChange("added", node, [], after.get(id)));
    } else if (!newNode) {
      resources.push(resourceChange("removed", node, [], before.get(id)));
    } else {
      const fields = diffValues(before.get(id) ?? nodeFacts(oldNode), after.get(id) ?? nodeFacts(newNode));
      if (fields.length > 0) resources.push(resourceChange("changed", newNode, fields, after.get(id)));
    }
  }

  const relationships: RelationshipChange[] = [];
  const oldEdges = new Map(
    baseline.graph.edges.filter((e) => !SKIPPED_EDGE_TYPES.has(e.type)).map((e) => [e.id, e]),
  );
  const newEdges = new Map(
    current.graph.edges.filter((e) => !SKIPPED_EDGE_TYPES.has(e.type)).map((e) => [e.id, e]),
  );
  const nameOf = (id: string) =>
    afterNodes.get(id)?.name ?? beforeNodes.get(id)?.name ?? id.split("/").pop() ?? id;
  for (const [id, e] of newEdges)
    if (!oldEdges.has(id)) relationships.push(relationshipChange("added", e, nameOf));
  for (const [id, e] of oldEdges)
    if (!newEdges.has(id)) relationships.push(relationshipChange("removed", e, nameOf));
  relationships.sort((a, b) => a.id.localeCompare(b.id));

  const byCategory = Object.fromEntries(CATEGORY_ORDER.map((c) => [c, 0])) as Record<DriftCategory, number>;
  for (const c of [...resources, ...relationships]) byCategory[c.category]++;
  const familyCount = (f: IpFamily) =>
    resources.filter((r) => r.families.includes(f)).length +
    relationships.filter((r) => r.family === f || r.family === "both").length;

  return {
    baseline: { generatedAt: baseline.inventory.generatedAt },
    current: { generatedAt: current.inventory.generatedAt },
    resources,
    relationships,
    summary: {
      added: resources.filter((r) => r.kind === "added").length,
      removed: resources.filter((r) => r.kind === "removed").length,
      changed: resources.filter((r) => r.kind === "changed").length,
      relationshipsAdded: relationships.filter((r) => r.kind === "added").length,
      relationshipsRemoved: relationships.filter((r) => r.kind === "removed").length,
      byCategory,
      ipv4Changes: familyCount("ipv4"),
      ipv6Changes: familyCount("ipv6"),
    },
  };
}

// ---------------------------------------------------------------------------------------------

function entityIndex(model: NetworkModel): Map<string, unknown> {
  const map = new Map<string, unknown>();
  for (const value of Object.values(model.inventory)) {
    if (!Array.isArray(value)) continue;
    for (const entity of value as Record<string, unknown>[]) {
      if (typeof entity["id"] === "string" && !map.has(entity["id"])) map.set(entity["id"], entity);
    }
  }
  return map;
}

/** Fallback comparison basis for graph nodes without an inventory entity. */
function nodeFacts(node: GraphNode): unknown {
  return { name: node.name, addressing: node.addressing, properties: node.properties };
}

function resourceChange(
  kind: ChangeKind,
  node: GraphNode,
  fields: FieldChange[],
  entity: unknown,
): ResourceChange {
  const families =
    kind === "changed"
      ? familiesOf(fields.flatMap((f) => [f.before, f.after]))
      : familiesOf([entity ?? node.addressing]);
  const category = classifyResourceChange(kind, node, fields);
  const label = NODE_TYPE_LABELS[node.type];
  const summary =
    kind === "added"
      ? `${label} hinzugefügt`
      : kind === "removed"
        ? `${label} entfernt`
        : `${label} geändert: ${[...new Set(fields.map((f) => topLevel(f.path)))].join(", ")}`;
  return {
    id: node.id,
    kind,
    nodeType: node.type,
    name: node.name,
    ...(node.subscriptionId ? { subscriptionId: node.subscriptionId } : {}),
    category,
    families,
    summary,
    fields,
  };
}

function relationshipChange(
  kind: "added" | "removed",
  e: GraphEdge,
  nameOf: (id: string) => string,
): RelationshipChange {
  let category: DriftCategory = "ARCHITECTURE_RELEVANT";
  if (e.type === "securedBy" && kind === "removed") category = "POTENTIALLY_BREAKING";
  else if (
    e.type === "securedBy" ||
    e.type === "policyOf" ||
    (e.type === "attached" && /\/(networksecuritygroups|publicipaddresses)\//.test(e.target))
  )
    category = "SECURITY_RELEVANT";
  else if (e.type === "route" && /^internet:/.test(e.target)) category = "SECURITY_RELEVANT";
  else if (e.type === "monitoredBy" || e.type === "connectedTo") category = "INFORMATIONAL";
  const verb = kind === "added" ? "neu" : "entfernt";
  return {
    id: e.id,
    kind,
    type: e.type,
    source: e.source,
    target: e.target,
    ...(e.family ? { family: e.family } : {}),
    category,
    summary: `${EDGE_TYPE_LABELS[e.type]} ${verb}: ${nameOf(e.source)} → ${nameOf(e.target)}${e.label ? ` (${e.label})` : ""}`,
  };
}

const topLevel = (path: string) => path.split(/[.[]/)[0] ?? path;

function classifyResourceChange(kind: ChangeKind, node: GraphNode, fields: FieldChange[]): DriftCategory {
  const type = node.type;
  if (kind !== "changed") {
    if (type === "route")
      return node.properties["defaultRoute"] === true ? "POTENTIALLY_BREAKING" : "ARCHITECTURE_RELEVANT";
    if (SECURITY_TYPES.has(type)) return "SECURITY_RELEVANT";
    if (ARCHITECTURE_TYPES.has(type) || ROUTING_TYPES.has(type)) return "ARCHITECTURE_RELEVANT";
    return "INFORMATIONAL";
  }
  const paths = fields.map((f) => f.path);
  if (paths.every((p) => topLevel(p) === "tags")) return "INFORMATIONAL";
  if (
    ROUTING_TYPES.has(type) &&
    paths.some((p) => /nextHop|addressPrefix|defaultRoute|disableBgpRoutePropagation/.test(p))
  ) {
    return "POTENTIALLY_BREAKING";
  }
  if (type === "vnet" && fields.some((f) => topLevel(f.path) === "addressSpace" && f.kind !== "added"))
    return "POTENTIALLY_BREAKING";
  if (paths.some((p) => /useRemoteGateways|allowGatewayTransit|allowForwardedTraffic|peeringState/.test(p)))
    return "POTENTIALLY_BREAKING";
  if (fields.some(opensInboundAccess)) return "SECURITY_RELEVANT";
  if (
    SECURITY_TYPES.has(type) ||
    paths.some((p) => /nsgId|rules|publicIp|firewallPolicyId|threatIntel/.test(p))
  ) {
    return "SECURITY_RELEVANT";
  }
  if (paths.some((p) => /topology|nva/.test(p))) return "ARCHITECTURE_RELEVANT";
  return ARCHITECTURE_TYPES.has(type) || ROUTING_TYPES.has(type) ? "ARCHITECTURE_RELEVANT" : "INFORMATIONAL";
}

/** An NSG rule (new or changed) that allows inbound traffic from any/Internet source. */
function opensInboundAccess(field: FieldChange): boolean {
  if (!field.path.startsWith("rules") || field.after === undefined) return false;
  const rule = field.after as { direction?: string; access?: string; sources?: string[] };
  return (
    rule.direction === "Inbound" &&
    rule.access === "Allow" &&
    (rule.sources ?? []).some((s) => OPEN_SOURCES.has(s.toLowerCase()))
  );
}

function familiesOf(values: unknown[]): IpFamily[] {
  const found = new Set<IpFamily>();
  const walk = (v: unknown, depth: number) => {
    if (depth > 6 || found.size === 2) return;
    if (typeof v === "string") {
      const f = ipFamilyOf(v);
      if (f) found.add(f);
    } else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1);
    else if (v && typeof v === "object") for (const x of Object.values(v)) walk(x, depth + 1);
  };
  for (const v of values) walk(v, 0);
  return [...found].sort();
}

// ---------------------------------------------------------------------------------------------
// Structural value diff

function stable(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) {
    const items = value.map(canonical);
    return items.every((i) => typeof i !== "object" || i === null)
      ? [...items].sort((a, b) => String(a).localeCompare(String(b)))
      : [...items].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((k) => [k, canonical((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
}

const keyOf = (item: unknown): string | undefined => {
  if (!item || typeof item !== "object") return undefined;
  const o = item as Record<string, unknown>;
  const key = o["id"] ?? o["name"];
  return typeof key === "string" ? key : undefined;
};

/** Field-level diff of two normalized entities; keyed arrays (rules, routes, links, …) are diffed per element. */
export function diffValues(before: unknown, after: unknown, path = ""): FieldChange[] {
  if (stable(before) === stable(after)) return [];
  const isObj = (v: unknown) => v !== null && typeof v === "object" && !Array.isArray(v);

  if (isObj(before) && isObj(after)) {
    const b = before as Record<string, unknown>;
    const a = after as Record<string, unknown>;
    const out: FieldChange[] = [];
    for (const key of [...new Set([...Object.keys(b), ...Object.keys(a)])].sort()) {
      const p = path ? `${path}.${key}` : key;
      if (!(key in b) || b[key] === undefined) {
        if (a[key] !== undefined && !isEmpty(a[key])) out.push({ path: p, kind: "added", after: a[key] });
      } else if (!(key in a) || a[key] === undefined) {
        if (!isEmpty(b[key])) out.push({ path: p, kind: "removed", before: b[key] });
      } else {
        out.push(...diffValues(b[key], a[key], p));
      }
    }
    return out;
  }

  if (Array.isArray(before) && Array.isArray(after)) {
    const all: unknown[] = [...(before as unknown[]), ...(after as unknown[])];
    const keyed = all.length > 0 && all.every((i) => keyOf(i) !== undefined);
    if (keyed) {
      const b = new Map(before.map((i) => [keyOf(i)!, i]));
      const a = new Map(after.map((i) => [keyOf(i)!, i]));
      const out: FieldChange[] = [];
      for (const [k, v] of a) {
        const label = `${path}[${k.split("/").pop()}]`;
        if (!b.has(k)) out.push({ path: label, kind: "added", after: v });
        else if (stable(b.get(k)) !== stable(v))
          out.push({ path: label, kind: "changed", before: b.get(k), after: v });
      }
      for (const [k, v] of b)
        if (!a.has(k)) out.push({ path: `${path}[${k.split("/").pop()}]`, kind: "removed", before: v });
      return out;
    }
    if (before.every((i) => typeof i !== "object") && after.every((i) => typeof i !== "object")) {
      const b = new Set(before.map(String));
      const a = new Set(after.map(String));
      const added = [...a].filter((x) => !b.has(x));
      const removed = [...b].filter((x) => !a.has(x));
      const out: FieldChange[] = [];
      if (added.length) out.push({ path, kind: "added", after: added });
      if (removed.length) out.push({ path, kind: "removed", before: removed });
      return out;
    }
  }
  return [{ path, kind: "changed", before, after }];
}

const isEmpty = (v: unknown) => (Array.isArray(v) && v.length === 0) || v === "" || v === null;

// ---------------------------------------------------------------------------------------------
// Display graph

export interface ComparisonGraph {
  graph: NetworkGraph;
  nodeChanges: Map<string, ResourceChange>;
  edgeChanges: Map<string, RelationshipChange>;
  /** Number of changed resources/relationships at or below each node (for "Δ n" badges). */
  changesBelow: Map<string, number>;
}

/**
 * Current graph plus "ghost" nodes/edges that only exist in the baseline, so removed components
 * stay visible at their former place.
 */
export function buildComparisonGraph(
  baseline: NetworkGraph,
  current: NetworkGraph,
  diff: SnapshotDiff,
): ComparisonGraph {
  const nodes = new Map(current.nodes.map((n) => [n.id, n]));
  const baselineNodes = new Map(baseline.nodes.map((n) => [n.id, n]));
  const removed = diff.resources.filter((r) => r.kind === "removed");
  const addGhost = (id: string): void => {
    // External placeholders (e.g. a peering to a deleted VNet) are replaced by the former resource.
    if (nodes.has(id) && nodes.get(id)!.type !== "externalResource") return;
    const node = baselineNodes.get(id);
    if (!node) return;
    nodes.set(id, node);
    if (node.parentId) addGhost(node.parentId);
  };
  for (const r of removed) addGhost(r.id);

  const edges = new Map(current.edges.map((e) => [e.id, e]));
  for (const e of baseline.edges) {
    if (!edges.has(e.id) && nodes.has(e.source) && nodes.has(e.target)) edges.set(e.id, e);
  }

  const nodeChanges = new Map(diff.resources.map((r) => [r.id, r]));
  const edgeChanges = new Map(diff.relationships.map((r) => [r.id, r]));
  const changesBelow = new Map<string, number>();
  const bump = (id: string | undefined) => {
    let current = id;
    const guard = new Set<string>();
    while (current && !guard.has(current)) {
      guard.add(current);
      changesBelow.set(current, (changesBelow.get(current) ?? 0) + 1);
      current = nodes.get(current)?.parentId;
    }
  };
  for (const r of diff.resources) bump(r.id);
  for (const r of diff.relationships) bump(r.source);

  return {
    graph: {
      nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
      edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)),
    },
    nodeChanges,
    edgeChanges,
    changesBelow,
  };
}

// ---------------------------------------------------------------------------------------------
// Export (Lastenheft § 78)

const pad = (n: number) => String(n).padStart(2, "0");

export function diffFileName(date: Date): string {
  return `azure-network-diff-${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}.json`;
}

export function buildDiffExport(diff: SnapshotDiff, now = new Date()) {
  const byArea = (pattern: RegExp) =>
    diff.resources.filter((r) => pattern.test(r.nodeType) || r.fields.some((f) => pattern.test(f.path)));
  return {
    metadata: {
      tool: "azure-network-audit-assistant",
      schemaVersion: "0.1.0",
      exportedAt: now.toISOString(),
    },
    sourceSnapshot: diff.baseline,
    targetSnapshot: diff.current,
    summary: {
      added: diff.summary.added,
      removed: diff.summary.removed,
      changed: diff.summary.changed,
      relationshipsAdded: diff.summary.relationshipsAdded,
      relationshipsRemoved: diff.summary.relationshipsRemoved,
      byCategory: diff.summary.byCategory,
      newFindings: null,
      resolvedFindings: null,
    },
    resources: {
      added: diff.resources.filter((r) => r.kind === "added"),
      removed: diff.resources.filter((r) => r.kind === "removed"),
      changed: diff.resources.filter((r) => r.kind === "changed"),
    },
    relationships: diff.relationships,
    networkChanges: {
      addressing: byArea(/addressSpace|prefixes|addressing/),
      routing: byArea(/^route|routeTable|nextHop/),
      peerings: diff.relationships.filter((r) => r.type === "peering"),
      firewall: byArea(/azureFirewall|firewallPolicy|ruleCollectionGroup/),
      nsg: byArea(/^nsg$|rules/),
      nat: byArea(/natGateway/),
      dns: byArea(/Dns|dns/),
    },
    ipv4Changes: diff.resources.filter((r) => r.families.includes("ipv4")),
    ipv6Changes: diff.resources.filter((r) => r.families.includes("ipv6")),
    assessment: {
      note: "Finding lifecycle follows with the assessment engine (IMPLEMENTATION_PLAN.md phase 11).",
    },
  };
}
