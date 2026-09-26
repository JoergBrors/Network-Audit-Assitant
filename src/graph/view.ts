import type { EdgeType, GraphEdge, GraphNode, NetworkGraph, NodeType } from "../models/graph.js";

/** UI modes for IP families (ARCHITECTURE.md § 18). */
export type IpViewMode = "all" | "ipv4" | "ipv6" | "dual";

export interface ViewState {
  /** Level of detail 1–5. */
  level: number;
  /** Nodes whose children are shown regardless of level (drill-down). */
  expanded: ReadonlySet<string>;
  /** Restricts the view to this node's subtree plus its direct relationships. */
  focusId?: string | undefined;
  subscriptionIds?: ReadonlySet<string> | undefined;
  ipMode: IpViewMode;
  /** Snapshot comparison: IDs of changed components (resources and endpoints of changed relationships). */
  changedIds?: ReadonlySet<string> | undefined;
  /** Show only changed components (plus related context). */
  onlyChanges?: boolean | undefined;
  /**
   * Path highlighting: these nodes (and their containers) are shown regardless of level of detail;
   * everything else is hidden. Overrides the IP and change filters.
   */
  pathIds?: ReadonlySet<string> | undefined;
  /**
   * Element types left out of the overview (their children still show, grouped under the nearest
   * visible ancestor). Not applied to the focus subtree, path mode or children of expanded nodes.
   */
  hiddenTypes?: ReadonlySet<NodeType> | undefined;
  /**
   * Tag filter: nodes whose tags match. They are shown regardless of level of detail and type filter,
   * with their containers and directly related components as context.
   */
  tagIds?: ReadonlySet<string> | undefined;
}

/** Hierarchy levels that are always shown, so the view stays hierarchical under a type filter. */
export const STRUCTURAL_TYPES: ReadonlySet<NodeType> = new Set([
  "tenant",
  "subscription",
  "region",
  "vnet",
  "internet",
]);

export interface VisibleNode {
  node: GraphNode;
  /** Visible ancestor that renders as a container around this node. */
  containerId?: string | undefined;
  isContainer: boolean;
  /** Number of hidden children (for "+n" badges / drill-down hints). */
  hiddenChildren: number;
  /** True for nodes pulled in only because they are related to the focused subtree. */
  neighbor: boolean;
  /**
   * Filter emphasis: `match` = matches the active filters (IP mode, only changes), `context` = shown
   * only because it is related to (or contains) a matching component, `normal` = no filter active.
   */
  emphasis: "normal" | "match" | "context";
}

export interface VisibleEdge {
  id: string;
  type: EdgeType;
  source: string;
  target: string;
  /** Number of underlying graph edges merged into this edge. */
  count: number;
  families: ("ipv4" | "ipv6" | "both")[];
  label?: string | undefined;
  /** Underlying edge IDs (for the detail panel). */
  edgeIds: string[];
  /** True when neither endpoint matches the active IP mode (rendered in the background). */
  context: boolean;
}

export interface VisibleGraph {
  nodes: VisibleNode[];
  edges: VisibleEdge[];
  /** The requested level of detail exceeded MAX_VISIBLE_NODES; a reduced view is returned instead. */
  truncated: boolean;
  /** Number of elements the requested level of detail would have shown. */
  totalCandidates: number;
  /** Level of detail actually rendered (lower than requested when truncated). */
  effectiveLevel: number;
  /** Even the lowest level exceeded the limit; only the first MAX_VISIBLE_NODES elements are shown. */
  capped: boolean;
  /** Components matching the active IP mode (equals node count when no IP filter is active). */
  matchCount: number;
}

export const MAX_VISIBLE_NODES = 1500;
/** Related nodes outside a focused subtree are shown at most at this level of detail. */
const NEIGHBOR_MAX_LEVEL = 4;
/**
 * Path mode: resources attached to a path node are shown as context (security and routing
 * configuration, addresses, the VM/NIC pair). NICs and VMs are not pulled in from subnets or VNets,
 * which may hold hundreds of them.
 */
const PATH_CONTEXT_TYPES = new Set([
  "nsg",
  "routeTable",
  "natGateway",
  "publicIp",
  "publicIpPrefix",
  "firewallPolicy",
  "wafPolicy",
  "nic",
  "vm",
]);
const PATH_CONTEXT_EDGES = new Set<EdgeType>(["attached", "securedBy", "natThrough", "policyOf"]);

/** Organisational nodes are never pulled in as neighbours (they would only duplicate hierarchy). */
const CONTAINER_ONLY_TYPES = new Set(["tenant", "subscription", "region"]);

export interface GraphIndex {
  byId: Map<string, GraphNode>;
  children: Map<string, GraphNode[]>;
  relations: GraphEdge[];
  edgesByNode: Map<string, GraphEdge[]>;
}

const TYPE_ORDER: Record<string, number> = {
  tenant: 0,
  subscription: 1,
  region: 2,
  vnet: 3,
  subnet: 4,
  azureFirewall: 5,
  vpnGateway: 6,
  expressRouteGateway: 6,
  natGateway: 7,
  routeTable: 8,
  nsg: 9,
};

export function compareNodes(a: GraphNode, b: GraphNode): number {
  return (
    (TYPE_ORDER[a.type] ?? 50) - (TYPE_ORDER[b.type] ?? 50) ||
    a.type.localeCompare(b.type) ||
    a.name.localeCompare(b.name)
  );
}

export function indexGraph(graph: NetworkGraph): GraphIndex {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const children = new Map<string, GraphNode[]>();
  for (const n of graph.nodes) {
    if (!n.parentId) continue;
    const list = children.get(n.parentId) ?? [];
    list.push(n);
    children.set(n.parentId, list);
  }
  for (const list of children.values()) list.sort(compareNodes);
  const relations = graph.edges.filter((e) => e.type !== "contains");
  const edgesByNode = new Map<string, GraphEdge[]>();
  for (const e of relations) {
    for (const end of [e.source, e.target]) {
      const list = edgesByNode.get(end) ?? [];
      list.push(e);
      edgesByNode.set(end, list);
    }
  }
  return { byId, children, relations, edgesByNode };
}

export function ancestors(index: GraphIndex, id: string): GraphNode[] {
  const out: GraphNode[] = [];
  let current = index.byId.get(id)?.parentId;
  const guard = new Set<string>();
  while (current && !guard.has(current)) {
    guard.add(current);
    const node = index.byId.get(current);
    if (!node) break;
    out.unshift(node);
    current = node.parentId;
  }
  return out;
}

function inSubscriptionFilter(node: GraphNode, filter: ReadonlySet<string> | undefined): boolean {
  if (!filter || filter.size === 0) return true;
  if (!node.subscriptionId)
    return node.type === "tenant" || node.type === "internet" || node.type === "externalResource";
  return filter.has(node.subscriptionId);
}

/** True if the node itself is configured for the IP mode (own addresses / prefixes). */
export function nodeMatchesMode(node: GraphNode, mode: IpViewMode): boolean {
  switch (mode) {
    case "all":
      return true;
    case "ipv4":
      return node.addressing.ipv4.length > 0;
    case "ipv6":
      return node.addressing.ipv6.length > 0;
    case "dual":
      return node.addressing.classification === "dual-stack";
  }
}

function edgeMatchesMode(edge: GraphEdge, mode: IpViewMode): boolean {
  if (!edge.family || edge.family === "both" || mode === "all" || mode === "dual") return true;
  return edge.family === mode;
}

/** Computes the visible node/edge set for the topology view. Pure and deterministic. */
/**
 * Visible graph for the view state. If the requested level of detail would exceed MAX_VISIBLE_NODES,
 * the level is reduced step by step until the view fits (expanded, focused and path nodes stay
 * visible); as a last resort the view is capped – there is always something to show.
 */
export function computeVisibleGraph(index: GraphIndex, state: ViewState): VisibleGraph {
  const requested = computeAtLevel(index, state, false);
  if (!requested.truncated) return requested;
  for (let level = state.level - 1; level >= 1; level--) {
    const reduced = computeAtLevel(index, { ...state, level }, false);
    if (!reduced.truncated)
      return { ...reduced, truncated: true, totalCandidates: requested.totalCandidates };
  }
  const capped = computeAtLevel(index, { ...state, level: Math.min(state.level, 1) }, true);
  return { ...capped, truncated: true, totalCandidates: requested.totalCandidates };
}

function computeAtLevel(index: GraphIndex, state: ViewState, cap: boolean): VisibleGraph {
  const visible = new Set<string>();
  const neighbors = new Set<string>();

  const focus = state.focusId ? index.byId.get(state.focusId) : undefined;
  const hiddenTypes = focus || state.pathIds ? undefined : state.hiddenTypes;
  const include = (node: GraphNode, depthOk: (n: GraphNode) => boolean): void => {
    const stack: [GraphNode, boolean][] = [[node, false]];
    while (stack.length > 0) {
      const [current, forced] = stack.pop()!;
      if (!inSubscriptionFilter(current, state.subscriptionIds)) continue;
      // Hidden types are skipped, but their children are still traversed (and grouped one level up).
      if (forced || !hiddenTypes?.has(current.type) || STRUCTURAL_TYPES.has(current.type))
        visible.add(current.id);
      const expanded = state.expanded.has(current.id);
      for (const child of index.children.get(current.id) ?? []) {
        if (expanded || depthOk(child)) stack.push([child, expanded]);
      }
    }
  };
  const byLevel = (n: GraphNode) => n.lod <= state.level;

  if (focus) {
    include(focus, byLevel);
    // Directly related nodes outside the focused subtree, lifted to the current level of detail.
    const subtree = new Set(visible);
    for (const id of subtree) {
      for (const e of index.edgesByNode.get(id) ?? []) {
        if (!edgeMatchesMode(e, state.ipMode)) continue;
        const other = e.source === id ? e.target : e.source;
        if (subtree.has(other)) continue;
        // Neighbours are summarised at resource level: routes/rules collapse into their table/policy.
        const lifted = liftToLevel(index, other, Math.min(state.level, NEIGHBOR_MAX_LEVEL));
        if (
          lifted &&
          !subtree.has(lifted.id) &&
          !CONTAINER_ONLY_TYPES.has(lifted.type) &&
          inSubscriptionFilter(lifted, state.subscriptionIds)
        ) {
          visible.add(lifted.id);
          neighbors.add(lifted.id);
        }
      }
    }
  } else {
    const roots = [...index.byId.values()].filter((n) => !n.parentId).sort(compareNodes);
    for (const root of roots) if (byLevel(root) || state.expanded.has(root.id)) include(root, byLevel);
  }

  // Path mode: path nodes, their attached resources (context) and all ancestors are always visible.
  const pathContext = new Set<string>();
  if (state.pathIds) {
    const onPath = [...state.pathIds].filter((id) => index.byId.has(id));
    const addContext = (id: string) => {
      if (state.pathIds!.has(id) || !inSubscriptionFilter(index.byId.get(id)!, state.subscriptionIds)) return;
      pathContext.add(id);
    };
    for (const id of onPath) {
      const node = index.byId.get(id)!;
      const bulk = node.type === "subnet" || node.type === "vnet";
      // A VM's NICs are its children; their NSGs and public IPs belong to the VM's path too.
      const sources = [id];
      if (node.type === "vm") {
        for (const c of index.children.get(id) ?? []) {
          if (c.type !== "nic") continue;
          addContext(c.id);
          sources.push(c.id);
        }
      }
      for (const src of sources) {
        for (const e of index.edgesByNode.get(src) ?? []) {
          if (!PATH_CONTEXT_EDGES.has(e.type)) continue;
          const other = index.byId.get(e.source === src ? e.target : e.source);
          if (!other || !PATH_CONTEXT_TYPES.has(other.type)) continue;
          if (bulk && (other.type === "nic" || other.type === "vm")) continue;
          addContext(other.id);
        }
      }
    }
    for (const id of [...onPath, ...pathContext]) {
      let current: string | undefined = id;
      while (current) {
        visible.add(current);
        current = index.byId.get(current)?.parentId;
      }
    }
  }

  // Tag filter: tagged nodes (and their ancestors) are shown regardless of level of detail.
  const tagFilter = !state.pathIds && state.tagIds !== undefined;
  if (tagFilter) {
    // In focus mode only tagged nodes inside the focused subtree are added.
    const subtreeOk = (id: string) => {
      if (!focus) return true;
      for (let c: string | undefined = id; c; c = index.byId.get(c)?.parentId)
        if (c === focus.id) return true;
      return visible.has(id);
    };
    for (const id of state.tagIds!) {
      const node = index.byId.get(id);
      if (!node || !inSubscriptionFilter(node, state.subscriptionIds) || !subtreeOk(id)) continue;
      let current: string | undefined = id;
      while (current) {
        visible.add(current);
        current = index.byId.get(current)?.parentId;
      }
    }
  }

  // Relationship edges are lifted to the nearest visible ancestors.
  const nearestVisible = (id: string): string | undefined => {
    let current: string | undefined = id;
    while (current) {
      if (visible.has(current)) return current;
      current = index.byId.get(current)?.parentId;
    }
    return undefined;
  };
  const isAncestor = (a: string, b: string): boolean => {
    let current = index.byId.get(b)?.parentId;
    while (current) {
      if (current === a) return true;
      current = index.byId.get(current)?.parentId;
    }
    return false;
  };
  const liftedEdge = (e: GraphEdge): [string, string] | undefined => {
    const s = nearestVisible(e.source);
    const t = nearestVisible(e.target);
    if (!s || !t || s === t || isAncestor(s, t) || isAncestor(t, s)) return undefined;
    return [s, t];
  };

  // IP mode filter: keep matching components, their containers and directly related components
  // (as background context); everything else is hidden.
  const matches = new Set<string>();
  const pathFilter = state.pathIds !== undefined;
  const changeFilter = !pathFilter && state.onlyChanges === true && state.changedIds !== undefined;
  const filterActive = pathFilter || state.ipMode !== "all" || changeFilter || tagFilter;
  if (pathFilter) {
    for (const id of state.pathIds!) if (visible.has(id)) matches.add(id);
    const keep = new Set([...matches, ...pathContext]);
    for (const id of [...keep]) {
      let parent = index.byId.get(id)?.parentId;
      while (parent && visible.has(parent)) {
        keep.add(parent);
        parent = index.byId.get(parent)?.parentId;
      }
    }
    for (const id of [...visible]) if (!keep.has(id)) visible.delete(id);
  } else if (filterActive) {
    // Changes hidden below the current level of detail are attributed to their nearest visible ancestor.
    const changedVisible = new Set<string>();
    if (changeFilter) {
      for (const id of state.changedIds!) {
        const v = nearestVisible(id);
        if (v) changedVisible.add(v);
      }
    }
    for (const id of visible) {
      if (!nodeMatchesMode(index.byId.get(id)!, state.ipMode)) continue;
      if (changeFilter && !changedVisible.has(id)) continue;
      if (tagFilter && !state.tagIds!.has(id)) continue;
      matches.add(id);
    }
    const keep = new Set(matches);
    for (const e of index.relations) {
      if (!edgeMatchesMode(e, state.ipMode)) continue;
      const ends = liftedEdge(e);
      if (!ends) continue;
      if (matches.has(ends[0])) keep.add(ends[1]);
      if (matches.has(ends[1])) keep.add(ends[0]);
    }
    for (const id of [...keep]) {
      // Ancestors of hidden types are not visible; the walk continues past them.
      let parent = index.byId.get(id)?.parentId;
      while (parent && !keep.has(parent)) {
        if (visible.has(parent)) keep.add(parent);
        parent = index.byId.get(parent)?.parentId;
      }
    }
    for (const id of [...visible]) if (!keep.has(id)) visible.delete(id);
  }
  const matchCount = filterActive ? matches.size : visible.size;

  const totalCandidates = visible.size;
  const truncated = totalCandidates > MAX_VISIBLE_NODES;
  const effectiveLevel = state.level;
  if (truncated && !cap)
    return { nodes: [], edges: [], truncated, totalCandidates, matchCount, effectiveLevel, capped: false };
  if (truncated) {
    // Keep the coarsest elements; a node's ancestors have a lower or equal level, so they sort first.
    const ordered = [...visible]
      .map((id) => index.byId.get(id)!)
      .sort((a, b) => a.lod - b.lod || compareNodes(a, b));
    const keep = new Set<string>();
    for (const n of ordered) {
      if (keep.size >= MAX_VISIBLE_NODES) break;
      if (!n.parentId || !visible.has(n.parentId) || keep.has(n.parentId)) keep.add(n.id);
    }
    for (const id of [...visible]) if (!keep.has(id)) visible.delete(id);
  }

  // Containers: visible nodes with at least one visible child.
  // The nearest visible ancestor is the container (a hidden-type parent is skipped).
  const visibleParent = (id: string): string | undefined => {
    const parent = index.byId.get(id)?.parentId;
    return parent ? nearestVisible(parent) : undefined;
  };
  const containerIds = new Set<string>();
  for (const id of visible) {
    const parent = visibleParent(id);
    if (parent && !neighbors.has(id)) containerIds.add(parent);
  }

  const nodes: VisibleNode[] = [...visible].map((id) => {
    const node = index.byId.get(id)!;
    const children = index.children.get(id) ?? [];
    const parent = visibleParent(id);
    return {
      node,
      containerId: parent && containerIds.has(parent) && !neighbors.has(id) ? parent : undefined,
      isContainer: containerIds.has(id),
      hiddenChildren: children.filter((c) => !visible.has(c.id)).length,
      neighbor: neighbors.has(id),
      emphasis: !filterActive ? "normal" : matches.has(id) ? "match" : "context",
    };
  });
  // Parents must precede children (React Flow requirement).
  const byVisibleId = new Map(nodes.map((v) => [v.node.id, v]));
  const depthCache = new Map<string, number>();
  const depth = (v: VisibleNode): number => {
    const cached = depthCache.get(v.node.id);
    if (cached !== undefined) return cached;
    const container = v.containerId ? byVisibleId.get(v.containerId) : undefined;
    const d = container ? depth(container) + 1 : 0;
    depthCache.set(v.node.id, d);
    return d;
  };
  nodes.sort((a, b) => depth(a) - depth(b) || compareNodes(a.node, b.node));

  // Merge lifted relationship edges.
  const merged = new Map<string, VisibleEdge>();
  for (const e of index.relations) {
    if (!edgeMatchesMode(e, state.ipMode)) continue;
    const ends = liftedEdge(e);
    if (!ends) continue;
    const [s, t] = ends;
    const key = `${e.type}:${s}->${t}`;
    const existing = merged.get(key);
    if (existing) {
      existing.count++;
      existing.edgeIds.push(e.id);
      if (e.family && !existing.families.includes(e.family)) existing.families.push(e.family);
    } else {
      merged.set(key, {
        id: key,
        type: e.type,
        source: s,
        target: t,
        count: 1,
        families: e.family ? [e.family] : [],
        label: e.label,
        edgeIds: [e.id],
        context: filterActive && !matches.has(s) && !matches.has(t),
      });
    }
  }
  return {
    nodes,
    edges: [...merged.values()],
    truncated,
    totalCandidates,
    matchCount,
    effectiveLevel,
    capped: truncated,
  };
}

/** Nearest ancestor-or-self whose level of detail is within `level`. */
export function liftToLevel(index: GraphIndex, id: string, level: number): GraphNode | undefined {
  let current = index.byId.get(id);
  while (current && current.lod > level)
    current = current.parentId ? index.byId.get(current.parentId) : undefined;
  return current;
}
