import type { VisibleGraph } from "../../graph/view.js";

/** Minimal ELK JSON types (subset of elkjs' ElkNode) shared between main thread and worker. */
export interface ElkInputNode {
  id: string;
  width?: number;
  height?: number;
  layoutOptions?: Record<string, string>;
  children?: ElkInputNode[];
  edges?: { id: string; sources: string[]; targets: string[] }[];
}

export interface ElkOutputNode {
  id: string;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  children?: ElkOutputNode[];
}

export const NODE_WIDTH = 230;
export const NODE_HEIGHT = 62;
export const CONTAINER_HEADER = 40;

/**
 * Builds a hierarchical ELK graph. Every container is laid out separately (SEPARATE_CHILDREN):
 * `layered` when its children are connected, `rectpacking` (compact grid) otherwise. Cross-container
 * relationships are added between the children of the lowest common container so that they still
 * influence placement (e.g. spokes next to their hub).
 */
export function toElkGraph(view: VisibleGraph): ElkInputNode {
  const byId = new Map<string, ElkInputNode>();
  const containerOf = new Map<string, string | undefined>();
  const root: ElkInputNode = { id: "__root__", children: [], edges: [] };

  for (const v of view.nodes) {
    byId.set(v.node.id, { id: v.node.id, children: [], edges: [] });
    containerOf.set(v.node.id, v.containerId);
  }
  for (const v of view.nodes) {
    const node = byId.get(v.node.id)!;
    const parent = v.containerId ? byId.get(v.containerId) : root;
    (parent ?? root).children!.push(node);
  }

  const chain = (id: string): string[] => {
    const out = [id];
    let current = containerOf.get(id);
    while (current) {
      out.unshift(current);
      current = containerOf.get(current);
    }
    return ["__root__", ...out];
  };
  const seen = new Set<string>();
  for (const e of view.edges) {
    const a = chain(e.source);
    const b = chain(e.target);
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    const lca = a[i - 1]!;
    const s = a[i];
    const t = b[i];
    if (!s || !t || s === t) continue;
    const key = `${lca}|${s}|${t}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const holder = lca === "__root__" ? root : byId.get(lca)!;
    holder.edges!.push({ id: `e${seen.size}`, sources: [s], targets: [t] });
  }

  const finalize = (node: ElkInputNode, isRoot: boolean): void => {
    const children = node.children ?? [];
    if (children.length === 0) {
      node.width = NODE_WIDTH;
      node.height = NODE_HEIGHT;
      delete node.children;
      delete node.edges;
      return;
    }
    for (const c of children) finalize(c, false);
    const connected = (node.edges?.length ?? 0) > 0;
    node.layoutOptions = {
      "elk.algorithm": connected ? "layered" : "rectpacking",
      "elk.direction": "DOWN",
      "elk.spacing.nodeNode": "28",
      "elk.layered.spacing.nodeNodeBetweenLayers": "60",
      "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
      // Bound the width of a layer so hubs with many spokes wrap into several rows.
      "elk.layered.layering.strategy": "COFFMAN_GRAHAM",
      "elk.layered.layering.coffmanGraham.layerBound": String(
        Math.max(4, Math.ceil(Math.sqrt(children.length) * 1.5)),
      ),
      "elk.rectpacking.widthApproximation.targetWidth": String(
        Math.max(3, Math.ceil(Math.sqrt(children.length))) * (NODE_WIDTH + 28),
      ),
      "elk.padding": isRoot
        ? "[top=20,left=20,bottom=20,right=20]"
        : `[top=${CONTAINER_HEADER},left=16,bottom=16,right=16]`,
      "elk.hierarchyHandling": "SEPARATE_CHILDREN",
    };
  };
  finalize(root, true);
  return root;
}

export interface Positioned {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Flattens the ELK result; positions are relative to the parent container (as React Flow expects). */
export function flattenLayout(result: ElkOutputNode): Map<string, Positioned> {
  const out = new Map<string, Positioned>();
  const walk = (n: ElkOutputNode) => {
    for (const c of n.children ?? []) {
      out.set(c.id, {
        x: c.x ?? 0,
        y: c.y ?? 0,
        width: c.width ?? NODE_WIDTH,
        height: c.height ?? NODE_HEIGHT,
      });
      walk(c);
    }
  };
  walk(result);
  return out;
}
