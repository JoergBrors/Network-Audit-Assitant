import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { EDGE_TYPE_LABELS } from "../../models/graph.js";
import type { IpViewMode, VisibleGraph } from "../../graph/view.js";
import type { ComparisonGraph } from "../../drift/diff.js";
import { LayoutClient } from "./layoutClient.js";
import type { Positioned } from "./elkGraph.js";
import { NODE_COMPONENTS, type TopologyNodeData } from "./nodes.js";
import { categoryOf, DIRECTED, EDGE_CLASS } from "./nodeStyle.js";

export interface TopologyViewProps {
  view: VisibleGraph;
  expanded: ReadonlySet<string>;
  selectedId: string | undefined;
  ipMode: IpViewMode;
  showEdgeLabels: boolean;
  /** Node to bring into view after the next layout (e.g. after a tree or search selection). */
  revealId: string | undefined;
  onSelect: (id: string | undefined) => void;
  onToggleExpand: (id: string) => void;
  /** Snapshot comparison decorations. */
  changes?: ComparisonGraph | undefined;
  /** True when IP mode or "only changes" filter is active (for the empty-result message). */
  filterActive?: boolean;
  /** Ordered node IDs of a traced network path, drawn as animated path edges. */
  pathEdges?: string[] | undefined;
}

export function TopologyView(props: TopologyViewProps) {
  return (
    <ReactFlowProvider>
      <TopologyCanvas {...props} />
    </ReactFlowProvider>
  );
}

function TopologyCanvas({
  view,
  expanded,
  selectedId,
  ipMode,
  showEdgeLabels,
  revealId,
  onSelect,
  onToggleExpand,
  changes,
  filterActive,
  pathEdges,
}: TopologyViewProps) {
  const layoutClient = useMemo(() => new LayoutClient(), []);
  useEffect(() => () => layoutClient.dispose(), [layoutClient]);
  const [positions, setPositions] = useState<{ key: string; map: Map<string, Positioned> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const layoutKey = useMemo(() => LayoutClient.key(view), [view]);
  const flow = useReactFlow();
  const lastFitKey = useRef<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    layoutClient
      .layout(view)
      .then((map) => {
        if (!cancelled) setPositions({ key: layoutKey, map });
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [layoutClient, view, layoutKey]);

  const ready = positions?.key === layoutKey;

  const nodes = useMemo<Node<TopologyNodeData>[]>(() => {
    if (!ready) return [];
    return view.nodes.map((v) => {
      const p = positions.map.get(v.node.id) ?? { x: 0, y: 0, width: 230, height: 62 };
      return {
        id: v.node.id,
        type: v.isContainer ? "container" : "resource",
        position: { x: p.x, y: p.y },
        ...(v.containerId ? { parentId: v.containerId } : {}),
        data: {
          node: v.node,
          hiddenChildren: v.hiddenChildren,
          expanded: expanded.has(v.node.id),
          neighbor: v.neighbor,
          emphasis: v.emphasis,
          change: changes?.nodeChanges.get(v.node.id)?.kind,
          changesBelow: changes?.changesBelow.get(v.node.id) ?? 0,
        },
        selected: v.node.id === selectedId,
        style: { width: p.width, height: p.height },
        className: `rf-${categoryOf(v.node.type)}`,
      } satisfies Node<TopologyNodeData>;
    });
  }, [ready, positions, view, expanded, selectedId, changes]);

  const edges = useMemo<Edge[]>(() => {
    if (!ready) return [];
    const result: Edge[] = view.edges.map((e) => {
      const family =
        e.families.length === 1 ? ` fam-${e.families[0]}` : e.families.length > 1 ? " fam-both" : "";
      const baseLabel = showEdgeLabels ? (e.label ?? EDGE_TYPE_LABELS[e.type]) : undefined;
      const label = e.count > 1 ? `${baseLabel ? `${baseLabel} ` : ""}×${e.count}` : baseLabel;
      const edgeChange = changes
        ? e.edgeIds.map((id) => changes.edgeChanges.get(id)?.kind).find(Boolean)
        : undefined;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        className: `${EDGE_CLASS[e.type]}${family}${e.context ? " edge-context" : ""}${edgeChange ? ` edge-${edgeChange}` : ""}`,
        ...(label ? { label } : {}),
        ...(DIRECTED.has(e.type) ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        focusable: false,
      } satisfies Edge;
    });
    if (pathEdges && pathEdges.length > 1) {
      const visibleIds = new Set(view.nodes.map((n) => n.node.id));
      const chain = pathEdges.filter((id) => visibleIds.has(id));
      for (let i = 1; i < chain.length; i++) {
        result.push({
          id: `path:${i}:${chain[i - 1]}->${chain[i]}`,
          source: chain[i - 1]!,
          target: chain[i]!,
          className: "edge-path",
          animated: true,
          label: String(i),
          markerEnd: { type: MarkerType.ArrowClosed },
          focusable: false,
          zIndex: 1000,
        });
      }
    }
    return result;
  }, [ready, view, showEdgeLabels, changes, pathEdges]);

  // Fit the whole view when the structure changes; center on a revealed node otherwise.
  useEffect(() => {
    if (!ready) return;
    const handle = requestAnimationFrame(() => {
      if (revealId && view.nodes.some((n) => n.node.id === revealId)) {
        void flow.fitView({ nodes: [{ id: revealId }], maxZoom: 1.1, duration: 400 });
        lastFitKey.current = layoutKey;
      } else if (lastFitKey.current !== layoutKey) {
        void flow.fitView({ duration: 300 });
        lastFitKey.current = layoutKey;
      }
    });
    return () => cancelAnimationFrame(handle);
  }, [ready, layoutKey, revealId, flow, view]);

  if (filterActive && view.matchCount === 0) {
    const label =
      ipMode === "ipv4"
        ? "IPv4-konfigurierten "
        : ipMode === "ipv6"
          ? "IPv6-konfigurierten "
          : ipMode === "dual"
            ? "Dual-Stack-"
            : "geänderten ";
    return (
      <div className="topology-message">
        <p>
          <strong>Keine {label}Komponenten</strong> in dieser Ansicht.
        </p>
        <p className="muted">
          Detailstufe erhöhen, Subscription-Filter/Fokus ändern oder IP-Modus „Alle“ wählen.
        </p>
      </div>
    );
  }

  return (
    <div className="topology-canvas">
      {!ready && !error && <div className="topology-overlay">Layout wird berechnet …</div>}
      {error && <div className="topology-overlay status-error">Layout-Fehler: {error}</div>}
      {view.truncated && (
        <div className="topology-notice status-warn" role="status">
          {view.capped ? (
            <>
              <strong>Ansicht gekürzt:</strong> {view.totalCandidates} Elemente, gezeigt werden die ersten{" "}
              {view.nodes.length}.
            </>
          ) : (
            <>
              <strong>Detailstufe automatisch auf {view.effectiveLevel} reduziert</strong> –{" "}
              {view.totalCandidates} Elemente wären zu viele für eine lesbare Darstellung.
            </>
          )}{" "}
          Für mehr Details eine Subscription filtern, ein Element aufklappen (Doppelklick) oder „Fokus“
          setzen.
        </div>
      )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_COMPONENTS}
        onNodeClick={(_, node) => onSelect(node.id)}
        onNodeDoubleClick={(_, node) => onToggleExpand(node.id)}
        onPaneClick={() => onSelect(undefined)}
        nodesConnectable={false}
        edgesFocusable={false}
        onlyRenderVisibleElements
        minZoom={0.05}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        zoomOnDoubleClick={false}
      >
        <Background gap={24} size={1} />
        <MiniMap
          pannable
          zoomable
          nodeClassName={(n) => (typeof n.className === "string" ? n.className : "")}
        />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
