import { memo, useEffect, useMemo, useRef, useState } from "react";
import type { GraphIndex } from "../../graph/view.js";
import { ancestors, compareNodes } from "../../graph/view.js";
import type { GraphNode } from "../../models/graph.js";
import { NODE_TYPE_LABELS } from "../../models/graph.js";
import { abbreviationOf, categoryOf } from "../graph/nodeStyle.js";
import type { ChangeKind, ComparisonGraph } from "../../drift/diff.js";
import { KIND_LABEL } from "./Changes.js";

interface TreeViewProps {
  index: GraphIndex;
  selectedId: string | undefined;
  onSelect: (id: string) => void;
  changes?: ComparisonGraph | undefined;
}

interface Row {
  node: GraphNode;
  depth: number;
  childCount: number;
}

/** Hierarchy tree (tenant → subscription → region → VNet → subnet → resources), synchronized with the graph. */
export function TreeView({ index, selectedId, onSelect, changes }: TreeViewProps) {
  const [open, setOpen] = useState<Set<string>>(
    () => new Set([...index.byId.values()].filter((n) => n.type === "tenant").map((n) => n.id)),
  );
  const containerRef = useRef<HTMLDivElement>(null);

  // Graph selection → open ancestors and scroll into view.
  useEffect(() => {
    if (!selectedId) return;
    const chain = ancestors(index, selectedId).map((n) => n.id);
    setOpen((prev) => (chain.every((id) => prev.has(id)) ? prev : new Set([...prev, ...chain])));
    const handle = requestAnimationFrame(() => {
      containerRef.current
        ?.querySelector(`[data-id="${CSS.escape(selectedId)}"]`)
        ?.scrollIntoView({ block: "nearest" });
    });
    return () => cancelAnimationFrame(handle);
  }, [selectedId, index]);

  const rows = useMemo(() => {
    const out: Row[] = [];
    const roots = [...index.byId.values()].filter((n) => !n.parentId).sort(compareNodes);
    const walk = (node: GraphNode, depth: number) => {
      const children = index.children.get(node.id) ?? [];
      out.push({ node, depth, childCount: children.length });
      if (open.has(node.id)) for (const c of children) walk(c, depth + 1);
    };
    for (const r of roots) walk(r, 0);
    return out;
  }, [index, open]);

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="tree" ref={containerRef} role="tree">
      {rows.map((row) => (
        <TreeRow
          key={row.node.id}
          row={row}
          isOpen={open.has(row.node.id)}
          selected={row.node.id === selectedId}
          onToggle={toggle}
          onSelect={onSelect}
          change={changes?.nodeChanges.get(row.node.id)?.kind}
          changesBelow={changes?.changesBelow.get(row.node.id) ?? 0}
        />
      ))}
    </div>
  );
}

const TreeRow = memo(function TreeRow({
  row,
  isOpen,
  selected,
  onToggle,
  onSelect,
  change,
  changesBelow,
}: {
  change: ChangeKind | undefined;
  changesBelow: number;
  row: Row;
  isOpen: boolean;
  selected: boolean;
  onToggle: (id: string) => void;
  onSelect: (id: string) => void;
}) {
  const { node, depth, childCount } = row;
  return (
    <div
      className={`tree-row${selected ? " selected" : ""}${change ? ` tree-change-${change}` : ""}`}
      style={{ paddingLeft: 6 + depth * 14 }}
      data-id={node.id}
      role="treeitem"
      aria-selected={selected}
      aria-expanded={childCount > 0 ? isOpen : undefined}
      onClick={() => onSelect(node.id)}
      title={`${NODE_TYPE_LABELS[node.type]}: ${node.name}`}
    >
      <button
        className="tree-toggle"
        aria-label={isOpen ? "Zuklappen" : "Aufklappen"}
        onClick={(e) => {
          e.stopPropagation();
          onToggle(node.id);
        }}
        disabled={childCount === 0}
      >
        {childCount === 0 ? "" : isOpen ? "▾" : "▸"}
      </button>
      <span className={`type-abbr small cat-${categoryOf(node.type)}`}>{abbreviationOf(node.type)}</span>
      <span className="tree-name">{node.name}</span>
      {node.topology &&
        (node.topology.classification === "hub" || node.topology.classification === "spoke") && (
          <span className={`badge badge-${node.topology.classification}`}>
            {node.topology.classification === "hub" ? "Hub" : "Spoke"}
          </span>
        )}
      {change && <span className={`change-badge change-${change}`}>{KIND_LABEL[change]}</span>}
      {changesBelow - (change ? 1 : 0) > 0 && (
        <span className="badge badge-delta">Δ {changesBelow - (change ? 1 : 0)}</span>
      )}
      {childCount > 0 && <span className="tree-count">{childCount}</span>}
    </div>
  );
});
