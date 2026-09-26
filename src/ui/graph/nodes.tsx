import { memo } from "react";
import { Handle, Position, useStore, type Node, type NodeProps, type ReactFlowState } from "@xyflow/react";
import type { GraphNode } from "../../models/graph.js";
import { NODE_TYPE_LABELS } from "../../models/graph.js";
import type { VisibleNode } from "../../graph/view.js";
import type { ChangeKind } from "../../drift/diff.js";
import { abbreviationOf, addressSummary, categoryOf } from "./nodeStyle.js";

export interface TopologyNodeData extends Record<string, unknown> {
  node: GraphNode;
  hiddenChildren: number;
  expanded: boolean;
  neighbor: boolean;
  emphasis: VisibleNode["emphasis"];
  change?: ChangeKind | undefined;
  changesBelow: number;
}

export type ResourceFlowNode = Node<TopologyNodeData, "resource">;
export type ContainerFlowNode = Node<TopologyNodeData, "container">;

const TOPOLOGY_LABEL = {
  hub: "Hub",
  spoke: "Spoke",
  "shared-services": "Shared",
  standalone: "Standalone",
  unknown: "?",
} as const;

/**
 * Semantic zoom: 0 = overview (coloured boxes only), 1 = names, 2 = full details. Nodes subscribe to
 * the bucket, not to the zoom value, so they re-render only when a threshold is crossed.
 */
export const detailOf = (zoom: number): 0 | 1 | 2 => (zoom < 0.3 ? 0 : zoom < 0.6 ? 1 : 2);
const selectDetail = (s: ReactFlowState) => detailOf(s.transform[2]);

const emphasisClass = (e: VisibleNode["emphasis"]) =>
  e === "context" ? " context" : e === "match" ? " match" : "";
const changeClass = (c: ChangeKind | undefined) => (c ? ` change-${c}` : "");
const CHANGE_LABEL: Record<ChangeKind, string> = { added: "NEU", removed: "ENTFERNT", changed: "GEÄNDERT" };

/** Snapshot comparison markers: own change + number of changes in contained/related elements. */
function ChangeMarkers({ change, changesBelow }: { change: ChangeKind | undefined; changesBelow: number }) {
  const below = changesBelow - (change ? 1 : 0);
  return (
    <>
      {change && <span className={`change-badge change-${change}`}>{CHANGE_LABEL[change]}</span>}
      {below > 0 && (
        <span className="badge badge-delta" title={`${below} Änderung(en) in enthaltenen Elementen`}>
          Δ {below}
        </span>
      )}
    </>
  );
}

function Badges({ node }: { node: GraphNode }) {
  return (
    <>
      {node.topology && node.topology.classification !== "unknown" && (
        <span
          className={`badge badge-${node.topology.classification}`}
          title={node.topology.reasons.join("\n")}
        >
          {TOPOLOGY_LABEL[node.topology.classification]}
        </span>
      )}
      {node.nva?.potentialNva && (
        <span className="badge badge-nva" title={node.nva.reasons.join("\n")}>
          NVA
        </span>
      )}
      {node.addressing.classification !== "no-ip" && node.addressing.classification !== "unknown" && (
        <span className={`badge ip-${node.addressing.classification}`}>
          {node.addressing.classification === "dual-stack"
            ? "Dual"
            : node.addressing.classification === "ipv6-only"
              ? "v6"
              : "v4"}
        </span>
      )}
    </>
  );
}

export const ResourceNode = memo(function ResourceNode({ data, selected }: NodeProps<ResourceFlowNode>) {
  const { node, hiddenChildren, neighbor, emphasis, change, changesBelow } = data;
  const category = categoryOf(node.type);
  const detail = useStore(selectDetail);
  const className = `topo-node cat-${category} lod-${detail}${selected ? " selected" : ""}${neighbor ? " neighbor" : ""}${emphasisClass(emphasis)}${changeClass(change)}`;
  const title = `${NODE_TYPE_LABELS[node.type]}: ${node.name}${emphasis === "context" ? "\n(Kontext: Beziehung zu passenden Komponenten, passt selbst nicht zum aktiven Filter)" : ""}\n${node.id}`;
  if (detail === 0)
    return (
      <div className={className} title={title}>
        <Handle type="target" position={Position.Top} className="handle" isConnectable={false} />
        <Handle type="source" position={Position.Bottom} className="handle" isConnectable={false} />
      </div>
    );
  return (
    <div className={className} title={title}>
      <Handle type="target" position={Position.Top} className="handle" isConnectable={false} />
      <div className="topo-node-row">
        <span className="type-abbr">{abbreviationOf(node.type)}</span>
        <span className="topo-node-name">{node.name}</span>
      </div>
      {detail === 2 && (
        <div className="topo-node-row small">
          <span className="topo-node-address mono">
            {addressSummary(node) ||
              (node.type === "paasService" && typeof node.properties["service"] === "string"
                ? node.properties["service"]
                : NODE_TYPE_LABELS[node.type])}
          </span>
          <ChangeMarkers change={change} changesBelow={changesBelow} />
          <Badges node={node} />
          {hiddenChildren > 0 && (
            <span className="badge badge-more" title="Doppelklick zum Aufklappen">
              +{hiddenChildren}
            </span>
          )}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="handle" isConnectable={false} />
    </div>
  );
});

export const ContainerNode = memo(function ContainerNode({ data, selected }: NodeProps<ContainerFlowNode>) {
  const { node, hiddenChildren, emphasis, change, changesBelow } = data;
  const category = categoryOf(node.type);
  const detail = useStore(selectDetail);
  return (
    <div
      className={`topo-container cat-${category} lod-${detail}${selected ? " selected" : ""}${emphasisClass(emphasis)}${changeClass(change)}`}
    >
      <Handle type="target" position={Position.Top} className="handle" isConnectable={false} />
      {detail === 0 ? (
        // Region/tenant boxes nearly coincide with their parent: labelling them would cover it.
        node.type === "region" || node.type === "tenant" ? null : (
          // Overview: only the name, scaled against the zoom (CSS --zoom-inv) so it stays readable.
          <div className="topo-container-overview" title={`${NODE_TYPE_LABELS[node.type]}: ${node.name}`}>
            {node.name}
          </div>
        )
      ) : (
        <div className="topo-container-header" title={node.id}>
          <span className="type-abbr">{abbreviationOf(node.type)}</span>
          <span className="topo-node-name">{node.name}</span>
          {detail === 2 && (
            <>
              <span className="topo-node-address mono">{addressSummary(node)}</span>
              <ChangeMarkers change={change} changesBelow={changesBelow} />
              <Badges node={node} />
              {hiddenChildren > 0 && <span className="badge badge-more">+{hiddenChildren}</span>}
            </>
          )}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="handle" isConnectable={false} />
    </div>
  );
});

export const NODE_COMPONENTS = { resource: ResourceNode, container: ContainerNode };
