import { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
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
  return (
    <div
      className={`topo-node cat-${category}${selected ? " selected" : ""}${neighbor ? " neighbor" : ""}${emphasisClass(emphasis)}${changeClass(change)}`}
      title={`${NODE_TYPE_LABELS[node.type]}: ${node.name}${emphasis === "context" ? "\n(Kontext: Beziehung zu passenden Komponenten, selbst nicht im gewählten IP-Modus konfiguriert)" : ""}\n${node.id}`}
    >
      <Handle type="target" position={Position.Top} className="handle" isConnectable={false} />
      <div className="topo-node-row">
        <span className="type-abbr">{abbreviationOf(node.type)}</span>
        <span className="topo-node-name">{node.name}</span>
      </div>
      <div className="topo-node-row small">
        <span className="topo-node-address mono">{addressSummary(node) || NODE_TYPE_LABELS[node.type]}</span>
        <ChangeMarkers change={change} changesBelow={changesBelow} />
        <Badges node={node} />
        {hiddenChildren > 0 && (
          <span className="badge badge-more" title="Doppelklick zum Aufklappen">
            +{hiddenChildren}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="handle" isConnectable={false} />
    </div>
  );
});

export const ContainerNode = memo(function ContainerNode({ data, selected }: NodeProps<ContainerFlowNode>) {
  const { node, hiddenChildren, emphasis, change, changesBelow } = data;
  const category = categoryOf(node.type);
  return (
    <div
      className={`topo-container cat-${category}${selected ? " selected" : ""}${emphasisClass(emphasis)}${changeClass(change)}`}
    >
      <Handle type="target" position={Position.Top} className="handle" isConnectable={false} />
      <div className="topo-container-header" title={node.id}>
        <span className="type-abbr">{abbreviationOf(node.type)}</span>
        <span className="topo-node-name">{node.name}</span>
        <span className="topo-node-address mono">{addressSummary(node)}</span>
        <ChangeMarkers change={change} changesBelow={changesBelow} />
        <Badges node={node} />
        {hiddenChildren > 0 && <span className="badge badge-more">+{hiddenChildren}</span>}
      </div>
      <Handle type="source" position={Position.Bottom} className="handle" isConnectable={false} />
    </div>
  );
});

export const NODE_COMPONENTS = { resource: ResourceNode, container: ContainerNode };
