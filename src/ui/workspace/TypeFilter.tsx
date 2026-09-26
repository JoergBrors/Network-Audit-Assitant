import { useMemo } from "react";
import { NODE_TYPE_LABELS, type GraphNode, type NodeType } from "../../models/graph.js";
import { STRUCTURAL_TYPES } from "../../graph/view.js";

/** Quick selections: the listed types are shown, all other filterable types are hidden. */
const PRESETS: { label: string; show?: NodeType[] }[] = [
  { label: "Alle" },
  { label: "Nur VMs & PaaS", show: ["vm", "vmss", "paasService"] },
  {
    label: "Workloads",
    show: ["vm", "vmss", "paasService", "privateEndpoint", "loadBalancer", "applicationGateway"],
  },
  {
    label: "Netzwerk-Infrastruktur",
    show: [
      "subnet",
      "azureFirewall",
      "natGateway",
      "vpnGateway",
      "expressRouteGateway",
      "virtualHub",
      "virtualWan",
      "routeServer",
      "nva",
      "bastion",
      "routeTable",
      "loadBalancer",
      "applicationGateway",
    ],
  },
  {
    label: "Sicherheit",
    show: ["subnet", "nsg", "azureFirewall", "firewallPolicy", "wafPolicy", "publicIp"],
  },
];

/**
 * Element-type selection for the graph overview. The hierarchy (subscriptions, regions, VNets) always
 * stays; hidden types disappear and their children move up to the nearest visible container.
 */
export function TypeFilter({
  nodes,
  level,
  hidden,
  onChange,
}: {
  nodes: ReadonlyMap<string, GraphNode>;
  level: number;
  hidden: ReadonlySet<NodeType>;
  onChange: (hidden: Set<NodeType>) => void;
}) {
  const types = useMemo(() => {
    const counts = new Map<NodeType, number>();
    for (const n of nodes.values()) {
      if (STRUCTURAL_TYPES.has(n.type) || n.lod > level) continue;
      counts.set(n.type, (counts.get(n.type) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => NODE_TYPE_LABELS[a.type].localeCompare(NODE_TYPE_LABELS[b.type]));
  }, [nodes, level]);

  const hiddenHere = types.filter((t) => hidden.has(t.type)).length;
  const toggle = (type: NodeType) => {
    const next = new Set(hidden);
    if (next.has(type)) next.delete(type);
    else next.add(type);
    onChange(next);
  };
  const applyPreset = (show?: NodeType[]) => {
    if (!show) return onChange(new Set());
    const keep = new Set(show);
    onChange(new Set(types.map((t) => t.type).filter((t) => !keep.has(t))));
  };

  return (
    <details className="type-filter">
      <summary>
        Elemente {hiddenHere > 0 ? `(${types.length - hiddenHere}/${types.length})` : "(alle)"}
      </summary>
      <div className="type-filter-panel">
        <div className="type-filter-presets">
          {PRESETS.map((p) => (
            <button key={p.label} className="secondary small" onClick={() => applyPreset(p.show)}>
              {p.label}
            </button>
          ))}
        </div>
        {types.length === 0 ? (
          <p className="muted small">Auf dieser Detailstufe gibt es keine filterbaren Elemente.</p>
        ) : (
          <ul>
            {types.map((t) => (
              <li key={t.type}>
                <label className="checkbox">
                  <input type="checkbox" checked={!hidden.has(t.type)} onChange={() => toggle(t.type)} />{" "}
                  {NODE_TYPE_LABELS[t.type]} <span className="muted">({t.count})</span>
                </label>
              </li>
            ))}
          </ul>
        )}
        <p className="muted small">
          Subscriptions, Regionen und VNets bleiben immer sichtbar. Im Fokus, bei Pfaden und in aufgeklappten
          Elementen werden alle Typen gezeigt.
        </p>
      </div>
    </details>
  );
}
