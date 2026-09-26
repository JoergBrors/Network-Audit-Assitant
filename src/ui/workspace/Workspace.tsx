import { useCallback, useMemo, useState } from "react";
import { ancestors, computeVisibleGraph, indexGraph, type IpViewMode } from "../../graph/view.js";
import { buildComparisonGraph, buildDiffExport, diffFileName, type SnapshotDiff } from "../../drift/diff.js";
import type { NetworkModel } from "../../pipeline/analyze.js";
import { TopologyView } from "../graph/TopologyView.js";
import { DetailPanel } from "./DetailPanel.js";
import { buildEntityIndex } from "./entityIndex.js";
import { SearchBox } from "./SearchBox.js";
import { TreeView } from "./TreeView.js";
import { ChangeList, ComparisonBar } from "./Changes.js";
import { PathPanel } from "./PathPanel.js";
import { DefaultPathsView } from "./DefaultPathsView.js";
import { buildRoutingContext } from "../../routing/context.js";
import { analyzeDefaultPaths } from "../../routing/analysis.js";
import { analyzeInbound } from "../../routing/inbound.js";
import { downloadJson } from "./download.js";
import { TypeFilter } from "./TypeFilter.js";
import { TagFilter } from "./TagFilter.js";
import { buildTagIndex, nodesWithTag } from "../../graph/tags.js";
import type { NodeType } from "../../models/graph.js";

const HIDDEN_TYPES_KEY = "graph-hidden-types";
function loadHiddenTypes(): Set<NodeType> {
  try {
    const raw = localStorage.getItem(HIDDEN_TYPES_KEY);
    return new Set(raw ? (JSON.parse(raw) as NodeType[]) : []);
  } catch {
    return new Set();
  }
}

export interface WorkspaceComparison {
  diff: SnapshotDiff;
  baseline: NetworkModel;
  baselineLabel: string;
  onClose: () => void;
}

const LEVELS = [
  { level: 1, label: "1 · Subscriptions, Hubs, Spokes" },
  { level: 2, label: "2 · VNets & Peerings" },
  { level: 3, label: "3 · Subnets, Firewall, NAT, Gateways, UDRs" },
  { level: 4, label: "4 · NICs, VMs, Private Endpoints, NSGs" },
  { level: 5, label: "5 · Routen, Regeln, Details" },
];

const IP_MODES: { mode: IpViewMode; label: string }[] = [
  { mode: "all", label: "Alle" },
  { mode: "ipv4", label: "IPv4" },
  { mode: "ipv6", label: "IPv6" },
  { mode: "dual", label: "Dual Stack" },
];

const LEGEND = [
  ["edge-peering", "Peering"],
  ["edge-route", "Route (UDR)"],
  ["edge-security", "Security / Policy"],
  ["edge-nat", "NAT"],
  ["edge-gateway", "Gateway"],
  ["edge-pe", "Private Endpoint"],
  ["edge-dns", "DNS"],
  ["edge-attached", "Zuordnung"],
] as const;

export function Workspace({
  model,
  comparison,
}: {
  model: NetworkModel;
  comparison?: WorkspaceComparison | undefined;
}) {
  // With an active comparison the graph also contains "ghost" nodes/edges that only exist in the snapshot.
  const compareGraph = useMemo(
    () =>
      comparison ? buildComparisonGraph(comparison.baseline.graph, model.graph, comparison.diff) : undefined,
    [comparison, model.graph],
  );
  const index = useMemo(() => indexGraph(compareGraph?.graph ?? model.graph), [compareGraph, model.graph]);
  const entities = useMemo(() => {
    const current = buildEntityIndex(model.inventory);
    if (!comparison) return current;
    for (const [id, ref] of buildEntityIndex(comparison.baseline.inventory))
      if (!current.has(id)) current.set(id, ref);
    return current;
  }, [model.inventory, comparison]);
  const tagIndex = useMemo(() => buildTagIndex(entities), [entities]);
  const [tagQuery, setTagQuery] = useState("");
  const tagIds = useMemo(() => nodesWithTag(tagIndex, tagQuery), [tagIndex, tagQuery]);
  const changedIds = useMemo(() => {
    if (!comparison) return undefined;
    const ids = new Set(comparison.diff.resources.map((r) => r.id));
    for (const r of comparison.diff.relationships) {
      ids.add(r.source);
      ids.add(r.target);
    }
    return ids;
  }, [comparison]);
  const [onlyChanges, setOnlyChanges] = useState(false);

  const [level, setLevel] = useState(2);
  const [hiddenTypes, setHiddenTypesState] = useState<Set<NodeType>>(loadHiddenTypes);
  const setHiddenTypes = useCallback((next: Set<NodeType>) => {
    setHiddenTypesState(next);
    try {
      localStorage.setItem(HIDDEN_TYPES_KEY, JSON.stringify([...next]));
    } catch {
      // Storage unavailable: the selection just is not remembered.
    }
  }, []);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [focusId, setFocusId] = useState<string | undefined>();
  const [ipMode, setIpMode] = useState<IpViewMode>("all");
  const [subscription, setSubscription] = useState<string>("");
  const [selectedId, setSelectedId] = useState<string | undefined>();
  const [revealId, setRevealId] = useState<string | undefined>();
  const [showEdgeLabels, setShowEdgeLabels] = useState(false);
  const [center, setCenter] = useState<"graph" | "paths">("graph");
  const [pathSource, setPathSource] = useState<string | undefined>();
  const [pathShown, setPathShown] = useState<{ key: string; label: string; ids: string[] } | undefined>();
  const [pathDirection, setPathDirection] = useState<"outbound" | "inbound">("outbound");
  const routing = useMemo(() => buildRoutingContext(model.inventory), [model.inventory]);
  const defaultPaths = useMemo(
    () =>
      center === "paths" && pathDirection === "outbound" ? analyzeDefaultPaths(model.inventory, routing) : [],
    [center, pathDirection, model.inventory, routing],
  );
  const inboundPaths = useMemo(
    () => (center === "paths" && pathDirection === "inbound" ? analyzeInbound(routing) : []),
    [center, pathDirection, routing],
  );
  const pathIds = useMemo(() => (pathShown ? new Set(pathShown.ids) : undefined), [pathShown]);

  const subscriptionFilter = useMemo(
    () => (subscription ? new Set([subscription]) : undefined),
    [subscription],
  );
  const view = useMemo(
    () =>
      computeVisibleGraph(index, {
        level,
        expanded,
        focusId,
        subscriptionIds: subscriptionFilter,
        ipMode,
        changedIds,
        onlyChanges: onlyChanges && changedIds !== undefined,
        pathIds,
        hiddenTypes,
        tagIds,
      }),
    [
      index,
      level,
      expanded,
      focusId,
      subscriptionFilter,
      ipMode,
      changedIds,
      onlyChanges,
      pathIds,
      hiddenTypes,
      tagIds,
    ],
  );

  const toggleExpand = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setSelectedId(id);
  }, []);

  /** Selects a node from tree, search or links and makes sure it is visible in the graph. */
  const reveal = useCallback(
    (id: string) => {
      setSelectedId(id);
      setRevealId(id);
      const chain = ancestors(index, id).map((n) => n.id);
      if (focusId && focusId !== id && !chain.includes(focusId)) setFocusId(undefined);
      const node = index.byId.get(id);
      if (node?.subscriptionId && subscription && node.subscriptionId !== subscription) setSubscription("");
      setExpanded((prev) => {
        const missing = chain.filter((a) => !prev.has(a) && (index.byId.get(a)?.lod ?? 1) <= 5);
        return missing.length ? new Set([...prev, ...missing]) : prev;
      });
    },
    [index, focusId, subscription],
  );

  const focusChain = focusId ? [...ancestors(index, focusId), index.byId.get(focusId)!] : [];

  return (
    <div className="workspace">
      <aside className="pane pane-tree">
        <TreeView index={index} selectedId={selectedId} onSelect={reveal} changes={compareGraph} />
      </aside>

      <section className="pane pane-graph">
        <div className="toolbar">
          <div className="segmented" role="group" aria-label="Ansicht">
            <button className={center === "graph" ? "active" : ""} onClick={() => setCenter("graph")}>
              Graph
            </button>
            <button className={center === "paths" ? "active" : ""} onClick={() => setCenter("paths")}>
              Internet-Pfade
            </button>
          </div>
          <SearchBox index={index} tags={tagIndex} onSelect={reveal} />
          <label>
            Detailstufe{" "}
            <select value={level} onChange={(e) => setLevel(Number(e.target.value))}>
              {LEVELS.map((l) => (
                <option key={l.level} value={l.level}>
                  {l.label}
                </option>
              ))}
            </select>
          </label>
          <TypeFilter nodes={index.byId} level={level} hidden={hiddenTypes} onChange={setHiddenTypes} />
          <TagFilter index={tagIndex} value={tagQuery} matches={tagIds?.size} onChange={setTagQuery} />
          <div className="segmented" role="group" aria-label="IP-Modus">
            {IP_MODES.map((m) => (
              <button
                key={m.mode}
                className={ipMode === m.mode ? "active" : ""}
                onClick={() => setIpMode(m.mode)}
              >
                {m.label}
              </button>
            ))}
          </div>
          <select
            value={subscription}
            onChange={(e) => setSubscription(e.target.value)}
            aria-label="Subscription-Filter"
          >
            <option value="">Alle Subscriptions</option>
            {model.inventory.subscriptions
              .slice()
              .sort((a, b) => a.name.localeCompare(b.name))
              .map((s) => (
                <option key={s.subscriptionId} value={s.subscriptionId}>
                  {s.name}
                </option>
              ))}
          </select>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={showEdgeLabels}
              onChange={(e) => setShowEdgeLabels(e.target.checked)}
            />{" "}
            Beschriftung
          </label>
          {expanded.size > 0 && (
            <button className="secondary" onClick={() => setExpanded(new Set())}>
              Alle zuklappen
            </button>
          )}
        </div>

        {comparison && (
          <ComparisonBar
            info={{ diff: comparison.diff, baselineLabel: comparison.baselineLabel }}
            onlyChanges={onlyChanges}
            onToggleOnlyChanges={() => setOnlyChanges((v) => !v)}
            onExport={() => {
              const now = new Date();
              downloadJson(diffFileName(now), buildDiffExport(comparison.diff, now));
            }}
            onClose={comparison.onClose}
          />
        )}

        {focusId && (
          <div className="focus-bar small">
            Fokus:{" "}
            {focusChain.map((n, i) => (
              <span key={n.id}>
                {i > 0 && <span className="muted"> › </span>}
                <button className="link" onClick={() => setFocusId(n.id)}>
                  {n.name}
                </button>
              </span>
            ))}
            <button className="secondary small-button" onClick={() => setFocusId(undefined)}>
              Fokus aufheben
            </button>
          </div>
        )}

        {pathShown && (
          <div className="focus-bar small path-bar">
            Pfad ({pathShown.label}) wird hervorgehoben – andere Elemente sind ausgeblendet.
            <button className="secondary small-button" onClick={() => setPathShown(undefined)}>
              Pfad ausblenden
            </button>
          </div>
        )}

        {center === "paths" ? (
          <DefaultPathsView
            paths={defaultPaths}
            inbound={inboundPaths}
            direction={pathDirection}
            onDirection={setPathDirection}
            subscriptions={model.inventory.subscriptions}
            subscription={subscription}
            onOpen={(id) => {
              setSelectedId(id);
              setPathSource(id);
            }}
          />
        ) : (
          <TopologyView
            view={view}
            pathEdges={pathShown?.ids}
            expanded={expanded}
            selectedId={selectedId}
            ipMode={ipMode}
            showEdgeLabels={showEdgeLabels}
            revealId={revealId}
            changes={compareGraph}
            filterActive={!pathShown && (ipMode !== "all" || (onlyChanges && !!comparison) || !!tagIds)}
            tagQuery={tagIds ? tagQuery.trim() : undefined}
            onSelect={(id) => {
              setSelectedId(id);
              setRevealId(undefined);
            }}
            onToggleExpand={toggleExpand}
          />
        )}

        <div className="legend small">
          {LEGEND.map(([cls, label]) => (
            <span key={cls} className="legend-item">
              <span className={`legend-line ${cls}`} /> {label}
            </span>
          ))}
          {comparison && (
            <>
              <span className="legend-item">
                <span className="change-badge change-added">NEU</span>
                <span className="change-badge change-changed">GEÄNDERT</span>
                <span className="change-badge change-removed">ENTFERNT</span>
                <span className="badge badge-delta">Δ n</span> Änderungen darunter
              </span>
            </>
          )}
          {ipMode !== "all" && (
            <span className="legend-item">
              <span className="legend-context" /> Kontext (Beziehung, nicht{" "}
              {ipMode === "dual" ? "Dual Stack" : ipMode === "ipv4" ? "IPv4" : "IPv6"})
            </span>
          )}
          <span className="muted">
            {ipMode !== "all" || (onlyChanges && comparison) ? `${view.matchCount} passend · ` : ""}
            {view.nodes.length} Elemente · {view.edges.length} Beziehungen · Doppelklick = aufklappen
          </span>
        </div>
      </section>

      <aside className="pane pane-detail">
        {pathSource ? (
          <PathPanel
            key={pathSource}
            ctx={routing}
            sourceId={pathSource}
            sourceName={index.byId.get(pathSource)?.name ?? pathSource}
            onClose={() => {
              setPathSource(undefined);
              setPathShown(undefined);
            }}
            onSelect={reveal}
            shownKey={pathShown?.key}
            onShowPath={(key, label, ids) => {
              setCenter("graph");
              setPathShown((prev) => (prev?.key === key ? undefined : { key, label, ids }));
              setRevealId(ids[0]);
            }}
          />
        ) : selectedId ? (
          <DetailPanel
            model={model}
            index={index}
            entities={entities}
            nodeId={selectedId}
            expanded={expanded.has(selectedId)}
            focused={focusId === selectedId}
            onSelect={reveal}
            onFocus={(id) => {
              setFocusId(id);
              if (id) setRevealId(undefined);
            }}
            onToggleExpand={toggleExpand}
            changes={compareGraph}
            routing={routing}
            onTracePath={(id) => {
              setPathSource(id);
              setPathShown(undefined);
            }}
          />
        ) : comparison ? (
          <ChangeList diff={comparison.diff} onSelect={reveal} />
        ) : (
          <div className="detail muted">
            <p>Element im Baum, in der Suche oder im Graph auswählen.</p>
            <p>
              <strong>Drilldown:</strong> Doppelklick auf VNet, Subnet oder Subscription klappt die
              enthaltenen Ressourcen auf. „Fokus“ im Detailbereich zeigt nur dieses Element mit seinen
              direkten Beziehungen.
            </p>
          </div>
        )}
      </aside>
    </div>
  );
}
