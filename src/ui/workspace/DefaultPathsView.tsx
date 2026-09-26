import { useMemo, useState, type ReactNode } from "react";
import type { SubscriptionDependency } from "../../routing/dependencies.js";
import type { DefaultPathSummary } from "../../routing/analysis.js";
import type { InboundExposure } from "../../routing/inbound.js";
import { EGRESS_LABEL } from "../../routing/trace.js";
import { ENTRY_LABEL, STATUS_LABEL } from "./PathPanel.js";

type Filter = "all" | "bypass" | "uncontrolled" | "ipv6";

type SubscriptionName = (id: string | undefined) => string;

/** Other subscriptions a path depends on, with the resources as tooltip. */
function Dependencies({ deps, name }: { deps: SubscriptionDependency[]; name: SubscriptionName }): ReactNode {
  if (deps.length === 0) return "–";
  return deps.map((d) => (
    <span
      key={d.subscriptionId}
      className="badge badge-subscription"
      title={`Abhängig von ${name(d.subscriptionId)}:\n${d.resourceIds.map((r) => r.split("/").pop()).join("\n")}`}
    >
      ↗ {name(d.subscriptionId)}
    </span>
  ));
}

/** Overview of Internet paths: outbound per workload subnet, inbound per public entry point. */
export function DefaultPathsView({
  paths,
  inbound,
  direction,
  onDirection,
  onOpen,
  subscriptions,
  subscription,
}: {
  paths: DefaultPathSummary[];
  inbound: InboundExposure[];
  direction: "outbound" | "inbound";
  onDirection: (d: "outbound" | "inbound") => void;
  onOpen: (id: string) => void;
  /** Subscription names for display. */
  subscriptions: { subscriptionId: string; name: string }[];
  /** Selected subscription (workspace filter); empty = all. */
  subscription: string;
}) {
  const names = useMemo(
    () => new Map(subscriptions.map((s) => [s.subscriptionId.toLowerCase(), s.name])),
    [subscriptions],
  );
  const name: SubscriptionName = (id) => (id ? (names.get(id) ?? id) : "–");
  const sub = subscription.toLowerCase();
  const scopedPaths = useMemo(
    () => (sub ? paths.filter((p) => p.subscriptionId === sub) : paths),
    [paths, sub],
  );
  const scopedInbound = useMemo(
    () => (sub ? inbound.filter((e) => e.subscriptionId === sub) : inbound),
    [inbound, sub],
  );
  const toggle = (
    <div className="row">
      <button className={direction === "outbound" ? "" : "secondary"} onClick={() => onDirection("outbound")}>
        Ausgehend
      </button>
      <button className={direction === "inbound" ? "" : "secondary"} onClick={() => onDirection("inbound")}>
        Eingehend
      </button>
    </div>
  );
  return direction === "inbound" ? (
    <InboundView
      exposures={scopedInbound}
      onOpen={onOpen}
      toggle={toggle}
      name={name}
      scope={sub ? name(sub) : undefined}
    />
  ) : (
    <OutboundView
      paths={scopedPaths}
      onOpen={onOpen}
      toggle={toggle}
      name={name}
      scope={sub ? name(sub) : undefined}
    />
  );
}

function OutboundView({
  paths,
  onOpen,
  toggle,
  name,
  scope,
}: {
  paths: DefaultPathSummary[];
  onOpen: (subnetId: string) => void;
  toggle: React.ReactNode;
  name: SubscriptionName;
  scope: string | undefined;
}) {
  const [filter, setFilter] = useState<Filter>("all");
  const [text, setText] = useState("");
  const counts = useMemo(
    () => ({
      total: paths.length,
      controlled: paths.filter((p) => p.controlled && p.status !== "BLOCKED").length,
      bypass: paths.filter((p) => p.status === "POTENTIAL_BYPASS").length,
      uncontrolled: paths.filter(
        (p) => !p.controlled && (p.status === "ALLOWED" || p.status === "POTENTIAL_BYPASS"),
      ).length,
      ipv6: paths.filter((p) => p.family === "ipv6").length,
    }),
    [paths],
  );
  const rows = useMemo(() => {
    const q = text.trim().toLowerCase();
    return paths
      .filter((p) =>
        filter === "bypass"
          ? p.status === "POTENTIAL_BYPASS"
          : filter === "uncontrolled"
            ? !p.controlled && (p.status === "ALLOWED" || p.status === "POTENTIAL_BYPASS")
            : filter === "ipv6"
              ? p.family === "ipv6"
              : true,
      )
      .filter((p) => !q || `${name(p.subscriptionId)} ${p.vnet} ${p.subnet}`.toLowerCase().includes(q))
      .sort(
        (a, b) =>
          name(a.subscriptionId).localeCompare(name(b.subscriptionId)) ||
          a.vnet.localeCompare(b.vnet) ||
          a.subnet.localeCompare(b.subnet) ||
          a.family.localeCompare(b.family),
      );
  }, [paths, filter, text, name]);

  return (
    <div className="default-paths">
      <div className="row">
        <h2>Internet-Pfade je Subnet</h2>
        <span className="muted small">
          konfigurationsbasiert · {counts.total} Pfade{scope ? ` in ${scope}` : " in allen Subscriptions"}
        </span>
      </div>
      {toggle}
      <div className="row">
        <button className={filter === "all" ? "" : "secondary"} onClick={() => setFilter("all")}>
          Alle ({counts.total})
        </button>
        <button className={filter === "bypass" ? "" : "secondary"} onClick={() => setFilter("bypass")}>
          Potenzieller Bypass ({counts.bypass})
        </button>
        <button
          className={filter === "uncontrolled" ? "" : "secondary"}
          onClick={() => setFilter("uncontrolled")}
        >
          Ohne zentrale Kontrolle ({counts.uncontrolled})
        </button>
        <button className={filter === "ipv6" ? "" : "secondary"} onClick={() => setFilter("ipv6")}>
          IPv6 ({counts.ipv6})
        </button>
        <input
          type="search"
          placeholder="Subscription / VNet / Subnet filtern"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <span className="muted small">{counts.controlled} über Firewall/NVA</span>
      </div>
      <div className="table-scroll">
        <table className="grid">
          <thead>
            <tr>
              <th>Subscription</th>
              <th>VNet</th>
              <th>Subnet</th>
              <th>IP</th>
              <th>Status</th>
              <th>Erste Route</th>
              <th>Egress</th>
              <th>Kontrolle</th>
              <th title="Ressourcen in anderen Subscriptions, von denen der Pfad abhängt">Abhängig von</th>
              <th>Konfidenz</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr
                key={`${p.subnetId}-${p.family}`}
                className="clickable"
                onClick={() => onOpen(p.subnetId)}
                title={p.summary}
              >
                <td className="small">{name(p.subscriptionId)}</td>
                <td>{p.vnet}</td>
                <td>{p.subnet}</td>
                <td>{p.family === "ipv4" ? "IPv4" : "IPv6"}</td>
                <td>
                  <span className={`path-status path-status-${p.status}`}>{STATUS_LABEL[p.status]}</span>
                </td>
                <td className="mono">{p.firstHop}</td>
                <td>
                  {EGRESS_LABEL[p.egress]}
                  {p.publicIps.length > 0 && (
                    <span className="mono muted"> {p.publicIps.slice(0, 2).join(", ")}</span>
                  )}
                </td>
                <td>{p.controlled ? p.securityControls.map((c) => c.split("/").pop()).join(", ") : "–"}</td>
                <td>
                  <Dependencies deps={p.dependencies} name={name} />
                </td>
                <td>{p.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type InboundFilter = "all" | "open" | "uncontrolled" | "asymmetric" | "ipv6";

const reachable = (e: InboundExposure) => e.status !== "BLOCKED";
const INBOUND_TESTS: Record<InboundFilter, (e: InboundExposure) => boolean> = {
  all: () => true,
  open: reachable,
  uncontrolled: (e) => reachable(e) && !e.controlled && e.openPorts.length > 0,
  asymmetric: (e) => e.asymmetricRouting,
  ipv6: (e) => e.family === "ipv6",
};
const INBOUND_LABELS: Record<InboundFilter, string> = {
  all: "Alle",
  open: "Erreichbar",
  uncontrolled: "Ohne Firewall/WAF",
  asymmetric: "Asymmetrisch",
  ipv6: "IPv6",
};

function InboundView({
  exposures,
  onOpen,
  toggle,
  name,
  scope,
}: {
  exposures: InboundExposure[];
  onOpen: (id: string) => void;
  toggle: React.ReactNode;
  name: SubscriptionName;
  scope: string | undefined;
}) {
  const [filter, setFilter] = useState<InboundFilter>("open");
  const [text, setText] = useState("");
  const rows = useMemo(() => {
    const q = text.trim().toLowerCase();
    return exposures
      .filter(INBOUND_TESTS[filter])
      .filter(
        (e) =>
          !q ||
          `${name(e.subscriptionId)} ${e.targetName} ${e.entry.name} ${e.entry.publicAddress}`
            .toLowerCase()
            .includes(q),
      );
  }, [exposures, filter, text, name]);

  return (
    <div className="default-paths">
      <div className="row">
        <h2>Eingehende Internet-Pfade</h2>
        <span className="muted small">
          konfigurationsbasiert · {exposures.length} Eingangspfade
          {scope ? ` in ${scope}` : " in allen Subscriptions"}
        </span>
      </div>
      {toggle}
      <div className="row">
        {(Object.keys(INBOUND_LABELS) as InboundFilter[]).map((f) => (
          <button key={f} className={filter === f ? "" : "secondary"} onClick={() => setFilter(f)}>
            {INBOUND_LABELS[f]} ({exposures.filter(INBOUND_TESTS[f]).length})
          </button>
        ))}
        <input
          type="search"
          placeholder="Ziel / Eingang filtern"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </div>
      <div className="table-scroll">
        <table className="grid">
          <thead>
            <tr>
              <th>Subscription</th>
              <th>Eingang</th>
              <th>Öffentliche Adresse</th>
              <th>IP</th>
              <th>Ziel</th>
              <th>Status</th>
              <th>Offene Ports</th>
              <th>Kontrolle</th>
              <th title="Ressourcen in anderen Subscriptions, von denen der Pfad abhängt">Abhängig von</th>
              <th>Konfidenz</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className="clickable" onClick={() => onOpen(e.targetId)} title={e.summary}>
                <td className="small">{name(e.subscriptionId)}</td>
                <td>
                  {ENTRY_LABEL[e.entry.kind]} <span className="muted">{e.entry.name}</span>
                </td>
                <td className="mono">
                  {e.entry.publicAddress}
                  {e.entry.frontendPort ? `:${e.entry.frontendPort}` : ""}
                </td>
                <td>{e.family === "ipv4" ? "IPv4" : "IPv6"}</td>
                <td>
                  {e.targetName} <span className="mono muted">{e.targetAddress}</span>
                </td>
                <td>
                  <span className={`path-status path-status-${e.status}`}>{STATUS_LABEL[e.status]}</span>
                  {e.asymmetricRouting && <span className="status-warn small"> asymmetrisch</span>}
                </td>
                <td className="mono">
                  {e.openPorts.join(", ") || "–"}
                  {e.restricted.length > 0 && (
                    <span className="muted">
                      {" "}
                      (+{e.restricted.map((r) => r.port).join(", ")} eingeschränkt)
                    </span>
                  )}
                </td>
                <td>{e.controlled ? "Firewall/WAF" : "–"}</td>
                <td>
                  <Dependencies deps={e.dependencies} name={name} />
                </td>
                <td>{e.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
