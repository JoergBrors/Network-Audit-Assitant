import { useMemo, useState } from "react";
import type { IpFamily } from "../../addressing/ip.js";
import { ipFamilyOf } from "../../addressing/ip.js";
import type { PathComparison, PathDestination, PathHop, PathResult, PathStatus } from "../../models/path.js";
import type { RoutingContext } from "../../routing/context.js";
import { analyzeInbound, type InboundExposure } from "../../routing/inbound.js";
import { compareFamilies, EGRESS_LABEL } from "../../routing/trace.js";

export const STATUS_LABEL: Record<PathStatus, string> = {
  ALLOWED: "Erlaubt",
  BLOCKED: "Blockiert",
  UNKNOWN: "Unklar",
  POTENTIAL_BYPASS: "Potenzieller Bypass",
};

const HOP_ICON: Record<PathHop["type"], string> = {
  source: "●",
  subnet: "▭",
  route: "↳",
  peering: "⇄",
  firewall: "🛡",
  nva: "🛡",
  loadBalancer: "⚖",
  gateway: "⇪",
  virtualHub: "⬡",
  natGateway: "⇧",
  publicIp: "◎",
  internet: "☁",
  onPremises: "⌂",
  destination: "◆",
  drop: "✕",
};

interface PathPanelProps {
  ctx: RoutingContext;
  sourceId: string;
  sourceName: string;
  onClose: () => void;
  onSelect: (id: string) => void;
  /** Highlights a path in the graph; `key` identifies it (toggle), `label` names it in the banner. */
  onShowPath: (key: string, label: string, nodeIds: string[]) => void;
  shownKey: string | undefined;
}

/** Trace Network Path + Compare IPv4/IPv6 Path (Lastenheft §§ 45, 46, 53). */
export function PathPanel({
  ctx,
  sourceId,
  sourceName,
  onClose,
  onSelect,
  onShowPath,
  shownKey,
}: PathPanelProps) {
  const [target, setTarget] = useState("internet");
  const [protocol, setProtocol] = useState<"Tcp" | "Udp" | "*">("Tcp");
  const [port, setPort] = useState(443);
  const [query, setQuery] = useState<{
    destination: PathDestination;
    protocol: typeof protocol;
    port: number;
  }>({
    destination: { kind: "internet" },
    protocol: "Tcp",
    port: 443,
  });
  const comparison = useMemo<PathComparison>(
    () => compareFamilies(ctx, sourceId, query.destination, { protocol: query.protocol, port: query.port }),
    [ctx, sourceId, query],
  );
  const subnetNicNsgs = useMemo(() => nicNsgsInSubnet(ctx, sourceId), [ctx, sourceId]);
  const targetValid =
    target.trim().toLowerCase() === "internet" || ipFamilyOf(target.trim().split("/")[0]) !== undefined;

  return (
    <div className="detail path-panel">
      <div className="row">
        <h2>Pfadanalyse</h2>
        <button className="secondary small-button" onClick={onClose}>
          Schließen
        </button>
      </div>
      <p className="small">
        Quelle: <strong>{sourceName}</strong>
      </p>
      {subnetNicNsgs > 0 && (
        <p className="gap-banner small">
          Quelle ist ein Subnet: Die NSGs an {subnetNicNsgs === 1 ? "einer NIC" : `${subnetNicNsgs} NICs`}{" "}
          darin werden hier nicht bewertet. Für die NIC-NSG eine VM oder NIC als Quelle wählen.
        </p>
      )}
      <form
        className="path-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (!targetValid) return;
          const t = target.trim();
          setQuery({
            destination: t.toLowerCase() === "internet" ? { kind: "internet" } : { kind: "ip", address: t },
            protocol,
            port,
          });
        }}
      >
        <label>
          Ziel
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="internet oder IP (10.1.2.3, 2a02::1)"
          />
        </label>
        <label>
          Protokoll
          <select value={protocol} onChange={(e) => setProtocol(e.target.value as typeof protocol)}>
            <option value="Tcp">TCP</option>
            <option value="Udp">UDP</option>
            <option value="*">beliebig</option>
          </select>
        </label>
        <label>
          Port
          <input
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(Number(e.target.value))}
          />
        </label>
        <button type="submit" disabled={!targetValid}>
          Analysieren
        </button>
      </form>

      {comparison.architectureGap && <div className="gap-banner">{comparison.architectureGap}</div>}
      {comparison.differences.length > 0 && (
        <ul className="differences small">
          {comparison.differences.map((d) => (
            <li key={d}>{d}</li>
          ))}
        </ul>
      )}

      <div className="path-columns">
        {(["ipv4", "ipv6"] as const).map((family) => (
          <PathColumn
            key={family}
            family={family}
            result={comparison[family]}
            onSelect={onSelect}
            shown={shownKey === family}
            onShow={() =>
              onShowPath(family, family === "ipv4" ? "IPv4" : "IPv6", pathNodeIds(comparison[family]))
            }
          />
        ))}
      </div>
      <InboundSection
        ctx={ctx}
        targetId={sourceId}
        onSelect={onSelect}
        onShowPath={onShowPath}
        shownKey={shownKey}
      />
      <p className="muted small">
        Konfigurationsbasierte Analyse: per BGP gelernte Routen, NVA-Verhalten und FQDN-Regeln sind nicht
        einsehbar – die Konfidenz je Schritt zeigt, wie belastbar eine Aussage ist.
      </p>
    </div>
  );
}

/** NICs in a subnet source that carry their own NSG (not evaluated when the subnet is the source). */
export function nicNsgsInSubnet(ctx: RoutingContext, sourceId: string): number {
  if (!ctx.subnets.has(sourceId)) return 0;
  return ctx.inv.networkInterfaces.filter((n) => n.nsgId && n.subnetIds.includes(sourceId)).length;
}

export function pathNodeIds(result: Pick<PathResult, "hops">): string[] {
  const ids: string[] = [];
  for (const h of result.hops) if (h.nodeId && ids.at(-1) !== h.nodeId) ids.push(h.nodeId);
  return ids;
}

function PathColumn({
  family,
  result,
  onSelect,
  shown,
  onShow,
}: {
  family: IpFamily;
  result: PathResult;
  onSelect: (id: string) => void;
  shown: boolean;
  onShow: () => void;
}) {
  const label = family === "ipv4" ? "IPv4" : "IPv6";
  return (
    <section className={`path-column status-border-${result.status}`}>
      <div className="row">
        <strong>{label}</strong>
        <span className={`path-status path-status-${result.notApplicable ? "NA" : result.status}`}>
          {result.notApplicable ? "nicht konfiguriert" : STATUS_LABEL[result.status]}
        </span>
        <span className="muted small">Konfidenz {result.confidence}</span>
      </div>
      <p className="small">{result.summary}</p>
      {result.egress && (
        <p className="small">
          Egress: <strong>{EGRESS_LABEL[result.egress.mechanism]}</strong>
          {result.egress.publicIps.length > 0 && (
            <span className="mono"> ({result.egress.publicIps.join(", ")})</span>
          )}
          {result.egress.controlled ? " · zentral kontrolliert" : " · nicht zentral kontrolliert"}
        </p>
      )}
      {!result.notApplicable && (
        <button className={shown ? "small-button" : "secondary small-button"} onClick={onShow}>
          {shown ? "wird im Graph gezeigt" : "Im Graph zeigen"}
        </button>
      )}
      <HopList hops={result.hops} onSelect={onSelect} />
    </section>
  );
}

export function HopList({ hops, onSelect }: { hops: PathHop[]; onSelect: (id: string) => void }) {
  return (
    <ol className="hops">
      {hops.map((h) => (
        <li key={h.index} className={`hop hop-${h.type}`}>
          <span className="hop-icon" aria-hidden>
            {HOP_ICON[h.type]}
          </span>
          <div>
            <div>
              {h.nodeId ? (
                <button className="link" onClick={() => onSelect(h.nodeId!)}>
                  {h.label}
                </button>
              ) : (
                <strong>{h.label}</strong>
              )}{" "}
              <span className={`conf conf-${h.confidence}`}>{h.confidence}</span>
            </div>
            <div className="small">{h.reason}</div>
            {h.decision && (
              <div className="small">
                {CONTROL_LABEL[h.decision.control]} {h.decision.direction ?? ""}:{" "}
                <span
                  className={
                    h.decision.access === "Allow"
                      ? "status-ok"
                      : h.decision.access === "Deny"
                        ? "status-error"
                        : "status-warn"
                  }
                >
                  {h.decision.access}
                </span>
                {h.decision.rule ? ` (${h.decision.rule})` : ""}
              </div>
            )}
            {h.evidence.length > 0 && (
              <details className="evidence">
                <summary className="muted small">Evidence ({h.evidence.length})</summary>
                <ul className="small">
                  {h.evidence.map((e, i) => (
                    <li key={i}>
                      <span className="muted">[{e.kind}]</span> {e.description}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

const CONTROL_LABEL: Record<NonNullable<PathHop["decision"]>["control"], string> = {
  nsg: "NSG",
  firewall: "Firewall",
  avnm: "AVNM Admin",
};

/** Internet → workload: which public entry points reach this resource? */
function InboundSection({
  ctx,
  targetId,
  onSelect,
  onShowPath,
  shownKey,
}: {
  ctx: RoutingContext;
  targetId: string;
  onSelect: (id: string) => void;
  onShowPath: PathPanelProps["onShowPath"];
  shownKey: string | undefined;
}) {
  const exposures = useMemo(() => analyzeInbound(ctx, { targetId }), [ctx, targetId]);
  return (
    <section className="inbound-section">
      <h3>Eingehend aus dem Internet</h3>
      {exposures.length === 0 ? (
        <p className="muted small">
          Kein öffentlicher Eingangspunkt (Public IP, Load Balancer, Application Gateway, Firewall-DNAT) führt
          hierher.
        </p>
      ) : (
        exposures.map((e) => (
          <details key={e.id} className={`path-column status-border-${e.status}`}>
            <summary>
              <span className={`path-status path-status-${e.status}`}>{STATUS_LABEL[e.status]}</span>{" "}
              <strong>{ENTRY_LABEL[e.entry.kind]}</strong>{" "}
              <span className="mono">
                {e.entry.publicAddress}
                {e.entry.frontendPort ? `:${e.entry.frontendPort}` : ""}
              </span>{" "}
              <span className="muted small">
                {e.family === "ipv4" ? "IPv4" : "IPv6"} → {e.targetName}
              </span>
              <div className="small">{e.summary}</div>
            </summary>
            <button
              className={shownKey === e.id ? "small-button" : "secondary small-button"}
              onClick={() =>
                onShowPath(
                  e.id,
                  `eingehend ${e.family === "ipv4" ? "IPv4" : "IPv6"} → ${e.targetName}`,
                  pathNodeIds(e),
                )
              }
            >
              {shownKey === e.id ? "wird im Graph gezeigt" : "Im Graph zeigen"}
            </button>
            <HopList hops={e.hops} onSelect={onSelect} />
          </details>
        ))
      )}
    </section>
  );
}

export const ENTRY_LABEL: Record<InboundExposure["entry"]["kind"], string> = {
  publicIp: "Public IP an NIC",
  loadBalancer: "Load Balancer",
  loadBalancerNat: "LB Inbound NAT",
  applicationGateway: "Application Gateway",
  firewallDnat: "Firewall DNAT",
};
