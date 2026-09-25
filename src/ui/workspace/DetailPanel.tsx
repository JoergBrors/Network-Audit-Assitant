import type { ReactNode } from "react";
import type { GraphIndex } from "../../graph/view.js";
import { ancestors } from "../../graph/view.js";
import type { GraphEdge, GraphNode } from "../../models/graph.js";
import { EDGE_TYPE_LABELS, NODE_TYPE_LABELS } from "../../models/graph.js";
import type {
  LoadBalancerEntity,
  NatGatewayEntity,
  NsgEntity,
  NsgRuleEntity,
  PrivateDnsZoneEntity,
  PrivateEndpointEntity,
  RuleCollectionGroupEntity,
  SubnetEntity,
} from "../../models/network.js";
import type { NetworkModel } from "../../pipeline/analyze.js";
import { abbreviationOf, categoryOf } from "../graph/nodeStyle.js";
import type { EntityRef } from "./entityIndex.js";
import { downloadJson } from "./download.js";
import type { ComparisonGraph } from "../../drift/diff.js";
import { ChangeDetails } from "./Changes.js";

interface DetailPanelProps {
  model: NetworkModel;
  index: GraphIndex;
  entities: Map<string, EntityRef>;
  nodeId: string;
  expanded: boolean;
  focused: boolean;
  onSelect: (id: string) => void;
  onFocus: (id: string | undefined) => void;
  onToggleExpand: (id: string) => void;
  changes?: ComparisonGraph | undefined;
}

export function DetailPanel({
  model,
  index,
  entities,
  nodeId,
  expanded,
  focused,
  onSelect,
  onFocus,
  onToggleExpand,
  changes,
}: DetailPanelProps) {
  const node = index.byId.get(nodeId);
  if (!node) return <div className="detail muted">Element nicht gefunden.</div>;
  const entity = entities.get(nodeId);
  const children = index.children.get(nodeId) ?? [];
  const Link = ({ id, children: label }: { id: string | undefined; children?: ReactNode }) =>
    id ? (
      <NodeLink index={index} id={id} onSelect={onSelect}>
        {label}
      </NodeLink>
    ) : (
      <span className="muted">–</span>
    );

  return (
    <div className="detail">
      <div className="detail-header">
        <span className={`type-abbr cat-${categoryOf(node.type)}`}>{abbreviationOf(node.type)}</span>
        <div>
          <div className="muted small">{NODE_TYPE_LABELS[node.type]}</div>
          <h2>{node.name}</h2>
        </div>
      </div>
      <Breadcrumb index={index} node={node} onSelect={onSelect} />
      <div className="row detail-actions">
        <button onClick={() => onFocus(focused ? undefined : node.id)}>
          {focused ? "Fokus aufheben" : "Fokus"}
        </button>
        {children.length > 0 && (
          <button className="secondary" onClick={() => onToggleExpand(node.id)}>
            {expanded ? "Zuklappen" : `Aufklappen (${children.length})`}
          </button>
        )}
        <button
          className="secondary"
          onClick={() =>
            downloadJson(`${node.type}-${node.name}.json`, {
              graphNode: node,
              entity: entity?.entity ?? null,
              relationships: index.edgesByNode.get(node.id) ?? [],
            })
          }
        >
          JSON
        </button>
      </div>

      {changes && (
        <ChangeDetails
          change={changes.nodeChanges.get(node.id)}
          relationships={[...changes.edgeChanges.values()].filter(
            (r) => r.source === node.id || r.target === node.id,
          )}
        />
      )}

      <Section title="Allgemein">
        <KeyValues
          values={{
            Subscription: node.subscriptionName ?? node.subscriptionId,
            "Resource Group": node.resourceGroup,
            Region: node.region,
          }}
        />
        <div className="mono small detail-id">{node.id}</div>
      </Section>

      {(node.addressing.ipv4.length > 0 || node.addressing.ipv6.length > 0) && (
        <Section title={`Adressierung · ${node.addressing.classification}`}>
          <KeyValues
            values={{
              IPv4: node.addressing.ipv4.join(", ") || "–",
              IPv6: node.addressing.ipv6.join(", ") || "–",
            }}
          />
        </Section>
      )}

      {node.topology && (
        <Section
          title={`Topologie: ${node.topology.classification} (Konfidenz ${Math.round(node.topology.confidence * 100)} %)`}
        >
          <ul className="reasons">
            {node.topology.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          {node.topology.hubIds.length > 0 && (
            <div>
              Hub:{" "}
              {node.topology.hubIds.map((h) => (
                <Link key={h} id={h} />
              ))}
            </div>
          )}
        </Section>
      )}

      {node.nva && (
        <Section
          title={`NVA-Heuristik: ${node.nva.potentialNva ? "wahrscheinlich NVA" : "kein NVA"} (${Math.round(node.nva.confidence * 100)} %)`}
        >
          <ul className="reasons">
            {node.nva.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </Section>
      )}

      {Object.keys(node.properties).length > 0 && (
        <Section title="Eigenschaften">
          <KeyValues
            values={Object.fromEntries(
              Object.entries(node.properties).map(([k, v]) => [
                k,
                Array.isArray(v) ? v.join(", ") : String(v),
              ]),
            )}
          />
        </Section>
      )}

      <TypeSpecific model={model} node={node} entity={entity} Link={Link} />

      <Relationships index={index} node={node} onSelect={onSelect} />

      {children.length > 0 && (
        <Section title={`Enthält (${children.length})`}>
          <ul className="link-list">
            {children.slice(0, 100).map((c) => (
              <li key={c.id}>
                <span className="muted small">{NODE_TYPE_LABELS[c.type]}</span> <Link id={c.id} />
              </li>
            ))}
            {children.length > 100 && <li className="muted">… {children.length - 100} weitere (im Baum)</li>}
          </ul>
        </Section>
      )}

      <details className="section">
        <summary>JSON (normalisiert)</summary>
        <pre className="json">{JSON.stringify(entity?.entity ?? node, null, 2)}</pre>
      </details>
    </div>
  );
}

function Breadcrumb({
  index,
  node,
  onSelect,
}: {
  index: GraphIndex;
  node: GraphNode;
  onSelect: (id: string) => void;
}) {
  const chain = ancestors(index, node.id);
  if (chain.length === 0) return null;
  return (
    <nav className="breadcrumb small" aria-label="Pfad">
      {chain.map((a) => (
        <span key={a.id}>
          <button className="link" onClick={() => onSelect(a.id)}>
            {a.name}
          </button>
          <span className="muted"> › </span>
        </span>
      ))}
      <span>{node.name}</span>
    </nav>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function KeyValues({ values }: { values: Record<string, ReactNode | undefined> }) {
  const entries = Object.entries(values).filter(([, v]) => v !== undefined && v !== "");
  return (
    <table className="kv">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <th>{k}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function NodeLink({
  index,
  id,
  onSelect,
  children,
}: {
  index: GraphIndex;
  id: string;
  onSelect: (id: string) => void;
  children?: ReactNode;
}) {
  const target = index.byId.get(id);
  return (
    <button className="link" onClick={() => onSelect(id)} title={id}>
      {children ?? target?.name ?? id.split("/").pop()}
    </button>
  );
}

function Relationships({
  index,
  node,
  onSelect,
}: {
  index: GraphIndex;
  node: GraphNode;
  onSelect: (id: string) => void;
}) {
  const edges = index.edgesByNode.get(node.id) ?? [];
  if (edges.length === 0) return null;
  const groups = new Map<string, { edge: GraphEdge; outgoing: boolean }[]>();
  for (const edge of edges) {
    const outgoing = edge.source === node.id;
    const key = `${EDGE_TYPE_LABELS[edge.type]} ${outgoing ? "→" : "←"}`;
    groups.set(key, [...(groups.get(key) ?? []), { edge, outgoing }]);
  }
  return (
    <Section title={`Beziehungen (${edges.length})`}>
      {[...groups.entries()].map(([title, list]) => (
        <div key={title} className="rel-group">
          <div className="rel-title">
            {title} <span className="muted">({list.length})</span>
          </div>
          <ul className="link-list">
            {list.slice(0, 60).map(({ edge, outgoing }) => {
              const other = outgoing ? edge.target : edge.source;
              const otherNode = index.byId.get(other);
              return (
                <li key={edge.id}>
                  <span className="muted small">{otherNode ? NODE_TYPE_LABELS[otherNode.type] : ""}</span>{" "}
                  <NodeLink index={index} id={other} onSelect={onSelect} />
                  {edge.family && <span className={`badge fam-badge-${edge.family}`}>{edge.family}</span>}
                  {edge.label && <span className="muted small"> · {edge.label}</span>}
                </li>
              );
            })}
            {list.length > 60 && <li className="muted">… {list.length - 60} weitere</li>}
          </ul>
        </div>
      ))}
    </Section>
  );
}

type LinkComponent = (props: { id: string | undefined; children?: ReactNode }) => ReactNode;

function TypeSpecific({
  model,
  node,
  entity,
  Link,
}: {
  model: NetworkModel;
  node: GraphNode;
  entity: EntityRef | undefined;
  Link: LinkComponent;
}) {
  const inv = model.inventory;
  switch (node.type) {
    case "vnet": {
      const peerings = inv.peerings.filter((p) => p.vnetId === node.id);
      if (peerings.length === 0) return null;
      return (
        <Section title={`Peerings (${peerings.length})`}>
          <table className="grid">
            <thead>
              <tr>
                <th>Remote VNet</th>
                <th>Status</th>
                <th>Remote IPv4</th>
                <th>Remote IPv6</th>
                <th>Fwd</th>
                <th>GW-Transit</th>
                <th>Remote-GW</th>
              </tr>
            </thead>
            <tbody>
              {peerings.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link id={p.remoteVnetId} />
                  </td>
                  <td>
                    {p.peeringState}
                    {p.peeringSyncLevel && p.peeringSyncLevel !== "FullyInSync"
                      ? ` (${p.peeringSyncLevel})`
                      : ""}
                  </td>
                  <td className="mono">{p.remoteAddressSpace.ipv4.join(", ")}</td>
                  <td className="mono">{p.remoteAddressSpace.ipv6.join(", ")}</td>
                  <td>{yesNo(p.allowForwardedTraffic)}</td>
                  <td>{yesNo(p.allowGatewayTransit)}</td>
                  <td>{yesNo(p.useRemoteGateways)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      );
    }
    case "subnet": {
      const s = entity?.entity as SubnetEntity | undefined;
      if (!s) return null;
      return (
        <Section title="Subnet-Konfiguration">
          <KeyValues
            values={{
              NSG: <Link id={s.nsgId} />,
              "Route Table": <Link id={s.routeTableId} />,
              "NAT Gateway": <Link id={s.natGatewayId} />,
              Delegationen: s.delegations.join(", ") || "–",
              "Service Endpoints": s.serviceEndpoints.join(", ") || "–",
              "Default Outbound Access":
                s.defaultOutboundAccess === undefined ? "nicht gesetzt" : yesNo(s.defaultOutboundAccess),
              "PE Network Policies": s.privateEndpointNetworkPolicies,
              "IP-Konfigurationen": String(s.ipConfigurationCount),
            }}
          />
        </Section>
      );
    }
    case "routeTable": {
      const routes = inv.routes.filter((r) => r.routeTableId === node.id);
      return (
        <Section title={`Routen (${routes.length})`}>
          <table className="grid">
            <thead>
              <tr>
                <th>Name</th>
                <th>Präfix</th>
                <th>IP</th>
                <th>Next Hop</th>
                <th>Next-Hop-IP</th>
                <th>Ziel</th>
              </tr>
            </thead>
            <tbody>
              {routes.map((r) => (
                <tr key={r.id} className={r.defaultRoute ? "highlight" : ""}>
                  <td>{r.name}</td>
                  <td className="mono">{r.addressPrefix}</td>
                  <td>{r.ipVersion}</td>
                  <td>{r.nextHopType}</td>
                  <td className="mono">{r.nextHopIpAddress ?? ""}</td>
                  <td>{r.nextHopResourceId ? <Link id={r.nextHopResourceId} /> : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      );
    }
    case "nsg": {
      const nsg = entity?.entity as NsgEntity | undefined;
      if (!nsg) return null;
      return (
        <Section title={`Regeln (${nsg.rules.length} + ${nsg.defaultRules.length} Default)`}>
          <NsgRules rules={[...nsg.rules, ...nsg.defaultRules]} />
        </Section>
      );
    }
    case "firewallPolicy": {
      const groups = inv.ruleCollectionGroups.filter((g) => g.firewallPolicyId === node.id);
      return (
        <Section title={`Rule Collection Groups (${groups.length})`}>
          {groups.map((g) => (
            <FirewallRules key={g.id} group={g} />
          ))}
        </Section>
      );
    }
    case "ruleCollectionGroup": {
      const g = entity?.entity as RuleCollectionGroupEntity | undefined;
      return g ? (
        <Section title="Regeln">
          <FirewallRules group={g} />
        </Section>
      ) : null;
    }
    case "natGateway": {
      const nat = entity?.entity as NatGatewayEntity | undefined;
      if (!nat) return null;
      return (
        <Section title="NAT-Egress">
          <KeyValues
            values={{
              SKU: nat.sku,
              "IPv4 Egress konfiguriert": yesNo(nat.ipv4EgressConfigured),
              "IPv6 Egress konfiguriert": yesNo(nat.ipv6EgressConfigured),
              "Dual-Stack Egress": yesNo(nat.dualStackEgressConfigured),
              "Idle Timeout (min)":
                nat.idleTimeoutInMinutes !== undefined ? String(nat.idleTimeoutInMinutes) : undefined,
            }}
          />
          {nat.sku === "Standard" && (
            <p className="muted small">
              NAT Gateway Standard unterstützt keine IPv6-Public-IPs; für IPv6-Egress ist StandardV2
              erforderlich.
            </p>
          )}
        </Section>
      );
    }
    case "privateEndpoint": {
      const pe = entity?.entity as PrivateEndpointEntity | undefined;
      if (!pe) return null;
      return (
        <Section title="Private-Link-Ziele">
          <table className="grid">
            <thead>
              <tr>
                <th>Ziel</th>
                <th>Gruppe</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {pe.targets.map((t) => (
                <tr key={t.resourceId}>
                  <td>
                    <Link id={t.resourceId} />
                  </td>
                  <td>{t.groupIds.join(", ")}</td>
                  <td>{t.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {pe.customDnsConfigs.length > 0 && (
            <KeyValues
              values={Object.fromEntries(
                pe.customDnsConfigs.map((c) => [c.fqdn ?? "?", c.ipAddresses.join(", ")]),
              )}
            />
          )}
        </Section>
      );
    }
    case "privateDnsZone": {
      const z = entity?.entity as PrivateDnsZoneEntity | undefined;
      if (!z) return null;
      return (
        <Section title={`Records (${z.records.length}) · VNet-Links (${z.vnetLinks.length})`}>
          <table className="grid">
            <thead>
              <tr>
                <th>Name</th>
                <th>Typ</th>
                <th>Werte</th>
              </tr>
            </thead>
            <tbody>
              {z.records.slice(0, 200).map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td>{r.recordType}</td>
                  <td className="mono">{r.values.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      );
    }
    case "loadBalancer": {
      const lb = entity?.entity as LoadBalancerEntity | undefined;
      if (!lb) return null;
      return (
        <Section title="Frontends & Pools">
          <KeyValues
            values={{
              Frontends: lb.frontends
                .map((f) => `${f.name}: ${f.privateIpAddress ?? (f.publicIpId ? "Public IP" : "?")}`)
                .join("; "),
              "Backend Pools":
                lb.backendPools.map((p) => `${p.name} (${p.memberIds.length})`).join("; ") || "–",
              "Outbound Rules": lb.outboundRules.map((o) => o.name).join(", ") || "–",
            }}
          />
        </Section>
      );
    }
    default:
      return null;
  }
}

function NsgRules({ rules }: { rules: NsgRuleEntity[] }) {
  return (
    <table className="grid">
      <thead>
        <tr>
          <th>Prio</th>
          <th>Richtung</th>
          <th>Aktion</th>
          <th>Name</th>
          <th>Protokoll</th>
          <th>Quelle</th>
          <th>Ziel</th>
          <th>Ports</th>
          <th>IP</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r) => (
          <tr
            key={`${r.direction}-${r.priority}-${r.name}`}
            className={
              r.isDefault
                ? "muted"
                : r.access === "Allow" && r.direction === "Inbound" && r.sources.some(isOpenSource)
                  ? "highlight"
                  : ""
            }
          >
            <td>{r.priority}</td>
            <td>{r.direction === "Inbound" ? "in" : "out"}</td>
            <td className={r.access === "Allow" ? "status-ok" : "status-error"}>{r.access}</td>
            <td>{r.name}</td>
            <td>{r.protocol}</td>
            <td className="mono">
              {[...r.sources, ...r.sourceAsgIds.map((a) => `ASG:${a.split("/").pop()}`)].join(", ")}
            </td>
            <td className="mono">
              {[...r.destinations, ...r.destinationAsgIds.map((a) => `ASG:${a.split("/").pop()}`)].join(", ")}
            </td>
            <td className="mono">{r.destinationPorts.join(", ")}</td>
            <td>{r.ipFamilies.join(", ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FirewallRules({ group }: { group: RuleCollectionGroupEntity }) {
  return (
    <div className="rcg">
      <div className="rel-title">
        {group.name} <span className="muted">(Priorität {group.priority ?? "?"})</span>
      </div>
      {group.ruleCollections.map((c) => (
        <details key={c.name} className="rule-collection">
          <summary>
            {c.name} · {c.collectionType.replace("FirewallPolicy", "").replace("RuleCollection", "")} ·{" "}
            {c.action ?? ""} · Prio {c.priority ?? "?"} · {c.rules.length} Regeln
          </summary>
          <table className="grid">
            <thead>
              <tr>
                <th>Name</th>
                <th>Typ</th>
                <th>Quelle</th>
                <th>Ziel</th>
                <th>Ports/Protokolle</th>
                <th>IPv6</th>
              </tr>
            </thead>
            <tbody>
              {c.rules.map((r) => (
                <tr key={r.name}>
                  <td>{r.name}</td>
                  <td>{r.ruleType.replace("Rule", "")}</td>
                  <td className="mono">
                    {[...r.sources, ...r.sourceIpGroupIds.map((g) => `IPG:${g.split("/").pop()}`)].join(", ")}
                  </td>
                  <td className="mono">
                    {[
                      ...r.destinations,
                      ...r.destinationIpGroupIds.map((g) => `IPG:${g.split("/").pop()}`),
                      ...r.destinationFqdns,
                      ...r.targetFqdns,
                    ].join(", ")}
                  </td>
                  <td className="mono">{[...r.destinationPorts, ...r.protocols].join(", ")}</td>
                  <td>{r.ipv6Rule === undefined ? "" : yesNo(r.ipv6Rule)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      ))}
    </div>
  );
}

const isOpenSource = (s: string) =>
  s === "*" || s === "Internet" || s === "0.0.0.0/0" || s === "::/0" || s === "Any";
const yesNo = (v: boolean | undefined) => (v === undefined ? "–" : v ? "ja" : "nein");
