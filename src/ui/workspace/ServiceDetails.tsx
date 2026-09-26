import type { ReactNode } from "react";
import { assessServices } from "../../assessment/index.js";
import type { PeDnsCheck } from "../../assessment/dns.js";
import type { GraphNode } from "../../models/graph.js";
import type { PaasServiceEntity, SubnetEntity } from "../../models/network.js";
import type { NetworkModel } from "../../pipeline/analyze.js";
import type { EntityRef } from "./entityIndex.js";
import type { NormalizedInventory } from "../../models/network.js";
import { EGRESS_LABEL, INGRESS_LABEL } from "../../normalization/paasNetwork.js";
import { analyzeDefaultPaths, type DefaultPathSummary } from "../../routing/analysis.js";

type LinkComponent = (props: { id: string | undefined; children?: ReactNode }) => ReactNode;

export const EXPOSURE_LABEL: Record<PaasServiceEntity["exposure"], string> = {
  private: "nur privat",
  restricted: "öffentlich, eingeschränkt",
  public: "öffentlich, offen",
  none: "kein eigener Endpunkt",
  unknown: "unbekannt",
};

export const PE_DNS_LABEL: Record<PeDnsCheck["status"], string> = {
  ok: "OK",
  "missing-zone": "Zone fehlt",
  "missing-record": "Record fehlt",
  "not-linked": "Zone nicht verlinkt",
  unverifiable: "nicht prüfbar",
  "unknown-zone": "Zone unbekannt",
  inactive: "Verbindung inaktiv",
};

const SERVER_KIND: Record<string, string> = {
  azureDns: "Azure DNS",
  resolverInbound: "DNS Private Resolver",
  firewall: "Azure Firewall (DNS-Proxy)",
  vnet: "Server im VNet",
  external: "extern / On-Premises",
};

export function peDnsClass(status: PeDnsCheck["status"]): string {
  return status === "ok"
    ? "status-ok"
    : status === "unverifiable" || status === "inactive"
      ? "status-warn"
      : "status-error";
}

function Box({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="section">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function Rows({ values }: { values: Record<string, ReactNode | undefined> }) {
  const rows = Object.entries(values).filter(([, v]) => v !== undefined && v !== "" && v !== null);
  if (rows.length === 0) return null;
  return (
    <table className="kv">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th>{k}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Comma-separated links, or undefined (row hidden) for an empty list. */
function links(ids: string[], Link: LinkComponent): ReactNode | undefined {
  if (ids.length === 0) return undefined;
  return (
    <>
      {ids.map((id, i) => (
        <span key={id}>
          {i > 0 && ", "}
          <Link id={id} />
        </span>
      ))}
    </>
  );
}

function DnsChecks({
  checks,
  Link,
  first,
  zoneWhere,
}: {
  checks: PeDnsCheck[];
  Link: LinkComponent;
  first: "pe" | "target";
  zoneWhere: (id: string) => string | undefined;
}) {
  if (checks.length === 0) return null;
  // List layout: the detail pane is too narrow for a four-column table.
  return (
    <ul className="dns-checks">
      {checks.map((c) => (
        <li key={`${c.privateEndpointId}|${c.targetId}|${c.groupId}`}>
          <div>
            <Link id={first === "pe" ? c.privateEndpointId : c.targetId} />{" "}
            <span className="muted small">({c.groupId})</span>{" "}
            <strong className={peDnsClass(c.status)}>{PE_DNS_LABEL[c.status]}</strong>
          </div>
          <div className="small">{c.detail}</div>
          <ZoneLinks check={c} Link={Link} zoneWhere={zoneWhere} />
        </li>
      ))}
    </ul>
  );
}

function zoneState(c: PeDnsCheck, zoneId: string): { label: string; className: string } {
  if (c.linkedZoneIds.includes(zoneId)) return { label: "A-Record, verlinkt", className: "status-ok" };
  if (c.recordZoneIds.includes(zoneId))
    return { label: "A-Record, nicht verlinkt", className: "status-error" };
  // Resolution works through another zone: an equally named empty zone is only a side note.
  if (c.linkedZoneIds.length > 0) return { label: "gleichnamige Zone, ohne A-Record", className: "muted" };
  return { label: "ohne A-Record", className: "status-error" };
}

/** Linked Private DNS zones of a check and the VNets whose zone links resolve for the endpoint. */
function ZoneLinks({
  check: c,
  Link,
  zoneWhere,
}: {
  check: PeDnsCheck;
  Link: LinkComponent;
  zoneWhere: (id: string) => string | undefined;
}) {
  // Working zone first: equally named zones (split-horizon copies) are told apart by their location.
  const rank = (id: string) => (c.linkedZoneIds.includes(id) ? 0 : c.recordZoneIds.includes(id) ? 1 : 2);
  const zoneIds = [...new Set([...c.zoneIds, ...c.recordZoneIds])].sort((a, b) => rank(a) - rank(b));
  if (zoneIds.length === 0 && c.resolvingVnetIds.length === 0) return null;
  return (
    <ul className="link-list small">
      {zoneIds.map((id) => {
        const state = zoneState(c, id);
        return (
          <li key={id}>
            Private-DNS-Zone <Link id={id} />
            {zoneWhere(id) && <span className="muted"> ({zoneWhere(id)})</span>} ·{" "}
            <span className={state.className}>{state.label}</span>
          </li>
        );
      })}
      {c.resolvingVnetIds.length > 0 && (
        <li>
          Auflösung über VNet{c.resolvingVnetIds.length > 1 ? "s" : ""}{" "}
          {c.resolvingVnetIds.map((id, i) => (
            <span key={id}>
              {i > 0 && ", "}
              <Link id={id} />
            </span>
          ))}
        </li>
      )}
    </ul>
  );
}

/** Internet default path per subnet (computed once per inventory). */
const defaultPathCache = new WeakMap<NormalizedInventory, Map<string, DefaultPathSummary[]>>();
function defaultPathsBySubnet(inv: NormalizedInventory): Map<string, DefaultPathSummary[]> {
  let map = defaultPathCache.get(inv);
  if (!map) {
    map = new Map();
    for (const p of analyzeDefaultPaths(inv)) map.set(p.subnetId, [...(map.get(p.subnetId) ?? []), p]);
    defaultPathCache.set(inv, map);
  }
  return map;
}

const INGRESS_CLASS: Record<string, string> = {
  internet: "exposure-public",
  "internet-restricted": "exposure-restricted",
  vnet: "exposure-private",
  "private-endpoint": "exposure-private",
  none: "exposure-private",
  unknown: "exposure-unknown",
};

/** Ingress and egress profile of a PaaS service (rules, IPs, subnets with their Internet path, links). */
function NetworkProfile({
  service: s,
  inventory,
  Link,
}: {
  service: PaasServiceEntity;
  inventory: NormalizedInventory;
  Link: LinkComponent;
}) {
  const ingress = s.ingress;
  const egress = s.egress;
  if (!ingress || !egress) return null;
  const paths = defaultPathsBySubnet(inventory);
  const linksOf = (direction: "ingress" | "egress" | "other") =>
    (s.links ?? []).filter((l) => l.direction === direction);
  const LinkList = ({ direction }: { direction: "ingress" | "egress" | "other" }) =>
    linksOf(direction).length ? (
      <ul className="link-list small">
        {linksOf(direction).map((l) => (
          <li key={`${l.id}|${l.label}`}>
            {l.label}: <Link id={l.id} />
          </li>
        ))}
      </ul>
    ) : null;
  return (
    <>
      <Box title={`Ingress · ${INGRESS_LABEL[ingress.mode]}`}>
        <p className="small">
          <span className={`exposure ${INGRESS_CLASS[ingress.mode]}`}>{INGRESS_LABEL[ingress.mode]}</span>{" "}
          {ingress.summary.split(" · ").slice(1).join(" · ")}
        </p>
        {ingress.ips.length > 0 && (
          <p className="small">
            Eingangs-IPs: <span className="mono">{ingress.ips.join(", ")}</span>
          </p>
        )}
        {ingress.rules.length > 0 && (
          <table className="grid small">
            <thead>
              <tr>
                <th>Quelle</th>
                <th>Aktion</th>
                <th>Prio</th>
                <th>Bereich / Name</th>
              </tr>
            </thead>
            <tbody>
              {ingress.rules.map((r, i) => (
                <tr key={i}>
                  <td className="mono">
                    {r.source.startsWith("/subscriptions/") ? <Link id={r.source} /> : r.source}
                  </td>
                  <td className={r.action === "Deny" ? "status-error" : "status-ok"}>{r.action}</td>
                  <td>{r.priority ?? ""}</td>
                  <td>{[r.scope, r.name].filter(Boolean).join(" · ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <Rows values={ingress.details} />
        <LinkList direction="ingress" />
      </Box>
      <Box title={`Egress · ${EGRESS_LABEL[egress.mode]}`}>
        <p className="small">{egress.summary}</p>
        {egress.subnetIds.length > 0 && (
          <ul className="link-list small">
            {egress.subnetIds.map((id) => (
              <li key={id}>
                Subnet <Link id={id} />
                {(paths.get(id) ?? []).map((p) => (
                  <div key={p.family} className="muted">
                    Internet ({p.family === "ipv4" ? "IPv4" : "IPv6"}): {p.summary}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        )}
        {egress.outboundIps.length > 0 && (
          <p className="small">
            Ausgangs-IPs ({egress.outboundIps.length}):{" "}
            <span className="mono">
              {egress.outboundIps.slice(0, 12).join(", ")}
              {egress.outboundIps.length > 12 ? " …" : ""}
            </span>
          </p>
        )}
        {egress.allowedTargets && (
          <p className="small">
            Ausgang nur zu:{" "}
            {egress.allowedTargets.length ? (
              <span className="mono">{egress.allowedTargets.join(", ")}</span>
            ) : (
              "keinem Ziel (Liste leer)"
            )}
          </p>
        )}
        <Rows values={egress.details} />
        <LinkList direction="egress" />
      </Box>
      {linksOf("other").length > 0 && (
        <Box title="Verknüpft">
          <LinkList direction="other" />
        </Box>
      )}
    </>
  );
}

/** PaaS exposure, DNS resolution and assessment findings for the selected node. */
export function ServiceDetails({
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
  const assessment = assessServices(model.inventory);
  const findings = assessment.findings.filter((f) => f.resourceIds.includes(node.id));
  const sections: ReactNode[] = [];
  const subscriptionNames = new Map(model.inventory.subscriptions.map((s) => [s.subscriptionId, s.name]));
  const zoneWhere = (id: string) => {
    const z = model.inventory.privateDnsZones.find((zone) => zone.id === id);
    if (!z) return undefined;
    const sub = z.subscriptionId ? (subscriptionNames.get(z.subscriptionId) ?? z.subscriptionId) : undefined;
    return [z.resourceGroup, sub].filter(Boolean).join(" · ") || undefined;
  };

  if (node.type === "paasService" && entity) {
    const s = entity.entity as unknown as PaasServiceEntity;
    sections.push(
      <Box key="paas" title={`Netzwerkzugriff · ${EXPOSURE_LABEL[s.exposure]}`}>
        <Rows
          values={{
            Dienst: `${s.service}${s.kind ? ` (${s.kind})` : ""}${s.sku ? ` · ${s.sku}` : ""}`,
            Erreichbarkeit: (
              <span className={`exposure exposure-${s.exposure}`}>{EXPOSURE_LABEL[s.exposure]}</span>
            ),
            Begründung: s.exposureReasons.join("; "),
            "Public Network Access": s.publicNetworkAccess,
            "Firewall-Standardaktion":
              s.firewall.source === "none" ? "nicht lesbar" : (s.firewall.defaultAction ?? "–"),
            "Erlaubte IPs": s.firewall.ipRules.length ? (
              <span className="mono">{s.firewall.ipRules.join(", ")}</span>
            ) : undefined,
            "Erlaubte Subnets": links(s.firewall.subnetIds, Link),
            Ausnahmen: s.firewall.bypass,
            "Private Endpoints": links(s.privateEndpointIds, Link),
            [s.vnetIntegration.mode === "injection" ? "VNet-Injection" : "VNet-Integration"]: s
              .vnetIntegration.subnetIds.length ? (
              <>
                {links(s.vnetIntegration.subnetIds, Link)}
                {s.vnetIntegration.routeAll !== undefined &&
                  ` · gesamter ausgehender Verkehr über VNet: ${s.vnetIntegration.routeAll ? "ja" : "nein"}`}
              </>
            ) : undefined,
            Endpunkte: s.endpoints.length ? (
              <span className="mono">{s.endpoints.join(", ")}</span>
            ) : undefined,
            "Ausgehende IPs": s.outboundIps.length ? (
              <span className="mono">{s.outboundIps.join(", ")}</span>
            ) : undefined,
            "Mindest-TLS": s.minimumTlsVersion,
            "Regeln aus": { arg: "Resource Graph", arm: "ARM-Abfrage", none: undefined }[s.firewall.source],
          }}
        />
      </Box>,
    );
    sections.push(<NetworkProfile key="paas-network" service={s} inventory={model.inventory} Link={Link} />);
    const checks = assessment.dns.privateEndpoints.filter((c) => c.targetId === node.id);
    if (checks.length)
      sections.push(
        <Box key="paas-dns" title={`DNS-Auflösung der Private Endpoints (${checks.length})`}>
          <DnsChecks checks={checks} Link={Link} first="pe" zoneWhere={zoneWhere} />
        </Box>,
      );
  }

  if (node.type === "privateEndpoint") {
    const checks = assessment.dns.privateEndpoints.filter((c) => c.privateEndpointId === node.id);
    if (checks.length)
      sections.push(
        <Box key="pe-dns" title="DNS-Auflösung">
          <DnsChecks checks={checks} Link={Link} first="target" zoneWhere={zoneWhere} />
          <p className="small muted">
            Erwartete Zone(n): {[...new Set(checks.flatMap((c) => c.expectedZones))].join(", ") || "–"}
          </p>
        </Box>,
      );
  }

  if (node.type === "vnet") {
    const dns = assessment.dns.vnets.find((v) => v.vnetId === node.id);
    if (dns)
      sections.push(
        <Box key="vnet-dns" title={`DNS · ${dns.mode === "azure" ? "Azure-DNS" : "eigene DNS-Server"}`}>
          <Rows
            values={{
              "DNS-Server": dns.servers.length ? (
                <ul className="link-list">
                  {dns.servers.map((s) => (
                    <li key={s.ip}>
                      <span className="mono">{s.ip}</span> · {SERVER_KIND[s.kind]}
                      {s.resourceId ? (
                        <>
                          {" "}
                          (<Link id={s.resourceId} />)
                        </>
                      ) : s.vnetId && s.vnetId !== node.id ? (
                        <>
                          {" "}
                          in <Link id={s.vnetId} />
                        </>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : (
                "Azure-DNS (168.63.129.16)"
              ),
              "Private-DNS-Zonen wirken aus": links(dns.resolvingVnetIds, Link),
              Prüfbar: dns.verifiable ? "ja" : "nein (externe DNS-Server)",
              "Verlinkte Zonen": dns.linkedZones.length
                ? `${dns.linkedZones.length}: ${dns.linkedZones.join(", ")}`
                : "keine",
              Regelsätze: dns.rulesets.join(", ") || undefined,
            }}
          />
        </Box>,
      );
  }

  if (node.type === "subnet" && entity) {
    const subnet = entity.entity as unknown as SubnetEntity;
    if (subnet.delegations.length || subnet.serviceLinks?.length) {
      const known = new Set(model.inventory.paasServices.map((x) => x.id));
      sections.push(
        <Box key="delegation" title="Delegation">
          <Rows values={{ "Delegiert an": subnet.delegations.join(", ") || "–" }} />
          {subnet.serviceLinks?.length ? (
            <ul className="link-list small">
              {subnet.serviceLinks.map((l, i) => (
                <li key={i}>
                  {l.kind === "serviceAssociation" ? "Service Association Link" : "Resource Navigation Link"}
                  {l.linkedResourceType ? ` (${l.linkedResourceType})` : ""}:{" "}
                  {l.linkId ? (
                    known.has(l.linkId) ? (
                      <Link id={l.linkId} />
                    ) : (
                      <span className="mono" title={l.linkId}>
                        {l.linkId.split("/").pop()} <span className="status-warn">(nicht im Inventar)</span>
                      </span>
                    )
                  ) : (
                    (l.name ?? "–")
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="small muted">Kein Service Association Link – die Plattform meldet keinen Nutzer.</p>
          )}
        </Box>,
      );
    }
  }

  if (findings.length)
    sections.push(
      <Box key="findings" title={`Bewertung (${findings.length})`}>
        <ul className="ai-findings">
          {findings.map((f) => (
            <li key={f.id}>
              <span className={`severity-badge severity-${f.severity}`}>{f.severity}</span>{" "}
              <strong>{f.title}</strong>
              <p className="small">{f.detail}</p>
            </li>
          ))}
        </ul>
      </Box>,
    );

  return <>{sections}</>;
}
