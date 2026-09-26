import type { ReactNode } from "react";
import { assessServices } from "../../assessment/index.js";
import type { PeDnsCheck } from "../../assessment/dns.js";
import type { GraphNode } from "../../models/graph.js";
import type { PaasServiceEntity } from "../../models/network.js";
import type { NetworkModel } from "../../pipeline/analyze.js";
import type { EntityRef } from "./entityIndex.js";

type LinkComponent = (props: { id: string | undefined; children?: ReactNode }) => ReactNode;

export const EXPOSURE_LABEL: Record<PaasServiceEntity["exposure"], string> = {
  private: "nur privat",
  restricted: "öffentlich, eingeschränkt",
  public: "öffentlich, offen",
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
}: {
  checks: PeDnsCheck[];
  Link: LinkComponent;
  first: "pe" | "target";
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
        </li>
      ))}
    </ul>
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
    const checks = assessment.dns.privateEndpoints.filter((c) => c.targetId === node.id);
    if (checks.length)
      sections.push(
        <Box key="paas-dns" title={`DNS-Auflösung der Private Endpoints (${checks.length})`}>
          <DnsChecks checks={checks} Link={Link} first="pe" />
        </Box>,
      );
  }

  if (node.type === "privateEndpoint") {
    const checks = assessment.dns.privateEndpoints.filter((c) => c.privateEndpointId === node.id);
    if (checks.length)
      sections.push(
        <Box key="pe-dns" title="DNS-Auflösung">
          <DnsChecks checks={checks} Link={Link} first="target" />
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
