import { useMemo, useState } from "react";
import { assessServices, type Finding, type Severity } from "../../assessment/index.js";
import type { NormalizedInventory, PaasServiceEntity } from "../../models/network.js";
import { lastSegment } from "../../utils/ids.js";
import { EXPOSURE_LABEL, PE_DNS_LABEL, peDnsClass } from "../workspace/ServiceDetails.js";

const SEVERITIES: Severity[] = ["HIGH", "MEDIUM", "LOW", "INFO"];
const EXPOSURES: PaasServiceEntity["exposure"][] = ["public", "restricted", "unknown", "private"];
const SERVER_KIND: Record<string, string> = {
  azureDns: "Azure DNS",
  resolverInbound: "Private Resolver",
  firewall: "Firewall-DNS-Proxy",
  vnet: "Server im VNet",
  external: "extern",
};

const matches = (filter: string, ...values: (string | undefined)[]) =>
  !filter || values.some((v) => v?.toLowerCase().includes(filter));

/**
 * Overview of PaaS endpoints and DNS: findings, PaaS exposure, VNet DNS settings, Private DNS
 * zones, resolvers/rulesets and the per-endpoint DNS check (src/assessment).
 */
export function ServiceAssessmentView({ inventory }: { inventory: NormalizedInventory }) {
  const a = useMemo(() => assessServices(inventory), [inventory]);
  const [filter, setFilter] = useState("");
  const [category, setCategory] = useState<"all" | Finding["category"]>("all");
  const f = filter.trim().toLowerCase();
  const vnetName = useMemo(() => new Map(inventory.vnets.map((v) => [v.id, v.name])), [inventory]);
  const name = (id: string | undefined) => (id ? (vnetName.get(id) ?? lastSegment(id)) : "–");

  const findings = a.findings.filter(
    (x) => (category === "all" || x.category === category) && matches(f, x.title, x.detail, x.code),
  );
  const bySeverity = Object.fromEntries(
    SEVERITIES.map((s) => [s, a.findings.filter((x) => x.severity === s).length]),
  );
  const peStatus: Record<string, number> = {};
  for (const c of a.dns.privateEndpoints) peStatus[c.status] = (peStatus[c.status] ?? 0) + 1;
  const paas = [...inventory.paasServices]
    .filter((s) => matches(f, s.name, s.service, s.resourceGroup, ...s.endpoints))
    .sort(
      (x, y) => EXPOSURES.indexOf(x.exposure) - EXPOSURES.indexOf(y.exposure) || x.name.localeCompare(y.name),
    );

  return (
    <>
      <section className="panel">
        <h2>Bewertung: PaaS-Endpunkte & DNS</h2>
        <div className="assessment-tiles">
          <div className="tile">
            <div className="tile-value">{a.findings.length}</div>
            <div className="small">
              Befunde:{" "}
              {SEVERITIES.map((s) => (
                <span key={s} className={`severity-badge severity-${s}`}>
                  {s} {bySeverity[s]}
                </span>
              ))}
            </div>
          </div>
          <div className="tile">
            <div className="tile-value">{a.paas.total}</div>
            <div className="small">
              PaaS-Dienste:{" "}
              {EXPOSURES.map((e) => (
                <span key={e} className={`exposure exposure-${e}`}>
                  {EXPOSURE_LABEL[e]} {a.paas.byExposure[e]}
                </span>
              ))}
            </div>
          </div>
          <div className="tile">
            <div className="tile-value">{a.dns.privateEndpoints.length}</div>
            <div className="small">
              Private-Endpoint-Auflösungen:{" "}
              {Object.entries(peStatus).map(([s, n]) => (
                <span key={s} className={peDnsClass(s as keyof typeof PE_DNS_LABEL)}>
                  {PE_DNS_LABEL[s as keyof typeof PE_DNS_LABEL]} {n}{" "}
                </span>
              ))}
            </div>
          </div>
          <div className="tile">
            <div className="tile-value">{a.dns.vnets.filter((v) => v.mode === "custom").length}</div>
            <div className="small">
              von {a.dns.vnets.length} VNets mit eigenen DNS-Servern · {a.dns.zones.length} Private-DNS-Zonen
              · {a.dns.resolvers.length} Resolver
            </div>
          </div>
        </div>
        <div className="row assessment-filter">
          <input
            placeholder="Filtern nach Name, Dienst, Zone, Resource Group …"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <select value={category} onChange={(e) => setCategory(e.target.value as typeof category)}>
            <option value="all">Alle Befunde</option>
            <option value="paas">nur PaaS</option>
            <option value="dns">nur DNS</option>
          </select>
        </div>
      </section>

      <details className="panel" open>
        <summary>
          <h2>Befunde ({findings.length})</h2>
        </summary>
        {findings.length === 0 ? (
          <p className="muted small">Keine Befunde.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Schwere</th>
                <th>Befund</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((x) => (
                <tr key={x.id}>
                  <td>
                    <span className={`severity-badge severity-${x.severity}`}>{x.severity}</span>
                    <div className="muted small">{x.category.toUpperCase()}</div>
                  </td>
                  <td>{x.title}</td>
                  <td className="small">{x.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </details>

      <details className="panel" open>
        <summary>
          <h2>PaaS-Endpunkte ({paas.length})</h2>
        </summary>
        {paas.length === 0 ? (
          <p className="muted small">
            Keine PaaS-Dienste im Inventar. Ältere Exporte enthalten sie nicht – eine neue Discovery erfasst
            sie.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Dienst</th>
                <th>Erreichbarkeit</th>
                <th>Public Access</th>
                <th>Firewall</th>
                <th>Private Endpoints</th>
                <th>VNet</th>
                <th>Endpunkt</th>
              </tr>
            </thead>
            <tbody>
              {paas.map((s) => (
                <tr key={s.id}>
                  <td>
                    {s.name}
                    <div className="muted small">{s.resourceGroup}</div>
                  </td>
                  <td className="small">{s.service}</td>
                  <td>
                    <span className={`exposure exposure-${s.exposure}`} title={s.exposureReasons.join("\n")}>
                      {EXPOSURE_LABEL[s.exposure]}
                    </span>
                  </td>
                  <td className="small">{s.publicNetworkAccess}</td>
                  <td className="small">
                    {s.firewall.source === "none"
                      ? "nicht lesbar"
                      : `${s.firewall.defaultAction ?? "–"}${s.firewall.ipRules.length ? ` · ${s.firewall.ipRules.length} IP` : ""}${s.firewall.subnetIds.length ? ` · ${s.firewall.subnetIds.length} Subnet` : ""}${s.firewall.bypass ? ` · ${s.firewall.bypass}` : ""}`}
                  </td>
                  <td>{s.privateEndpointIds.length || "–"}</td>
                  <td className="small">
                    {s.vnetIntegration.subnetIds.length
                      ? `${s.vnetIntegration.mode === "injection" ? "Injection" : "Integration"}: ${s.vnetIntegration.subnetIds.map(lastSegment).join(", ")}`
                      : "–"}
                  </td>
                  <td className="mono small">{s.endpoints[0] ?? "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </details>

      <details className="panel">
        <summary>
          <h2>DNS-Einstellungen der VNets ({a.dns.vnets.length})</h2>
        </summary>
        <table>
          <thead>
            <tr>
              <th>VNet</th>
              <th>DNS-Server</th>
              <th>Zonen wirken aus</th>
              <th>Verlinkte Zonen</th>
              <th>Regelsätze</th>
            </tr>
          </thead>
          <tbody>
            {a.dns.vnets
              .filter((v) => matches(f, v.vnet, ...v.servers.map((s) => s.ip), ...v.linkedZones))
              .map((v) => (
                <tr key={v.vnetId}>
                  <td>{v.vnet}</td>
                  <td className="small">
                    {v.mode === "azure"
                      ? "Azure-DNS"
                      : v.servers.map((s) => (
                          <div key={s.ip}>
                            <span className="mono">{s.ip}</span> · {SERVER_KIND[s.kind]}
                            {s.name ? ` (${s.name})` : ""}
                          </div>
                        ))}
                  </td>
                  <td className="small">
                    {v.resolvingVnetIds.map(name).join(", ") || "–"}
                    {!v.verifiable && <div className="status-warn">externe Server – nicht prüfbar</div>}
                  </td>
                  <td>{v.linkedZones.length}</td>
                  <td className="small">{v.rulesets.join(", ") || "–"}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </details>

      <details className="panel">
        <summary>
          <h2>Private-DNS-Zonen ({a.dns.zones.length})</h2>
        </summary>
        <table>
          <thead>
            <tr>
              <th>Zone</th>
              <th>Resource Group</th>
              <th>Verlinkte VNets</th>
              <th>Auto-Registrierung</th>
              <th>Records (A)</th>
              <th>Hinweis</th>
            </tr>
          </thead>
          <tbody>
            {a.dns.zones
              .filter((z) => matches(f, z.name, z.resourceGroup))
              .sort((x, y) => x.name.localeCompare(y.name))
              .map((z) => (
                <tr key={z.id}>
                  <td className="mono small">{z.name}</td>
                  <td className="small">{z.resourceGroup}</td>
                  <td className="small">
                    {z.linkedVnetIds.map(name).join(", ") || <span className="status-warn">keine</span>}
                  </td>
                  <td className="small">{z.registrationVnetIds.map(name).join(", ") || "–"}</td>
                  <td>
                    {z.records} ({z.aRecords})
                  </td>
                  <td className="small">
                    {z.sameNameZones > 1 && <span className="status-warn">{z.sameNameZones}× vorhanden</span>}
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </details>

      <details className="panel">
        <summary>
          <h2>
            DNS Private Resolver & Weiterleitungs-Regelsätze ({a.dns.resolvers.length} /{" "}
            {a.dns.rulesets.length})
          </h2>
        </summary>
        {a.dns.resolvers.length + a.dns.rulesets.length === 0 ? (
          <p className="muted small">Keine DNS Private Resolver erfasst.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Typ</th>
                <th>Konfiguration</th>
                <th>Verwendet von / verlinkt mit</th>
              </tr>
            </thead>
            <tbody>
              {a.dns.resolvers.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="small">Resolver in {name(r.vnetId)}</td>
                  <td className="small">
                    Inbound: <span className="mono">{r.inboundIps.join(", ") || "–"}</span>
                    <br />
                    Outbound: {r.outboundEndpoints.join(", ") || "–"}
                  </td>
                  <td className="small">{r.usedByVnetIds.map(name).join(", ") || "–"}</td>
                </tr>
              ))}
              {a.dns.rulesets.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="small">Regelsatz · Outbound {r.outboundEndpoints.join(", ") || "–"}</td>
                  <td className="small">
                    {r.rules.map((x) => (
                      <div key={x.name} className={x.enabled ? "" : "muted"}>
                        <span className="mono">{x.domain}</span> →{" "}
                        <span className="mono">{x.targets.join(", ")}</span>
                        {!x.enabled && " (deaktiviert)"}
                      </div>
                    ))}
                  </td>
                  <td className="small">{r.linkedVnetIds.map(name).join(", ") || "–"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </details>

      <details className="panel">
        <summary>
          <h2>DNS-Prüfung der Private Endpoints ({a.dns.privateEndpoints.length})</h2>
        </summary>
        <table>
          <thead>
            <tr>
              <th>Private Endpoint</th>
              <th>Ziel</th>
              <th>Gruppe</th>
              <th>IP</th>
              <th>Status</th>
              <th>Befund</th>
            </tr>
          </thead>
          <tbody>
            {a.dns.privateEndpoints
              .filter((c) => matches(f, c.privateEndpoint, c.target, c.groupId, ...c.expectedZones))
              .map((c) => (
                <tr key={`${c.privateEndpointId}|${c.targetId}|${c.groupId}`}>
                  <td>{c.privateEndpoint}</td>
                  <td>{c.target}</td>
                  <td className="small">{c.groupId}</td>
                  <td className="mono small">{c.ips.join(", ")}</td>
                  <td className={peDnsClass(c.status)}>{PE_DNS_LABEL[c.status]}</td>
                  <td className="small">{c.detail}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </details>
    </>
  );
}
