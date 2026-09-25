import type { NetworkModel } from "../../pipeline/analyze.js";
import type { SubscriptionEntity } from "../../models/network.js";

const CONFIDENCE_CLASS = { HIGH: "status-ok", MEDIUM: "status-warn", LOW: "status-error" } as const;

interface Props {
  discovery: NetworkModel["discovery"];
  subscriptions: SubscriptionEntity[];
  queryCounts: Record<string, number> | null;
}

export function DiscoverySummary({ discovery, subscriptions, queryCounts }: Props) {
  const q = discovery.quality;
  const warnings = discovery.warnings.filter((w) => !w.optional);
  const notices = discovery.warnings.filter((w) => w.optional);

  return (
    <>
      <section className="panel">
        <h2>Discovery Quality</h2>
        <table>
          <tbody>
            <tr>
              <th>Tenants</th>
              <td>
                {q.tenants.readable}/{q.tenants.total} lesbar
              </td>
            </tr>
            <tr>
              <th>Subscriptions</th>
              <td>
                {q.subscriptions.readable}/{q.subscriptions.total} lesbar
              </td>
            </tr>
            <tr>
              <th>Netzwerkressourcen</th>
              <td>{q.networkResources}</td>
            </tr>
            <tr>
              <th>ARG-Abfragen</th>
              <td>
                {q.argQueries.executed} ({q.argQueries.pages} Seiten, {q.argQueries.failed} fehlgeschlagen,{" "}
                {q.argQueries.truncated} gekürzt)
              </td>
            </tr>
            <tr>
              <th>Assessment-Konfidenz</th>
              <td className={CONFIDENCE_CLASS[q.overallConfidence]}>{q.overallConfidence}</td>
            </tr>
          </tbody>
        </table>
      </section>

      {warnings.length > 0 && (
        <WarningTable title={`Warnungen (${warnings.length})`} className="status-warn" items={warnings} />
      )}
      {notices.length > 0 && (
        <WarningTable
          title={`Hinweise (${notices.length}) – optionale Daten, ohne Einfluss auf die Konfidenz`}
          className="muted"
          items={notices}
        />
      )}

      <section className="panel">
        <h2>Subscriptions ({subscriptions.length})</h2>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Subscription ID</th>
              <th>Management Groups</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {subscriptions.map((s) => (
              <tr key={s.subscriptionId}>
                <td>
                  {s.name}
                  {s.accessTenantId !== s.tenantId && <span className="muted"> (Lighthouse)</span>}
                </td>
                <td className="mono">{s.subscriptionId}</td>
                <td className="small">{s.managementGroupPath.join(" › ")}</td>
                <td>{s.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {queryCounts && (
        <section className="panel">
          <h2>Ressourcen je Abfrage</h2>
          <table>
            <tbody>
              {Object.entries(queryCounts)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([id, count]) => (
                  <tr key={id}>
                    <td className="mono">{id}</td>
                    <td>{count}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}

function WarningTable({
  title,
  className,
  items,
}: {
  title: string;
  className: string;
  items: NetworkModel["discovery"]["warnings"];
}) {
  return (
    <section className="panel">
      <h2 className={className}>{title}</h2>
      <table>
        <thead>
          <tr>
            <th>Grund</th>
            <th>Operation</th>
            <th>Scope</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {items.map((w, i) => (
            <tr key={i}>
              <td>{w.reason}</td>
              <td className="mono">{w.operation}</td>
              <td className="mono">{w.scope ?? w.resource ?? ""}</td>
              <td className="mono">{w.detail ?? ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
