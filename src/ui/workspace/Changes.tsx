import { useMemo, useState } from "react";
import type {
  ChangeKind,
  DriftCategory,
  FieldChange,
  RelationshipChange,
  ResourceChange,
  SnapshotDiff,
} from "../../drift/diff.js";
import { CATEGORY_ORDER } from "../../drift/diff.js";
import { NODE_TYPE_LABELS } from "../../models/graph.js";

export const CATEGORY_LABEL: Record<DriftCategory, string> = {
  POTENTIALLY_BREAKING: "Potenziell kritisch",
  SECURITY_RELEVANT: "Sicherheitsrelevant",
  ARCHITECTURE_RELEVANT: "Architekturrelevant",
  EXPECTED: "Erwartet",
  INFORMATIONAL: "Informativ",
};

export const KIND_LABEL: Record<ChangeKind, string> = {
  added: "NEU",
  removed: "ENTFERNT",
  changed: "GEÄNDERT",
};

const formatDate = (iso: string) => (iso ? new Date(iso).toLocaleString() : "?");

export interface ComparisonInfo {
  diff: SnapshotDiff;
  baselineLabel: string;
}

/** Compact summary bar shown above the topology while a comparison is active. */
export function ComparisonBar({
  info,
  onlyChanges,
  onToggleOnlyChanges,
  onExport,
  onClose,
}: {
  info: ComparisonInfo;
  onlyChanges: boolean;
  onToggleOnlyChanges: () => void;
  onExport: () => void;
  onClose: () => void;
}) {
  const { summary, baseline, current } = info.diff;
  const newerBaseline = baseline.generatedAt > current.generatedAt;
  return (
    <div className="compare-bar small">
      <span className="compare-title">
        Vergleich: <strong>{info.baselineLabel}</strong> ({formatDate(baseline.generatedAt)}) → aktuell (
        {formatDate(current.generatedAt)})
      </span>
      <span className="chip chip-added">+{summary.added} neu</span>
      <span className="chip chip-removed">−{summary.removed} entfernt</span>
      <span className="chip chip-changed">~{summary.changed} geändert</span>
      <span className="chip">
        Beziehungen +{summary.relationshipsAdded} / −{summary.relationshipsRemoved}
      </span>
      {summary.byCategory.POTENTIALLY_BREAKING > 0 && (
        <span className="chip chip-breaking">
          {summary.byCategory.POTENTIALLY_BREAKING} potenziell kritisch
        </span>
      )}
      {summary.byCategory.SECURITY_RELEVANT > 0 && (
        <span className="chip chip-security">{summary.byCategory.SECURITY_RELEVANT} sicherheitsrelevant</span>
      )}
      {summary.ipv6Changes > 0 && <span className="chip chip-ipv6">{summary.ipv6Changes} IPv6</span>}
      {newerBaseline && (
        <span className="status-warn">Hinweis: Vergleichsbasis ist neuer als der aktuelle Stand.</span>
      )}
      <label className="checkbox">
        <input type="checkbox" checked={onlyChanges} onChange={onToggleOnlyChanges} /> Nur Änderungen
      </label>
      <button className="secondary small-button" onClick={onExport}>
        Diff exportieren
      </button>
      <button className="secondary small-button" onClick={onClose}>
        Vergleich beenden
      </button>
    </div>
  );
}

type Entry =
  { kind: "resource"; change: ResourceChange } | { kind: "relationship"; change: RelationshipChange };

/** Change list grouped by drift category (most critical first). */
export function ChangeList({ diff, onSelect }: { diff: SnapshotDiff; onSelect: (id: string) => void }) {
  const [filter, setFilter] = useState("");
  const groups = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const entries: Entry[] = [
      ...diff.resources.map((change) => ({ kind: "resource" as const, change })),
      ...diff.relationships.map((change) => ({ kind: "relationship" as const, change })),
    ].filter(
      (e) =>
        !q ||
        (e.kind === "resource" ? `${e.change.name} ${e.change.summary}` : e.change.summary)
          .toLowerCase()
          .includes(q),
    );
    return CATEGORY_ORDER.map((category) => ({
      category,
      entries: entries.filter((e) => e.change.category === category),
    })).filter((g) => g.entries.length > 0);
  }, [diff, filter]);

  if (diff.resources.length + diff.relationships.length === 0) {
    return (
      <div className="detail">
        <h2>Keine Änderungen</h2>
        <p className="muted">Der aktuelle Stand entspricht dem Snapshot.</p>
      </div>
    );
  }
  return (
    <div className="detail">
      <h2>Änderungen seit Snapshot</h2>
      <input
        type="search"
        placeholder="Änderungen filtern"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="change-filter"
      />
      {groups.map((g) => (
        <section key={g.category} className="section">
          <h3 className={`cat-title cat-title-${g.category}`}>
            {CATEGORY_LABEL[g.category]} ({g.entries.length})
          </h3>
          <ul className="change-list">
            {g.entries.slice(0, 300).map((e) =>
              e.kind === "resource" ? (
                <li key={`r:${e.change.id}`} onClick={() => onSelect(e.change.id)}>
                  <span className={`change-badge change-${e.change.kind}`}>{KIND_LABEL[e.change.kind]}</span>
                  <span className="muted small">{NODE_TYPE_LABELS[e.change.nodeType]}</span>{" "}
                  <strong>{e.change.name}</strong>
                  {e.change.families.map((f) => (
                    <span key={f} className={`badge fam-badge-${f}`}>
                      {f}
                    </span>
                  ))}
                  {e.change.kind === "changed" && <div className="muted small">{e.change.summary}</div>}
                </li>
              ) : (
                <li
                  key={`e:${e.change.id}`}
                  onClick={() => onSelect(e.change.kind === "removed" ? e.change.source : e.change.source)}
                >
                  <span className={`change-badge change-${e.change.kind}`}>{KIND_LABEL[e.change.kind]}</span>
                  <span className="small">{e.change.summary}</span>
                </li>
              ),
            )}
            {g.entries.length > 300 && (
              <li className="muted">… {g.entries.length - 300} weitere (Diff-Export)</li>
            )}
          </ul>
        </section>
      ))}
    </div>
  );
}

/** Field-level before/after view for one resource. */
export function ChangeDetails({
  change,
  relationships,
}: {
  change: ResourceChange | undefined;
  relationships: RelationshipChange[];
}) {
  if (!change && relationships.length === 0) return null;
  return (
    <section className={`section change-section change-${change?.kind ?? "changed"}-border`}>
      <h3>
        Änderung seit Snapshot
        {change && (
          <>
            {" "}
            <span className={`change-badge change-${change.kind}`}>{KIND_LABEL[change.kind]}</span>{" "}
            <span className={`cat-title-${change.category}`}>{CATEGORY_LABEL[change.category]}</span>
          </>
        )}
      </h3>
      {change && change.fields.length > 0 && (
        <table className="grid diff-table">
          <thead>
            <tr>
              <th>Feld</th>
              <th>Vorher</th>
              <th>Nachher</th>
            </tr>
          </thead>
          <tbody>
            {change.fields.map((f) => (
              <FieldRow key={`${f.path}-${f.kind}`} field={f} />
            ))}
          </tbody>
        </table>
      )}
      {relationships.length > 0 && (
        <ul className="change-list">
          {relationships.map((r) => (
            <li key={r.id}>
              <span className={`change-badge change-${r.kind}`}>{KIND_LABEL[r.kind]}</span>{" "}
              <span className="small">{r.summary}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function FieldRow({ field }: { field: FieldChange }) {
  return (
    <tr>
      <td className="mono">{field.path}</td>
      <td className="mono diff-before">{field.kind === "added" ? "" : formatValue(field.before)}</td>
      <td className="mono diff-after">{field.kind === "removed" ? "" : formatValue(field.after)}</td>
    </tr>
  );
}

function formatValue(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((v) => typeof v !== "object")) return value.join(", ");
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    // NSG rule / route: one readable line instead of raw JSON.
    if ("priority" in o && "access" in o) {
      return `${String(o["priority"])} ${String(o["direction"])} ${String(o["access"])} ${String(o["protocol"])} ${fmtList(o["sources"])} → ${fmtList(o["destinations"])}:${fmtList(o["destinationPorts"])}`;
    }
    if ("addressPrefix" in o && "nextHopType" in o) {
      return `${String(o["addressPrefix"])} → ${String(o["nextHopType"])} ${typeof o["nextHopIpAddress"] === "string" ? o["nextHopIpAddress"] : ""}`;
    }
  }
  const json = JSON.stringify(value);
  return json.length > 300 ? `${json.slice(0, 300)} …` : json;
}

const fmtList = (v: unknown) =>
  Array.isArray(v)
    ? v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(",")
    : typeof v === "string"
      ? v
      : "";
