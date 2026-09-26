export type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEVERITY_ORDER: Record<Severity, number> = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };

/** A rule-based assessment result (deterministic, derived from the normalized inventory). */
export interface Finding {
  /** Stable id: `<code>:<primary resource id>`. */
  id: string;
  category: "paas" | "dns";
  severity: Severity;
  code: string;
  title: string;
  detail: string;
  resourceIds: string[];
}

export function finding(
  category: Finding["category"],
  severity: Severity,
  code: string,
  title: string,
  detail: string,
  resourceIds: string[],
): Finding {
  return { id: `${code}:${resourceIds[0] ?? ""}`, category, severity, code, title, detail, resourceIds };
}

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      a.code.localeCompare(b.code) ||
      a.id.localeCompare(b.id),
  );
}
