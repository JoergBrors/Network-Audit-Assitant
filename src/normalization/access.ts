/** Defensive accessors for untyped ARG payloads (properties can be missing in ARG results). */

export type Obj = Record<string, unknown>;

export function obj(value: unknown): Obj {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Obj) : {};
}

export function arr(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function num(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value)))
    return Number(value);
  return undefined;
}

export function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (value === "true" || value === "True") return true;
  if (value === "false" || value === "False") return false;
  return undefined;
}

export function strings(value: unknown): string[] {
  return arr(value).flatMap((v) => (typeof v === "string" && v.length > 0 ? [v] : []));
}

/** Merges the singular and plural variants ARM uses (e.g. addressPrefix / addressPrefixes). */
export function singleOrMany(single: unknown, many: unknown): string[] {
  const out = strings(many);
  const s = str(single);
  if (s && !out.includes(s)) out.unshift(s);
  return out;
}

export function tagsOf(value: unknown): Record<string, string> | undefined {
  const o = obj(value);
  const entries = Object.entries(o).filter((e): e is [string, string] => typeof e[1] === "string");
  return entries.length > 0 ? Object.fromEntries(entries.map(([k, v]) => [k.trim(), v])) : undefined;
}

/** Collects every ARM resource ID referenced anywhere in a payload (used for unclassified resources). */
export function collectReferencedIds(value: unknown, out = new Set<string>(), depth = 0): Set<string> {
  if (depth > 6) return out;
  if (typeof value === "string") {
    if (/^\/subscriptions\/[^/]+\/resourcegroups\//i.test(value)) out.add(value.toLowerCase());
  } else if (Array.isArray(value)) {
    for (const v of value) collectReferencedIds(v, out, depth + 1);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) collectReferencedIds(v, out, depth + 1);
  }
  return out;
}
