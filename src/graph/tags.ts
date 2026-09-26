/** Azure tags per graph node, for the tag filter and the global search. */
export type TagIndex = ReadonlyMap<string, Readonly<Record<string, string>>>;

/** Collects the tags of all entities that carry some (`tags` field of normalized entities). */
export function buildTagIndex(entities: Iterable<[string, { entity: Record<string, unknown> }]>): TagIndex {
  const map = new Map<string, Record<string, string>>();
  for (const [id, ref] of entities) {
    const tags = ref.entity["tags"];
    if (tags && typeof tags === "object" && Object.keys(tags).length > 0)
      map.set(id, tags as Record<string, string>);
  }
  return map;
}

export interface TagQuery {
  key?: string;
  value?: string;
  /** Free text without `=`: matches keys or values. */
  text?: string;
}

/**
 * `key=value` (also `key:value`): key equal (case-insensitive), value containing the text;
 * `key=` or `key=*`: key present; anything else: key or value containing the text.
 */
export function parseTagQuery(input: string): TagQuery | undefined {
  const q = input.trim().toLowerCase();
  if (!q) return undefined;
  const sep = q.search(/[=:]/);
  if (sep < 0) return { text: q };
  const key = q.slice(0, sep).trim();
  const value = q.slice(sep + 1).trim();
  return { ...(key ? { key } : {}), ...(value && value !== "*" ? { value } : {}) };
}

/** The first tag matching the query, as `key=value`, or undefined. */
export function matchTag(tags: Readonly<Record<string, string>>, query: TagQuery): string | undefined {
  for (const [k, v] of Object.entries(tags)) {
    const key = k.toLowerCase();
    const value = String(v).toLowerCase();
    const ok = query.text
      ? key.includes(query.text) || value.includes(query.text)
      : (!query.key || key === query.key) && (!query.value || value.includes(query.value));
    if (ok) return `${k}=${v}`;
  }
  return undefined;
}

/** IDs of all nodes whose tags match the query text (undefined when the query is empty). */
export function nodesWithTag(index: TagIndex, input: string): Set<string> | undefined {
  const query = parseTagQuery(input);
  if (!query) return undefined;
  const ids = new Set<string>();
  for (const [id, tags] of index) if (matchTag(tags, query)) ids.add(id);
  return ids;
}

/** Distinct `key=value` pairs with their resource counts, most frequent first (for suggestions). */
export function tagSuggestions(index: TagIndex, limit = 200): { tag: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const tags of index.values()) {
    for (const [k, v] of Object.entries(tags)) {
      counts.set(`${k}=${v}`, (counts.get(`${k}=${v}`) ?? 0) + 1);
      counts.set(`${k}=`, (counts.get(`${k}=`) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag))
    .slice(0, limit);
}
