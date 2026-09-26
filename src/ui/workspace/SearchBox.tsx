import { useMemo, useState } from "react";
import { cidrContains, ipFamilyOf } from "../../addressing/ip.js";
import type { GraphIndex } from "../../graph/view.js";
import { matchTag, parseTagQuery, type TagIndex } from "../../graph/tags.js";
import type { GraphNode } from "../../models/graph.js";
import { NODE_TYPE_LABELS } from "../../models/graph.js";
import { abbreviationOf, categoryOf } from "../graph/nodeStyle.js";

const MAX_RESULTS = 40;

/** Global search over name, resource ID, subscription, resource group, IP address / CIDR and tags. */
export function searchNodes(
  index: GraphIndex,
  query: string,
  tags?: TagIndex,
): { node: GraphNode; reason: string }[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const tagQuery = tags ? parseTagQuery(q) : undefined;
  const isIp = ipFamilyOf(q) !== undefined;
  const results: { node: GraphNode; reason: string; score: number }[] = [];
  for (const node of index.byId.values()) {
    if (node.type === "route" && !isIp) continue;
    const addresses = [...node.addressing.ipv4, ...node.addressing.ipv6];
    if (isIp) {
      const exact = addresses.find((a) => a.toLowerCase() === q || a.toLowerCase().split("/")[0] === q);
      const containing = exact ? undefined : addresses.find((a) => a.includes("/") && cidrContains(a, q));
      if (exact) results.push({ node, reason: `Adresse ${exact}`, score: 0 });
      else if (containing) {
        const length = Number(containing.split("/")[1] ?? 0);
        results.push({ node, reason: `enthält ${q} (${containing})`, score: 200 - length });
      }
      continue;
    }
    const name = node.name.toLowerCase();
    if (name === q) results.push({ node, reason: "Name", score: 0 });
    else if (name.includes(q)) results.push({ node, reason: "Name", score: 10 + name.indexOf(q) });
    else if (node.id.includes(q)) results.push({ node, reason: "Resource ID", score: 50 });
    else if (node.subscriptionName?.toLowerCase().includes(q) && node.type === "subscription")
      results.push({ node, reason: "Subscription", score: 20 });
    else if (node.resourceGroup === q && node.type === "vnet")
      results.push({ node, reason: "Resource Group", score: 30 });
    else if (addresses.some((a) => a.toLowerCase().includes(q)))
      results.push({ node, reason: "Adresse", score: 40 });
    else {
      const nodeTags = tagQuery && tags?.get(node.id);
      const tag = nodeTags ? matchTag(nodeTags, tagQuery) : undefined;
      if (tag) results.push({ node, reason: `Tag ${tag}`, score: 45 });
    }
  }
  return results
    .sort((a, b) => a.score - b.score || a.node.name.localeCompare(b.node.name))
    .slice(0, MAX_RESULTS)
    .map(({ node, reason }) => ({ node, reason }));
}

export function SearchBox({
  index,
  tags,
  onSelect,
}: {
  index: GraphIndex;
  tags?: TagIndex | undefined;
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const results = useMemo(() => searchNodes(index, query, tags), [index, query, tags]);

  return (
    <div className="search">
      <input
        type="search"
        placeholder="Suche: Name, Resource ID, IP (10.1.2.3, 2a02::1), CIDR oder Tag"
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="Globale Suche"
      />
      {open && results.length > 0 && (
        <ul className="search-results" role="listbox">
          {results.map(({ node, reason }) => (
            <li
              key={node.id}
              role="option"
              aria-selected={false}
              onMouseDown={(e) => {
                e.preventDefault();
                onSelect(node.id);
                setOpen(false);
              }}
            >
              <span className={`type-abbr small cat-${categoryOf(node.type)}`}>
                {abbreviationOf(node.type)}
              </span>
              <span className="search-name">{node.name}</span>
              <span className="muted small">
                {NODE_TYPE_LABELS[node.type]}
                {node.subscriptionName ? ` · ${node.subscriptionName}` : ""} · {reason}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
