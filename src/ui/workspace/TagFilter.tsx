import { useMemo } from "react";
import { tagSuggestions, type TagIndex } from "../../graph/tags.js";

/** Tag filter for the graph: `key=value`, `key=` (key present) or free text over keys and values. */
export function TagFilter({
  index,
  value,
  matches,
  onChange,
}: {
  index: TagIndex;
  value: string;
  /** Number of matching resources (undefined when the filter is empty). */
  matches: number | undefined;
  onChange: (value: string) => void;
}) {
  const suggestions = useMemo(() => tagSuggestions(index), [index]);
  if (index.size === 0) return null;
  return (
    <div className="tag-filter">
      <input
        type="search"
        list="tag-suggestions"
        placeholder="Tag: key=value"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Tag-Filter"
        title="Tag-Filter: key=value, key= (Tag vorhanden) oder Freitext über Schlüssel und Werte"
      />
      <datalist id="tag-suggestions">
        {suggestions.map((s) => (
          <option key={s.tag} value={s.tag}>
            {s.count} Ressourcen
          </option>
        ))}
      </datalist>
      {matches !== undefined && (
        <span className={`small ${matches ? "muted" : "status-warn"}`}>{matches} Treffer</span>
      )}
    </div>
  );
}
