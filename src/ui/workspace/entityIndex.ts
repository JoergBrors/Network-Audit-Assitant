import type { NormalizedInventory } from "../../models/network.js";

export interface EntityRef {
  collection: keyof NormalizedInventory;
  entity: Record<string, unknown>;
}

/** Maps every normalized entity ID to its inventory collection, for the detail panel. */
export function buildEntityIndex(inv: NormalizedInventory): Map<string, EntityRef> {
  const map = new Map<string, EntityRef>();
  for (const [collection, value] of Object.entries(inv) as [keyof NormalizedInventory, unknown][]) {
    if (!Array.isArray(value)) continue;
    for (const entity of value as Record<string, unknown>[]) {
      const id = typeof entity["id"] === "string" ? entity["id"] : undefined;
      if (id && !map.has(id)) map.set(id, { collection, entity });
    }
  }
  return map;
}
