import type { RawInventory } from "../../src/models/discovery.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import { buildRoutingContext } from "../../src/routing/context.js";
import * as F from "../fixtures/hubSpoke.js";

export const lc = (s: string) => s.toLowerCase();

export function ctxFor(raw: RawInventory = F.hubSpokeRaw()) {
  return buildRoutingContext(analyzeInventory(raw).inventory);
}

/** Mutates one subnet inside a VNet row of the raw fixture. */
export function patchSubnet(raw: RawInventory, subnetId: string, patch: Record<string, unknown>) {
  for (const row of raw.resources["Q-NET-VNET"]!) {
    for (const s of (row.properties!["subnets"] as { id: string; properties: Record<string, unknown> }[]) ??
      []) {
      if (s.id === subnetId) s.properties = { ...s.properties, ...patch };
    }
  }
}
