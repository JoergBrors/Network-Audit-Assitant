import { buildGraph } from "../graph/buildGraph.js";
import type { DiscoveryQuality, DiscoveryWarning, RawInventory } from "../models/discovery.js";
import type { NetworkGraph } from "../models/graph.js";
import type { NormalizedInventory } from "../models/network.js";
import { normalizeInventory } from "../normalization/normalize.js";
import { classifyTopology } from "../topology/classify.js";

/** Result of the isomorphic analysis pipeline; this is what UI and exports consume. */
export interface NetworkModel {
  inventory: NormalizedInventory;
  graph: NetworkGraph;
  discovery: { quality: DiscoveryQuality; warnings: DiscoveryWarning[] };
}

/** RawInventory → normalization → hub/spoke & NVA classification → network graph. */
export function analyzeInventory(raw: RawInventory): NetworkModel {
  const inventory = normalizeInventory(raw);
  classifyTopology(inventory);
  const graph = buildGraph(inventory);
  return { inventory, graph, discovery: { quality: raw.quality, warnings: raw.warnings } };
}
