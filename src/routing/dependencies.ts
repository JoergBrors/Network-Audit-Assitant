import type { PathHop } from "../models/path.js";
import { subscriptionOf } from "../utils/ids.js";

/** Resources of another subscription a path depends on (hub firewall, peered VNet, public IP, …). */
export interface SubscriptionDependency {
  subscriptionId: string;
  resourceIds: string[];
}

/**
 * Groups every resource a path touches by subscription and returns those outside the source's
 * subscription. Internet and synthetic nodes (no subscription in the ID) are ignored.
 */
export function crossSubscriptionDependencies(
  sourceId: string,
  hops: Pick<PathHop, "nodeId">[],
  extraIds: (string | undefined)[] = [],
): SubscriptionDependency[] {
  const own = subscriptionOf(sourceId);
  const bySub = new Map<string, Set<string>>();
  for (const id of [...hops.map((h) => h.nodeId), ...extraIds]) {
    if (!id) continue;
    const sub = subscriptionOf(id);
    if (!sub || sub === own) continue;
    const set = bySub.get(sub) ?? new Set<string>();
    set.add(id);
    bySub.set(sub, set);
  }
  return [...bySub.entries()]
    .map(([subscriptionId, ids]) => ({ subscriptionId, resourceIds: [...ids].sort() }))
    .sort((a, b) => a.subscriptionId.localeCompare(b.subscriptionId));
}
