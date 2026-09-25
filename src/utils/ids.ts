/** Helpers for Azure resource IDs. All IDs in the normalized model are lowercase. */

export function normalizeId(id: string): string;
export function normalizeId(id: string | undefined | null): string | undefined;
export function normalizeId(id: string | undefined | null): string | undefined {
  if (!id) return undefined;
  return id.trim().replace(/\/+$/, "").toLowerCase();
}

/** Extracts `{ id }` style references (`{ id: "..." }`) and plain strings. */
export function refId(value: unknown): string | undefined {
  if (typeof value === "string") return normalizeId(value);
  if (value && typeof value === "object" && "id" in value && typeof value.id === "string") {
    return normalizeId(value.id);
  }
  return undefined;
}

export function refIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((v) => {
    const id = refId(v);
    return id ? [id] : [];
  });
}

export function lastSegment(id: string): string {
  return id.split("/").pop() ?? id;
}

export function subscriptionOf(id: string): string | undefined {
  return /\/subscriptions\/([^/]+)/i.exec(id)?.[1]?.toLowerCase();
}

export function resourceGroupOf(id: string): string | undefined {
  return /\/resourcegroups\/([^/]+)/i.exec(id)?.[1]?.toLowerCase();
}

/** Strips `n` trailing `/type/name` pairs. */
export function parentId(id: string, pairs = 1): string {
  const parts = id.split("/");
  return parts.slice(0, Math.max(0, parts.length - pairs * 2)).join("/");
}

/**
 * Maps an IP configuration ID (NIC, firewall, gateway, LB frontend, bastion, …) to the ID of the
 * resource that owns it. VM scale set instance NICs are rolled up to the scale set.
 */
export function ownerOfIpConfiguration(ipConfigurationId: string): string {
  const id = normalizeId(ipConfigurationId);
  const vmss = /^(.*\/providers\/microsoft\.compute\/virtualmachinescalesets\/[^/]+)\//.exec(id);
  if (vmss?.[1]) return vmss[1];
  return parentId(id);
}

/** VM scale set instance NIC → owning scale set. Other IDs are returned unchanged. */
export function rollUpScaleSet(id: string): string {
  const m = /^(.*\/providers\/microsoft\.compute\/virtualmachinescalesets\/[^/]+)\/virtualmachines\//.exec(
    id,
  );
  return m?.[1] ?? id;
}
