import { describe, expect, it } from "vitest";
import {
  DISCOVERY_QUERIES,
  NETWORK_QUERIES,
  UNCLASSIFIED_QUERIES,
} from "../../src/azure/resourceGraph/queries.js";

describe("query catalog", () => {
  it("has unique ids", () => {
    const ids = DISCOVERY_QUERIES.map((q) => q.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("orders every query by id for stable paging", () => {
    for (const q of DISCOVERY_QUERIES) expect(q.kql.trimEnd().endsWith("| order by id asc")).toBe(true);
  });

  it("uses lowercase resource types", () => {
    for (const q of NETWORK_QUERIES) for (const t of q.types) expect(t).toBe(t.toLowerCase());
  });

  it("excludes every explicitly queried network type from the unclassified catch-all", () => {
    const known = NETWORK_QUERIES.flatMap((q) => q.types).filter((t) => t.startsWith("microsoft.network/"));
    for (const q of UNCLASSIFIED_QUERIES) for (const t of known) expect(q.kql).toContain(`'${t}'`);
  });

  it("never projects the VM osProfile", () => {
    const vm = NETWORK_QUERIES.find((q) => q.id === "Q-CMP-VM")!;
    expect(vm.kql).not.toMatch(/osProfile/i);
    expect(vm.kql).not.toMatch(/\bproperties\s*[,\n]/);
  });

  it("contains only read-only KQL operators", () => {
    for (const q of DISCOVERY_QUERIES) expect(q.kql).not.toMatch(/\b(update|delete|set|insert)\b/i);
  });
});
