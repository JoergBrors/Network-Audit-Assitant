import { describe, expect, it } from "vitest";
import {
  buildComparisonGraph,
  buildDiffExport,
  diffFileName,
  diffModels,
  diffValues,
} from "../../src/drift/diff.js";
import { computeVisibleGraph, indexGraph } from "../../src/graph/view.js";
import type { RawInventory } from "../../src/models/discovery.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const model = (raw: RawInventory) => analyzeInventory(raw);
const vnetRow = (raw: RawInventory, id: string) => raw.resources["Q-NET-VNET"]!.find((r) => r.id === id)!;
const setAddressSpace = (raw: RawInventory, id: string, prefixes: string[]) => {
  const row = vnetRow(raw, id);
  row.properties = { ...row.properties, addressSpace: { addressPrefixes: prefixes } };
};

describe("semantic snapshot diff", () => {
  it("reports no changes for identical snapshots", () => {
    const d = diffModels(model(F.hubSpokeRaw()), model(F.hubSpokeRaw()));
    expect(d.resources).toEqual([]);
    expect(d.relationships).toEqual([]);
  });

  it("Akzeptanztest 3: IPv6 prefix added to an IPv4-only VNet is an architecture change", () => {
    const before = F.hubSpokeRaw();
    setAddressSpace(before, F.LONELY, ["192.168.0.0/24"]);
    const after = F.hubSpokeRaw();
    setAddressSpace(after, F.LONELY, ["192.168.0.0/24", "fd00:99::/48"]);
    const d = diffModels(model(before), model(after));
    const change = d.resources.find((r) => r.id === lc(F.LONELY))!;
    expect(change).toMatchObject({ kind: "changed", category: "ARCHITECTURE_RELEVANT", families: ["ipv6"] });
    expect(change.fields).toEqual(
      expect.arrayContaining([
        { path: "addressSpace.ipv6", kind: "added", after: ["fd00:99::/48"] },
        { path: "ipClassification", kind: "changed", before: "ipv4-only", after: "dual-stack" },
      ]),
    );
    expect(d.summary.ipv6Changes).toBeGreaterThan(0);
  });

  it("Akzeptanztest 4: ::/0 moved from Internet to the firewall is flagged as potentially breaking (IPv6)", () => {
    const d = diffModels(
      model(F.hubSpokeRaw({ spokeIpv6Route: "Internet" })),
      model(F.hubSpokeRaw({ spokeIpv6Route: "Firewall" })),
    );
    const route = d.resources.find((r) => r.id === lc(`${F.RT_SPOKE}/routes/default-v6`))!;
    expect(route).toMatchObject({ kind: "changed", category: "POTENTIALLY_BREAKING", families: ["ipv6"] });
    expect(route.fields).toEqual(
      expect.arrayContaining([
        { path: "nextHopType", kind: "changed", before: "Internet", after: "VirtualAppliance" },
      ]),
    );
    expect(d.relationships.find((r) => r.kind === "removed" && r.target === "internet:ipv6")).toMatchObject({
      category: "SECURITY_RELEVANT",
    });
  });

  it("Akzeptanztest 5: NSG newly allowing ::/0 inbound is security relevant", () => {
    const before = F.hubSpokeRaw();
    const nsg = before.resources["Q-NET-NSG"]![0]!;
    nsg.properties = {
      ...nsg.properties,
      securityRules: (nsg.properties!["securityRules"] as unknown[]).slice(1),
    };
    const d = diffModels(model(before), model(F.hubSpokeRaw()));
    const change = d.resources.find((r) => r.id === lc(F.NSG_SPOKE))!;
    expect(change).toMatchObject({
      kind: "changed",
      category: "SECURITY_RELEVANT",
      families: expect.arrayContaining(["ipv6"]) as unknown,
    });
    expect(change.fields.find((f) => f.path === "rules[allow-https-v6]")).toMatchObject({ kind: "added" });
  });

  it("Akzeptanztest 6: removed IPv6 default route is potentially breaking", () => {
    const d = diffModels(
      model(F.hubSpokeRaw({ spokeIpv6Route: "Internet" })),
      model(F.hubSpokeRaw({ spokeIpv6Route: "none" })),
    );
    expect(d.resources.find((r) => r.id === lc(`${F.RT_SPOKE}/routes/default-v6`))).toMatchObject({
      kind: "removed",
      category: "POTENTIALLY_BREAKING",
    });
  });

  it("reports a deleted VNet that is still referenced by a peering as removed", () => {
    const after = F.hubSpokeRaw();
    after.resources["Q-NET-VNET"] = after.resources["Q-NET-VNET"]!.filter((r) => r.id !== F.SPOKE);
    const baseline = model(F.hubSpokeRaw());
    const current = model(after);
    expect(current.graph.nodes.find((n) => n.id === lc(F.SPOKE))?.type).toBe("externalResource");
    const d = diffModels(baseline, current);
    expect(d.resources.find((r) => r.id === lc(F.SPOKE))).toMatchObject({
      kind: "removed",
      nodeType: "vnet",
    });
    const cmp = buildComparisonGraph(baseline.graph, current.graph, d);
    expect(cmp.graph.nodes.find((n) => n.id === lc(F.SPOKE))?.type).toBe("vnet");
  });

  it("classifies tag-only changes as informational and removed resources by type", () => {
    const after = F.hubSpokeRaw();
    vnetRow(after, F.SPOKE)["tags"] = { owner: "network-team" };
    after.resources["Q-NET-VNET"] = after.resources["Q-NET-VNET"]!.filter((r) => r.id !== F.LONELY);
    const d = diffModels(model(F.hubSpokeRaw()), model(after));
    expect(d.resources.find((r) => r.id === lc(F.SPOKE))).toMatchObject({
      kind: "changed",
      category: "INFORMATIONAL",
    });
    expect(d.resources.find((r) => r.id === lc(F.LONELY))).toMatchObject({
      kind: "removed",
      category: "ARCHITECTURE_RELEVANT",
    });
    expect(d.summary).toMatchObject({ removed: 1, changed: 1 });
  });

  it("diffs keyed arrays per element and plain arrays as sets", () => {
    expect(
      diffValues(
        {
          rules: [
            { name: "a", p: 1 },
            { name: "b", p: 1 },
          ],
        },
        {
          rules: [
            { name: "b", p: 2 },
            { name: "c", p: 1 },
          ],
        },
      ),
    ).toEqual([
      { path: "rules[b]", kind: "changed", before: { name: "b", p: 1 }, after: { name: "b", p: 2 } },
      { path: "rules[c]", kind: "added", after: { name: "c", p: 1 } },
      { path: "rules[a]", kind: "removed", before: { name: "a", p: 1 } },
    ]);
    expect(diffValues({ x: ["1", "2"] }, { x: ["2", "1"] })).toEqual([]);
  });
});

describe("comparison graph & view", () => {
  const before = F.hubSpokeRaw();
  const after = F.hubSpokeRaw();
  after.resources["Q-NET-VNET"] = after.resources["Q-NET-VNET"]!.filter((r) => r.id !== F.LONELY);
  setAddressSpace(after, F.SPOKE, ["10.1.0.0/16", "fd00:11::/48", "10.2.0.0/16"]);
  const baseline = model(before);
  const current = model(after);
  const diff = diffModels(baseline, current);
  const cmp = buildComparisonGraph(baseline.graph, current.graph, diff);

  it("keeps removed components as ghost nodes at their former place", () => {
    expect(cmp.graph.nodes.find((n) => n.id === lc(F.LONELY))?.parentId).toBe(
      `/subscriptions/${F.SUB_APP}/locations/westeurope`,
    );
    expect(cmp.nodeChanges.get(lc(F.LONELY))?.kind).toBe("removed");
  });

  it("counts changes on all ancestors for Δ badges", () => {
    expect(cmp.changesBelow.get(`/subscriptions/${F.SUB_APP}`)).toBeGreaterThanOrEqual(2);
    expect(cmp.changesBelow.get(`/subscriptions/${F.SUB_CONN}`)).toBeUndefined();
  });

  it("'only changes' shows changed components with their context, even below the level of detail", () => {
    const changedIds = new Set([...diff.resources.map((r) => r.id)]);
    const v = computeVisibleGraph(indexGraph(cmp.graph), {
      level: 2,
      expanded: new Set(),
      ipMode: "all",
      changedIds,
      onlyChanges: true,
    });
    const byId = new Map(v.nodes.map((n) => [n.node.id, n.emphasis]));
    expect(byId.get(lc(F.SPOKE))).toBe("match");
    expect(byId.get(lc(F.LONELY))).toBe("match");
    expect(byId.get(lc(F.HUB))).toBe("context"); // peered with the changed spoke
  });

  it("exports the diff with the documented structure and file name", () => {
    const doc = buildDiffExport(diff, new Date(2026, 8, 25, 9, 5));
    expect(diffFileName(new Date(2026, 8, 25, 9, 5))).toBe("azure-network-diff-20260925-0905.json");
    expect(Object.keys(doc)).toEqual(
      expect.arrayContaining([
        "metadata",
        "sourceSnapshot",
        "targetSnapshot",
        "summary",
        "resources",
        "networkChanges",
        "ipv4Changes",
        "ipv6Changes",
        "assessment",
      ]),
    );
    expect(doc.resources.removed.map((r) => r.id)).toEqual([lc(F.LONELY)]);
    expect(doc.ipv4Changes.map((r) => r.id)).toContain(lc(F.SPOKE));
  });
});
