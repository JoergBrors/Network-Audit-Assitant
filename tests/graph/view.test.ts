import { describe, expect, it } from "vitest";
import { computeVisibleGraph, indexGraph, MAX_VISIBLE_NODES } from "../../src/graph/view.js";
import type { NetworkGraph } from "../../src/models/graph.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const index = indexGraph(analyzeInventory(F.hubSpokeRaw()).graph);
const view = (state: Partial<Parameters<typeof computeVisibleGraph>[1]>) =>
  computeVisibleGraph(index, { level: 2, expanded: new Set(), ipMode: "all", ...state });
const ids = (v: ReturnType<typeof view>) => v.nodes.map((n) => n.node.id);

describe("computeVisibleGraph", () => {
  it("shows VNets and peerings at level 2, nested in containers", () => {
    const v = view({ level: 2 });
    expect(ids(v)).toEqual(expect.arrayContaining([lc(F.HUB), lc(F.SPOKE), lc(F.LONELY)]));
    expect(ids(v)).not.toContain(lc(F.SNET_APP));
    expect(v.nodes.find((n) => n.node.id === lc(F.HUB))).toMatchObject({
      containerId: `/subscriptions/${F.SUB_CONN}/locations/westeurope`,
      hiddenChildren: 3,
    });
    expect(v.edges.find((e) => e.type === "peering" && e.source === lc(F.SPOKE))).toMatchObject({
      target: lc(F.HUB),
    });
  });

  it("drills down into an expanded VNet regardless of level", () => {
    const v = view({ level: 2, expanded: new Set([lc(F.SPOKE)]) });
    expect(ids(v)).toContain(lc(F.SNET_APP));
    expect(v.nodes.find((n) => n.node.id === lc(F.SPOKE))?.isContainer).toBe(true);
  });

  it("lifts relationships to the nearest visible ancestor", () => {
    // Level 3: route nodes (lod 5) are hidden, their next-hop edge is lifted to the route table.
    const v = view({ level: 3 });
    expect(
      v.edges.find((e) => e.type === "route" && e.source === lc(F.RT_SPOKE) && e.target === lc(F.FW)),
    ).toBeDefined();
    expect(v.edges.find((e) => e.type === "securedBy" && e.source === lc(F.SNET_APP))).toBeDefined();
  });

  it("filters edges by IP family", () => {
    const v4 = view({ level: 5, ipMode: "ipv4" });
    expect(v4.edges.some((e) => e.families.includes("ipv6"))).toBe(false);
    const v6 = view({ level: 5, ipMode: "ipv6" });
    expect(v6.edges.some((e) => e.families.includes("ipv4"))).toBe(false);
    expect(v6.edges.some((e) => e.type === "route" && e.families.includes("ipv6"))).toBe(true);
  });

  it("IPv6 mode shows IPv6-configured components and keeps related ones as background context", () => {
    const v = view({ level: 5, ipMode: "ipv6" });
    const emphasis = (id: string) => v.nodes.find((n) => n.node.id === lc(id))?.emphasis;
    expect(emphasis(F.SPOKE)).toBe("match");
    expect(emphasis(F.SNET_APP)).toBe("match");
    expect(emphasis(F.NIC_VM)).toBe("match"); // dual-stack NIC
    expect(emphasis(F.PIP_VM)).toBe("match"); // public IPv6
    expect(emphasis(F.NSG_SPOKE)).toBe("context"); // attached to an IPv6 subnet, has no own addresses
    expect(emphasis(F.RT_SPOKE)).toBe("match"); // routes ::/0
    expect(emphasis(F.NAT)).toBeUndefined(); // IPv4-only egress, unrelated to IPv6 components → hidden
    expect(emphasis(F.LONELY)).toBeUndefined(); // IPv4-only and unrelated → hidden
    expect(emphasis(F.PE)).toBeUndefined(); // IPv4-only private endpoint → hidden
    expect(emphasis(`/subscriptions/${F.SUB_APP}`)).toBe("context"); // container of matches
    expect(v.matchCount).toBe(v.nodes.filter((n) => n.emphasis === "match").length);
  });

  it("marks edges between context-only components as background", () => {
    const v = view({ level: 5, ipMode: "ipv6" });
    const matches = new Set(v.nodes.filter((n) => n.emphasis === "match").map((n) => n.node.id));
    for (const e of v.edges) expect(e.context).toBe(!matches.has(e.source) && !matches.has(e.target));
  });

  it("dual-stack mode keeps only dual-stack components as matches", () => {
    const v = view({ level: 5, ipMode: "dual" });
    for (const n of v.nodes.filter((x) => x.emphasis === "match"))
      expect(n.node.addressing.classification).toBe("dual-stack");
    // IPv6-only public IP: not dual-stack itself, but attached to the dual-stack NIC → context.
    expect(v.nodes.find((n) => n.node.id === lc(F.PIP_VM))?.emphasis).toBe("context");
    expect(v.nodes.find((n) => n.node.id === lc(F.LONELY))).toBeUndefined();
  });

  it("reports zero matches instead of an empty graph", () => {
    const v = view({
      level: 2,
      ipMode: "ipv6",
      subscriptionIds: new Set(["99999999-9999-9999-9999-999999999999"]),
    });
    expect(v.matchCount).toBe(0);
  });

  it("uses normal emphasis without IP filter", () => {
    expect(view({ level: 3 }).nodes.every((n) => n.emphasis === "normal")).toBe(true);
  });

  it("focuses a subtree plus its directly related nodes", () => {
    const v = view({ level: 3, focusId: lc(F.SPOKE) });
    expect(ids(v)).toEqual(expect.arrayContaining([lc(F.SPOKE), lc(F.SNET_APP), lc(F.HUB), lc(F.RT_SPOKE)]));
    expect(ids(v)).not.toContain(lc(F.LONELY));
    expect(v.nodes.find((n) => n.node.id === lc(F.HUB))?.neighbor).toBe(true);
  });

  it("filters by subscription", () => {
    const v = view({ level: 2, subscriptionIds: new Set([F.SUB_APP]) });
    expect(ids(v)).toContain(lc(F.SPOKE));
    expect(ids(v)).not.toContain(lc(F.HUB));
  });

  it("orders containers before their children", () => {
    const v = view({ level: 4 });
    const position = new Map(v.nodes.map((n, i) => [n.node.id, i]));
    for (const n of v.nodes)
      if (n.containerId) expect(position.get(n.containerId)!).toBeLessThan(position.get(n.node.id)!);
  });

  it("refuses to render oversized views", () => {
    const big: NetworkGraph = {
      nodes: Array.from({ length: MAX_VISIBLE_NODES + 1 }, (_, i) => ({
        id: `n${i}`,
        type: "vnet",
        name: `n${i}`,
        lod: 1,
        addressing: { ipv4: [], ipv6: [], classification: "no-ip" },
        properties: {},
      })),
      edges: [],
    };
    const v = computeVisibleGraph(indexGraph(big), { level: 1, expanded: new Set(), ipMode: "all" });
    expect(v).toMatchObject({ truncated: true, nodes: [], totalCandidates: MAX_VISIBLE_NODES + 1 });
  });
});
