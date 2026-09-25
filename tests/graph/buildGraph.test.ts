import { describe, expect, it } from "vitest";
import { EXTERNAL_ROOT_ID, internetNodeId } from "../../src/graph/buildGraph.js";
import { NetworkGraphSchema } from "../../src/models/graph.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();

describe("buildGraph", () => {
  const { graph } = analyzeInventory(F.hubSpokeRaw());
  const node = (id: string) => graph.nodes.find((n) => n.id === lc(id));
  const edge = (type: string, s: string, t: string) =>
    graph.edges.find((e) => e.type === type && e.source === lc(s) && e.target === lc(t));

  it("is a valid, self-consistent graph", () => {
    expect(NetworkGraphSchema.safeParse(graph).success).toBe(true);
    const ids = new Set(graph.nodes.map((n) => n.id));
    for (const e of graph.edges) {
      expect(ids.has(e.source), e.id).toBe(true);
      expect(ids.has(e.target), e.id).toBe(true);
    }
    for (const n of graph.nodes) if (n.parentId) expect(ids.has(n.parentId), n.id).toBe(true);
  });

  it("builds the tenant → subscription → region → VNet → subnet → resource hierarchy", () => {
    expect(node(`/subscriptions/${F.SUB_CONN}`)?.parentId).toBe(`tenant:${F.TENANT}`);
    expect(node(F.HUB)?.parentId).toBe(`/subscriptions/${F.SUB_CONN}/locations/westeurope`);
    expect(node(F.SNET_FW)?.parentId).toBe(lc(F.HUB));
    expect(node(F.FW)?.parentId).toBe(lc(F.SNET_FW));
    expect(node(F.VNG)?.parentId).toBe(lc(F.SNET_GW));
    expect(node(F.VM)?.parentId).toBe(lc(F.SNET_APP));
    expect(node(F.NIC_VM)?.parentId).toBe(lc(F.VM));
    expect(edge("contains", F.HUB, F.SNET_FW)).toBeDefined();
  });

  it("assigns levels of detail", () => {
    expect(node(F.HUB)?.lod).toBe(1); // hub
    expect(node(F.SPOKE)?.lod).toBe(1); // spoke
    expect(node(F.LONELY)?.lod).toBe(2);
    expect(node(F.SNET_APP)?.lod).toBe(3);
    expect(node(F.FW)?.lod).toBe(3);
    expect(node(F.NSG_SPOKE)?.lod).toBe(4);
    expect(node(`${F.RT_SPOKE}/routes/default-v4`)?.lod).toBe(5);
  });

  it("merges private endpoint NICs into the private endpoint", () => {
    expect(node(F.NIC_PE)).toBeUndefined();
    expect(node(F.PE)?.addressing.ipv4).toEqual(["10.1.1.10"]);
    expect(edge("privateEndpoint", F.PE, F.SQL)).toMatchObject({
      properties: { groupIds: ["sqlServer"], status: "Approved" },
    });
  });

  it("creates typed relationships", () => {
    expect(edge("peering", F.SPOKE, F.HUB)?.properties).toMatchObject({
      useRemoteGateways: true,
      state: "Connected",
    });
    expect(edge("attached", F.SNET_APP, F.NSG_SPOKE)).toBeDefined();
    expect(edge("attached", F.SNET_APP, F.RT_SPOKE)).toBeDefined();
    expect(edge("natThrough", F.SNET_HUB_NAT, F.NAT)).toBeDefined();
    expect(edge("natThrough", F.NAT, F.PIP_NAT)).toBeDefined();
    expect(edge("attached", F.NIC_VM, F.PIP_VM)).toBeDefined();
    expect(edge("policyOf", F.FW_POLICY, F.FW)).toBeDefined();
  });

  it("links default routes to their next hop per IP family and marks firewall-secured subnets", () => {
    expect(edge("route", `${F.RT_SPOKE}/routes/default-v4`, F.FW)).toMatchObject({ family: "ipv4" });
    const v6 = graph.edges.find(
      (e) => e.type === "route" && e.source === lc(`${F.RT_SPOKE}/routes/default-v6`),
    );
    expect(v6).toMatchObject({ target: internetNodeId("ipv6"), family: "ipv6" });
    const secured = graph.edges.filter((e) => e.type === "securedBy" && e.source === lc(F.SNET_APP));
    expect(secured.map((e) => [e.target, e.family])).toEqual([[lc(F.FW), "ipv4"]]);
  });

  it("keeps targets outside the readable scope as external nodes", () => {
    expect(node(F.FOREIGN_VNET)).toMatchObject({ type: "externalResource", parentId: EXTERNAL_ROOT_ID });
    expect(node(F.SQL)).toMatchObject({ type: "externalResource" });
  });

  it("is deterministic", () => {
    expect(analyzeInventory(F.hubSpokeRaw()).graph).toEqual(graph);
  });
});
