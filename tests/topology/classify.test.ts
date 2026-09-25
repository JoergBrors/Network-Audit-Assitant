import { describe, expect, it } from "vitest";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import { architectureType, classifyTopology } from "../../src/topology/classify.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();

function classified(raw = F.hubSpokeRaw()) {
  const inv = normalizeInventory(raw);
  classifyTopology(inv);
  return inv;
}

describe("hub/spoke detection", () => {
  const inv = classified();
  const vnet = (id: string) => inv.vnets.find((v) => v.id === lc(id))!;

  it("detects the hub with explainable reasons", () => {
    const hub = vnet(F.HUB).topology!;
    expect(hub.classification).toBe("hub");
    expect(hub.confidence).toBeGreaterThanOrEqual(0.8);
    expect(hub.reasons).toEqual(
      expect.arrayContaining([
        "Azure Firewall present",
        "VPN/ExpressRoute gateway present",
        "Gateway transit enabled",
        "Default route of 1 subnet(s) in 1 other VNet(s) points into this VNet",
      ]),
    );
  });

  it("detects the spoke and links it to its hub", () => {
    const spoke = vnet(F.SPOKE).topology!;
    expect(spoke.classification).toBe("spoke");
    expect(spoke.hubIds).toEqual([lc(F.HUB)]);
    expect(spoke.reasons).toContain("Uses remote gateways (useRemoteGateways)");
    expect(spoke.reasons).toContain("Default route points to an appliance in a hub VNet");
  });

  it("classifies VNets without peerings as standalone", () => {
    expect(vnet(F.LONELY).topology).toMatchObject({
      classification: "standalone",
      reasons: ["No VNet peerings"],
    });
  });

  it("derives the architecture type", () => {
    expect(architectureType(inv.vnets)).toBe("hub-spoke");
  });
});

describe("NVA heuristic", () => {
  it("flags VMs with IP forwarding that are UDR next hops", () => {
    const raw = F.hubSpokeRaw();
    const nic = raw.resources["Q-NET-NIC"]![0]!;
    nic.properties = { ...nic.properties, enableIPForwarding: true };
    const rt = raw.resources["Q-NET-RT"]![0]!;
    (rt.properties!["routes"] as Record<string, unknown>[]).push({
      name: "to-nva",
      properties: {
        addressPrefix: "172.16.0.0/12",
        nextHopType: "VirtualAppliance",
        nextHopIpAddress: "10.1.1.4",
      },
    });
    const inv = classified(raw);
    expect(inv.virtualMachines[0]!.nva).toEqual({
      potentialNva: true,
      confidence: 0.75,
      reasons: ["IP forwarding enabled", "Referenced as UDR next hop (1 route)"],
    });
  });

  it("does not flag ordinary VMs", () => {
    expect(classified().virtualMachines[0]!.nva).toBeUndefined();
  });
});
