import { describe, expect, it } from "vitest";
import { selectRoute, synthesizeRoutes } from "../../src/routing/routes.js";
import type { EffectiveRoute } from "../../src/models/path.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc } from "./helpers.js";

const r = (
  prefix: string,
  nextHopType: EffectiveRoute["nextHopType"],
  source: EffectiveRoute["source"],
): EffectiveRoute => ({
  prefix,
  family: prefix.includes(":") ? "ipv6" : "ipv4",
  nextHopType,
  source,
  confidence: "CONFIRMED",
});

describe("effective route synthesis", () => {
  const ctx = ctxFor();

  it("builds VNet, peering, default and UDR routes for IPv4", () => {
    const routes = synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv4");
    const has = (prefix: string, type: string, source: string) =>
      routes.some((x) => x.prefix === prefix && x.nextHopType === type && x.source === source);
    expect(has("10.1.0.0/16", "VnetLocal", "system")).toBe(true);
    expect(has("10.0.0.0/16", "VNetPeering", "peering")).toBe(true);
    expect(has("0.0.0.0/0", "Internet", "system")).toBe(true);
    expect(has("0.0.0.0/0", "VirtualAppliance", "udr")).toBe(true);
    // 10/8 None is removed because the VNet space overlaps it; 172.16/12 stays.
    expect(has("10.0.0.0/8", "None", "system")).toBe(false);
    expect(has("172.16.0.0/12", "None", "system")).toBe(true);
  });

  it("builds IPv6 routes separately", () => {
    const routes = synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv6");
    expect(routes.every((x) => x.family === "ipv6")).toBe(true);
    expect(routes.find((x) => x.prefix === "::/0" && x.source === "udr")?.nextHopType).toBe("Internet");
    expect(routes.find((x) => x.nextHopType === "VNetPeering")?.prefix).toBe("fd00:10::/48");
  });

  it("derives gateway routes from local network gateways unless propagation is disabled", () => {
    const raw = F.hubSpokeRaw();
    const lng =
      "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-hub/providers/Microsoft.Network/localNetworkGateways/lng-dc";
    raw.resources["Q-HYB-GW"]!.push(
      {
        id: lng,
        name: "lng-dc",
        type: "microsoft.network/localnetworkgateways",
        subscriptionId: F.SUB_CONN,
        properties: { localNetworkAddressSpace: { addressPrefixes: ["192.168.10.0/24"] } },
      },
      {
        id: `${lng}-conn`,
        name: "conn",
        type: "microsoft.network/connections",
        subscriptionId: F.SUB_CONN,
        properties: {
          virtualNetworkGateway1: { id: F.VNG },
          localNetworkGateway2: { id: lng },
          connectionType: "IPsec",
        },
      },
    );
    const c = ctxFor(raw);
    const spoke = synthesizeRoutes(c, lc(F.SNET_APP), "ipv4"); // route table disables propagation
    expect(spoke.some((x) => x.source === "gateway")).toBe(false);
    const hub = synthesizeRoutes(c, lc(F.SNET_HUB_NAT), "ipv4");
    expect(hub.find((x) => x.source === "gateway")).toMatchObject({
      prefix: "192.168.10.0/24",
      nextHopType: "VirtualNetworkGateway",
      confidence: "POSSIBLE",
    });
  });
});

describe("route selection", () => {
  it("uses longest prefix match", () => {
    const routes = [
      r("10.0.0.0/16", "VnetLocal", "system"),
      r("10.0.0.0/24", "VirtualAppliance", "udr"),
      r("0.0.0.0/0", "Internet", "system"),
    ];
    expect(selectRoute(routes, "10.0.0.5")?.prefix).toBe("10.0.0.0/24");
    expect(selectRoute(routes, "10.0.1.5")?.prefix).toBe("10.0.0.0/16");
    expect(selectRoute(routes, "8.8.8.8")?.prefix).toBe("0.0.0.0/0");
  });

  it("prefers UDR over gateway over system routes for equal prefixes", () => {
    expect(
      selectRoute(
        [r("0.0.0.0/0", "Internet", "system"), r("0.0.0.0/0", "VirtualAppliance", "udr")],
        "8.8.8.8",
      )?.source,
    ).toBe("udr");
    expect(
      selectRoute(
        [r("0.0.0.0/0", "Internet", "system"), r("0.0.0.0/0", "VirtualNetworkGateway", "gateway")],
        "8.8.8.8",
      )?.source,
    ).toBe("gateway");
  });

  it("keeps VNet/peering system routes ahead of more specific gateway routes", () => {
    const routes = [
      r("10.0.0.0/16", "VNetPeering", "peering"),
      r("10.0.5.0/24", "VirtualNetworkGateway", "gateway"),
    ];
    expect(selectRoute(routes, "10.0.5.1")?.nextHopType).toBe("VNetPeering");
  });

  it("never mixes IP families", () => {
    expect(selectRoute([r("0.0.0.0/0", "Internet", "system")], "2001:db8::1")).toBeUndefined();
  });
});
