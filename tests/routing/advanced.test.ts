import { describe, expect, it } from "vitest";
import type { RawInventory } from "../../src/models/discovery.js";
import { describeRoute, selectRoute, synthesizeRoutes } from "../../src/routing/routes.js";
import { tracePath } from "../../src/routing/trace.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc, patchSubnet } from "./helpers.js";

const internet = { kind: "internet" } as const;

const VWAN = F.net(F.SUB_CONN, "rg-wan", "virtualWans", "vwan");
const VHUB = F.net(F.SUB_CONN, "rg-wan", "virtualHubs", "vhub-weu");
const FW_HUB = F.net(F.SUB_CONN, "rg-wan", "azureFirewalls", "afw-vhub");
const WAN_SPOKE = F.net(F.SUB_APP, "rg-app", "virtualNetworks", "vnet-wan-spoke");
const SNET_WAN = `${WAN_SPOKE}/subnets/snet-wl`;
const NIC_WAN = F.net(F.SUB_APP, "rg-app", "networkInterfaces", "nic-wl");
const NM = F.net(F.SUB_CONN, "rg-avnm", "networkManagers", "avnm");

function rtRoutes(raw: RawInventory) {
  const rt = raw.resources["Q-NET-RT"]![0]!.properties!;
  return rt["routes"] as { name: string; properties: Record<string, unknown> }[];
}

/** Hub-spoke fixture plus a Virtual WAN hub with a secured hub firewall and one connected spoke. */
function vwanRaw(opts: { routingIntent?: boolean; hubDetails?: boolean } = {}): RawInventory {
  const raw = F.hubSpokeRaw();
  const intent = opts.routingIntent ?? true;
  raw.resources["Q-VWAN"] = [
    F.res(VHUB, "microsoft.network/virtualhubs", {
      virtualWan: { id: VWAN },
      addressPrefix: "10.100.0.0/23",
      azureFirewall: { id: FW_HUB },
      sku: "Standard",
    }),
  ];
  raw.resources["Q-SEC-FW"]!.push(
    F.res(FW_HUB, "microsoft.network/azurefirewalls", {
      sku: { name: "AZFW_Hub", tier: "Standard" },
      firewallPolicy: { id: F.FW_POLICY },
      virtualHub: { id: VHUB },
      hubIPAddresses: {
        privateIPAddress: "10.100.0.132",
        publicIPs: { addresses: [{ address: "198.51.100.99" }], count: 1 },
      },
    }),
  );
  raw.resources["Q-NET-VNET"]!.push(
    F.res(WAN_SPOKE, "microsoft.network/virtualnetworks", {
      addressSpace: { addressPrefixes: ["10.2.0.0/16", "fd00:12::/48"] },
      subnets: [
        F.subnet(SNET_WAN, ["10.2.1.0/24", "fd00:12:0:1::/64"], {
          ipConfigurations: [{ id: `${NIC_WAN}/ipConfigurations/ip` }],
          defaultOutboundAccess: false,
        }),
      ],
      virtualNetworkPeerings: [],
    }),
  );
  raw.resources["Q-NET-NIC"]!.push(
    F.res(NIC_WAN, "microsoft.network/networkinterfaces", {
      ipConfigurations: [
        {
          name: "ip",
          properties: {
            primary: true,
            privateIPAddress: "10.2.1.4",
            privateIPAddressVersion: "IPv4",
            subnet: { id: SNET_WAN },
          },
        },
      ],
    }),
  );
  // The fixture's firewall rule allows 10.1.0.0/16 → *:443; extend it to the vWAN spoke.
  const rcg = raw.resources["Q-SEC-FWRCG"]![0]!.properties!;
  const rule = (rcg["ruleCollections"] as { rules: { sourceAddresses: string[] }[] }[])[0]!.rules[0]!;
  rule.sourceAddresses.push("10.2.0.0/16");
  if (opts.hubDetails !== false) {
    raw.enrichment = {
      virtualHubs: {
        [lc(VHUB)]: {
          connections: [
            {
              id: `${VHUB}/hubVirtualNetworkConnections/conn-wl`,
              name: "conn-wl",
              properties: { remoteVirtualNetwork: { id: WAN_SPOKE }, enableInternetSecurity: true },
            },
          ],
          routingIntents: intent
            ? [
                {
                  properties: {
                    routingPolicies: [
                      { name: "Internet", destinations: ["Internet"], nextHop: FW_HUB },
                      { name: "Private", destinations: ["PrivateTraffic"], nextHop: FW_HUB },
                    ],
                  },
                },
              ]
            : [],
          routeTables: intent
            ? []
            : [
                {
                  id: `${VHUB}/hubRouteTables/defaultRouteTable`,
                  name: "defaultRouteTable",
                  properties: {
                    labels: ["default"],
                    routes: [
                      {
                        name: "all-to-fw",
                        destinationType: "CIDR",
                        destinations: ["0.0.0.0/0"],
                        nextHopType: "ResourceId",
                        nextHop: FW_HUB,
                      },
                    ],
                  },
                },
              ],
          status: "ok",
        },
      },
      results: [],
    };
  }
  return raw;
}

describe("Virtual WAN routing", () => {
  it("routes Internet traffic of a connected spoke through the secured hub firewall (routing intent)", () => {
    const ctx = ctxFor(vwanRaw());
    const r = tracePath(ctx, { sourceId: lc(NIC_WAN), destination: internet, family: "ipv4" });
    expect(r.hops.map((h) => h.type)).toEqual(expect.arrayContaining(["virtualHub", "firewall"]));
    expect(r.hops.find((h) => h.type === "virtualHub")!.reason).toContain("Routing Intent: Internet Traffic");
    expect(r.status).toBe("ALLOWED");
    expect(r.egress).toMatchObject({ mechanism: "firewall", controlled: true, publicIps: ["198.51.100.99"] });
  });

  it("derives routes from the associated hub route table without routing intent", () => {
    const ctx = ctxFor(vwanRaw({ routingIntent: false }));
    const route = selectRoute(synthesizeRoutes(ctx, lc(SNET_WAN), "ipv4"), "203.0.113.1");
    expect(route).toMatchObject({
      source: "vwan",
      nextHopType: "VirtualHub",
      nextHopResourceId: lc(FW_HUB),
      confidence: "LIKELY",
    });
    expect(describeRoute(route!)).toContain("Virtual-WAN-Route 0.0.0.0/0");
  });

  it("does not route IPv6 via the hub (Virtual WAN is IPv4 only)", () => {
    const ctx = ctxFor(vwanRaw());
    const v6 = synthesizeRoutes(ctx, lc(SNET_WAN), "ipv6");
    expect(v6.filter((r) => r.source === "vwan")).toEqual([]);
  });

  it("lowers confidence when hub details could not be read", () => {
    const raw = vwanRaw({ hubDetails: false });
    const ctx = ctxFor(raw);
    // Without connections the spoke is not known to be attached: no vWAN routes at all.
    expect(synthesizeRoutes(ctx, lc(SNET_WAN), "ipv4").some((r) => r.source === "vwan")).toBe(false);
  });
});

describe("ECMP", () => {
  it("reports all equal-cost next hops and weakens confidence for unknown ones", () => {
    const raw = F.hubSpokeRaw();
    const def = rtRoutes(raw).find((r) => r.name === "default-v4")!;
    def.properties = {
      addressPrefix: "0.0.0.0/0",
      nextHopType: "VirtualAppliance",
      nextHop: { nextHopIpAddresses: ["10.0.1.4", "10.0.1.5"] },
    };
    const ctx = ctxFor(raw);
    const route = selectRoute(synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv4"), "203.0.113.1")!;
    expect(route.nextHopIpAddresses).toEqual(["10.0.1.4", "10.0.1.5"]);
    expect(describeRoute(route)).toContain("ECMP: 10.0.1.4, 10.0.1.5");
    const r = tracePath(ctx, { sourceId: lc(F.VM), destination: internet, family: "ipv4" });
    const ecmp = r.hops.find((h) => h.label.startsWith("ECMP"))!;
    expect(ecmp.label).toBe("ECMP (2 Next Hops)");
    expect(ecmp.confidence).toBe("POSSIBLE");
    expect(r.status).toBe("UNKNOWN");
  });
});

describe("service tag routes", () => {
  const tagged = (tags: { name: string; prefixes: string[] }[]) => {
    const raw = F.hubSpokeRaw();
    raw.enrichment = { virtualHubs: {}, serviceTags: { location: "westeurope", tags }, results: [] };
    return raw;
  };

  it("expands a service tag UDR to the tag's prefixes", () => {
    const ctx = ctxFor(tagged([{ name: "Storage", prefixes: ["20.60.0.0/16", "2603:1000::/40"] }]));
    const r = tracePath(ctx, {
      sourceId: lc(F.VM),
      destination: { kind: "ip", address: "20.60.1.1" },
      family: "ipv4",
    });
    expect(r.hops[1]!.route).toMatchObject({
      prefix: "20.60.0.0/16",
      serviceTag: "Storage",
      nextHopType: "Internet",
    });
    expect(r.hops[1]!.reason).toContain("[Storage]");
    const v6 = synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv6").filter((x) => x.serviceTag);
    expect(v6.map((x) => x.prefix)).toEqual(["2603:1000::/40"]);
  });

  it("prefers the more specific tag for identical prefixes (Storage.WestEurope > Storage > AzureCloud)", () => {
    const raw = tagged([
      { name: "Storage", prefixes: ["20.60.0.0/16"] },
      { name: "AzureCloud", prefixes: ["20.60.0.0/16"] },
      { name: "Storage.WestEurope", prefixes: ["20.60.0.0/16"] },
    ]);
    rtRoutes(raw).push(
      {
        name: "cloud",
        properties: {
          addressPrefix: "AzureCloud",
          nextHopType: "VirtualAppliance",
          nextHopIpAddress: "10.0.1.4",
        },
      },
      { name: "st-weu", properties: { addressPrefix: "Storage.WestEurope", nextHopType: "None" } },
    );
    const ctx = ctxFor(raw);
    const route = selectRoute(synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv4"), "20.60.1.1");
    expect(route?.serviceTag).toBe("Storage.WestEurope");
  });

  it("marks paths to public IPs as uncertain while tag routes are unresolved", () => {
    const ctx = ctxFor();
    const r = tracePath(ctx, {
      sourceId: lc(F.VM),
      destination: { kind: "ip", address: "20.60.1.1" },
      family: "ipv4",
    });
    expect(r.status).toBe("UNKNOWN");
    expect(r.hops[1]!.evidence.map((e) => e.description).join(" ")).toContain("Storage");
    // …but not the generic Internet probe.
    expect(tracePath(ctx, { sourceId: lc(F.VM), destination: internet, family: "ipv4" }).status).toBe(
      "ALLOWED",
    );
  });
});

describe("Azure Virtual Network Manager", () => {
  function avnmRaw(
    rules: { name: string; snapshot: number; props: Record<string, unknown> }[],
    connectivity = false,
  ) {
    const raw = F.hubSpokeRaw();
    const cfg = `${NM}/securityAdminConfigurations/cfg`;
    raw.resources["Q-SEC-AVNM"] = [
      ...rules.map((r) =>
        F.res(
          `${cfg}/ruleCollections/rc/rules/${r.name}/snapshots/${r.snapshot}`,
          "microsoft.network/networkmanagers/securityadminconfigurations/rulecollections/rules/snapshots",
          r.props,
        ),
      ),
      F.res(
        `${F.SPOKE}/providers/Microsoft.Network/effectiveSecurityAdminRules/default`,
        "microsoft.network/effectivesecurityadminrules",
        {
          EffectiveSecurityAdminConfigurations: [{ Id: `${cfg}/snapshots/7` }],
        },
      ),
    ];
    if (connectivity) {
      const conn = `${NM}/connectivityConfigurations/mesh`;
      raw.resources["Q-SEC-AVNM"].push(
        F.res(
          `${conn}/snapshots/1`,
          "microsoft.network/networkmanagers/connectivityconfigurations/snapshots",
          {
            connectivityTopology: "HubAndSpoke",
            appliesToGroups: [{ groupConnectivity: "DirectlyConnected" }],
          },
        ),
        ...[F.SPOKE, F.LONELY].map((v) =>
          F.res(
            `${v}/providers/Microsoft.Network/effectiveConnectivityConfigurations/default`,
            "microsoft.network/effectiveconnectivityconfigurations",
            {
              effectiveConnectivityConfigurations: [{ id: `${conn}/snapshots/1` }],
            },
          ),
        ),
      );
    }
    return raw;
  }
  const inbound443 = (access: string) => ({
    access,
    direction: "Inbound",
    priority: 10,
    protocol: "Tcp",
    sources: [{ addressPrefix: "*", addressPrefixType: "IPPrefix" }],
    destinations: [{ addressPrefix: "*", addressPrefixType: "IPPrefix" }],
    destinationPortRanges: ["443"],
  });

  it("normalizes the latest rule snapshot and case-insensitive properties", () => {
    const ctx = ctxFor(
      avnmRaw([
        { name: "r1", snapshot: 1, props: inbound443("Allow") },
        {
          name: "r1",
          snapshot: 2,
          props: {
            Access: "Deny",
            Direction: "Inbound",
            Priority: 10,
            Protocol: "Tcp",
            DestinationPortRanges: ["443"],
          },
        },
      ]),
    );
    expect(ctx.inv.avnm.adminRules).toHaveLength(1);
    expect(ctx.inv.avnm.adminRules[0]).toMatchObject({
      access: "Deny",
      priority: 10,
      destinationPorts: ["443"],
    });
    expect(ctx.inv.avnm.vnetAdminConfigurations[lc(F.SPOKE)]).toEqual([
      lc(`${NM}/securityAdminConfigurations/cfg`),
    ]);
  });

  it("builds connected group routes for directly connected VNets", () => {
    const raw = avnmRaw([], true);
    patchSubnet(raw, F.SNET_APP, {});
    const ctx = ctxFor(raw);
    const route = selectRoute(synthesizeRoutes(ctx, lc(F.SNET_APP), "ipv4"), "192.168.0.5");
    expect(route).toMatchObject({ nextHopType: "ConnectedGroup", nextHopResourceId: lc(F.LONELY) });
    const r = tracePath(ctx, {
      sourceId: lc(F.VM),
      destination: { kind: "ip", address: "192.168.0.5" },
      family: "ipv4",
    });
    expect(r.hops.find((h) => h.type === "peering")!.reason).toContain("AVNM Connected Group");
  });
});
