import { describe, expect, it } from "vitest";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();

describe("normalizeInventory", () => {
  const inv = normalizeInventory(F.hubSpokeRaw());

  it("normalizes VNets with dual-stack address spaces and inline subnets", () => {
    const hub = inv.vnets.find((v) => v.id === lc(F.HUB))!;
    expect(hub.addressSpace).toEqual({ ipv4: ["10.0.0.0/16"], ipv6: ["fd00:10::/48"] });
    expect(hub.ipClassification).toBe("dual-stack");
    expect(hub.subnetIds).toHaveLength(3);
    const lonely = inv.vnets.find((v) => v.id === lc(F.LONELY))!;
    expect(lonely.ipClassification).toBe("ipv4-only");
  });

  it("merges addressPrefix and addressPrefixes and resolves subnet attachments", () => {
    const app = inv.subnets.find((s) => s.id === lc(F.SNET_APP))!;
    expect(app.prefixes).toEqual({ ipv4: ["10.1.1.0/24"], ipv6: ["fd00:11:0:1::/64"] });
    expect(app.nsgId).toBe(lc(F.NSG_SPOKE));
    expect(app.routeTableId).toBe(lc(F.RT_SPOKE));
    expect(app.defaultOutboundAccess).toBe(false);
    expect(app.connectedResourceIds).toEqual([lc(F.NIC_PE), lc(F.NIC_VM), lc(F.PE)].sort());
    const fwSubnet = inv.subnets.find((s) => s.id === lc(F.SNET_FW))!;
    expect(fwSubnet.connectedResourceIds).toEqual([lc(F.FW)]);
  });

  it("normalizes peerings with flags and remote address spaces", () => {
    const spokeToHub = inv.peerings.find((p) => p.vnetId === lc(F.SPOKE))!;
    expect(spokeToHub).toMatchObject({
      remoteVnetId: lc(F.HUB),
      useRemoteGateways: true,
      allowGatewayTransit: false,
      peeringState: "Connected",
      remoteAddressSpace: { ipv4: ["10.0.0.0/16"], ipv6: ["fd00:10::/48"] },
    });
  });

  it("classifies routes by IP version, detects default routes and resolves next hops", () => {
    const routes = inv.routes.filter((r) => r.routeTableId === lc(F.RT_SPOKE));
    const v4 = routes.find((r) => r.name === "default-v4")!;
    const v6 = routes.find((r) => r.name === "default-v6")!;
    const tag = routes.find((r) => r.name === "storage")!;
    expect(v4).toMatchObject({
      ipVersion: "ipv4",
      defaultRoute: true,
      nextHopType: "VirtualAppliance",
      nextHopResourceId: lc(F.FW),
    });
    expect(v6).toMatchObject({ ipVersion: "ipv6", defaultRoute: true, nextHopType: "Internet" });
    expect(tag).toMatchObject({ ipVersion: "serviceTag", defaultRoute: false });
  });

  it("normalizes NSG rules incl. IP families", () => {
    const nsg = inv.nsgs[0]!;
    expect(nsg.rules.map((r) => [r.name, r.ipFamilies])).toEqual([
      ["allow-https-v6", ["any", "ipv6"]],
      ["allow-lb", ["any"]],
    ]);
    expect(nsg.defaultRules[0]).toMatchObject({ isDefault: true, access: "Deny" });
  });

  it("computes NAT gateway egress families from attached public IPs", () => {
    expect(inv.natGateways[0]).toMatchObject({
      sku: "Standard",
      ipv4EgressConfigured: true,
      ipv6EgressConfigured: false,
      dualStackEgressConfigured: false,
    });
  });

  it("reads StandardV2 IPv6 addresses from publicIpAddressesV6 (IPv6-only NAT gateway)", () => {
    const raw = F.hubSpokeRaw();
    const pip6 = F.net(F.SUB_CONN, "rg-hub", "publicIPAddresses", "pip-nat6");
    const nat = raw.resources["Q-NET-NAT"]![0]!;
    nat.sku = { name: "StandardV2" };
    nat.properties = { ...nat.properties, publicIpAddresses: [], publicIpAddressesV6: [{ id: pip6 }] };
    raw.resources["Q-NET-PIP"] = [
      ...raw.resources["Q-NET-PIP"]!.filter((r) => r.id !== F.PIP_NAT),
      F.res(
        pip6,
        "microsoft.network/publicipaddresses",
        { ipAddress: "2001:db8:1::1", publicIPAddressVersion: "IPv6" },
        { sku: { name: "StandardV2" } },
      ),
    ];
    expect(normalizeInventory(raw).natGateways[0]).toMatchObject({
      sku: "StandardV2",
      publicIpIds: [lc(pip6)],
      ipv4EgressConfigured: false,
      ipv6EgressConfigured: true,
    });
  });

  it("adds NAT gateway public IPs known only from the IP's natGateway back-reference", () => {
    const raw = F.hubSpokeRaw();
    const nat = raw.resources["Q-NET-NAT"]![0]!;
    nat.properties = { ...nat.properties, publicIpAddresses: [] };
    expect(normalizeInventory(raw).natGateways[0]).toMatchObject({
      publicIpIds: [lc(F.PIP_NAT)],
      ipv4EgressConfigured: true,
    });
  });

  it("attaches public IPs to their owning resource and merges PE NIC addresses", () => {
    expect(inv.publicIps.find((p) => p.id === lc(F.PIP_VM))).toMatchObject({
      ipVersion: "ipv6",
      attachedToId: lc(F.NIC_VM),
    });
    expect(inv.privateEndpoints[0]).toMatchObject({
      addressing: { ipv4: ["10.1.1.10"], ipv6: [] },
      targets: [{ resourceId: lc(F.SQL), groupIds: ["sqlServer"], status: "Approved", manual: false }],
    });
  });

  it("keeps firewall policy rules including the ipv6Rule flag", () => {
    const rcg = inv.ruleCollectionGroups[0]!;
    expect(rcg.firewallPolicyId).toBe(lc(F.FW_POLICY));
    expect(rcg.ruleCollections[0]!.rules[0]).toMatchObject({
      ruleType: "NetworkRule",
      destinationPorts: ["443"],
      ipv6Rule: false,
    });
  });

  it("keeps unknown Microsoft.Network types as unclassified resources", () => {
    expect(inv.unclassifiedNetworkResources).toHaveLength(1);
    expect(inv.unclassifiedNetworkResources[0]).toMatchObject({
      azureType: "microsoft.network/brandnewthings",
      subnetIds: [lc(F.SNET_HUB_NAT)],
    });
  });

  it("never copies secret-like properties", () => {
    const raw = F.hubSpokeRaw();
    raw.resources["Q-NET-ALL"]![0]!.properties = {
      sharedKey: "s3cr3t",
      subnet: { id: F.SNET_HUB_NAT },
      plain: "ok",
    };
    const json = JSON.stringify(normalizeInventory(raw));
    expect(json).not.toContain("s3cr3t");
    expect(json).toContain('"plain":"ok"');
  });
});
