import { describe, expect, it } from "vitest";
import type { RawInventory } from "../../src/models/discovery.js";
import { analyzeInbound } from "../../src/routing/inbound.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc } from "./helpers.js";

const LB = F.net(F.SUB_APP, "rg-app", "loadBalancers", "lb-web");
const PIP_LB = F.net(F.SUB_APP, "rg-app", "publicIPAddresses", "pip-lb");
const NM = F.net(F.SUB_CONN, "rg-avnm", "networkManagers", "avnm");

function nsgRules(raw: RawInventory) {
  return raw.resources["Q-NET-NSG"]![0]!.properties!["securityRules"] as unknown[];
}

function allowFromInternet(raw: RawInventory, port: string) {
  nsgRules(raw).push({
    name: `allow-${port}`,
    properties: {
      priority: 110,
      direction: "Inbound",
      access: "Allow",
      protocol: "Tcp",
      sourceAddressPrefix: "Internet",
      destinationAddressPrefix: "*",
      destinationPortRange: port,
      sourcePortRange: "*",
    },
  });
}

function withLoadBalancer(raw: RawInventory) {
  raw.resources["Q-NET-PIP"]!.push(
    F.res(
      PIP_LB,
      "microsoft.network/publicipaddresses",
      { ipAddress: "198.51.100.30", publicIPAddressVersion: "IPv4" },
      { sku: { name: "Standard" } },
    ),
  );
  raw.resources["Q-NET-LB"] = [
    F.res(
      LB,
      "microsoft.network/loadbalancers",
      {
        frontendIPConfigurations: [
          {
            id: `${LB}/frontendIPConfigurations/fe`,
            name: "fe",
            properties: { publicIPAddress: { id: PIP_LB } },
          },
        ],
        backendAddressPools: [
          {
            id: `${LB}/backendAddressPools/web`,
            name: "web",
            properties: { backendIPConfigurations: [{ id: `${F.NIC_VM}/ipConfigurations/ipconfig1` }] },
          },
        ],
        loadBalancingRules: [
          {
            name: "https",
            properties: {
              protocol: "Tcp",
              frontendPort: 443,
              backendPort: 8443,
              frontendIPConfiguration: { id: `${LB}/frontendIPConfigurations/fe` },
              backendAddressPool: { id: `${LB}/backendAddressPools/web` },
            },
          },
        ],
        inboundNatRules: [
          {
            name: "rdp",
            properties: {
              protocol: "Tcp",
              frontendPort: 50001,
              backendPort: 3389,
              frontendIPConfiguration: { id: `${LB}/frontendIPConfigurations/fe` },
              backendIPConfiguration: { id: `${F.NIC_VM}/ipConfigurations/ipconfig1` },
            },
          },
        ],
      },
      { sku: { name: "Standard" } },
    ),
  ];
}

function withDnat(raw: RawInventory, sources = ["*"]) {
  const rcg = raw.resources["Q-SEC-FWRCG"]![0]!.properties!;
  (rcg["ruleCollections"] as unknown[]).push({
    name: "dnat",
    ruleCollectionType: "FirewallPolicyNatRuleCollection",
    priority: 50,
    action: { type: "DNAT" },
    rules: [
      {
        name: "web-in",
        ruleType: "NatRule",
        sourceAddresses: sources,
        destinationAddresses: ["198.51.100.20"],
        destinationPorts: ["443"],
        ipProtocols: ["TCP"],
        translatedAddress: "10.1.1.4",
        translatedPort: "443",
      },
    ],
  });
}

describe("inbound Internet → workload paths", () => {
  it("finds the instance-level public IPv6 and its open ports (no central control)", () => {
    const ctx = ctxFor();
    const [e, ...rest] = analyzeInbound(ctx);
    expect(rest).toEqual([]);
    expect(e).toMatchObject({
      family: "ipv6",
      entry: { kind: "publicIp", publicAddress: "2001:db8::10" },
      targetId: lc(F.VM),
      status: "ALLOWED",
      controlled: false,
      openPorts: [443],
      asymmetricRouting: false,
    });
    expect(e!.hops.map((h) => h.type)).toEqual(
      ["internet", "publicIp", "subnet", "destination"].filter((t) => e!.hops.some((h) => h.type === t)),
    );
  });

  it("shows the allowing NSG as a hop so it can be highlighted in the graph", () => {
    const [e] = analyzeInbound(ctxFor());
    const nsgHop = e!.hops.find((h) => h.nodeId === lc(F.NSG_SPOKE));
    expect(nsgHop).toMatchObject({
      label: "nsg-spoke",
      decision: { control: "nsg", direction: "Inbound", access: "Allow", rule: "allow-https-v6" },
    });
    expect(nsgHop!.reason).toContain("NSG (Subnet) erlaubt eingehend");
  });

  it("blocks load balancer traffic the NSG does not allow and lists restricted ports", () => {
    const raw = F.hubSpokeRaw();
    withLoadBalancer(raw);
    nsgRules(raw).push({
      name: "rdp-admins",
      properties: {
        priority: 120,
        direction: "Inbound",
        access: "Allow",
        protocol: "Tcp",
        sourceAddressPrefix: "203.0.113.0/28",
        destinationAddressPrefix: "*",
        destinationPortRange: "3389",
        sourcePortRange: "*",
      },
    });
    const list = analyzeInbound(ctxFor(raw)).filter((e) => e.family === "ipv4");
    const rule = list.find((e) => e.entry.kind === "loadBalancer")!;
    expect(rule).toMatchObject({ status: "BLOCKED", entry: { frontendPort: 443 }, openPorts: [] });
    const nat = list.find((e) => e.entry.kind === "loadBalancerNat")!;
    // Reachable for the admin range only – and the reply would leave via the firewall (UDR 0/0).
    expect(nat).toMatchObject({
      status: "UNKNOWN",
      openPorts: [],
      restricted: [{ port: 3389, sources: ["203.0.113.0/28"] }],
      asymmetricRouting: true,
    });
    // The NSG that lets the admin range in is part of the path.
    expect(nat.hops.find((h) => h.nodeId === lc(F.NSG_SPOKE))).toMatchObject({
      decision: { control: "nsg", access: "Allow", rule: "rdp-admins" },
    });
  });

  it("detects asymmetric routing when the backend subnet sends 0.0.0.0/0 to the firewall", () => {
    const raw = F.hubSpokeRaw();
    withLoadBalancer(raw);
    allowFromInternet(raw, "8443");
    const e = analyzeInbound(ctxFor(raw)).find((x) => x.entry.kind === "loadBalancer")!;
    expect(e.openPorts).toEqual([8443]);
    expect(e.asymmetricRouting).toBe(true);
    expect(e.status).toBe("UNKNOWN");
    expect(e.hops.at(-1)!.evidence[0]!.description).toContain("Asymmetrisches Routing");
  });

  it("treats Azure Firewall DNAT as controlled; the NSG sees the firewall's private IP", () => {
    const raw = F.hubSpokeRaw();
    withDnat(raw);
    // Real NSGs always carry AllowVnetInBound (the fixture only lists DenyAllInBound).
    (raw.resources["Q-NET-NSG"]![0]!.properties!["defaultSecurityRules"] as unknown[]).unshift({
      name: "AllowVnetInBound",
      properties: {
        priority: 65000,
        direction: "Inbound",
        access: "Allow",
        protocol: "*",
        sourceAddressPrefix: "VirtualNetwork",
        destinationAddressPrefix: "VirtualNetwork",
        destinationPortRange: "*",
        sourcePortRange: "*",
      },
    });
    const e = analyzeInbound(ctxFor(raw)).find((x) => x.entry.kind === "firewallDnat")!;
    expect(e).toMatchObject({
      family: "ipv4",
      targetId: lc(F.VM),
      targetAddress: "10.1.1.4",
      controlled: true,
      status: "ALLOWED",
      openPorts: [443],
      asymmetricRouting: false,
    });
    expect(e.hops[1]).toMatchObject({
      type: "firewall",
      decision: { control: "firewall", rule: "rcg-net/dnat/web-in" },
    });
  });

  it("filters exposures by target (VM, NIC or subnet)", () => {
    const raw = F.hubSpokeRaw();
    withDnat(raw);
    const ctx = ctxFor(raw);
    expect(analyzeInbound(ctx, { targetId: lc(F.NIC_VM) })).toHaveLength(2);
    expect(analyzeInbound(ctx, { targetId: lc(F.SNET_APP) })).toHaveLength(2);
    expect(analyzeInbound(ctx, { targetId: lc(F.HUB) })).toHaveLength(0);
  });

  it("applies AVNM security admin rules before the NSG (Deny stops, AlwaysAllow bypasses)", () => {
    const raw = F.hubSpokeRaw();
    const cfg = `${NM}/securityAdminConfigurations/cfg`;
    const rule = (name: string, access: string, port: string, priority: number) =>
      F.res(
        `${cfg}/ruleCollections/rc/rules/${name}/snapshots/1`,
        "microsoft.network/networkmanagers/securityadminconfigurations/rulecollections/rules/snapshots",
        {
          access,
          direction: "Inbound",
          priority,
          protocol: "Tcp",
          sources: [{ addressPrefix: "*" }],
          destinations: [{ addressPrefix: "*" }],
          destinationPortRanges: [port],
        },
      );
    raw.resources["Q-SEC-AVNM"] = [
      rule("deny-https", "Deny", "443", 10),
      rule("always-ssh", "AlwaysAllow", "22", 20),
      F.res(
        `${F.SPOKE}/providers/Microsoft.Network/effectiveSecurityAdminRules/default`,
        "microsoft.network/effectivesecurityadminrules",
        {
          effectiveSecurityAdminConfigurations: [{ id: `${cfg}/snapshots/1` }],
        },
      ),
    ];
    const e = analyzeInbound(ctxFor(raw))[0]!;
    expect(e.openPorts).toEqual([22]);
    const avnm = e.hops.find((h) => h.decision?.control === "avnm")!;
    expect(avnm.decision).toMatchObject({ access: "AlwaysAllow", rule: "AVNM always-ssh" });
  });
});
