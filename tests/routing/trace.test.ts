import { describe, expect, it } from "vitest";
import { analyzeDefaultPaths } from "../../src/routing/analysis.js";
import { compareFamilies, resolveEgress, tracePath } from "../../src/routing/trace.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc, patchSubnet } from "./helpers.js";

const internet = { kind: "internet" } as const;

describe("path tracer", () => {
  const ctx = ctxFor();

  it("traces IPv4 internet traffic of a spoke VM through the hub firewall", () => {
    const r = tracePath(ctx, { sourceId: lc(F.VM), destination: internet, family: "ipv4" });
    expect(r.status).toBe("ALLOWED");
    expect(r.hops.map((h) => h.type)).toEqual([
      "source",
      "route",
      "firewall",
      "route",
      "publicIp",
      "internet",
    ]);
    expect(r.hops[1]!.reason).toBe("UDR 0.0.0.0/0 → VirtualAppliance 10.0.1.4");
    expect(r.hops[2]).toMatchObject({
      nodeId: lc(F.FW),
      decision: { access: "Allow", rule: "rcg-net/allow-web/web" },
    });
    expect(r.egress).toMatchObject({ mechanism: "firewall", controlled: true, publicIps: ["198.51.100.20"] });
    expect(r.securityControls).toEqual([lc(F.FW)]);
  });

  it("Akzeptanztest 1/2 (Pfad): IPv6 leaves directly via the VM's public IPv6 and bypasses the firewall", () => {
    const r = tracePath(ctx, { sourceId: lc(F.VM), destination: internet, family: "ipv6" });
    expect(r.status).toBe("POTENTIAL_BYPASS");
    expect(r.hops[1]!.reason).toContain("UDR ::/0 → Internet");
    expect(r.egress).toMatchObject({
      mechanism: "instancePublicIp",
      controlled: false,
      publicIps: ["2001:db8::10"],
    });
    expect(r.summary).toContain("umgeht die zentrale Sicherheitskontrolle afw-hub");
  });

  it("compares IPv4 and IPv6 and reports the architecture gap", () => {
    const c = compareFamilies(ctx, lc(F.VM), internet);
    expect(c.architectureGap).toContain("IPv6 umgeht");
    expect(c.differences).toEqual(
      expect.arrayContaining(["Sicherheitskontrollen: IPv4 afw-hub, IPv6 keine"]),
    );
  });

  it("closes the gap when ::/0 points to the firewall", () => {
    const c = ctxFor(F.hubSpokeRaw({ spokeIpv6Route: "Firewall" }));
    const r = tracePath(c, { sourceId: lc(F.VM), destination: internet, family: "ipv6" });
    // The firewall in the fixture has no IPv6 address: the IPv6 next hop cannot be resolved.
    expect(r.status).toBe("UNKNOWN");
    expect(r.hops.at(-1)!.reason).toContain("keiner bekannten Ressource zugeordnet");
  });

  it("delivers spoke-to-hub traffic over the peering (routes win over the default UDR)", () => {
    const r = tracePath(ctx, {
      sourceId: lc(F.VM),
      destination: { kind: "ip", address: "10.0.1.4" },
      family: "ipv4",
    });
    expect(r.status).toBe("ALLOWED");
    expect(r.hops.map((h) => h.type)).toEqual(["source", "route", "peering", "destination"]);
    expect(r.hops.at(-1)!.nodeId).toBe(lc(F.FW));
  });

  it("drops traffic to reserved ranges via the None system route", () => {
    const r = tracePath(ctx, {
      sourceId: lc(F.VM),
      destination: { kind: "ip", address: "172.16.5.5" },
      family: "ipv4",
    });
    expect(r.status).toBe("BLOCKED");
    expect(r.summary).toContain("172.16.0.0/12 → None");
  });

  it("blocks traffic denied by the destination NSG", () => {
    const r = tracePath(ctx, {
      sourceId: lc(F.SNET_HUB_NAT),
      destination: { kind: "ip", address: "10.1.1.4" },
      family: "ipv4",
      port: 22,
    });
    expect(r.status).toBe("BLOCKED");
    expect(r.hops.at(-1)!.decision).toMatchObject({
      control: "nsg",
      direction: "Inbound",
      access: "Deny",
      rule: "DenyAllInBound",
    });
  });

  it("reports missing IPv6 at the source as not applicable", () => {
    const r = tracePath(ctx, { sourceId: lc(F.SNET_HUB_NAT), destination: internet, family: "ipv6" });
    expect(r).toMatchObject({ notApplicable: true, status: "BLOCKED" });
  });

  it("uses the NAT gateway for IPv4 and detects that NAT Standard cannot carry IPv6", () => {
    const r = tracePath(ctx, { sourceId: lc(F.SNET_HUB_NAT), destination: internet, family: "ipv4" });
    expect(r.egress).toMatchObject({ mechanism: "natGateway", publicIps: ["198.51.100.10"] });
    const subnet = {
      ...ctx.subnets.get(lc(F.SNET_HUB_NAT))!,
      prefixes: { ipv4: ["10.0.3.0/24"], ipv6: ["fd00:10:0:3::/64"] },
    };
    const e = resolveEgress(ctx, { subnet, family: "ipv6" });
    expect(e.mechanism).toBe("unknown");
    expect(e.evidence.map((x) => x.description)).toEqual(
      expect.arrayContaining([expect.stringContaining("unterstützt kein IPv6")]),
    );
  });

  it("finds no IPv4 egress for a private subnet without explicit outbound", () => {
    const raw = F.hubSpokeRaw();
    patchSubnet(raw, F.SNET_APP, { routeTable: undefined });
    const r = tracePath(ctxFor(raw), { sourceId: lc(F.SNET_APP), destination: internet, family: "ipv4" });
    expect(r.status).toBe("BLOCKED");
    expect(r.egress?.evidence[0]?.description).toContain("Privates Subnet");
  });

  it("detects routing loops", () => {
    const raw = F.hubSpokeRaw();
    const rt = raw.resources["Q-NET-RT"]![0]!;
    patchSubnet(raw, F.SNET_FW, { routeTable: { id: F.RT_SPOKE } });
    (rt.properties!["subnets"] as unknown[]).push({ id: F.SNET_FW });
    const r = tracePath(ctxFor(raw), { sourceId: lc(F.VM), destination: internet, family: "ipv4" });
    expect(r.summary).toBe("Routing-Schleife");
  });
});

describe("default path analysis", () => {
  it("summarizes the internet path of every workload subnet per family", () => {
    const inv = analyzeInventory(F.hubSpokeRaw()).inventory;
    const paths = analyzeDefaultPaths(inv);
    expect(paths.map((p) => `${p.subnet}/${p.family}`).sort()).toEqual([
      "snet-app/ipv4",
      "snet-app/ipv6",
      "snet-egress/ipv4",
    ]);
    expect(paths.find((p) => p.subnet === "snet-app" && p.family === "ipv4")).toMatchObject({
      controlled: true,
      egress: "firewall",
      status: "ALLOWED",
    });
    expect(paths.find((p) => p.subnet === "snet-egress")).toMatchObject({
      controlled: false,
      egress: "natGateway",
    });
  });
});
