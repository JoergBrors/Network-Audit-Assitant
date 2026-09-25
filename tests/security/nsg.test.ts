import { describe, expect, it } from "vitest";
import type { NsgEntity, NsgRuleEntity } from "../../src/models/network.js";
import { evaluateNsg, type FlowTuple } from "../../src/security/nsg.js";

const rule = (
  name: string,
  priority: number,
  direction: string,
  access: string,
  sources: string[],
  destinations: string[],
  ports = ["*"],
  extra: Partial<NsgRuleEntity> = {},
): NsgRuleEntity => ({
  name,
  priority,
  direction,
  access,
  protocol: "Tcp",
  sources,
  destinations,
  sourcePorts: ["*"],
  destinationPorts: ports,
  sourceAsgIds: [],
  destinationAsgIds: [],
  ipFamilies: ["any"],
  isDefault: false,
  ...extra,
});
const nsg = (rules: NsgRuleEntity[]): NsgEntity => ({
  id: "nsg",
  name: "nsg",
  azureType: "x",
  rules,
  defaultRules: [],
  subnetIds: [],
  nicIds: [],
});
const flow = (source: string, destination: string, port = 443): FlowTuple => ({
  source,
  destination,
  protocol: "Tcp",
  port,
  virtualNetworkPrefixes: ["10.1.0.0/16", "fd00:11::/48"],
});

describe("NSG evaluation", () => {
  it("applies rules by priority, first match wins", () => {
    const n = nsg([
      rule("deny-443", 200, "Inbound", "Deny", ["*"], ["*"], ["443"]),
      rule("allow-web", 100, "Inbound", "Allow", ["Internet"], ["*"], ["443", "8000-8100"]),
    ]);
    expect(evaluateNsg(n, "Inbound", flow("203.0.113.5", "10.1.1.4"))).toMatchObject({
      access: "Allow",
      rule: "allow-web",
    });
    expect(evaluateNsg(n, "Inbound", flow("203.0.113.5", "10.1.1.4", 8050))).toMatchObject({
      access: "Allow",
      rule: "allow-web",
    });
    expect(evaluateNsg(n, "Inbound", flow("10.1.2.3", "10.1.1.4"))).toMatchObject({
      access: "Deny",
      rule: "deny-443",
    });
  });

  it("falls back to Azure default rules", () => {
    const n = nsg([]);
    expect(evaluateNsg(n, "Inbound", flow("203.0.113.5", "10.1.1.4"))).toMatchObject({
      access: "Deny",
      rule: "DenyAllInBound",
      isDefault: true,
    });
    expect(evaluateNsg(n, "Inbound", flow("10.1.9.9", "10.1.1.4"))).toMatchObject({
      access: "Allow",
      rule: "AllowVnetInBound",
    });
    expect(evaluateNsg(n, "Outbound", flow("10.1.1.4", "8.8.8.8"))).toMatchObject({
      access: "Allow",
      rule: "AllowInternetOutBound",
    });
  });

  it("matches IPv6 prefixes only against IPv6 addresses", () => {
    const n = nsg([rule("allow-v6", 100, "Inbound", "Allow", ["::/0"], ["*"])]);
    expect(evaluateNsg(n, "Inbound", flow("2a02::1", "fd00:11:0:1::4"))).toMatchObject({
      access: "Allow",
      rule: "allow-v6",
    });
    expect(evaluateNsg(n, "Inbound", flow("203.0.113.5", "10.1.1.4"))).toMatchObject({
      rule: "DenyAllInBound",
    });
  });

  it("lowers confidence when a higher-priority rule uses an unresolvable service tag", () => {
    const n = nsg([
      rule("storage", 100, "Outbound", "Deny", ["*"], ["Storage"]),
      rule("allow", 200, "Outbound", "Allow", ["*"], ["*"]),
    ]);
    expect(evaluateNsg(n, "Outbound", flow("10.1.1.4", "8.8.8.8"))).toMatchObject({
      access: "Allow",
      confidence: "POSSIBLE",
    });
  });

  it("uses ASG membership when known", () => {
    const n = nsg([
      rule("asg", 100, "Inbound", "Allow", ["*"], [], ["443"], { destinationAsgIds: ["asg-web"] }),
    ]);
    expect(
      evaluateNsg(n, "Inbound", { ...flow("203.0.113.5", "10.1.1.4"), destinationAsgIds: ["asg-web"] }),
    ).toMatchObject({ access: "Allow", rule: "asg" });
    expect(
      evaluateNsg(n, "Inbound", { ...flow("203.0.113.5", "10.1.1.4"), destinationAsgIds: [] }),
    ).toMatchObject({ rule: "DenyAllInBound" });
  });

  it("resolves service tags via the Service Tag API data; unknown tags lower the confidence", () => {
    const n = nsg([rule("storage-out", 100, "Outbound", "Deny", ["*"], ["Storage"])]);
    const f = flow("10.1.1.4", "20.60.1.1");
    const resolveTag = (t: string) => (t === "Storage" ? ["20.60.0.0/16"] : undefined);
    expect(evaluateNsg(n, "Outbound", { ...f, resolveTag })).toMatchObject({
      rule: "storage-out",
      access: "Deny",
      confidence: "CONFIRMED",
    });
    expect(evaluateNsg(n, "Outbound", { ...f, destination: "20.61.1.1", resolveTag })).toMatchObject({
      rule: "AllowInternetOutBound",
    });
    expect(evaluateNsg(n, "Outbound", f)).toMatchObject({
      rule: "AllowInternetOutBound",
      confidence: "POSSIBLE",
    });
  });
});
