import { describe, expect, it } from "vitest";
import { assessServices } from "../../src/assessment/index.js";
import { expectedZonesFor } from "../../src/assessment/dns.js";
import type { RawInventory, RawResource } from "../../src/models/discovery.js";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const DNS_RG = (name: string) =>
  `/subscriptions/${F.SUB_CONN}/resourceGroups/rg-dns/providers/Microsoft.Network/${name}`;
const ZONE = DNS_RG("privateDnsZones/privatelink.database.windows.net");
const RESOLVER = DNS_RG("dnsResolvers/dnspr-hub");
const RULESET = DNS_RG("dnsForwardingRulesets/rs-hub");
const PE_IP = "10.1.1.10";

const zone = (id: string) => F.res(id, "microsoft.network/privatednszones", {}, { location: "global" });
const link = (zoneId: string, vnet: string, name = "l") =>
  F.res(`${zoneId}/virtualNetworkLinks/${name}`, "microsoft.network/privatednszones/virtualnetworklinks", {
    virtualNetwork: { id: vnet },
    registrationEnabled: false,
  });
const aRecord = (zoneId: string, name: string, ip: string) =>
  F.res(`${zoneId}/A/${name}`, "microsoft.network/privatednszones/a", {
    aRecords: [{ ipv4Address: ip }],
    ttl: 10,
  });

function setVnetDns(raw: RawInventory, vnet: string, servers: string[]) {
  const row = raw.resources["Q-NET-VNET"]!.find((r) => r.id === vnet)!;
  row.properties = { ...row.properties, dhcpOptions: { dnsServers: servers } };
}

/** Spoke uses the hub's DNS Private Resolver; the SQL private endpoint lives in the spoke. */
function scenario(dns: { zones?: RawResource[]; records?: RawResource[]; extra?: RawResource[] } = {}) {
  const raw = F.hubSpokeRaw();
  setVnetDns(raw, F.SPOKE, ["10.0.5.4"]);
  raw.resources["Q-DNS-ZONES"] = [
    F.res(RESOLVER, "microsoft.network/dnsresolvers", { virtualNetwork: { id: F.HUB } }),
    F.res(`${RESOLVER}/inboundEndpoints/in`, "microsoft.network/dnsresolvers/inboundendpoints", {
      ipConfigurations: [{ privateIpAddress: "10.0.5.4", subnet: { id: `${F.HUB}/subnets/snet-dns-in` } }],
    }),
    ...(dns.zones ?? []),
    ...(dns.extra ?? []),
  ];
  raw.resources["Q-DNS-REC"] = dns.records ?? [];
  raw.resources["Q-PAAS"] = [F.res(F.SQL, "microsoft.sql/servers", { publicNetworkAccess: "Disabled" })];
  return raw;
}

const assess = (raw: RawInventory) => assessServices(normalizeInventory(raw));
const peCheck = (raw: RawInventory) =>
  assess(raw).dns.privateEndpoints.find((c) => c.privateEndpointId === lc(F.PE))!;
const codes = (raw: RawInventory) => assess(raw).findings.map((f) => f.code);

describe("DNS assessment", () => {
  it("resolves the spoke via the hub resolver and accepts a zone linked to the hub", () => {
    const raw = scenario({ zones: [zone(ZONE), link(ZONE, F.HUB)], records: [aRecord(ZONE, "sql1", PE_IP)] });
    const a = assess(raw);
    const spoke = a.dns.vnets.find((v) => v.vnetId === lc(F.SPOKE))!;
    expect(spoke).toMatchObject({
      mode: "custom",
      servers: [{ ip: "10.0.5.4", kind: "resolverInbound", name: "dnspr-hub", vnetId: lc(F.HUB) }],
      resolvingVnetIds: [lc(F.HUB)],
      verifiable: true,
    });
    expect(a.dns.vnets.find((v) => v.vnetId === lc(F.HUB))!.mode).toBe("azure");
    expect(peCheck(raw)).toMatchObject({
      groupId: "sqlServer",
      expectedZones: ["privatelink.database.windows.net"],
      ips: [PE_IP],
      status: "ok",
      linkedZoneIds: [lc(ZONE)],
      resolvingVnetIds: [lc(F.HUB)],
    });
    // The graph links the private endpoint to the zone holding its A record.
    const graph = analyzeInventory(raw).graph;
    expect(
      graph.edges.some((e) => e.type === "dnsLink" && e.source === lc(F.PE) && e.target === lc(ZONE)),
    ).toBe(true);
    expect(a.dns.resolvers[0]).toMatchObject({ inboundIps: ["10.0.5.4"], usedByVnetIds: [lc(F.SPOKE)] });
    expect(codes(raw)).not.toContain("PAAS_UNREACHABLE_PRIVATE_DNS");
  });

  it("flags a zone linked only to the spoke, since the hub resolver answers", () => {
    const raw = scenario({
      zones: [zone(ZONE), link(ZONE, F.SPOKE)],
      records: [aRecord(ZONE, "sql1", PE_IP)],
    });
    expect(peCheck(raw).status).toBe("not-linked");
    expect(codes(raw)).toEqual(expect.arrayContaining(["PE_DNS_NOT_LINKED", "PAAS_UNREACHABLE_PRIVATE_DNS"]));
  });

  it("flags a missing A record and names a record found in an unexpected zone", () => {
    const custom = DNS_RG("privateDnsZones/corp.privatelink.database.windows.net");
    const raw = scenario({
      zones: [zone(ZONE), link(ZONE, F.HUB), zone(custom), link(custom, F.HUB)],
      records: [aRecord(custom, "sql1", PE_IP)],
    });
    const c = peCheck(raw);
    expect(c.status).toBe("missing-record");
    expect(c.detail).toContain("corp.privatelink.database.windows.net");
  });

  it("flags a missing zone", () => {
    const raw = scenario();
    expect(peCheck(raw).status).toBe("missing-zone");
    expect(codes(raw)).toContain("PE_DNS_MISSING_ZONE");
  });

  it("does not check disconnected connections but reports them", () => {
    const raw = scenario();
    const pe = raw.resources["Q-PE"]![0]!;
    const conn = (
      pe.properties!["privateLinkServiceConnections"] as { properties: Record<string, unknown> }[]
    )[0]!;
    conn.properties["privateLinkServiceConnectionState"] = { status: "Disconnected" };
    expect(peCheck(raw).status).toBe("inactive");
    expect(codes(raw)).toContain("PE_DNS_INACTIVE");
    expect(codes(raw)).not.toContain("PE_DNS_MISSING_ZONE");
  });

  it("cannot verify resolution through DNS servers outside Azure", () => {
    const raw = scenario({ zones: [zone(ZONE), link(ZONE, F.HUB)], records: [aRecord(ZONE, "sql1", PE_IP)] });
    setVnetDns(raw, F.SPOKE, ["192.0.2.53"]);
    const a = assess(raw);
    expect(a.dns.vnets.find((v) => v.vnetId === lc(F.SPOKE))).toMatchObject({
      verifiable: false,
      servers: [{ ip: "192.0.2.53", kind: "external" }],
    });
    expect(peCheck(raw).status).toBe("unverifiable");
    expect(a.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(["DNS_EXTERNAL_SERVERS", "PE_DNS_UNVERIFIABLE"]),
    );
  });

  it("treats a domain forwarded by a linked ruleset as not verifiable", () => {
    const raw = scenario({
      extra: [F.res(RULESET, "microsoft.network/dnsforwardingrulesets", {})],
    });
    raw.resources["Q-DNS-REC"] = [
      F.res(`${RULESET}/forwardingRules/sql`, "microsoft.network/dnsforwardingrulesets/forwardingrules", {
        domainName: "database.windows.net.",
        targetDnsServers: [{ ipAddress: "192.0.2.53", port: 53 }],
        forwardingRuleState: "Enabled",
      }),
      F.res(
        `${RULESET}/virtualNetworkLinks/hub`,
        "microsoft.network/dnsforwardingrulesets/virtualnetworklinks",
        {
          virtualNetwork: { id: F.HUB },
        },
      ),
    ];
    const a = assess(raw);
    expect(a.dns.rulesets[0]).toMatchObject({
      name: "rs-hub",
      linkedVnetIds: [lc(F.HUB)],
      rules: [{ domain: "database.windows.net.", targets: ["192.0.2.53:53"], enabled: true }],
    });
    expect(peCheck(raw).status).toBe("unverifiable");
  });

  it("reports duplicate and unlinked zones", () => {
    const copy = `/subscriptions/${F.SUB_APP}/resourceGroups/rg-app/providers/Microsoft.Network/privateDnsZones/privatelink.database.windows.net`;
    const raw = scenario({
      zones: [zone(ZONE), link(ZONE, F.HUB), zone(copy)],
      records: [aRecord(ZONE, "sql1", PE_IP)],
    });
    expect(codes(raw)).toEqual(expect.arrayContaining(["DNS_DUPLICATE_ZONE", "DNS_ZONE_NOT_LINKED"]));
    expect(assess(raw).dns.zones.find((z) => z.id === lc(copy))!.sameNameZones).toBe(2);
  });

  it("derives expected zones from the group ID, else from the FQDN", () => {
    expect(expectedZonesFor("blob", [])).toEqual(["privatelink.blob.core.windows.net"]);
    expect(expectedZonesFor("vault", ["kv.vault.azure.net"])).toEqual(["privatelink.vaultcore.azure.net"]);
    expect(expectedZonesFor("custom", ["x.svc.contoso.net"])).toEqual(["privatelink.svc.contoso.net"]);
    expect(expectedZonesFor("custom", [])).toEqual([]);
  });
});

describe("PaaS assessment", () => {
  it("rates open public endpoints of data services higher", () => {
    const raw = scenario();
    const vault = `/subscriptions/${F.SUB_APP}/resourceGroups/rg-data/providers/Microsoft.KeyVault/vaults/kv1`;
    const acr = `/subscriptions/${F.SUB_APP}/resourceGroups/rg-app/providers/Microsoft.ContainerRegistry/registries/acr1`;
    raw.resources["Q-PAAS"]!.push(
      F.res(vault, "microsoft.keyvault/vaults", { minimumTlsVersion: "1.1" }),
      F.res(acr, "microsoft.containerregistry/registries", { loginServer: "acr1.azurecr.io" }),
    );
    const a = assess(raw);
    const open = a.findings.filter((f) => f.code === "PAAS_PUBLIC_OPEN");
    expect(open.find((f) => f.resourceIds[0] === lc(vault))!.severity).toBe("HIGH");
    expect(open.find((f) => f.resourceIds[0] === lc(acr))!.severity).toBe("MEDIUM");
    expect(a.findings.map((f) => f.code)).toContain("PAAS_WEAK_TLS");
    expect(a.paas.byExposure).toMatchObject({ public: 2, private: 1 });
    // Sorted most severe first.
    expect(a.findings[0]!.severity).toBe("HIGH");
  });

  it("flags a service still public although it has a private endpoint", () => {
    const raw = scenario({ zones: [zone(ZONE), link(ZONE, F.HUB)], records: [aRecord(ZONE, "sql1", PE_IP)] });
    raw.resources["Q-PAAS"] = [F.res(F.SQL, "microsoft.sql/servers", { publicNetworkAccess: "Enabled" })];
    raw.enrichment = {
      virtualHubs: {},
      results: [],
      paasNetworkRules: {
        [lc(F.SQL)]: {
          firewallRules: [{ properties: { startIpAddress: "0.0.0.0", endIpAddress: "255.255.255.255" } }],
          virtualNetworkRules: [],
          siteConfig: [],
          status: "ok",
        },
      },
    };
    const a = assess(raw);
    expect(a.findings.map((f) => f.code)).toEqual(
      expect.arrayContaining(["PAAS_PUBLIC_OPEN", "PAAS_PUBLIC_WITH_PRIVATE_ENDPOINT"]),
    );
  });
});
