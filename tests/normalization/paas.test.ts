import { describe, expect, it } from "vitest";
import type { RawInventory } from "../../src/models/discovery.js";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import { buildGraph } from "../../src/graph/buildGraph.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const id = (rg: string, provider: string, name: string) =>
  `/subscriptions/${F.SUB_APP}/resourceGroups/${rg}/providers/${provider}/${name}`;

const STORAGE = id("rg-data", "Microsoft.Storage/storageAccounts", "stdata");
const VAULT = id("rg-data", "Microsoft.KeyVault/vaults", "kv-open");
const WEB = id("rg-app", "Microsoft.Web/sites", "app1");
const AKS_PRIVATE = id("rg-app", "Microsoft.ContainerService/managedClusters", "aks-private");
const AKS_PUBLIC = id("rg-app", "Microsoft.ContainerService/managedClusters", "aks-public");
const PG = id("rg-data", "Microsoft.DBforPostgreSQL/flexibleServers", "pg1");
const COSMOS = id("rg-data", "Microsoft.DocumentDB/databaseAccounts", "cosmos1");
const PE_STORAGE = F.net(F.SUB_APP, "rg-data", "privateEndpoints", "pe-st");
const PE_PENDING = F.net(F.SUB_APP, "rg-data", "privateEndpoints", "pe-pending");

function rawWithPaas(): RawInventory {
  const raw = F.hubSpokeRaw();
  raw.resources["Q-PAAS"] = [
    F.res(
      STORAGE,
      "microsoft.storage/storageaccounts",
      {
        primaryEndpoints: {
          blob: "https://stdata.blob.core.windows.net/",
          file: "https://stdata.file.core.windows.net/",
        },
        minimumTlsVersion: "TLS1_0",
        networkAcls: {
          defaultAction: "Deny",
          bypass: "AzureServices",
          ipRules: [{ value: "198.51.100.0/24", action: "Allow" }],
          virtualNetworkRules: [{ id: F.SNET_APP, action: "Allow" }],
        },
        privateEndpointConnections: [
          {
            properties: {
              privateEndpoint: { id: PE_STORAGE },
              privateLinkServiceConnectionState: { status: "Approved" },
            },
          },
          {
            properties: {
              privateEndpoint: { id: PE_PENDING },
              privateLinkServiceConnectionState: { status: "Pending" },
            },
          },
        ],
      },
      { kind: "StorageV2", sku: { name: "Standard_LRS" } },
    ),
    F.res(VAULT, "microsoft.keyvault/vaults", { vaultUri: "https://kv-open.vault.azure.net/" }),
    F.res(F.SQL, "microsoft.sql/servers", {
      fullyQualifiedDomainName: "sql1.database.windows.net",
      publicNetworkAccess: "Enabled",
    }),
    F.res(
      WEB,
      "microsoft.web/sites",
      {
        defaultHostName: "app1.azurewebsites.net",
        hostNames: ["app1.azurewebsites.net", "www.example.org"],
        virtualNetworkSubnetId: F.SNET_APP,
        vnetRouteAllEnabled: true,
        possibleOutboundIpAddresses: "203.0.113.1,203.0.113.2",
      },
      { kind: "functionapp,linux" },
    ),
    F.res(AKS_PRIVATE, "microsoft.containerservice/managedclusters", {
      apiServerAccessProfile: { enablePrivateCluster: true },
      privateFQDN: "aks-private-abc.privatelink.westeurope.azmk8s.io",
      agentPoolProfiles: [{ name: "sys", vnetSubnetID: F.SNET_APP }],
    }),
    F.res(AKS_PUBLIC, "microsoft.containerservice/managedclusters", {
      fqdn: "aks-public.hcp.westeurope.azmk8s.io",
    }),
    F.res(PG, "microsoft.dbforpostgresql/flexibleservers", {
      network: { delegatedSubnetResourceId: F.SNET_APP, publicNetworkAccess: "Disabled" },
    }),
    F.res(COSMOS, "microsoft.documentdb/databaseaccounts", {
      documentEndpoint: "https://cosmos1.documents.azure.com:443/",
      ipRules: [{ ipAddressOrRange: "198.51.100.7" }],
    }),
  ];
  raw.enrichment = {
    virtualHubs: {},
    results: [],
    paasNetworkRules: {
      [lc(F.SQL)]: {
        firewallRules: [
          {
            name: "AllowAllWindowsAzureIps",
            properties: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" },
          },
          { name: "office", properties: { startIpAddress: "198.51.100.10", endIpAddress: "198.51.100.20" } },
        ],
        virtualNetworkRules: [{ properties: { virtualNetworkSubnetId: F.SNET_APP } }],
        siteConfig: [],
        status: "ok",
      },
      [lc(WEB)]: {
        firewallRules: [],
        virtualNetworkRules: [],
        siteConfig: [
          {
            name: "web",
            properties: {
              ipSecurityRestrictions: [
                { ipAddress: "198.51.100.1/32", action: "Allow", priority: 100 },
                { ipAddress: "AzureFrontDoor.Backend", tag: "ServiceTag", action: "Allow", priority: 200 },
                { ipAddress: "Any", action: "Deny", priority: 2147483647 },
              ],
              ipSecurityRestrictionsDefaultAction: "Deny",
            },
          },
        ],
        status: "ok",
      },
    },
  };
  return raw;
}

describe("PaaS normalization", () => {
  const inv = normalizeInventory(rawWithPaas());
  const byName = (name: string) => inv.paasServices.find((s) => s.name === name)!;

  it("reads storage firewall, endpoints and private endpoint connections", () => {
    expect(byName("stdata")).toMatchObject({
      service: "Storage Account",
      category: "storage",
      kind: "StorageV2",
      sku: "Standard_LRS",
      publicNetworkAccess: "Enabled",
      endpoints: ["stdata.blob.core.windows.net", "stdata.file.core.windows.net"],
      firewall: {
        defaultAction: "Deny",
        ipRules: ["198.51.100.0/24"],
        subnetIds: [lc(F.SNET_APP)],
        bypass: "AzureServices",
        source: "arg",
      },
      privateEndpointIds: [lc(PE_PENDING), lc(PE_STORAGE)],
      privateEndpointConnectionStates: [{ privateEndpointId: lc(PE_PENDING), status: "Pending" }],
      exposure: "restricted",
    });
  });

  it("treats a Key Vault without network ACLs as publicly open", () => {
    expect(byName("kv-open")).toMatchObject({ publicNetworkAccess: "Enabled", exposure: "public" });
  });

  it("uses ARM firewall rules for SQL and recognizes the Azure services exception", () => {
    expect(byName("sql1")).toMatchObject({
      firewall: {
        defaultAction: "Deny",
        ipRules: ["198.51.100.10-198.51.100.20"],
        subnetIds: [lc(F.SNET_APP)],
        bypass: "AzureServices",
        source: "arm",
      },
      exposure: "restricted",
    });
    // The fixture's private endpoint targets sql1 – linked although the server does not list it.
    expect(byName("sql1").privateEndpointIds).toEqual([lc(F.PE)]);
  });

  it("reads App Service access restrictions and VNet integration", () => {
    expect(byName("app1")).toMatchObject({
      service: "App Service / Function App",
      publicNetworkAccess: "Enabled",
      firewall: {
        defaultAction: "Deny",
        ipRules: ["198.51.100.1/32"],
        bypass: "AzureFrontDoor.Backend",
        source: "arm",
      },
      vnetIntegration: { subnetIds: [lc(F.SNET_APP)], mode: "integration", routeAll: true },
      outboundIps: ["203.0.113.1", "203.0.113.2"],
      endpoints: ["app1.azurewebsites.net", "www.example.org"],
      exposure: "restricted",
    });
  });

  it("classifies AKS by private cluster and authorized IP ranges", () => {
    expect(byName("aks-private")).toMatchObject({
      publicNetworkAccess: "Disabled",
      exposure: "private",
      vnetIntegration: { subnetIds: [lc(F.SNET_APP)], mode: "injection" },
    });
    expect(byName("aks-public")).toMatchObject({ publicNetworkAccess: "Enabled", exposure: "public" });
  });

  it("treats a delegated PostgreSQL flexible server as private (VNet injection)", () => {
    expect(byName("pg1")).toMatchObject({
      publicNetworkAccess: "Disabled",
      exposure: "private",
      vnetIntegration: { subnetIds: [lc(F.SNET_APP)], mode: "injection" },
    });
  });

  it("derives the Cosmos DB firewall from its IP rules", () => {
    expect(byName("cosmos1")).toMatchObject({
      endpoints: ["cosmos1.documents.azure.com"],
      firewall: { defaultAction: "Deny", ipRules: ["198.51.100.7"] },
      exposure: "restricted",
    });
  });

  it("marks firewall rules as not readable when the ARM enrichment is missing", () => {
    const raw = rawWithPaas();
    delete raw.enrichment;
    const sql = normalizeInventory(raw).paasServices.find((s) => s.name === "sql1")!;
    expect(sql.firewall.source).toBe("none");
    expect(sql.exposure).toBe("unknown");
  });

  it("adds PaaS nodes to the graph, connected to private endpoints and subnets", () => {
    const g = buildGraph(inv);
    const sqlNode = g.nodes.find((n) => n.id === lc(F.SQL))!;
    expect(sqlNode.type).toBe("paasService");
    expect(
      g.edges.some((e) => e.type === "privateEndpoint" && e.source === lc(F.PE) && e.target === lc(F.SQL)),
    ).toBe(true);
    expect(
      g.edges.some((e) => e.type === "attached" && e.source === lc(WEB) && e.target === lc(F.SNET_APP)),
    ).toBe(true);
    expect(
      g.edges.some(
        (e) => e.type === "connectedTo" && e.source === lc(F.SNET_APP) && e.target === lc(STORAGE),
      ),
    ).toBe(true);
    // The PE target is no longer an "external resource" placeholder.
    expect(g.nodes.some((n) => n.id === lc(F.SQL) && n.type === "externalResource")).toBe(false);
  });
});
