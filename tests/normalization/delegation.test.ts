import { describe, expect, it } from "vitest";
import { assessServices } from "../../src/assessment/index.js";
import { buildGraph } from "../../src/graph/buildGraph.js";
import type { RawInventory, RawResource } from "../../src/models/discovery.js";
import type { GraphNode } from "../../src/models/graph.js";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import { nodeAbbreviation, nodeCategory } from "../../src/ui/graph/nodeStyle.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const rid = (rg: string, provider: string, name: string) =>
  `/subscriptions/${F.SUB_APP}/resourceGroups/${rg}/providers/${provider}/${name}`;

const PLAN = rid("rg-web", "Microsoft.Web/serverfarms", "asp1");
const APP = rid("rg-web", "Microsoft.Web/sites", "func1");
const AGC = rid("rg-aks", "Microsoft.ServiceNetworking/trafficControllers", "agc1");
const POOL = rid("rg-devops", "Microsoft.DevOpsInfrastructure/pools", "mdp1");
const FABRIC = rid("rg-fab", "Microsoft.Fabric/capacities", "fab1");
const FABRIC_PL = rid("rg-fab", "Microsoft.Fabric/privateLinkServicesForFabric", "tenant-pl");
const FOREIGN_PLAN =
  "/subscriptions/99999999-9999-9999-9999-999999999999/resourceGroups/rg-x/providers/Microsoft.Web/serverfarms/asp-foreign";
const SNET_INT = `${F.SPOKE}/subnets/snet-integration`;
const SNET_AGC = `${F.SPOKE}/subnets/snet-agc`;
const SNET_FOREIGN = `${F.SPOKE}/subnets/snet-foreign`;
const SNET_EMPTY = `${F.SPOKE}/subnets/snet-empty`;
const SNET_POOL = `${F.SPOKE}/subnets/snet-devops`;

const delegation = (service: string) => ({
  delegations: [{ name: "d", properties: { serviceName: service } }],
});
const sal = (type: string, link: string) => ({
  serviceAssociationLinks: [{ name: "AppServiceLink", properties: { linkedResourceType: type, link } }],
});

function scenario(withFabricPrivateLink: boolean): RawInventory {
  const raw = F.hubSpokeRaw();
  const spoke = raw.resources["Q-NET-VNET"]!.find((v) => v.id === F.SPOKE)!;
  (spoke.properties!["subnets"] as unknown[]).push(
    F.subnet(SNET_INT, ["10.1.2.0/27"], {
      ...delegation("Microsoft.Web/serverFarms"),
      ...sal("Microsoft.Web/serverfarms", PLAN),
    }),
    F.subnet(SNET_AGC, ["10.1.3.0/24"], delegation("Microsoft.ServiceNetworking/trafficControllers")),
    F.subnet(SNET_FOREIGN, ["10.1.4.0/27"], {
      ...delegation("Microsoft.Web/serverFarms"),
      ...sal("Microsoft.Web/serverfarms", FOREIGN_PLAN),
    }),
    F.subnet(SNET_EMPTY, ["10.1.5.0/27"], delegation("Microsoft.App/environments")),
    F.subnet(SNET_POOL, ["10.1.6.0/27"], delegation("Microsoft.DevOpsInfrastructure/pools")),
  );
  const rows: RawResource[] = [
    F.res(PLAN, "microsoft.web/serverfarms", { numberOfSites: 1 }, { kind: "linux", sku: { name: "P1v3" } }),
    F.res(
      APP,
      "microsoft.web/sites",
      { serverFarmId: PLAN, defaultHostName: "func1.azurewebsites.net" },
      { kind: "functionapp,linux" },
    ),
    F.res(AGC, "microsoft.servicenetworking/trafficcontrollers", {
      configurationEndpoints: ["abc.alb.azure.com"],
    }),
    F.res(`${AGC}/associations/assoc`, "microsoft.servicenetworking/trafficcontrollers/associations", {
      associationType: "subnets",
      subnet: { id: SNET_AGC },
    }),
    F.res(`${AGC}/frontends/fe`, "microsoft.servicenetworking/trafficcontrollers/frontends", {
      fqdn: "fe-1.alb.azure.com",
    }),
    F.res(POOL, "microsoft.devopsinfrastructure/pools", {
      maximumConcurrency: 4,
      fabricProfile: { networkProfile: { subnetId: SNET_POOL } },
    }),
    F.res(FABRIC, "microsoft.fabric/capacities", { state: "Active" }),
  ];
  if (withFabricPrivateLink) rows.push(F.res(FABRIC_PL, "microsoft.fabric/privatelinkservicesforfabric", {}));
  raw.resources["Q-PAAS"] = rows;
  raw.enrichment = {
    virtualHubs: {},
    results: [],
    paasNetworkRules: {
      // Classic VNet integration: only config/web knows the VNet name, the subnet comes from the plan.
      [lc(APP)]: {
        firewallRules: [],
        virtualNetworkRules: [],
        siteConfig: [
          {
            id: `${APP}/config/web`,
            name: "func1",
            properties: { vnetName: "abc_snet-integration", vnetRouteAllEnabled: true },
          },
        ],
        status: "ok",
      },
    },
  };
  return raw;
}

describe("subnet delegations and service links", () => {
  const inv = normalizeInventory(scenario(false));
  const svc = (id: string) => inv.paasServices.find((s) => s.id === lc(id))!;
  const findings = assessServices(inv).findings;

  it("reads service association links and assigns the delegated subnet to the App Service plan", () => {
    expect(inv.subnets.find((s) => s.id === lc(SNET_INT))!.serviceLinks).toEqual([
      {
        kind: "serviceAssociation",
        name: "AppServiceLink",
        linkedResourceType: "Microsoft.Web/serverfarms",
        linkId: lc(PLAN),
      },
    ]);
    const plan = svc(PLAN);
    expect(plan.exposure).toBe("none");
    expect(plan.vnetIntegration).toMatchObject({ subnetIds: [lc(SNET_INT)], mode: "integration" });
    expect(plan.links).toEqual(expect.arrayContaining([{ id: lc(APP), label: "App", direction: "other" }]));
  });

  it("derives a classic app VNet integration from the plan's subnet", () => {
    const app = svc(APP);
    expect(app.vnetIntegration).toMatchObject({
      subnetIds: [lc(SNET_INT)],
      mode: "integration",
      routeAll: true,
    });
    expect(app.egress).toMatchObject({ mode: "vnet", subnetIds: [lc(SNET_INT)] });
  });

  it("links Application Gateway for Containers to its subnet and frontends", () => {
    const agc = svc(AGC);
    expect(agc.ingress!.mode).toBe("internet");
    expect(agc.endpoints).toContain("fe-1.alb.azure.com");
    expect(agc.vnetIntegration.subnetIds).toEqual([lc(SNET_AGC)]);
    expect(svc(POOL)).toMatchObject({
      exposure: "none",
      egress: { mode: "vnet", subnetIds: [lc(SNET_POOL)] },
    });
  });

  it("reports delegation users missing from the inventory and unused delegations", () => {
    const byCode = (code: string) => findings.filter((f) => f.code === code).map((f) => f.resourceIds[0]);
    expect(byCode("DELEGATION_USER_NOT_DISCOVERED")).toEqual([lc(SNET_FOREIGN)]);
    expect(byCode("DELEGATION_UNUSED")).toEqual([lc(SNET_EMPTY)]);
  });

  it("treats Fabric without tenant Private Link as public and links an existing one", () => {
    expect(svc(FABRIC)).toMatchObject({ exposure: "public", ingress: { mode: "internet" } });
    const withLink = normalizeInventory(scenario(true)).paasServices.find((s) => s.id === lc(FABRIC))!;
    expect(withLink.ingress!.mode).toBe("unknown");
    expect(withLink.links).toEqual([
      { id: lc(FABRIC_PL), label: "Tenant-Private-Link", direction: "ingress" },
    ]);
  });

  it("gives PaaS nodes service-specific abbreviations and colour groups", () => {
    const node = (id: string) => buildGraph(inv).nodes.find((n) => n.id === lc(id))!;
    expect(nodeAbbreviation(node(APP))).toBe("FUNC");
    expect(nodeAbbreviation(node(PLAN))).toBe("ASP");
    expect(nodeAbbreviation(node(AGC))).toBe("AGC");
    expect(nodeCategory(node(APP))).toBe("app");
    expect(nodeCategory(node(FABRIC))).toBe("analytics");
    // Older exports carry only the service label.
    const legacy = {
      type: "paasService",
      properties: { service: "PostgreSQL Flexible Server" },
    } as unknown as GraphNode;
    expect(nodeAbbreviation(legacy)).toBe("PG");
    expect(nodeCategory(legacy)).toBe("data");
  });
});
