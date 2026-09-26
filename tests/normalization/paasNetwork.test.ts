import { describe, expect, it } from "vitest";
import { assessServices } from "../../src/assessment/index.js";
import { buildGraph } from "../../src/graph/buildGraph.js";
import type { RawInventory } from "../../src/models/discovery.js";
import { normalizeInventory } from "../../src/normalization/normalize.js";
import * as F from "../fixtures/hubSpoke.js";

const lc = (s: string) => s.toLowerCase();
const rid = (rg: string, provider: string, name: string) =>
  `/subscriptions/${F.SUB_APP}/resourceGroups/${rg}/providers/${provider}/${name}`;

const WEB = rid("rg-app", "Microsoft.Web/sites", "app1");
const ENV = rid("rg-aca", "Microsoft.App/managedEnvironments", "cae-int");
const ENV_CONS = rid("rg-aca", "Microsoft.App/managedEnvironments", "cae-cons");
const APP = rid("rg-aca", "Microsoft.App/containerApps", "ca-api");
const APP_PUBLIC = rid("rg-aca", "Microsoft.App/containerApps", "ca-web");
const AKS = rid("rg-aks", "Microsoft.ContainerService/managedClusters", "aks1");
const NODE_RG = "MC_rg-aks_aks1_westeurope";
const AKS_LB = `/subscriptions/${F.SUB_APP}/resourceGroups/${NODE_RG}/providers/Microsoft.Network/loadBalancers/kubernetes`;
const AKS_PIP_IN = `/subscriptions/${F.SUB_APP}/resourceGroups/${NODE_RG}/providers/Microsoft.Network/publicIPAddresses/kubernetes-svc`;
const AKS_PIP_OUT = `/subscriptions/${F.SUB_APP}/resourceGroups/${NODE_RG}/providers/Microsoft.Network/publicIPAddresses/outbound`;
const POOL = rid("rg-avd", "Microsoft.DesktopVirtualization/hostPools", "hp1");
const SB = rid("rg-app", "Microsoft.ServiceBus/namespaces", "sb1");
const LAW = rid("rg-mon", "Microsoft.OperationalInsights/workspaces", "law1");
const FABRIC = rid("rg-fab", "Microsoft.Fabric/capacities", "fab1");

function scenario(): RawInventory {
  const raw = F.hubSpokeRaw();
  raw.resources["Q-PAAS"] = [
    F.res(WEB, "microsoft.web/sites", {
      defaultHostName: "app1.azurewebsites.net",
      virtualNetworkSubnetId: F.SNET_APP,
      outboundVnetRouting: { allTraffic: false },
      possibleOutboundIpAddresses: "203.0.113.1,203.0.113.2",
    }),
    F.res(ENV, "microsoft.app/managedenvironments", {
      vnetConfiguration: { infrastructureSubnetId: F.SNET_APP, internal: true },
      workloadProfiles: [{ name: "Consumption", workloadProfileType: "Consumption" }],
      staticIp: "10.1.1.200",
    }),
    F.res(ENV_CONS, "microsoft.app/managedenvironments", {
      vnetConfiguration: { infrastructureSubnetId: F.SNET_APP, internal: false },
      staticIp: "20.0.0.1",
    }),
    F.res(APP, "microsoft.app/containerapps", {
      managedEnvironmentId: ENV,
      outboundIpAddresses: ["20.1.1.1"],
      configuration: { ingress: { external: true, targetPort: 8080, transport: "http" } },
    }),
    F.res(APP_PUBLIC, "microsoft.app/containerapps", {
      managedEnvironmentId: ENV_CONS,
      configuration: {
        ingress: {
          external: true,
          allowInsecure: true,
          ipSecurityRestrictions: [{ name: "office", ipAddressRange: "198.51.100.0/24", action: "Allow" }],
        },
      },
    }),
    F.res(AKS, "microsoft.containerservice/managedclusters", {
      fqdn: "aks1.hcp.westeurope.azmk8s.io",
      nodeResourceGroup: NODE_RG,
      agentPoolProfiles: [{ name: "sys", vnetSubnetID: F.SNET_APP }],
      apiServerAccessProfile: { authorizedIPRanges: ["198.51.100.0/24"] },
      networkProfile: {
        networkPlugin: "azure",
        networkPluginMode: "overlay",
        outboundType: "loadBalancer",
        loadBalancerProfile: { effectiveOutboundIPs: [{ id: AKS_PIP_OUT }] },
      },
      ingressProfile: {
        webAppRouting: { enabled: true, nginx: { defaultIngressControllerType: "External" } },
      },
    }),
    F.res(POOL, "microsoft.desktopvirtualization/hostpools", {
      hostPoolType: "Pooled",
      publicNetworkAccess: "EnabledForClientsOnly",
    }),
    F.res(SB, "microsoft.servicebus/namespaces", {
      serviceBusEndpoint: "https://sb1.servicebus.windows.net:443/",
    }),
    F.res(LAW, "microsoft.operationalinsights/workspaces", {
      publicNetworkAccessForIngestion: "Enabled",
      publicNetworkAccessForQuery: "Disabled",
    }),
    F.res(FABRIC, "microsoft.fabric/capacities", { state: "Active" }),
  ];
  raw.resources["Q-NET-LB"] = [
    F.res(
      AKS_LB,
      "microsoft.network/loadbalancers",
      {
        frontendIPConfigurations: [
          { name: "A1b2", properties: { publicIPAddress: { id: AKS_PIP_IN } } },
          { name: "outbound", properties: { publicIPAddress: { id: AKS_PIP_OUT } } },
        ],
        loadBalancingRules: [
          {
            name: "svc-80",
            properties: {
              frontendIPConfiguration: { id: `${AKS_LB}/frontendIPConfigurations/A1b2` },
              protocol: "Tcp",
              frontendPort: 80,
            },
          },
        ],
      },
      { sku: { name: "Standard" } },
    ),
  ];
  raw.resources["Q-NET-PIP"]!.push(
    F.res(AKS_PIP_IN, "microsoft.network/publicipaddresses", { ipAddress: "20.50.0.1" }),
    F.res(AKS_PIP_OUT, "microsoft.network/publicipaddresses", { ipAddress: "20.50.0.2" }),
  );
  raw.enrichment = {
    virtualHubs: {},
    results: [],
    paasNetworkRules: {
      [lc(WEB)]: {
        firewallRules: [],
        virtualNetworkRules: [],
        // "Web Apps - Get Configuration": named after the app, identified by …/config/web.
        siteConfig: [
          {
            id: `${WEB}/config/web`,
            name: "app1",
            properties: {
              ipSecurityRestrictions: [
                { ipAddress: "198.51.100.1/32", action: "Allow", priority: 100, name: "office" },
                { ipAddress: "Any", action: "Deny", priority: 2147483647 },
              ],
              scmIpSecurityRestrictions: [{ ipAddress: "Any", action: "Allow", priority: 2147483647 }],
              scmIpSecurityRestrictionsUseMain: false,
              minTlsVersion: "1.2",
            },
          },
        ],
        status: "ok",
      },
      [lc(POOL)]: {
        firewallRules: [],
        virtualNetworkRules: [],
        siteConfig: [],
        extra: { sessionHosts: [{ properties: { resourceId: F.VM } }] },
        status: "ok",
      },
      [lc(SB)]: {
        firewallRules: [],
        virtualNetworkRules: [],
        siteConfig: [],
        extra: {
          networkRuleSet: [
            {
              properties: {
                defaultAction: "Deny",
                ipRules: [{ ipMask: "198.51.100.5", action: "Allow" }],
                virtualNetworkRules: [{ subnet: { id: F.SNET_APP } }],
              },
            },
          ],
        },
        status: "ok",
      },
    },
  };
  return raw;
}

describe("PaaS ingress/egress profiles", () => {
  const inv = normalizeInventory(scenario());
  const svc = (id: string) => inv.paasServices.find((s) => s.id === lc(id))!;
  const findings = assessServices(inv).findings;
  const codes = (id: string) => findings.filter((f) => f.resourceIds[0] === lc(id)).map((f) => f.code);

  it("reads App Service main and SCM restrictions from config/web and flags the open SCM site", () => {
    const web = svc(WEB);
    expect(web.firewall).toMatchObject({
      source: "arm",
      defaultAction: "Deny",
      ipRules: ["198.51.100.1/32"],
    });
    expect(web.ingress!.rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "198.51.100.1/32", action: "Allow", priority: 100 }),
        expect.objectContaining({ source: "Any", action: "Allow", scope: "SCM/Kudu" }),
      ]),
    );
    expect(web.egress).toMatchObject({ mode: "vnet-partial", subnetIds: [lc(F.SNET_APP)] });
    expect(codes(WEB)).toEqual(expect.arrayContaining(["WEB_SCM_UNRESTRICTED", "WEB_EGRESS_NOT_ROUTED"]));
  });

  it("treats external ingress in an internal Container Apps environment as VNet-only", () => {
    const app = svc(APP);
    expect(app.ingress).toMatchObject({ mode: "vnet" });
    expect(app.publicNetworkAccess).toBe("Disabled");
    expect(app.exposure).toBe("private");
    expect(app.egress).toMatchObject({ mode: "vnet", subnetIds: [lc(F.SNET_APP)] });
    expect(svc(ENV).ingress).toMatchObject({ mode: "vnet", ips: ["10.1.1.200"] });
    expect(svc(ENV).links).toEqual([{ id: lc(APP), label: "Container App", direction: "other" }]);
  });

  it("reads container app IP restrictions and consumption-only egress", () => {
    const app = svc(APP_PUBLIC);
    expect(app.ingress).toMatchObject({
      mode: "internet-restricted",
      rules: [{ name: "office", source: "198.51.100.0/24", action: "Allow" }],
    });
    expect(app.exposure).toBe("restricted");
    expect(svc(ENV_CONS).egress!.mode).toBe("azure-default");
    expect(codes(ENV_CONS)).toContain("ACA_EGRESS_NOT_CONTROLLABLE");
    expect(codes(APP_PUBLIC)).toContain("ACA_INSECURE_HTTP");
  });

  it("links AKS to its node resource group load balancer and outbound IPs", () => {
    const aks = svc(AKS);
    expect(aks.ingress).toMatchObject({
      mode: "internet",
      ips: ["20.50.0.1"],
      rules: [{ source: "198.51.100.0/24", action: "Allow", scope: "API-Server" }],
    });
    expect(aks.ingress!.details["App Routing (verwaltetes NGINX)"]).toBe(
      "aktiv · Standard-Controller: External",
    );
    expect(aks.egress).toMatchObject({ mode: "load-balancer", outboundIps: ["20.50.0.2"] });
    expect(aks.egress!.details["Netzwerk-Plugin"]).toBe("azure / overlay");
    expect(aks.links).toEqual(
      expect.arrayContaining([{ id: lc(AKS_LB), label: "Load Balancer (öffentlich)", direction: "ingress" }]),
    );
    expect(codes(AKS)).toEqual(
      expect.arrayContaining(["AKS_PUBLIC_WORKLOAD_INGRESS", "AKS_EGRESS_NOT_CONTROLLED"]),
    );
    // The graph draws the link to the load balancer.
    expect(buildGraph(inv).edges.some((e) => e.source === lc(AKS) && e.target === lc(AKS_LB))).toBe(true);
  });

  it("resolves AVD session hosts to their subnets", () => {
    const pool = svc(POOL);
    expect(pool.publicNetworkAccess).toBe("Enabled");
    expect(pool.ingress!.details["Session Hosts über Internet"]).toBe("nein");
    expect(pool.egress).toMatchObject({ mode: "vnet", subnetIds: [lc(F.SNET_APP)] });
    expect(pool.links).toEqual([{ id: lc(F.VM), label: "Session Host", direction: "egress" }]);
  });

  it("reads the Service Bus network rule set", () => {
    expect(svc(SB).firewall).toMatchObject({
      source: "arm",
      defaultAction: "Deny",
      ipRules: ["198.51.100.5"],
      subnetIds: [lc(F.SNET_APP)],
    });
    expect(svc(SB).exposure).toBe("restricted");
  });

  it("rates public monitoring ingestion low and explains Fabric's tenant-level network settings", () => {
    expect(svc(LAW).exposure).toBe("public");
    expect(
      findings.find((f) => f.resourceIds[0] === lc(LAW) && f.code === "PAAS_PUBLIC_OPEN")!.severity,
    ).toBe("LOW");
    expect(svc(FABRIC).ingress!.summary).toContain("Admin-Portal");
  });
});
