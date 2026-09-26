import { describe, expect, it } from "vitest";
import type { TokenCredential } from "@azure/core-auth";
import { referencedServiceTags, runEnrichment } from "../../src/azure/arm/enrichment.js";
import type { ArmReader } from "../../src/azure/arm/armReader.js";
import * as F from "../fixtures/hubSpoke.js";
import { memoryLogger, restError } from "../helpers/fakes.js";

const VHUB = F.net(F.SUB_CONN, "rg-wan", "virtualHubs", "vhub-weu");
const credential: TokenCredential = { getToken: () => Promise.reject(new Error("not used")) };

function rawWithHub() {
  const raw = F.hubSpokeRaw();
  raw.resources["Q-VWAN"] = [
    F.res(VHUB, "microsoft.network/virtualhubs", {
      virtualWan: { id: "/subscriptions/x/vwan" },
      addressPrefix: "10.100.0.0/23",
    }),
    // Route Server hubs have no virtualWan reference and are skipped.
    F.res(F.net(F.SUB_CONN, "rg-wan", "virtualHubs", "routeserver"), "microsoft.network/virtualhubs", {}),
  ];
  return raw;
}

describe("ARM enrichment (phase 5)", () => {
  it("collects referenced service tags but not built-in tags or addresses", () => {
    expect(referencedServiceTags(F.hubSpokeRaw())).toEqual(["Storage"]);
  });

  it("reads hub details and service tags (`values` key) via GET only, filtered to referenced tags", async () => {
    const calls: { path: string; itemsKey: string | undefined }[] = [];
    const reader: ArmReader = {
      list: (path, _api, itemsKey) => {
        calls.push({ path, itemsKey });
        if (path.endsWith("/serviceTags"))
          return Promise.resolve([
            { name: "Storage", properties: { addressPrefixes: ["20.60.0.0/16"] } },
            { name: "AzureCloud", properties: { addressPrefixes: ["20.0.0.0/8"] } },
          ]);
        if (path.endsWith("/hubVirtualNetworkConnections")) return Promise.resolve([{ name: "conn" }]);
        return Promise.resolve([]);
      },
    };
    const { enrichment, warnings } = await runEnrichment({
      raw: rawWithHub(),
      credential,
      logger: memoryLogger().logger,
      readerFactory: () => reader,
    });
    expect(warnings).toEqual([]);
    expect(Object.keys(enrichment.virtualHubs)).toEqual([VHUB.toLowerCase()]);
    expect(enrichment.virtualHubs[VHUB.toLowerCase()]).toMatchObject({
      status: "ok",
      connections: [{ name: "conn" }],
    });
    expect(enrichment.serviceTags).toEqual({
      location: "westeurope",
      tags: [{ name: "Storage", prefixes: ["20.60.0.0/16"] }],
    });
    expect(calls.find((c) => c.path.endsWith("/serviceTags"))!.itemsKey).toBe("values");
    expect(calls).toHaveLength(4);
  });

  it("isolates 403s per call and reports them as warnings", async () => {
    const reader: ArmReader = {
      list: (path) =>
        path.endsWith("/routingIntent")
          ? Promise.reject(restError(403, "AuthorizationFailed"))
          : Promise.resolve([]),
    };
    const { enrichment, warnings } = await runEnrichment({
      raw: rawWithHub(),
      credential,
      logger: memoryLogger().logger,
      readerFactory: () => reader,
    });
    expect(enrichment.virtualHubs[VHUB.toLowerCase()]!.status).toBe("partial");
    expect(warnings).toEqual([
      expect.objectContaining({ operation: "ARM:RoutingIntent.list", reason: "InsufficientPermissions" }),
    ]);
    expect(enrichment.results.find((r) => r.operation === "RoutingIntent.list")!.status).toBe("forbidden");
    expect(enrichment.serviceTags?.tags).toEqual([]);
  });

  it("reads PaaS network rules via GET for SQL and App Service, skipping private-only services", async () => {
    const raw = F.hubSpokeRaw();
    const sql = F.SQL;
    const web = F.net(F.SUB_APP, "rg-app", "sites", "app1").replace("Microsoft.Network", "Microsoft.Web");
    const privateSql = sql.replace("sql1", "sql-private");
    raw.resources["Q-PAAS"] = [
      F.res(sql, "microsoft.sql/servers", { publicNetworkAccess: "Enabled" }),
      F.res(privateSql, "microsoft.sql/servers", { publicNetworkAccess: "Disabled" }),
      F.res(web, "microsoft.web/sites", {}),
    ];
    const calls: { path: string; api: string }[] = [];
    const reader: ArmReader = {
      list: (path, api) => {
        calls.push({ path, api });
        if (path.endsWith("/firewallRules"))
          return Promise.resolve([{ properties: { startIpAddress: "0.0.0.0", endIpAddress: "0.0.0.0" } }]);
        if (path.endsWith("/virtualNetworkRules"))
          return Promise.reject(restError(403, "AuthorizationFailed"));
        if (path.endsWith("/config")) return Promise.resolve([{ name: "web", properties: {} }]);
        return Promise.resolve([]);
      },
    };
    const { enrichment } = await runEnrichment({
      raw,
      credential,
      logger: memoryLogger().logger,
      readerFactory: () => reader,
    });
    const rules = enrichment.paasNetworkRules!;
    expect(Object.keys(rules).sort()).toEqual([sql.toLowerCase(), web.toLowerCase()].sort());
    expect(rules[sql.toLowerCase()]).toMatchObject({ status: "partial", firewallRules: [expect.anything()] });
    expect(rules[web.toLowerCase()]).toMatchObject({
      status: "ok",
      siteConfig: [{ name: "web", properties: {} }],
    });
    expect(calls.find((c) => c.path === `${sql}/firewallRules`)!.api).toBe("2021-11-01");
    expect(calls.find((c) => c.path === `${web}/config`)!.api).toBe("2023-12-01");
    expect(calls.some((c) => c.path.startsWith(privateSql))).toBe(false);
  });
});
