import { describe, expect, it } from "vitest";
import {
  assessmentFileName,
  buildAssessmentExport,
  parseAssessmentExport,
  SnapshotImportError,
} from "../../src/export/assessmentJson.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

describe("assessment JSON export", () => {
  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });

  it("uses the required file name pattern", () => {
    expect(assessmentFileName(new Date(2026, 8, 25, 14, 7))).toBe(
      "azure-network-assessment-20260925-1407.json",
    );
  });

  it("contains the documented top-level sections", () => {
    expect(Object.keys(doc)).toEqual(
      expect.arrayContaining([
        "metadata",
        "snapshotMetadata",
        "summary",
        "assessmentContext",
        "addressing",
        "subscriptions",
        "vnets",
        "subnets",
        "peerings",
        "routeTables",
        "routes",
        "firewalls",
        "firewallPolicies",
        "nsgs",
        "natGateways",
        "publicIps",
        "publicIpPrefixes",
        "networkInterfaces",
        "loadBalancers",
        "applicationGateways",
        "vpnGateways",
        "privateEndpoints",
        "unclassifiedNetworkResources",
        "graph",
      ]),
    );
    expect(doc.metadata.coverage.routingAnalysis).toBe("not-yet-implemented");
  });

  it("describes the architecture for AI consumers", () => {
    expect(doc.assessmentContext).toMatchObject({
      architectureType: "hub-spoke",
      regions: ["westeurope"],
      networkCharacteristics: { ipv4: true, ipv6: true, dualStack: true },
      centralServices: { firewall: true, natGateway: true, vpnGateway: true, expressRoute: false },
    });
    expect(doc.assessmentContext.identifiedHubs.map((h) => h.name)).toEqual(["vnet-hub"]);
    expect(doc.addressing.ipv6.vnetAddressSpaces.map((a) => a.prefix)).toEqual([
      "fd00:10::/48",
      "fd00:11::/48",
    ]);
    expect(doc.summary).toMatchObject({ vnets: 3, dualStackVnets: 2, ipv4OnlyVnets: 1, hubs: 1, spokes: 1 });
  });

  it("round-trips through import (offline snapshot)", () => {
    const imported = parseAssessmentExport(JSON.stringify(doc));
    expect(imported.graph).toEqual(model.graph);
    expect(imported.inventory.vnets).toEqual(model.inventory.vnets);
    expect(imported.discovery).toEqual(model.discovery);
  });

  it("rejects foreign or broken files", () => {
    expect(() => parseAssessmentExport("{")).toThrow(SnapshotImportError);
    expect(() => parseAssessmentExport(JSON.stringify({ metadata: { tool: "other" } }))).toThrow(
      SnapshotImportError,
    );
  });

  it("exports a compact graph without redundant hierarchy edges and route nodes", () => {
    expect(doc.graph.edges.some((e) => e.type === "contains")).toBe(false);
    expect(doc.graph.nodes.some((n) => n.type === "route")).toBe(false);
    const ids = new Set(doc.graph.nodes.map((n) => n.id));
    for (const e of doc.graph.edges) expect(ids.has(e.source) && ids.has(e.target), e.id).toBe(true);
    const routeEdge = doc.graph.edges.find(
      (e) => e.type === "route" && e.properties["route"] === "default-v4",
    );
    expect(routeEdge?.source).toBe(F.RT_SPOKE.toLowerCase());
  });

  it("contains no raw ARM payload fields", () => {
    const json = JSON.stringify(doc);
    expect(json).not.toContain("provisioningState");
    expect(json).not.toContain("resourceGuid");
  });
});
