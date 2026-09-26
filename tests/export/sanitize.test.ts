import { describe, expect, it } from "vitest";
import { buildAssessmentExport } from "../../src/export/assessmentJson.js";
import { sanitizeExport, sanitizedFileName } from "../../src/export/sanitize.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

describe("sanitizeExport", () => {
  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });

  it("uses the required file name pattern", () => {
    expect(sanitizedFileName(new Date(2026, 8, 25, 14, 7))).toBe(
      "azure-network-assessment-sanitized-20260925-1407.json",
    );
  });

  // Azure-mandated literal subnet names carry no tenant-identifying information and are kept as-is.
  const PLATFORM_RESERVED = new Set([
    "gatewaysubnet",
    "azurefirewallsubnet",
    "azurefirewallmanagementsubnet",
    "azurebastionsubnet",
    "routeserversubnet",
  ]);

  it("removes real subscription IDs and resource names from IDs, keeps resource types", async () => {
    const { export: out } = await sanitizeExport(doc, { key: "test-key" });
    const json = JSON.stringify(out);
    for (const sub of doc.snapshotMetadata.subscriptionIds) expect(json).not.toContain(sub);
    for (const vnet of doc.vnets) expect(json).not.toContain(vnet.name);
    for (const subnet of doc.subnets)
      if (!PLATFORM_RESERVED.has(subnet.name.toLowerCase())) expect(json).not.toContain(subnet.name);
    expect(json).toContain("microsoft.network/virtualnetworks");
    expect(out.metadata.sanitized).toBe(true);
  });

  it("keeps Azure-mandated platform subnet names (not tenant-identifying)", async () => {
    const { export: out } = await sanitizeExport(doc, { key: "test-key" });
    expect(JSON.stringify(out)).toContain("AzureFirewallSubnet");
  });

  it("also scrubs real names embedded in compound graph-edge IDs and free-text hop reasons", async () => {
    const { export: out } = await sanitizeExport(doc, { key: "test-key" });
    const json = JSON.stringify(out);
    // peering/route/securedBy/natThrough edge IDs join two full resource IDs with "->": a bug that
    // only scrubs top-level id/name fields would leave the real names inside these compound strings.
    const edgeIdJoins = out.graph.edges.filter((e) => e.id.includes("->"));
    expect(edgeIdJoins.length).toBeGreaterThan(0);
    for (const vnet of doc.vnets) expect(json).not.toContain(vnet.name);
    // ipv4DefaultPaths[].firstHop / vnet / subnet are free text and denormalized name fields, not
    // ARM resource IDs, so they only get scrubbed by the second (whole-word) pass.
    for (const path of doc.assessmentContext.ipv4DefaultPaths) {
      expect(json).not.toContain(path.vnet);
      expect(json).not.toContain(path.subnet);
    }
  });

  it("is deterministic for the same key", async () => {
    const a = await sanitizeExport(doc, { key: "same-key" });
    const b = await sanitizeExport(doc, { key: "same-key" });
    expect(a.export.vnets[0]?.id).toBe(b.export.vnets[0]?.id);
  });

  it("differs for a different key", async () => {
    const a = await sanitizeExport(doc, { key: "key-a" });
    const b = await sanitizeExport(doc, { key: "key-b" });
    expect(a.export.vnets[0]?.id).not.toBe(b.export.vnets[0]?.id);
  });

  it("preserves structural fields needed for IPv6/analysis (prefixes, counts, relationships)", async () => {
    const { export: out } = await sanitizeExport(doc, { key: "test-key" });
    expect(out.summary).toEqual(doc.summary);
    expect(out.addressing.ipv4.vnetAddressSpaces.map((v) => v.prefix)).toEqual(
      doc.addressing.ipv4.vnetAddressSpaces.map((v) => v.prefix),
    );
    expect(out.addressing.ipv6.vnetAddressSpaces.map((v) => v.prefix)).toEqual(
      doc.addressing.ipv6.vnetAddressSpaces.map((v) => v.prefix),
    );
    expect(out.graph.edges.length).toBe(doc.graph.edges.length);
    expect(out.assessmentContext.architectureType).toBe(doc.assessmentContext.architectureType);
  });

  it("replaces real public IPs with RFC 5737/3849 documentation addresses", async () => {
    const withPip = {
      ...doc,
      publicIps: [...doc.publicIps, { id: "/subscriptions/x/resourceGroups/y/pip1", ipAddress: "20.1.2.3" }],
    };
    const { export: out, stats } = await sanitizeExport(withPip as never, { key: "test-key" });
    const json = JSON.stringify(out);
    expect(json).not.toContain("20.1.2.3");
    expect(stats.publicIpsReplaced).toBeGreaterThan(0);
    expect(json).toMatch(/198\.51\.\d+\.\d+/);
  });

  it("removes fields that look like secrets regardless of value", async () => {
    const withSecret = { ...doc, extra: { sharedKey: "supersecret", apiKey: "abc" } };
    const { export: out } = await sanitizeExport(withSecret, { key: "test-key" });
    expect(JSON.stringify(out)).not.toContain("supersecret");
  });
});
