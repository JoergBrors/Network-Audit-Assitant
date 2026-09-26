import { describe, expect, it } from "vitest";
import { crossSubscriptionDependencies } from "../../src/routing/dependencies.js";
import { analyzeDefaultPaths } from "../../src/routing/analysis.js";
import { analyzeInbound } from "../../src/routing/inbound.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc } from "./helpers.js";

describe("cross-subscription dependencies", () => {
  it("groups resources outside the source subscription and ignores synthetic nodes", () => {
    const deps = crossSubscriptionDependencies(
      lc(F.SNET_APP),
      [{ nodeId: lc(F.SNET_APP) }, { nodeId: "internet:ipv4" }, { nodeId: lc(F.HUB) }, { nodeId: undefined }],
      [lc(F.FW), lc(F.FW), lc(F.RT_SPOKE)],
    );
    expect(deps).toEqual([{ subscriptionId: F.SUB_CONN, resourceIds: [lc(F.FW), lc(F.HUB)].sort() }]);
  });

  it("marks the spoke's Internet path as depending on the hub subscription's firewall", () => {
    const ctx = ctxFor();
    const path = analyzeDefaultPaths(ctx.inv, ctx).find(
      (p) => p.subnetId === lc(F.SNET_APP) && p.family === "ipv4",
    )!;
    expect(path.subscriptionId).toBe(F.SUB_APP);
    expect(path.dependencies.map((d) => d.subscriptionId)).toEqual([F.SUB_CONN]);
    expect(path.dependencies[0]!.resourceIds).toContain(lc(F.FW));
  });

  it("records the target subscription of inbound exposures", () => {
    const [e] = analyzeInbound(ctxFor());
    expect(e!.subscriptionId).toBe(F.SUB_APP);
    expect(e!.dependencies).toEqual([]);
  });
});
