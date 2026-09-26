import { describe, expect, it } from "vitest";
import { analyzeInbound } from "../../../src/routing/inbound.js";
import { nicNsgsInSubnet, pathNodeIds } from "../../../src/ui/workspace/PathPanel.js";
import * as F from "../../fixtures/hubSpoke.js";
import { ctxFor, lc } from "../../routing/helpers.js";

describe("path panel helpers", () => {
  it("counts NIC-level NSGs only when the source is a subnet", () => {
    const ctx = ctxFor();
    expect(nicNsgsInSubnet(ctx, lc(F.SNET_APP))).toBe(0);
    ctx.inv.networkInterfaces.find((n) => n.id === lc(F.NIC_VM))!.nsgId = lc(F.NSG_SPOKE);
    expect(nicNsgsInSubnet(ctx, lc(F.SNET_APP))).toBe(1);
    expect(nicNsgsInSubnet(ctx, lc(F.VM))).toBe(0);
  });

  it("highlights inbound exposures including the allowing NSG", () => {
    const [e] = analyzeInbound(ctxFor());
    const ids = pathNodeIds(e!);
    expect(ids).toContain(lc(F.NSG_SPOKE));
    expect(ids.at(-1)).toBe(lc(F.VM));
  });
});
