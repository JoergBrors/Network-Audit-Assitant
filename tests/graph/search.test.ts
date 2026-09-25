import { describe, expect, it } from "vitest";
import { indexGraph } from "../../src/graph/view.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import { searchNodes } from "../../src/ui/workspace/SearchBox.js";
import * as F from "../fixtures/hubSpoke.js";

const index = indexGraph(analyzeInventory(F.hubSpokeRaw()).graph);
const found = (q: string) => searchNodes(index, q).map((r) => r.node.name);

describe("global search", () => {
  it("finds the NIC/VM by exact IPv4 and the containing subnet and VNet", () => {
    const results = found("10.1.1.4");
    expect(results.slice(0, 2).sort()).toEqual(["nic-vm1", "vm1"]);
    expect(results).toEqual(expect.arrayContaining(["snet-app", "vnet-spoke"]));
    expect(results.indexOf("snet-app")).toBeLessThan(results.indexOf("vnet-spoke"));
  });

  it("finds IPv6 addresses inside prefixes", () => {
    expect(found("fd00:11:0:1::99")).toEqual(expect.arrayContaining(["snet-app", "vnet-spoke"]));
    expect(found("2001:db8::10")).toContain("pip-vm6");
  });

  it("finds by name and resource id", () => {
    expect(found("afw-hub")[0]).toBe("afw-hub");
    expect(found("rg-hub")).toContain("vnet-hub");
  });
});
