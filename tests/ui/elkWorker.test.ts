import { readFileSync } from "node:fs";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import { computeVisibleGraph, indexGraph } from "../../src/graph/view.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import { flattenLayout, toElkGraph, type ElkOutputNode } from "../../src/ui/graph/elkGraph.js";
import * as F from "../fixtures/hubSpoke.js";

/**
 * Regression test for the layout worker: the UI starts ELK's own worker script as a classic Web
 * Worker and talks to it via elk-api. Here the script runs in a simulated worker global scope
 * (self === globalThis, no document) and must answer layout requests via self.postMessage.
 */
describe("ELK worker protocol", () => {
  it("answers register and layout commands from a worker scope", () => {
    const messages: { id: number; data?: ElkOutputNode; error?: unknown }[] = [];
    const scope: Record<string, unknown> = {
      postMessage: (m: never) => messages.push(m),
      setTimeout,
      clearTimeout,
      console,
    };
    scope["self"] = scope;
    vm.runInContext(
      readFileSync("node_modules/elkjs/lib/elk-worker.min.js", "utf8"),
      vm.createContext(scope),
    );
    const onmessage = scope["onmessage"] as (e: { data: unknown }) => void;
    expect(typeof onmessage).toBe("function");

    const view = computeVisibleGraph(indexGraph(analyzeInventory(F.hubSpokeRaw()).graph), {
      level: 3,
      expanded: new Set(),
      ipMode: "all",
    });
    onmessage({ data: { id: 0, cmd: "register", algorithms: ["layered", "rectpacking"] } });
    onmessage({
      data: {
        id: 1,
        cmd: "layout",
        graph: structuredClone(toElkGraph(view)),
        layoutOptions: {},
        options: {},
      },
    });

    const response = messages.find((m) => m.id === 1);
    expect(response?.error).toBeUndefined();
    const positions = flattenLayout(response!.data!);
    for (const n of view.nodes) expect(positions.has(n.node.id), n.node.id).toBe(true);
  });
});
