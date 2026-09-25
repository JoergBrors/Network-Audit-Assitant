import ELK from "elkjs/lib/elk-api.js";
// ELK's own worker script, served as a static asset and started as a classic Web Worker.
// (Bundling elk.bundled.js into a custom worker does not work: in a worker scope ELK registers
// itself as message dispatcher and posts its results to the main thread, bypassing the caller.)
import elkWorkerUrl from "elkjs/lib/elk-worker.min.js?url";
import type { VisibleGraph } from "../../graph/view.js";
import { flattenLayout, toElkGraph, type ElkOutputNode, type Positioned } from "./elkGraph.js";

export const LAYOUT_TIMEOUT_MS = 60_000;

/**
 * Layout in a Web Worker with a small result cache. The cache key only contains structure
 * (visible nodes, containers, edges), so selection or hover never triggers a new layout.
 */
export class LayoutClient {
  private elk: InstanceType<typeof ELK> | undefined;
  private readonly cache = new Map<string, Map<string, Positioned>>();

  static key(view: VisibleGraph): string {
    const nodes = view.nodes.map((n) => `${n.node.id}<${n.containerId ?? ""}`).join("|");
    const edges = view.edges.map((e) => e.id).join("|");
    return `${nodes}#${edges}`;
  }

  async layout(view: VisibleGraph): Promise<Map<string, Positioned>> {
    const key = LayoutClient.key(view);
    const cached = this.cache.get(key);
    if (cached) return cached;
    this.elk ??= new ELK({ workerUrl: elkWorkerUrl });
    const graph = toElkGraph(view) as Parameters<InstanceType<typeof ELK>["layout"]>[0];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Layout nach ${LAYOUT_TIMEOUT_MS / 1000} s abgebrochen`)),
        LAYOUT_TIMEOUT_MS,
      );
    });
    try {
      const result = (await Promise.race([this.elk.layout(graph), timeout])) as ElkOutputNode;
      const positions = flattenLayout(result);
      if (this.cache.size > 30) this.cache.delete(this.cache.keys().next().value!);
      this.cache.set(key, positions);
      return positions;
    } finally {
      clearTimeout(timer);
    }
  }

  dispose(): void {
    this.elk?.terminateWorker();
    this.elk = undefined;
  }
}
