import { afterEach, describe, expect, it, vi } from "vitest";
import {
  endSession,
  generateReport,
  resumeSession,
  sendChatMessage,
  startAnalysisSession,
} from "../../src/ai/analyze.js";
import { buildAssessmentExport } from "../../src/export/assessmentJson.js";
import { analyzeInventory } from "../../src/pipeline/analyze.js";
import * as F from "../fixtures/hubSpoke.js";

function stubBackend(onQuery: (body: Record<string, unknown>) => unknown) {
  return vi.fn().mockImplementation((url: string, init: RequestInit) => {
    if (init?.method === "DELETE") return { ok: true, json: async () => ({ deleted: true }) };
    if (init?.body instanceof FormData) return { ok: true, json: async () => ({ id: "file-abc" }) };
    if (url.includes("/vector_stores") && !url.includes("/files/") && init?.method === "POST")
      return { ok: true, json: async () => ({ id: "vs-abc" }) };
    if (url.includes("/files/file-abc")) return { ok: true, json: async () => ({ status: "completed" }) };
    if (url.includes("/responses")) {
      const body = JSON.parse(init.body as string) as Record<string, unknown>;
      return { ok: true, json: async () => onQuery(body) };
    }
    throw new Error(`unexpected request ${url}`);
  });
}

describe("startAnalysisSession", () => {
  afterEach(() => vi.unstubAllGlobals());

  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  it("uploads the sanitized export once, enables file_search, and stores the response/vector-store ids", async () => {
    let uploadedContent = "";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        if (init?.body instanceof FormData) {
          uploadedContent = String(await (init.body.get("file") as Blob).text());
          return { ok: true, json: async () => ({ id: "file-abc" }) };
        }
        if (url.includes("/vector_stores") && !url.includes("/files/") && init?.method === "POST")
          return { ok: true, json: async () => ({ id: "vs-abc" }) };
        if (url.includes("/files/file-abc")) return { ok: true, json: async () => ({ status: "completed" }) };
        if (url.includes("/responses")) return { ok: true, json: async () => ({ id: "resp_1", output_text: "Bereit." }) };
        throw new Error(`unexpected request ${url}`);
      }),
    );

    const session = await startAnalysisSession(doc, config, { key: "test-key" });

    expect(session.lastResponseId).toBe("resp_1");
    expect(session.doc).toEqual({ fileId: "file-abc", vectorStoreId: "vs-abc" });
    expect(session.messages).toEqual([{ role: "assistant", text: "Bereit." }]);
    expect(session.sanitizationStats.pseudonymizedTokens).toBeGreaterThan(0);
    for (const vnet of doc.vnets) expect(uploadedContent).not.toContain(vnet.name);
    for (const sub of doc.snapshotMetadata.subscriptionIds) expect(uploadedContent).not.toContain(sub);
  });

  it("assigns each session a unique local id (never sent to Azure OpenAI)", async () => {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));

    const a = await startAnalysisSession(doc, config, { key: "test-key" });
    const b = await startAnalysisSession(doc, config, { key: "test-key" });

    expect(a.id).toEqual(expect.any(String));
    expect(a.id).not.toBe(b.id);
  });

  it("reports sanitizing/uploading/indexing/ready phases in order", async () => {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));

    const phases: string[] = [];
    await startAnalysisSession(doc, config, { key: "test-key" }, { onProgress: (p) => phases.push(p) });

    expect(phases).toEqual(["sanitizing", "uploading", "indexing", "ready"]);
  });

  it("cleans up the uploaded file/vector store if the setup call fails", async () => {
    const deletedUrls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string, init: RequestInit) => {
        if (init?.method === "DELETE") {
          deletedUrls.push(url);
          return { ok: true, json: async () => ({ deleted: true }) };
        }
        if (init?.body instanceof FormData) return { ok: true, json: async () => ({ id: "file-abc" }) };
        if (url.includes("/vector_stores") && !url.includes("/files/") && init?.method === "POST")
          return { ok: true, json: async () => ({ id: "vs-abc" }) };
        if (url.includes("/files/file-abc")) return { ok: true, json: async () => ({ status: "completed" }) };
        if (url.includes("/responses"))
          return { ok: false, status: 400, headers: new Headers(), text: async () => "boom" };
        throw new Error(`unexpected request ${url}`);
      }),
    );

    await expect(startAnalysisSession(doc, config, { key: "test-key" })).rejects.toThrow();

    expect(deletedUrls.some((u) => u.includes("vs-abc"))).toBe(true);
    expect(deletedUrls.some((u) => u.includes("file-abc"))).toBe(true);
  });
});

describe("sendChatMessage", () => {
  afterEach(() => vi.unstubAllGlobals());

  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  it("chains via previous_response_id, keeps file_search enabled, and sends only the new message", async () => {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));
    const session = await startAnalysisSession(doc, config, { key: "test-key" });

    let sentBody: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init: RequestInit) => {
        sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
        return Promise.resolve({ ok: true, json: async () => ({ id: "resp_2", output_text: "Antwort." }) });
      }),
    );

    const updated = await sendChatMessage(session, "Welche Subnets haben ein IPv6-Leck?");

    expect(sentBody.previous_response_id).toBe("resp_1");
    expect(sentBody.input).toBe("Welche Subnets haben ein IPv6-Leck?");
    expect(sentBody.tools).toEqual([{ type: "file_search", vector_store_ids: ["vs-abc"] }]);
    expect(updated.lastResponseId).toBe("resp_2");
    expect(updated.messages).toEqual([
      { role: "assistant", text: "Bereit." },
      { role: "user", text: "Welche Subnets haben ein IPv6-Leck?" },
      { role: "assistant", text: "Antwort." },
    ]);
  });

  it("attaches a pasted image as vision input and records it on the user message for the transcript", async () => {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));
    const session = await startAnalysisSession(doc, config, { key: "test-key" });

    let sentBody: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init: RequestInit) => {
        sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
        return Promise.resolve({ ok: true, json: async () => ({ id: "resp_2", output_text: "Ich sehe das Bild." }) });
      }),
    );

    const dataUri = "data:image/png;base64,AAA=";
    const updated = await sendChatMessage(session, "Was zeigt der Screenshot?", {
      images: [{ dataUri }],
    });

    expect(sentBody.input).toEqual([
      {
        role: "user",
        content: [
          { type: "input_text", text: "Was zeigt der Screenshot?" },
          { type: "input_image", image_url: dataUri },
        ],
      },
    ]);
    expect(updated.messages[1]).toEqual({
      role: "user",
      text: "Was zeigt der Screenshot?",
      images: [dataUri],
    });
  });
});

describe("generateReport", () => {
  afterEach(() => vi.unstubAllGlobals());

  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  async function makeSession() {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));
    return startAnalysisSession(doc, config, { key: "test-key" });
  }

  it("requests structured output with file_search enabled and parses it into a typed AiReport", async () => {
    const session = await makeSession();
    let sentBody: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init: RequestInit) => {
        sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
        return Promise.resolve({
          ok: true,
          json: async () => ({
            id: "resp_2",
            output_text: JSON.stringify({
              summary: "Alles im Griff, bis auf ein IPv6-Leck.",
              findings: [
                { severity: "HIGH", title: "IPv6-Bypass", description: "desc", affected: ["res-1a2b3c4d"] },
              ],
              recommendations: ["Firewall-Regel für IPv6 ergänzen."],
            }),
          }),
        });
      }),
    );

    const report = await generateReport(session);

    expect(sentBody.previous_response_id).toBe("resp_1");
    expect(sentBody.tools).toEqual([{ type: "file_search", vector_store_ids: ["vs-abc"] }]);
    expect((sentBody.text as { format?: { type?: string } })?.format?.type).toBe("json_schema");
    expect(report).toEqual({
      summary: "Alles im Griff, bis auf ein IPv6-Leck.",
      findings: [{ severity: "HIGH", title: "IPv6-Bypass", description: "desc", affected: ["res-1a2b3c4d"] }],
      recommendations: ["Firewall-Regel für IPv6 ergänzen."],
    });
  });

  it("strips a ```json fence before parsing", async () => {
    const session = await makeSession();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: "resp_2",
          output_text: '```json\n{"summary":"s","findings":[],"recommendations":[]}\n```',
        }),
      }),
    );

    const report = await generateReport(session);
    expect(report).toEqual({ summary: "s", findings: [], recommendations: [] });
  });

  it("falls back to raw text as the summary when the model doesn't return valid JSON", async () => {
    const session = await makeSession();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: "resp_2", output_text: "not json at all" }) }),
    );

    const report = await generateReport(session);
    expect(report).toEqual({ summary: "not json at all", findings: [], recommendations: [] });
  });

  it("drops findings with an unknown severity or missing fields instead of throwing", async () => {
    const session = await makeSession();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: "resp_2",
          output_text: JSON.stringify({
            summary: "s",
            findings: [
              { severity: "WEIRD", title: "x", description: "y", affected: [] },
              { severity: "LOW", title: "ok" }, // missing description/affected
              { severity: "INFO", title: "fine", description: "d", affected: [] },
            ],
            recommendations: [],
          }),
        }),
      }),
    );

    const report = await generateReport(session);
    expect(report.findings).toEqual([{ severity: "INFO", title: "fine", description: "d", affected: [] }]);
  });
});

describe("endSession", () => {
  afterEach(() => vi.unstubAllGlobals());

  const model = analyzeInventory(F.hubSpokeRaw());
  const doc = buildAssessmentExport(model, { now: new Date(2026, 8, 25, 14, 7), snapshotId: "snap-1" });
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  it("deletes the session's uploaded file and vector store", async () => {
    vi.stubGlobal("fetch", stubBackend(() => ({ id: "resp_1", output_text: "Bereit." })));
    const session = await startAnalysisSession(doc, config, { key: "test-key" });

    const deletedUrls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string) => {
        deletedUrls.push(url);
        return { ok: true, json: async () => ({ deleted: true }) };
      }),
    );

    await endSession(session);

    expect(deletedUrls.some((u) => u.includes("vs-abc"))).toBe(true);
    expect(deletedUrls.some((u) => u.includes("file-abc"))).toBe(true);
  });
});

describe("resumeSession", () => {
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  it("reconstructs a session from persisted state without any network calls", () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const session = resumeSession("s1", config, {
      doc: { fileId: "file-abc", vectorStoreId: "vs-abc" },
      lastResponseId: "resp_5",
      messages: [
        { role: "assistant", text: "Bereit." },
        { role: "user", text: "Frage" },
        { role: "assistant", text: "Antwort" },
      ],
      sanitizationStats: { pseudonymizedTokens: 12, publicIpsReplaced: 1 },
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(session).toEqual({
      id: "s1",
      config,
      doc: { fileId: "file-abc", vectorStoreId: "vs-abc" },
      lastResponseId: "resp_5",
      messages: [
        { role: "assistant", text: "Bereit." },
        { role: "user", text: "Frage" },
        { role: "assistant", text: "Antwort" },
      ],
      sanitizationStats: { pseudonymizedTokens: 12, publicIpsReplaced: 1 },
    });
    vi.unstubAllGlobals();
  });

  it("a resumed session can continue chatting via the usual chain", async () => {
    let sentBody: Record<string, unknown> = {};
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init: RequestInit) => {
        sentBody = JSON.parse(init.body as string) as Record<string, unknown>;
        return Promise.resolve({ ok: true, json: async () => ({ id: "resp_6", output_text: "Weiter geht's." }) });
      }),
    );

    const session = resumeSession("s1", config, {
      doc: { fileId: "file-abc", vectorStoreId: "vs-abc" },
      lastResponseId: "resp_5",
      messages: [{ role: "assistant", text: "Bereit." }],
      sanitizationStats: { pseudonymizedTokens: 12, publicIpsReplaced: 1 },
    });
    const updated = await sendChatMessage(session, "Noch eine Frage");

    expect(sentBody.previous_response_id).toBe("resp_5");
    expect(sentBody.tools).toEqual([{ type: "file_search", vector_store_ids: ["vs-abc"] }]);
    expect(updated.messages.at(-1)).toEqual({ role: "assistant", text: "Weiter geht's." });
    vi.unstubAllGlobals();
  });
});
