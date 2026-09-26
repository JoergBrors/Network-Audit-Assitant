import { describe, expect, it } from "vitest";
import {
  downloadGeneratedFile,
  endSession,
  exportOverview,
  generateReport,
  parseReport,
  sendChatMessage,
  startAnalysisSession,
  WELCOME_TEXT,
  type AiContext,
} from "../../src/ai/analyze.js";
import { createAzureOpenAiClient, AzureOpenAiError } from "../../src/ai/azureOpenAi.js";
import type { AssessmentExport } from "../../src/export/assessmentJson.js";
import { createFakeAzure, textResponse } from "./fakeAzure.js";

const EXPORT = {
  metadata: { tool: "test" },
  vnets: [
    { id: "/subscriptions/1/resourcegroups/rg-prod/providers/microsoft.network/virtualnetworks/vnet-real" },
  ],
  subnets: [{}, {}],
  nsgs: [],
  graph: { nodes: [{}, {}, {}], edges: [{}] },
} as unknown as AssessmentExport;

function setup(effort?: "low") {
  const azure = createFakeAzure();
  const config = {
    endpoint: "https://x.openai.azure.com",
    model: "gpt-5-mini",
    reasoningEffort: effort,
    scope: "s",
  };
  const ctx: AiContext = {
    client: createAzureOpenAiClient(config, async () => "token", { fetch: azure.fetch, maxRetries: 0 }),
    config,
  };
  return { azure, ctx };
}

const responseCalls = (azure: ReturnType<typeof createFakeAzure>) =>
  azure.requests.filter((r) => r.path === "/responses").map((r) => r.json!);

describe("KI-Analyse session", () => {
  it("uploads the export unchanged (no anonymization) and makes no model call to start", async () => {
    const { azure, ctx } = setup();
    const session = await startAnalysisSession(ctx, EXPORT);
    expect(azure.requests).toHaveLength(1);
    const upload = azure.requests[0]!.upload!;
    expect(upload.purpose).toBe("assistants");
    expect(upload.text).toContain("vnet-real");
    expect(upload.text).toContain("rg-prod");
    expect(session.files).toEqual([{ id: "file-1", name: "azure-network-assessment.json", kind: "export" }]);
    expect(session.messages).toEqual([{ role: "assistant", text: WELCOME_TEXT }]);
  });

  it("streams the answer and runs Code Interpreter over the session files", async () => {
    const { azure, ctx } = setup("low");
    const session = await startAnalysisSession(ctx, EXPORT);
    azure.queueResponse(textResponse("resp_1", "Zwei Subnets haben IPv6 ohne Firewall."));
    const streamed: string[] = [];
    const activities: string[] = [];
    const after = await sendChatMessage(ctx, session, "Welche Subnets haben IPv6?", {
      onText: (t) => streamed.push(t),
      onActivity: (a) => activities.push(a),
    });

    const [body] = responseCalls(azure);
    expect(body).toMatchObject({
      model: "gpt-5-mini",
      stream: true,
      store: true,
      truncation: "auto",
      reasoning: { effort: "low" },
      tools: [{ type: "code_interpreter", container: { type: "auto", file_ids: ["file-1"] } }],
    });
    expect(body!["previous_response_id"]).toBeUndefined();
    expect(String(body!["instructions"])).toContain("Code Interpreter");
    // The first question carries the export overview so the model needs no exploration step.
    const content = (body!["input"] as { content: { text: string }[] }[])[0]!.content;
    expect(content[0]!.text).toContain("subnets: 2");
    expect(content[0]!.text).toContain("Welche Subnets haben IPv6?");

    expect(streamed.length).toBeGreaterThan(1);
    expect(streamed.at(-1)).toBe("Zwei Subnets haben IPv6 ohne Firewall.");
    expect(activities).toContain("Werte die Daten mit Python aus …");
    expect(after.lastResponseId).toBe("resp_1");
    expect(after.messages.slice(1)).toEqual([
      { role: "user", text: "Welche Subnets haben IPv6?" },
      { role: "assistant", text: "Zwei Subnets haben IPv6 ohne Firewall." },
    ]);
  });

  it("chains follow-ups with previous_response_id and sends only the new message", async () => {
    const { azure, ctx } = setup();
    let session = await startAnalysisSession(ctx, EXPORT);
    azure.queueResponse(textResponse("resp_1", "a"));
    session = await sendChatMessage(ctx, session, "Frage 1");
    azure.queueResponse(textResponse("resp_2", "b"));
    session = await sendChatMessage(ctx, session, "Frage 2");
    const second = responseCalls(azure)[1]!;
    expect(second["previous_response_id"]).toBe("resp_1");
    expect(second["reasoning"]).toBeUndefined();
    const content = (second["input"] as { content: { text: string }[] }[])[0]!.content;
    expect(content[0]!.text).toBe("Frage 2");
    expect(session.responseIds).toEqual(["resp_1", "resp_2"]);
  });

  it("uploads attachments into the container and sends images inline", async () => {
    const { azure, ctx } = setup();
    const session = await startAnalysisSession(ctx, EXPORT);
    const csv = new File(["name,port\nvm1,22\n"], "ports.csv", { type: "text/csv" });
    const after = await sendChatMessage(ctx, session, "Abgleich", {
      attachments: [csv],
      images: ["data:image/png;base64,AAAA"],
    });
    expect(azure.requests.find((r) => r.upload?.name === "ports.csv")?.upload?.text).toContain("vm1,22");
    const body = responseCalls(azure)[0]!;
    expect(body["tools"]).toEqual([
      { type: "code_interpreter", container: { type: "auto", file_ids: ["file-1", "file-2"] } },
    ]);
    const content = (body["input"] as { content: Record<string, unknown>[] }[])[0]!.content;
    expect(content[0]!["text"]).toContain("ports.csv");
    expect(content[1]).toEqual({
      type: "input_image",
      image_url: "data:image/png;base64,AAAA",
      detail: "auto",
    });
    expect(after.files.map((f) => f.kind)).toEqual(["export", "attachment"]);
    expect(after.messages.at(-2)).toMatchObject({
      attachments: ["ports.csv"],
      images: ["data:image/png;base64,AAAA"],
    });
  });

  it("offers files the model generated in the container for download", async () => {
    const { azure, ctx } = setup();
    const session = await startAnalysisSession(ctx, EXPORT);
    azure.queueResponse(
      textResponse("resp_1", "Siehe CSV.", [
        {
          type: "container_file_citation",
          container_id: "cntr_1",
          file_id: "cfile_1",
          filename: "open-ports.csv",
          start_index: 0,
          end_index: 1,
        },
      ]),
    );
    const after = await sendChatMessage(ctx, session, "Als CSV bitte");
    const generated = after.messages.at(-1)!.generated!;
    expect(generated).toEqual([{ containerId: "cntr_1", fileId: "cfile_1", filename: "open-ports.csv" }]);
    const blob = await downloadGeneratedFile(ctx, generated[0]!);
    expect(await blob.text()).toContain("a,b");
    expect(azure.requests.at(-1)!.path).toBe("/containers/cntr_1/files/cfile_1/content");
  });

  it("reports a failed stream as an error", async () => {
    const { azure, ctx } = setup();
    const session = await startAnalysisSession(ctx, EXPORT);
    azure.queueResponse([
      { type: "error", message: "rate limit", code: "too_many_requests", sequence_number: 1 },
    ]);
    await expect(sendChatMessage(ctx, session, "x")).rejects.toThrow(AzureOpenAiError);
  });

  it("builds the report with Structured Outputs and more reasoning", async () => {
    const { azure, ctx } = setup("low");
    const session = await startAnalysisSession(ctx, EXPORT);
    const report = {
      summary: "IPv6 umgeht die Firewall.",
      findings: [{ severity: "HIGH", title: "Bypass", description: "d", affected: ["snet-app (rg-prod)"] }],
      recommendations: ["UDR ::/0 ergänzen"],
    };
    azure.queueResponse(textResponse("resp_r", JSON.stringify(report)));
    const result = await generateReport(ctx, session);
    const body = responseCalls(azure)[0]!;
    expect(body["reasoning"]).toEqual({ effort: "medium" });
    expect(body["text"]).toMatchObject({
      format: { type: "json_schema", name: "network_audit_report", strict: true },
    });
    expect(result.report).toEqual(report);
    expect(result.session.responseIds).toEqual(["resp_r"]);
  });

  it("deletes uploaded files and stored responses when the session ends", async () => {
    const { azure, ctx } = setup();
    let session = await startAnalysisSession(ctx, EXPORT);
    azure.queueResponse(textResponse("resp_1", "a"));
    session = await sendChatMessage(ctx, session, "x");
    await endSession(ctx, session);
    const deletes = azure.requests.filter((r) => r.method === "DELETE").map((r) => r.path);
    expect(deletes.sort()).toEqual(["/files/file-1", "/responses/resp_1"]);
  });
});

describe("helpers", () => {
  it("summarizes the export by section", () => {
    expect(exportOverview(EXPORT, "x.json")).toBe(
      "[Kontext: Export-Datei /mnt/data/…x.json – vnets: 1, subnets: 2, graph: 3 Knoten, 1 Kanten]",
    );
  });

  it("parses fenced or partial reports defensively", () => {
    expect(parseReport('```json\n{"summary":"s","findings":[],"recommendations":["r"]}\n```')).toEqual({
      summary: "s",
      findings: [],
      recommendations: ["r"],
    });
    expect(parseReport("kein JSON")).toEqual({ summary: "kein JSON", findings: [], recommendations: [] });
    expect(
      parseReport(
        '{"summary":"s","findings":[{"severity":"BAD","title":"t","description":"d","affected":[]}]}',
      ).findings,
    ).toEqual([]);
  });
});
