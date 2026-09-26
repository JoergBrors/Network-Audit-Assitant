import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AzureOpenAiError,
  callAzureOpenAi,
  deleteFileSearchDocument,
  uploadFileSearchDocument,
} from "../../src/ai/azureOpenAi.js";

describe("callAzureOpenAi", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  it("posts to the Responses API with the api-key header and returns id + output_text", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "resp_1", output_text: "hello" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await callAzureOpenAi(config, "prompt");

    expect(result).toEqual({ id: "resp_1", text: "hello" });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit & { headers: Record<string, string> }];
    expect(url).toBe("https://example.openai.azure.com/openai/v1/responses?api-version=preview");
    expect(init.headers["api-key"]).toBe("key");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toMatchObject({ model: "gpt-5-mini", input: "prompt", store: true });
    expect(body.previous_response_id).toBeUndefined();
  });

  it("chains a follow-up turn via previous_response_id instead of resending context", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "resp_2", output_text: "follow-up answer" }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await callAzureOpenAi(config, "follow-up question", { previousResponseId: "resp_1" });

    expect(result).toEqual({ id: "resp_2", text: "follow-up answer" });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body.previous_response_id).toBe("resp_1");
    expect(body.input).toBe("follow-up question"); // only the new message, not the prior context
  });

  it("requests structured output via a json_schema text format when jsonSchema is given", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "resp_3", output_text: '{"a":1}' }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await callAzureOpenAi(config, "make a report", {
      jsonSchema: { name: "report", schema: { type: "object" } },
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as {
      text?: { format?: { type?: string; name?: string; strict?: boolean } };
    };
    expect(body.text?.format).toMatchObject({ type: "json_schema", name: "report", strict: true });
  });

  it("sends the file_search tool with the given vector store ids", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: "resp_x", output_text: "ok" }) });
    vi.stubGlobal("fetch", fetchMock);

    await callAzureOpenAi(config, "find leaks", { vectorStoreIds: ["vs_123"] });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { tools?: unknown[] };
    expect(body.tools).toEqual([{ type: "file_search", vector_store_ids: ["vs_123"] }]);
  });

  it("sends a structured input_text/input_image payload when images are attached", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: "resp_x", output_text: "ok" }) });
    vi.stubGlobal("fetch", fetchMock);

    await callAzureOpenAi(config, "what is this?", {
      images: [{ dataUri: "data:image/png;base64,AAA=" }],
    });

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { input: unknown };
    expect(body.input).toEqual([
      {
        role: "user",
        content: [
          { type: "input_text", text: "what is this?" },
          { type: "input_image", image_url: "data:image/png;base64,AAA=" },
        ],
      },
    ]);
  });

  it("sends plain string input when there are no images", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: "resp_x", output_text: "ok" }) });
    vi.stubGlobal("fetch", fetchMock);

    await callAzureOpenAi(config, "plain question");

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string) as { input: unknown };
    expect(body.input).toBe("plain question");
  });

  it("reconstructs text from the output array when output_text is absent", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          id: "resp_4",
          output: [
            {
              type: "message",
              content: [
                { type: "output_text", text: "part one " },
                { type: "output_text", text: "part two" },
              ],
            },
          ],
        }),
      }),
    );

    expect((await callAzureOpenAi(config, "prompt")).text).toBe("part one part two");
  });

  it("throws AzureOpenAiError on a non-OK, non-retryable response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        headers: new Headers(),
        text: async () => "bad request",
      }),
    );

    await expect(callAzureOpenAi(config, "prompt", { maxRetries: 0 })).rejects.toThrow(AzureOpenAiError);
  });

  it("throws AzureOpenAiError on a network failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    await expect(callAzureOpenAi(config, "prompt")).rejects.toThrow(AzureOpenAiError);
  });

  it("throws AzureOpenAiError when there is no text anywhere in the response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: "resp_5" }) }));

    await expect(callAzureOpenAi(config, "prompt")).rejects.toThrow(AzureOpenAiError);
  });

  it("retries on 429 (token rate limit) and succeeds once the limit clears", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ "retry-after": "0" }),
        text: async () => JSON.stringify({ error: { code: "rate_limit_exceeded" } }),
      })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: "resp_6", output_text: "ok after retry" }) });
    vi.stubGlobal("fetch", fetchMock);
    const onRetry = vi.fn();

    const result = await callAzureOpenAi(config, "prompt", { onRetry });

    expect(result.text).toBe("ok after retry");
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(onRetry).toHaveBeenCalledWith(expect.objectContaining({ attempt: 1, status: 429 }));
  });

  it("gives up after maxRetries and throws AzureOpenAiError with the 429 status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 429,
        headers: new Headers({ "retry-after": "0" }),
        text: async () => "still limited",
      }),
    );

    await expect(callAzureOpenAi(config, "prompt", { maxRetries: 1 })).rejects.toMatchObject({
      status: 429,
    });
  });

  it("honours a Retry-After header instead of the default backoff", async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ "retry-after": "5" }),
        text: async () => "limited",
      })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ id: "resp_7", output_text: "done" }) });
    vi.stubGlobal("fetch", fetchMock);

    const promise = callAzureOpenAi(config, "prompt");
    await vi.advanceTimersByTimeAsync(5000);
    await expect(promise).resolves.toEqual({ id: "resp_7", text: "done" });
    vi.useRealTimers();
  });
});

describe("uploadFileSearchDocument / deleteFileSearchDocument", () => {
  afterEach(() => vi.unstubAllGlobals());
  const config = { endpoint: "https://example.openai.azure.com", apiKey: "key", model: "gpt-5-mini" };

  /** Routes: POST /files (multipart, create the file) -> POST /vector_stores (no /files/ suffix,
   * create the empty store) -> POST /vector_stores/{id}/files (attach) -> GET .../files/{fileId}
   * (poll status), matched in that order of specificity so the plain "/files" attach path isn't
   * mistaken for the create-file or create-store calls. */
  function stubUploadBackend(status: (attachCount: number) => { status: string; last_error?: unknown }) {
    let attachCount = 0;
    return vi.fn().mockImplementation((url: string, init: RequestInit) => {
      if (init?.body instanceof FormData) return { ok: true, json: async () => ({ id: "file-abc" }) };
      if (url.endsWith("/openai/v1/vector_stores") || url.includes("/vector_stores?"))
        return { ok: true, json: async () => ({ id: "vs-abc" }) };
      if (url.includes("/vector_stores/vs-abc/files") && init?.method === "POST") {
        attachCount++;
        return { ok: true, json: async () => ({ id: "file-abc", status: "in_progress" }) };
      }
      if (url.includes("/vector_stores/vs-abc/files/file-abc") && (init?.method ?? "GET") === "GET")
        return { ok: true, json: async () => status(attachCount) };
      throw new Error(`unexpected request ${url}`);
    });
  }

  it("uploads a file, creates a vector store, attaches, polls until ingestion completes, and returns both ids", async () => {
    vi.stubGlobal("fetch", stubUploadBackend(() => ({ status: "completed" })));

    const doc = await uploadFileSearchDocument(config, '{"a":1}', "export.json", { pollIntervalMs: 1 });

    expect(doc).toEqual({ fileId: "file-abc", vectorStoreId: "vs-abc" });
  });

  it("re-indents minified JSON before upload so the file isn't a single very long line", async () => {
    let uploadedContent = "";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
        if (init?.body instanceof FormData) {
          uploadedContent = String(await (init.body.get("file") as Blob).text());
          return { ok: true, json: async () => ({ id: "file-abc" }) };
        }
        if (url.includes("/openai/v1/vector_stores?")) return { ok: true, json: async () => ({ id: "vs-abc" }) };
        if (url.includes("/vector_stores/vs-abc/files") && init?.method === "POST")
          return { ok: true, json: async () => ({ id: "file-abc" }) };
        if (url.includes("/files/file-abc")) return { ok: true, json: async () => ({ status: "completed" }) };
        throw new Error(`unexpected request ${url}`);
      }),
    );

    await uploadFileSearchDocument(config, '{"a":1,"b":{"c":2}}', "export.json", { pollIntervalMs: 1 });

    expect(uploadedContent).toContain("\n");
    expect(JSON.parse(uploadedContent)).toEqual({ a: 1, b: { c: 2 } });
  });

  it("polls again while the file is still processing, then resolves once completed", async () => {
    let statusCalls = 0;
    vi.stubGlobal(
      "fetch",
      stubUploadBackend(() => {
        statusCalls++;
        return { status: statusCalls < 2 ? "in_progress" : "completed" };
      }),
    );

    await uploadFileSearchDocument(config, "{}", "export.json", { pollIntervalMs: 1 });
    expect(statusCalls).toBeGreaterThanOrEqual(2);
  });

  it("retries with a completely fresh file+vector-store on a server_error, not the same failed one", async () => {
    let uploadCount = 0;
    const deletedIds: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string, init: RequestInit) => {
        if (init?.method === "DELETE") {
          deletedIds.push(url);
          return { ok: true, json: async () => ({ deleted: true }) };
        }
        if (init?.body instanceof FormData) {
          uploadCount++;
          return { ok: true, json: async () => ({ id: `file-${uploadCount}` }) };
        }
        if (url.includes("/openai/v1/vector_stores?")) return { ok: true, json: async () => ({ id: `vs-${uploadCount}` }) };
        if (url.includes("/files") && init?.method === "POST")
          return { ok: true, json: async () => ({ id: `file-${uploadCount}` }) };
        if (url.includes(`/files/file-${uploadCount}`)) {
          return {
            ok: true,
            json: async () =>
              uploadCount < 2
                ? { status: "failed", last_error: { code: "server_error", message: "An internal error occurred." } }
                : { status: "completed" },
          };
        }
        throw new Error(`unexpected request ${url}`);
      }),
    );

    const doc = await uploadFileSearchDocument(config, "{}", "export.json", { pollIntervalMs: 1 });

    expect(doc).toEqual({ fileId: "file-2", vectorStoreId: "vs-2" });
    expect(uploadCount).toBe(2); // second (fresh) attempt succeeded, not a retry of the first
    expect(deletedIds.some((u) => u.includes("vs-1"))).toBe(true); // failed first attempt cleaned up
    expect(deletedIds.some((u) => u.includes("file-1"))).toBe(true);
  });

  it("throws AzureOpenAiError with the server's error code after exhausting ingest retries", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string, init: RequestInit) => {
        if (init?.method === "DELETE") return { ok: true, json: async () => ({ deleted: true }) };
        if (init?.body instanceof FormData) return { ok: true, json: async () => ({ id: "file-abc" }) };
        if (url.includes("/openai/v1/vector_stores?")) return { ok: true, json: async () => ({ id: "vs-abc" }) };
        if (url.includes("/files") && init?.method === "POST")
          return { ok: true, json: async () => ({ id: "file-abc" }) };
        if (url.includes("/files/file-abc"))
          return {
            ok: true,
            json: async () => ({
              status: "failed",
              last_error: { code: "server_error", message: "An internal error occurred." },
            }),
          };
        throw new Error(`unexpected request ${url}`);
      }),
    );

    await expect(
      uploadFileSearchDocument(config, "{}", "export.json", { pollIntervalMs: 1, maxIngestAttempts: 2 }),
    ).rejects.toThrow(/server_error/);
  });

  it("deletes both the vector store and the file", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ deleted: true }) });
    vi.stubGlobal("fetch", fetchMock);

    await deleteFileSearchDocument(config, { fileId: "file-abc", vectorStoreId: "vs-abc" });

    const urls = fetchMock.mock.calls.map((c) => c[0] as string);
    expect(urls.some((u) => u.includes("/vector_stores/vs-abc"))).toBe(true);
    expect(urls.some((u) => u.includes("/files/file-abc"))).toBe(true);
    for (const call of fetchMock.mock.calls) expect((call[1] as RequestInit).method).toBe("DELETE");
  });

  it("does not throw even if one of the deletes fails (best effort cleanup)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    await expect(
      deleteFileSearchDocument(config, { fileId: "file-abc", vectorStoreId: "vs-abc" }),
    ).resolves.toBeUndefined();
  });
});
