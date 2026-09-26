/**
 * In-memory stand-in for the Azure OpenAI v1 endpoints the KI-Analyse uses (files, responses with
 * SSE streaming, container file content, deletes). Passed to the SDK as its `fetch`, so the real
 * `openai` client code runs end to end.
 */
export interface RecordedRequest {
  method: string;
  path: string;
  headers: Headers;
  json?: Record<string, unknown>;
  upload?: { name: string; text: string; purpose: string };
}

export type StreamEvent = Record<string, unknown> & { type: string };

export interface FakeAzure {
  fetch: typeof fetch;
  requests: RecordedRequest[];
  /** Events streamed for the next /responses calls (one array per call). */
  queueResponse(events: StreamEvent[]): void;
  /** Status code for the next /responses call before streaming (e.g. 403). */
  failNext(status: number, message: string): void;
}

export function textResponse(id: string, text: string, annotations: unknown[] = []): StreamEvent[] {
  const deltas = text.match(/.{1,5}/gs) ?? [];
  return [
    { type: "response.created", response: { id, status: "in_progress", output: [] } },
    { type: "response.code_interpreter_call.in_progress", item_id: "ci_1", output_index: 0 },
    ...deltas.map((delta) => ({
      type: "response.output_text.delta",
      delta,
      item_id: "msg_1",
      output_index: 1,
    })),
    {
      type: "response.completed",
      response: {
        id,
        status: "completed",
        output: [
          { type: "code_interpreter_call", id: "ci_1", container_id: "cntr_1", status: "completed" },
          {
            type: "message",
            id: "msg_1",
            role: "assistant",
            content: [{ type: "output_text", text, annotations }],
          },
        ],
      },
    },
  ];
}

export function createFakeAzure(): FakeAzure {
  const requests: RecordedRequest[] = [];
  const queued: StreamEvent[][] = [];
  let failure: { status: number; message: string } | undefined;
  let fileCounter = 0;

  const fakeFetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    // The SDK probes FormData support with a data: URL; that is not an Azure call.
    if (url.protocol !== "https:") return fetch(url, init);
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/openai\/v1/, "");
    const record: RecordedRequest = { method, path, headers: new Headers(init.headers) };
    if (init.body instanceof FormData) {
      const file = init.body.get("file") as File;
      record.upload = {
        name: file.name,
        text: await file.text(),
        purpose: init.body.get("purpose") as string,
      };
    } else if (typeof init.body === "string") {
      record.json = JSON.parse(init.body) as Record<string, unknown>;
    }
    requests.push(record);
    const json = (body: unknown, status = 200) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

    if (method === "POST" && path === "/files") return json({ id: `file-${++fileCounter}`, object: "file" });
    if (method === "DELETE") return json({ id: path.split("/").pop(), deleted: true });
    if (method === "GET" && /\/containers\/[^/]+\/files\/[^/]+\/content$/.test(path)) {
      return new Response("a,b\n1,2\n", { headers: { "content-type": "text/csv" } });
    }
    if (method === "POST" && path === "/responses") {
      if (failure) {
        const f = failure;
        failure = undefined;
        return json({ error: { message: f.message, code: "denied" } }, f.status);
      }
      const events = queued.shift() ?? textResponse("resp_default", "ok");
      const body = events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join("");
      return new Response(body, { headers: { "content-type": "text/event-stream" } });
    }
    return json({ error: { message: `unexpected ${method} ${path}` } }, 404);
  };

  return {
    fetch: fakeFetch,
    requests,
    queueResponse: (events) => void queued.push(events),
    failNext: (status, message) => {
      failure = { status, message };
    },
  };
}
