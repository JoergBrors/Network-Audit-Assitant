/**
 * Minimal Azure OpenAI (Foundry Models) Responses API client, called directly from the browser with
 * the sanitized export (see src/export/sanitize.ts) as context. No SDK dependency: one JSON POST per
 * turn. Config comes from Vite env vars (see .env.example) — never from tenant data, never logged.
 *
 * Chat turns are chained via `previous_response_id` (Azure OpenAI keeps the conversation state
 * server-side under `store: true`, the default), so only the new message is sent on each follow-up
 * turn instead of resending the whole export every time — this is what keeps a multi-turn chat cheap
 * once the first turn has established the context.
 */
export interface AzureOpenAiConfig {
  /** e.g. https://sandbox-joerg-brors-001-resource.services.ai.azure.com */
  endpoint: string;
  apiKey: string;
  /** Deployment/model name, e.g. "gpt-5-mini". */
  model: string;
}

export class AzureOpenAiError extends Error {
  override readonly name = "AzureOpenAiError";
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export function readAzureOpenAiConfigFromEnv(): AzureOpenAiConfig | undefined {
  const endpoint = import.meta.env.VITE_AZURE_OPENAI_ENDPOINT as string | undefined;
  const apiKey = import.meta.env.VITE_AZURE_OPENAI_API_KEY as string | undefined;
  const model = import.meta.env.VITE_AZURE_OPENAI_MODEL as string | undefined;
  if (!endpoint || !apiKey || !model) return undefined;
  return { endpoint: endpoint.replace(/\/+$/, ""), apiKey, model };
}

export interface CallOptions {
  signal?: AbortSignal;
  /** Retries on 429/5xx before giving up. Default 4 (5 attempts total). */
  maxRetries?: number;
  /** Called before each wait, e.g. to show "Rate-Limit, warte 12 s …" in the UI. */
  onRetry?: (info: { attempt: number; waitMs: number; status: number }) => void;
}

export interface AzureOpenAiResponse {
  /** This turn's response id — pass as `previousResponseId` on the next turn to continue the chat. */
  id: string;
  text: string;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Parses `Retry-After` (seconds or HTTP-date) into milliseconds; undefined if absent/unparsable. */
function retryAfterMs(res: Response): number | undefined {
  const header = res.headers.get("retry-after");
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(header);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : undefined;
}

/** Sends one HTTP request against the Azure OpenAI resource, retrying on 429/5xx with exponential
 * backoff (or the server's own `Retry-After`). */
async function requestWithRetry(
  config: AzureOpenAiConfig,
  path: string,
  init: RequestInit,
  options: CallOptions = {},
): Promise<Response> {
  const maxRetries = options.maxRetries ?? 4;
  const url = `${config.endpoint}${path}${path.includes("?") ? "&" : "?"}api-version=preview`;

  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        ...init,
        headers: { "api-key": config.apiKey, ...init.headers },
        ...(options.signal ? { signal: options.signal } : {}),
      });
    } catch (e) {
      throw new AzureOpenAiError(`Netzwerkfehler beim Aufruf von Azure OpenAI: ${String(e)}`);
    }
    if (res.ok) return res;

    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= maxRetries) {
      const body = await res.text().catch(() => "");
      throw new AzureOpenAiError(
        `Azure OpenAI antwortete mit ${res.status}: ${body.slice(0, 500)}`,
        res.status,
      );
    }
    // Prefer the server's own Retry-After; otherwise exponential backoff with jitter (base 2s).
    const waitMs = retryAfterMs(res) ?? Math.min(30_000, 2000 * 2 ** attempt) + Math.random() * 500;
    options.onRetry?.({ attempt: attempt + 1, waitMs, status: res.status });
    await sleep(waitMs);
  }
}

/** An image pasted/attached for this turn only — sent inline as a base64 data URI (`input_image`),
 * never uploaded to the vector store (file_search only indexes text-extractable documents). */
export interface ImageAttachment {
  /** Full data URI, e.g. "data:image/png;base64,...." (as produced by FileReader.readAsDataURL). */
  dataUri: string;
}

/** Sends one chat turn to the Responses API. Pass `previousResponseId` (from the prior turn's
 * result) to continue an existing conversation cheaply — Azure OpenAI keeps the prior turns
 * server-side, so only `input` (the new message) is sent, not the full history again. Pass
 * `jsonSchema` to force a structured-output turn (used for the final PDF-report JSON). Pass
 * `vectorStoreIds` to enable the `file_search` tool so the model retrieves only the relevant
 * chunks of an uploaded document instead of the full document being part of every turn's context
 * (see uploadFileSearchDocument) — this is what keeps a large export from exceeding the model's
 * per-request/per-minute token budget in the first place. Pass `images` to attach one or more
 * pasted/uploaded images to just this turn (vision input, not part of file_search). */
export async function callAzureOpenAi(
  config: AzureOpenAiConfig,
  input: string,
  options: CallOptions & {
    previousResponseId?: string;
    jsonSchema?: { name: string; schema: Record<string, unknown> };
    vectorStoreIds?: string[];
    images?: ImageAttachment[];
  } = {},
): Promise<AzureOpenAiResponse> {
  const body: Record<string, unknown> = {
    model: config.model,
    input: options.images?.length
      ? [
          {
            role: "user",
            content: [
              { type: "input_text", text: input },
              ...options.images.map((img) => ({ type: "input_image", image_url: img.dataUri })),
            ],
          },
        ]
      : input,
    store: true,
  };
  if (options.previousResponseId) body.previous_response_id = options.previousResponseId;
  if (options.jsonSchema) {
    body.text = {
      format: { type: "json_schema", name: options.jsonSchema.name, schema: options.jsonSchema.schema, strict: true },
    };
  }
  if (options.vectorStoreIds?.length) {
    body.tools = [{ type: "file_search", vector_store_ids: options.vectorStoreIds }];
  }
  const res = await requestWithRetry(
    config,
    "/openai/v1/responses",
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
    options,
  );
  const json = (await res.json()) as { id: string; output_text?: string; output?: unknown };
  return { id: json.id, text: extractText(json) };
}

export interface FileSearchDocument {
  fileId: string;
  vectorStoreId: string;
}

/** Uploads `content` as a fresh file, creates a fresh vector store for it, attaches the file, and
 * polls until ingestion completes. Combined with `file_search` in `callAzureOpenAi`, this lets the
 * model work with a large export without the whole document counting against every turn's token
 * budget — only the query-relevant chunks are pulled in per call.
 *
 * Ingestion failures with `code: server_error` ("An internal error occurred") from Azure's own file
 * pipeline are a known, generally transient failure mode; a single minified (no-newline) JSON blob
 * is also more likely to trip a text-extraction parser than the same content pretty-printed, so
 * `content` is re-indented before upload. On failure the whole attempt — file, vector store and the
 * failed attachment — is thrown away and redone from scratch (a fresh file id, not the same one
 * re-attached): if the uploaded artifact itself is what Azure's parser choked on, re-attaching that
 * identical file to a new vector-store-file entry reproduces the same failure, which is what a
 * same-file retry was observed to do in practice. */
export async function uploadFileSearchDocument(
  config: AzureOpenAiConfig,
  content: string,
  fileName: string,
  options: CallOptions & { pollIntervalMs?: number; pollTimeoutMs?: number; maxIngestAttempts?: number } = {},
): Promise<FileSearchDocument> {
  const prettyContent = rePrettyPrint(content);
  const maxIngestAttempts = options.maxIngestAttempts ?? 3;
  let lastError: AzureOpenAiError | undefined;

  for (let attempt = 1; attempt <= maxIngestAttempts; attempt++) {
    let doc: FileSearchDocument | undefined;
    try {
      const form = new FormData();
      form.append("purpose", "assistants");
      form.append("file", new Blob([prettyContent], { type: "text/plain" }), fileName);
      const fileRes = await requestWithRetry(config, "/openai/v1/files", { method: "POST", body: form }, options);
      const file = (await fileRes.json()) as { id: string };

      const storeRes = await requestWithRetry(
        config,
        "/openai/v1/vector_stores",
        { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: fileName }) },
        options,
      );
      const store = (await storeRes.json()) as { id: string };
      doc = { fileId: file.id, vectorStoreId: store.id };

      await requestWithRetry(
        config,
        `/openai/v1/vector_stores/${store.id}/files`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ file_id: file.id }),
        },
        options,
      );
      await pollVectorStoreFileIngestion(config, store.id, file.id, options);
      return doc;
    } catch (e) {
      lastError = e instanceof AzureOpenAiError ? e : new AzureOpenAiError(String(e));
      if (doc) await deleteFileSearchDocument(config, doc); // best effort, don't leave the failed attempt behind
      if (attempt < maxIngestAttempts) {
        options.onRetry?.({ attempt, waitMs: 1500, status: 0 });
        await sleep(1500);
      }
    }
  }
  throw lastError!;
}

/** `JSON.stringify(x)` produces one line with no whitespace; re-indent it so the uploaded document
 * is normal multi-line text rather than a single very long line, which some text-extraction/chunking
 * pipelines handle less reliably. No effect on the data itself (same JSON, just formatted). */
function rePrettyPrint(json: string): string {
  try {
    return JSON.stringify(JSON.parse(json), null, 2);
  } catch {
    return json;
  }
}

async function pollVectorStoreFileIngestion(
  config: AzureOpenAiConfig,
  vectorStoreId: string,
  fileId: string,
  options: CallOptions & { pollIntervalMs?: number; pollTimeoutMs?: number },
): Promise<void> {
  const intervalMs = options.pollIntervalMs ?? 1000;
  const timeoutMs = options.pollTimeoutMs ?? 60_000;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await requestWithRetry(
      config,
      `/openai/v1/vector_stores/${vectorStoreId}/files/${fileId}`,
      { method: "GET" },
      options,
    );
    const status = (await res.json()) as {
      status: string;
      last_error?: { code?: string; message?: string };
    };
    if (status.status === "completed") return;
    if (status.status === "failed" || status.status === "cancelled") {
      throw new AzureOpenAiError(
        `Verarbeitung der hochgeladenen Datei fehlgeschlagen (${status.last_error?.code ?? status.status}): ${status.last_error?.message ?? status.status}`,
      );
    }
    if (Date.now() > deadline) {
      throw new AzureOpenAiError("Zeitüberschreitung beim Warten auf die Dateiverarbeitung durch Azure OpenAI.");
    }
    await sleep(intervalMs);
  }
}

/** Deletes the vector store and the underlying file — call this once the session ends so the
 * (already sanitized) copy of the export doesn't linger in the Azure OpenAI resource. Best effort:
 * never throws; a leftover file/store is a cleanup nuisance, not a data leak. */
export async function deleteFileSearchDocument(
  config: AzureOpenAiConfig,
  doc: FileSearchDocument,
): Promise<void> {
  await Promise.allSettled([
    fetch(`${config.endpoint}/openai/v1/vector_stores/${doc.vectorStoreId}?api-version=preview`, {
      method: "DELETE",
      headers: { "api-key": config.apiKey },
    }),
    fetch(`${config.endpoint}/openai/v1/files/${doc.fileId}?api-version=preview`, {
      method: "DELETE",
      headers: { "api-key": config.apiKey },
    }),
  ]);
}

function extractText(json: { output_text?: string; output?: unknown }): string {
  if (typeof json.output_text === "string" && json.output_text.length > 0) return json.output_text;
  // Fallback: reconstruct text from the `output` array (message -> content -> output_text items).
  const output = Array.isArray(json.output) ? json.output : [];
  const text = output
    .flatMap((item) => (isMessageItem(item) ? item.content : []))
    .filter((c): c is { type: "output_text"; text: string } => c.type === "output_text")
    .map((c) => c.text)
    .join("");
  if (text) return text;
  throw new AzureOpenAiError("Azure OpenAI lieferte keine Textantwort.");
}

interface MessageItem {
  type: "message";
  content: { type: string; text?: string }[];
}
function isMessageItem(value: unknown): value is MessageItem {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "message" &&
    Array.isArray((value as { content?: unknown }).content)
  );
}
