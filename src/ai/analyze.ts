import type { AssessmentExport } from "../export/assessmentJson.js";
import { sanitizeExport, type SanitizeOptions } from "../export/sanitize.js";
import {
  callAzureOpenAi,
  deleteFileSearchDocument,
  uploadFileSearchDocument,
  type AzureOpenAiConfig,
  type CallOptions,
  type FileSearchDocument,
  type ImageAttachment,
} from "./azureOpenAi.js";

export interface AiFinding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  /** Pseudonymized resource references from the sanitized export (e.g. "res-1a2b3c4d"). */
  affected: string[];
}

/** Structured result of the whole chat session, typed so the frontend can render it (e.g. a PDF
 * report) without re-parsing free text. See `REPORT_JSON_SCHEMA` for the exact contract enforced on
 * the model via Structured Outputs. */
export interface AiReport {
  summary: string;
  findings: AiFinding[];
  recommendations: string[];
}

export interface ChatMessage {
  role: "user" | "assistant";
  text: string;
  /** Data URIs of images attached to this (user) message, for rendering a thumbnail in the transcript. */
  images?: string[];
}

/**
 * One ongoing chat session. The sanitized export is uploaded ONCE as a file and indexed into a
 * temporary vector store; every turn (including the first) uses the `file_search` tool against that
 * store instead of pasting the export into the prompt — the model only pulls in the chunks relevant
 * to the current question, so token usage per call stays small regardless of tenant size, and chat
 * turns are chained via `previous_response_id` so follow-up questions don't repeat prior answers.
 * `endSession` deletes the uploaded file/vector store; call it when the user closes the panel.
 */
export interface AiChatSession {
  /** Stable per-session id (not an Azure id) — used only for the local session directory (browser
   * history of past sessions), never sent to Azure OpenAI. */
  id: string;
  config: AzureOpenAiConfig;
  doc: FileSearchDocument;
  /** Response id of the most recent turn; pass-through target for the next call. */
  lastResponseId: string;
  messages: ChatMessage[];
  sanitizationStats: { pseudonymizedTokens: number; publicIpsReplaced: number };
}

export type StartSessionPhase = "sanitizing" | "uploading" | "indexing" | "ready";

export interface StartSessionOptions {
  signal?: AbortSignal;
  onProgress?: (phase: StartSessionPhase) => void;
}

const SESSION_INSTRUCTIONS = `Du bist ein Azure-Netzwerk-Security-Reviewer. Im angehängten Dokument \
(per file_search durchsuchbar) liegt dir ein anonymisierter JSON-Export einer Azure-Netzwerktopologie \
vor (Ressourcennamen, Subscription-/Resource-Group-IDs und öffentliche IP-Adressen sind durch \
Pseudonyme ersetzt; Struktur, Beziehungen, Präfixlängen, Ports, Protokolle, NSG-/Routing-/ \
Firewall-Entscheidungen und private Adressbereiche sind unverändert). Durchsuche das Dokument gezielt \
für jede Frage, statt zu raten. Antworte kurz und konkret, referenziere immer die betroffenen \
Ressourcen-Pseudonyme (z. B. "res-1a2b3c4d"). Erfinde nie Ressourcennamen oder IP-Adressen, die nicht \
im Dokument vorkommen. Bestätige jetzt in einem Satz, dass du bereit bist – ohne JSON, ohne Analyse.`;

const REPORT_INSTRUCTIONS = `Durchsuche das Dokument gezielt nach 1) IPv6-spezifischen Lecks – \
Subnets/NICs mit öffentlicher IPv6-Konnektivität, die eine zentrale Sicherheitskontrolle (Azure \
Firewall/NVA) umgehen, obwohl IPv4 kontrolliert ist; NSG-Regeln, die IPv6 versehentlich breiter \
erlauben als IPv4; fehlende Default-Routen für IPv6 (prüfe dafür Subnet, NSG-Regeln UND Routen \
gemeinsam, bevor du einen Fund meldest) und 2) weiteren Architektur-Gaps (ungesicherte Inbound-Pfade, \
asymmetrisches Routing, fehlende/unsichere Daten). Beziehe auch bereits im Chat besprochene Punkte \
ein. Fasse alles zu einem strukturierten Bericht zusammen: kurze Gesamteinschätzung, alle Findings, \
priorisierte Empfehlungen. Nutze ausschließlich Ressourcen/Pseudonyme aus dem Dokument.`;

const REPORT_JSON_SCHEMA = {
  name: "network_audit_report",
  schema: {
    type: "object",
    additionalProperties: false,
    properties: {
      summary: { type: "string" },
      findings: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] },
            title: { type: "string" },
            description: { type: "string" },
            affected: { type: "array", items: { type: "string" } },
          },
          required: ["severity", "title", "description", "affected"],
        },
      },
      recommendations: { type: "array", items: { type: "string" } },
    },
    required: ["summary", "findings", "recommendations"],
  },
} as const;

/**
 * Sanitizes the export (see src/export/sanitize.ts — real names/IDs/public IPs are replaced by
 * deterministic pseudonyms), uploads it once to a temporary vector store, and opens a chat session
 * backed by `file_search` against that store. This keeps every turn — including this first one —
 * small: the model retrieves only the chunks relevant to what's actually asked, instead of the
 * complete export counting against the token budget of every call (which previously caused
 * `HTTP 429 rate_limit_exceeded` even on the very first message for larger tenants).
 */
export async function startAnalysisSession(
  input: AssessmentExport,
  config: AzureOpenAiConfig,
  sanitizeOptions: SanitizeOptions,
  options: StartSessionOptions = {},
): Promise<AiChatSession> {
  const callOptions: CallOptions = options.signal ? { signal: options.signal } : {};
  options.onProgress?.("sanitizing");
  const { export: sanitized, stats } = await sanitizeExport(input, sanitizeOptions);

  options.onProgress?.("uploading");
  const doc = await uploadFileSearchDocument(
    config,
    JSON.stringify(sanitized),
    "azure-network-assessment-sanitized.json",
    callOptions,
  );

  options.onProgress?.("indexing");
  try {
    const res = await callAzureOpenAi(config, SESSION_INSTRUCTIONS, {
      ...callOptions,
      vectorStoreIds: [doc.vectorStoreId],
    });
    options.onProgress?.("ready");
    return {
      id: crypto.randomUUID(),
      config,
      doc,
      lastResponseId: res.id,
      messages: [{ role: "assistant", text: res.text }],
      sanitizationStats: stats,
    };
  } catch (e) {
    await deleteFileSearchDocument(config, doc);
    throw e;
  }
}

/**
 * Reconstructs an `AiChatSession` from a previously minimized session's persisted state (see
 * src/ui/workspace/aiSessionDirectory.ts), without any network calls — its Azure OpenAI file and
 * vector store are still alive because minimizing (unlike ending) never deleted them. `config` is
 * rebuilt fresh from the current environment rather than persisted, since the API key must never be
 * written to `localStorage`.
 */
export function resumeSession(
  id: string,
  config: AzureOpenAiConfig,
  resumable: {
    doc: FileSearchDocument;
    lastResponseId: string;
    messages: ChatMessage[];
    sanitizationStats: { pseudonymizedTokens: number; publicIpsReplaced: number };
  },
): AiChatSession {
  return { id, config, ...resumable };
}

/** Sends one more chat message in an existing session (see startAnalysisSession). `file_search`
 * stays enabled so this turn, too, only pulls in the chunks relevant to the new question. Pass
 * `images` (e.g. a screenshot pasted from the clipboard) to attach them to just this turn as vision
 * input — they are sent inline with the message, never uploaded to the vector store. */
export async function sendChatMessage(
  session: AiChatSession,
  text: string,
  options: CallOptions & { images?: ImageAttachment[] } = {},
): Promise<AiChatSession> {
  const res = await callAzureOpenAi(session.config, text, {
    ...options,
    previousResponseId: session.lastResponseId,
    vectorStoreIds: [session.doc.vectorStoreId],
  });
  const userMessage: ChatMessage = {
    role: "user",
    text,
    ...(options.images?.length ? { images: options.images.map((i) => i.dataUri) } : {}),
  };
  return {
    ...session,
    lastResponseId: res.id,
    messages: [...session.messages, userMessage, { role: "assistant", text: res.text }],
  };
}

/**
 * Ends the analysis: asks the model, within the same session, to condense a fresh `file_search` pass
 * plus the chat so far into one strictly-typed JSON report (Structured Outputs — `REPORT_JSON_SCHEMA`),
 * so the frontend gets a typed `AiReport` back that can be rendered straight to a PDF.
 */
export async function generateReport(session: AiChatSession, options: CallOptions = {}): Promise<AiReport> {
  const res = await callAzureOpenAi(session.config, REPORT_INSTRUCTIONS, {
    ...options,
    previousResponseId: session.lastResponseId,
    vectorStoreIds: [session.doc.vectorStoreId],
    jsonSchema: REPORT_JSON_SCHEMA,
  });
  return parseReport(res.text);
}

/** Deletes the uploaded file and vector store. Call once the user is done with the session (closes
 * the panel, or after downloading the report) — best effort, never throws. */
export async function endSession(session: AiChatSession): Promise<void> {
  await deleteFileSearchDocument(session.config, session.doc);
}

function parseReport(raw: string): AiReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJson(raw));
  } catch {
    return { summary: raw, findings: [], recommendations: [] };
  }
  if (typeof parsed !== "object" || parsed === null) return { summary: raw, findings: [], recommendations: [] };
  const p = parsed as Record<string, unknown>;
  return {
    summary: typeof p.summary === "string" ? p.summary : "",
    findings: Array.isArray(p.findings) ? p.findings.filter(isFinding) : [],
    recommendations: Array.isArray(p.recommendations) ? p.recommendations.filter((r) => typeof r === "string") : [],
  };
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
function isFinding(value: unknown): value is AiFinding {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.severity === "string" &&
    SEVERITIES.has(v.severity) &&
    typeof v.title === "string" &&
    typeof v.description === "string" &&
    Array.isArray(v.affected)
  );
}

/** Models sometimes wrap JSON in a ```json fence despite instructions; strip it if present. */
function extractJson(text: string): string {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  return (fenced ? fenced[1] : text)!.trim();
}
