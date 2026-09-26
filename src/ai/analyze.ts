import type OpenAI from "openai";
import { toFile } from "openai";
import type {
  ResponseCreateParamsStreaming,
  ResponseInputContent,
} from "openai/resources/responses/responses";
import type { AssessmentExport } from "../export/assessmentJson.js";
import {
  AzureOpenAiError,
  toAzureOpenAiError,
  type AzureOpenAiConfig,
  type ReasoningEffort,
} from "./azureOpenAi.js";

export interface AiFinding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  /** Affected resources (names, with resource group where helpful). */
  affected: string[];
}

/** Structured result of a chat session (Structured Outputs, see `REPORT_JSON_SCHEMA`). */
export interface AiReport {
  summary: string;
  findings: AiFinding[];
  recommendations: string[];
}

/** A file in the session's Code Interpreter container: the export or a user attachment. */
export interface SessionFile {
  id: string;
  name: string;
  kind: "export" | "attachment";
}

/** A file the model created in the container (chart, CSV, …), cited in its answer. */
export interface GeneratedFile {
  containerId: string;
  fileId: string;
  filename: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  text: string;
  /** Data URIs of images attached to this (user) message. */
  images?: string[];
  /** Names of files attached to this (user) message. */
  attachments?: string[];
  /** Files the model generated for this (assistant) message. */
  generated?: GeneratedFile[];
}

/**
 * One chat session. The export is uploaded once, unchanged (internal Azure OpenAI deployment), and
 * mounted into a Code Interpreter container: the model answers by querying the JSON with Python
 * instead of guessing from retrieved chunks. Turns are chained with `previous_response_id`, so each
 * request carries only the new message; answers are streamed.
 */
export interface AiChatSession {
  /** Local id (session directory, prompt cache key) — not an Azure id. */
  id: string;
  files: SessionFile[];
  /** Stored responses of this session (deleted with the session). */
  responseIds: string[];
  lastResponseId?: string | undefined;
  /** Export overview, sent with the first question only. */
  overview: string;
  messages: ChatMessage[];
}

export interface AiContext {
  client: OpenAI;
  config: AzureOpenAiConfig;
}

export interface TurnCallbacks {
  signal?: AbortSignal | undefined;
  /** Streamed answer text so far. */
  onText?: ((text: string) => void) | undefined;
  /** Short activity label, e.g. while Python runs in the container. */
  onActivity?: ((label: string) => void) | undefined;
}

const INSTRUCTIONS = `Du bist ein erfahrener Reviewer für Azure-Netzwerkarchitektur und -sicherheit \
und arbeitest für das interne Audit-Team. Im Python-Sandbox-Container (Code Interpreter) liegt unter \
/mnt/data der vollständige, nicht anonymisierte JSON-Export einer Azure-Netzwerklandschaft \
(Dateiname beginnt mit "azure-network-assessment"), dazu ggf. weitere vom Nutzer angehängte Dateien.

Aufbau des Exports: Top-Level-Arrays je Ressourcentyp (u. a. subscriptions, vnets, subnets, peerings, \
routeTables, routes, nsgs, networkInterfaces, virtualMachines, publicIps, natGateways, firewalls, \
firewallPolicies, ruleCollectionGroups, loadBalancers, applicationGateways, vpnGateways, privateEndpoints, \
privateDnsZones, dnsResolvers, paasServices, virtualHubs) mit normalisierten Objekten; Resource IDs sind kleingeschrieben und \
verweisen aufeinander (z. B. subnets[].nsgId, networkInterfaces[].nsgId, subnets[].routeTableId). \
nsgs[].rules und nsgs[].defaultRules enthalten die Regeln; paasServices[] beschreibt PaaS-Endpunkte \
(publicNetworkAccess, firewall, privateEndpointIds, vnetIntegration, exposure) mit ingress \
(mode, rules, ips, details), egress (mode, subnetIds, outboundIps, allowedTargets, details) und links. \
assessmentContext.serviceAssessment enthält die regelbasierte Bewertung: DNS-Einstellungen je VNet, \
die DNS-Prüfung jedes Private Endpoints und Befunde (findings) zu PaaS und DNS. "graph" enthält Knoten \
und Beziehungen, "summary" und "discovery" Kennzahlen und Lücken der Datenerfassung.

Arbeitsweise:
- Beantworte Fragen zu konkreten Daten immer, indem du den Export mit Python lädt und gezielt \
auswertest (json.load einmal, dann filtern). Rate nie, erfinde keine Ressourcen, Adressen oder Regeln.
- Prüfe Sicherheitsaussagen im Zusammenhang: Subnet- und NIC-NSG, Routen/UDRs, Firewall, Public IPs.
- Nenne betroffene Ressourcen mit Namen und Resource Group.
- Antworte auf Deutsch, knapp und konkret; Listen und kurze Tabellen sind erwünscht, keine langen \
Einleitungen.
- Wenn eine Datei (CSV, Diagramm als PNG) hilft, erzeuge sie unter /mnt/data und verweise darauf.
- Zeige keinen Python-Code, außer der Nutzer fragt danach.`;

const REPORT_PROMPT = `Erstelle jetzt den Abschlussbericht dieser Sitzung. Werte den Export dafür \
mit Python systematisch aus: 1) IPv6-spezifische Lücken – Subnets/NICs mit öffentlicher \
IPv6-Konnektivität, die eine zentrale Kontrolle (Azure Firewall/NVA) umgehen, während IPv4 kontrolliert \
ist; NSG-Regeln, die IPv6 breiter erlauben als IPv4; fehlende IPv6-Default-Routen (Subnet, NSG und \
Routen gemeinsam prüfen); 2) weitere Architektur- und Sicherheitslücken – ungeschützte eingehende \
Pfade, offene Management-Ports aus dem Internet, asymmetrisches Routing, Default Outbound Access, \
Lücken der Datenerfassung; 3) PaaS-Endpunkte und DNS – öffentlich erreichbare Dienste, \
fehlerhafte Private-Endpoint-Auflösung, doppelte Private-DNS-Zonen (nutze \
assessmentContext.serviceAssessment als Ausgangspunkt und prüfe nach). Beziehe die im Chat besprochenen Punkte ein. Liefere eine kurze \
Gesamteinschätzung, alle Findings mit betroffenen Ressourcen und priorisierte Empfehlungen.`;

const REPORT_JSON_SCHEMA = {
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
} as const;

export const WELCOME_TEXT =
  "Der Export ist hochgeladen. Stellen Sie Ihre Frage – ich werte die Daten direkt mit Python aus.";

/** Compact overview of the export (counts per section) so the model needs no exploration step. */
export function exportOverview(data: AssessmentExport, fileName: string): string {
  const counts = Object.entries(data as unknown as Record<string, unknown>)
    .map(([key, value]) => {
      if (Array.isArray(value)) return value.length > 0 ? `${key}: ${value.length}` : undefined;
      if (value && typeof value === "object" && Array.isArray((value as { nodes?: unknown }).nodes)) {
        const g = value as { nodes: unknown[]; edges?: unknown[] };
        return `${key}: ${g.nodes.length} Knoten, ${g.edges?.length ?? 0} Kanten`;
      }
      return undefined;
    })
    .filter(Boolean);
  return `[Kontext: Export-Datei /mnt/data/…${fileName} – ${counts.join(", ")}]`;
}

/**
 * Uploads the export unchanged as one JSON file and opens a session. No model call happens here:
 * the first question already runs against the file, so the session is ready right after upload.
 */
export async function startAnalysisSession(
  ctx: AiContext,
  data: AssessmentExport,
  options: { signal?: AbortSignal | undefined; fileName?: string } = {},
): Promise<AiChatSession> {
  const fileName = options.fileName ?? "azure-network-assessment.json";
  try {
    const file = await ctx.client.files.create(
      {
        file: await toFile(new Blob([JSON.stringify(data)], { type: "application/json" }), fileName),
        purpose: "assistants",
      },
      { signal: options.signal },
    );
    return {
      id: crypto.randomUUID(),
      files: [{ id: file.id, name: fileName, kind: "export" }],
      responseIds: [],
      overview: exportOverview(data, fileName),
      messages: [{ role: "assistant", text: WELCOME_TEXT }],
    };
  } catch (e) {
    throw toAzureOpenAiError(e);
  }
}

/** Uploads user attachments (PDF, CSV, JSON, …) into the session's container. */
async function uploadAttachments(
  ctx: AiContext,
  attachments: File[],
  signal?: AbortSignal,
): Promise<SessionFile[]> {
  return Promise.all(
    attachments.map(async (f) => {
      const uploaded = await ctx.client.files.create(
        { file: await toFile(f, f.name), purpose: "assistants" },
        { signal },
      );
      return { id: uploaded.id, name: f.name, kind: "attachment" as const };
    }),
  );
}

function nextEffort(effort: ReasoningEffort | undefined): ReasoningEffort | undefined {
  if (!effort) return undefined;
  return effort === "minimal" || effort === "low" ? "medium" : effort;
}

interface TurnResult {
  id: string;
  text: string;
  generated: GeneratedFile[];
}

/** One streamed Responses API turn with Code Interpreter over the session's files. */
async function runTurn(
  ctx: AiContext,
  session: AiChatSession,
  content: ResponseInputContent[],
  callbacks: TurnCallbacks,
  extra: { effort?: ReasoningEffort | undefined; jsonSchema?: boolean } = {},
): Promise<TurnResult> {
  const effort = extra.effort ?? ctx.config.reasoningEffort;
  const body: ResponseCreateParamsStreaming = {
    model: ctx.config.model,
    instructions: INSTRUCTIONS,
    input: [{ role: "user", content }],
    tools: [
      { type: "code_interpreter", container: { type: "auto", file_ids: session.files.map((f) => f.id) } },
    ],
    store: true,
    stream: true,
    truncation: "auto",
    prompt_cache_key: "network-audit-ai",
    ...(session.lastResponseId ? { previous_response_id: session.lastResponseId } : {}),
    ...(effort ? { reasoning: { effort } } : {}),
    ...(extra.jsonSchema
      ? {
          text: {
            format: {
              type: "json_schema",
              name: "network_audit_report",
              schema: REPORT_JSON_SCHEMA,
              strict: true,
            },
          },
        }
      : {}),
  };

  let text = "";
  try {
    const stream = await ctx.client.responses.create(body, { signal: callbacks.signal });
    for await (const event of stream) {
      switch (event.type) {
        case "response.output_text.delta":
          text += event.delta;
          callbacks.onText?.(text);
          break;
        case "response.code_interpreter_call.in_progress":
        case "response.code_interpreter_call.interpreting":
          callbacks.onActivity?.("Werte die Daten mit Python aus …");
          break;
        case "response.reasoning_summary_part.added":
        case "response.in_progress":
          callbacks.onActivity?.("Denkt nach …");
          break;
        case "response.completed": {
          const r = event.response;
          return { id: r.id, text: outputText(r) || text, generated: generatedFiles(r) };
        }
        case "response.incomplete":
          throw new AzureOpenAiError(
            `Antwort unvollständig (${event.response.incomplete_details?.reason ?? "unbekannt"}).`,
          );
        case "response.failed":
          throw new AzureOpenAiError(
            `Azure OpenAI: ${event.response.error?.message ?? "Antwort fehlgeschlagen"}`,
          );
        case "error":
          throw new AzureOpenAiError(`Azure OpenAI: ${event.message}`);
      }
    }
  } catch (e) {
    throw toAzureOpenAiError(e);
  }
  throw new AzureOpenAiError("Die Verbindung zu Azure OpenAI wurde vor dem Ende der Antwort geschlossen.");
}

type CompletedResponse = Extract<Awaited<ReturnType<OpenAI["responses"]["retrieve"]>>, { output: unknown }>;

function messageContents(r: CompletedResponse) {
  return r.output.flatMap((item) => (item.type === "message" ? item.content : []));
}

function outputText(r: CompletedResponse): string {
  return messageContents(r)
    .map((c) => (c.type === "output_text" ? c.text : ""))
    .join("");
}

function generatedFiles(r: CompletedResponse): GeneratedFile[] {
  const out = new Map<string, GeneratedFile>();
  for (const c of messageContents(r)) {
    if (c.type !== "output_text") continue;
    for (const a of c.annotations) {
      if (a.type === "container_file_citation") {
        out.set(a.file_id, { containerId: a.container_id, fileId: a.file_id, filename: a.filename });
      }
    }
  }
  return [...out.values()];
}

/**
 * Sends one question. `images` (data URIs) go inline as vision input; `attachments` are uploaded
 * into the container and stay available for the rest of the session. The answer streams through
 * `callbacks.onText`.
 */
export async function sendChatMessage(
  ctx: AiContext,
  session: AiChatSession,
  text: string,
  options: TurnCallbacks & { images?: string[]; attachments?: File[] } = {},
): Promise<AiChatSession> {
  const images = options.images ?? [];
  const attachments = options.attachments ?? [];
  let files = session.files;
  if (attachments.length) {
    options.onActivity?.(`Lade ${attachments.length} Datei(en) hoch …`);
    try {
      files = [...files, ...(await uploadAttachments(ctx, attachments, options.signal))];
    } catch (e) {
      throw toAzureOpenAiError(e);
    }
  }
  const firstQuestion = session.lastResponseId === undefined;
  const attachmentNote = attachments.length
    ? `\n\n[Neu angehängte Dateien in /mnt/data: ${attachments.map((f) => f.name).join(", ")}]`
    : "";
  const content: ResponseInputContent[] = [
    { type: "input_text", text: `${firstQuestion ? `${session.overview}\n\n` : ""}${text}${attachmentNote}` },
    ...images.map((url) => ({ type: "input_image" as const, image_url: url, detail: "auto" as const })),
  ];
  const withFiles = { ...session, files };
  const res = await runTurn(ctx, withFiles, content, options);
  const userMessage: ChatMessage = {
    role: "user",
    text,
    ...(images.length ? { images } : {}),
    ...(attachments.length ? { attachments: attachments.map((f) => f.name) } : {}),
  };
  return {
    ...withFiles,
    lastResponseId: res.id,
    responseIds: [...session.responseIds, res.id],
    messages: [
      ...session.messages,
      userMessage,
      { role: "assistant", text: res.text, ...(res.generated.length ? { generated: res.generated } : {}) },
    ],
  };
}

/** Asks for the final report as strict JSON (Structured Outputs) within the same session. */
export async function generateReport(
  ctx: AiContext,
  session: AiChatSession,
  callbacks: TurnCallbacks = {},
): Promise<{ report: AiReport; session: AiChatSession }> {
  const prompt = `${session.lastResponseId === undefined ? `${session.overview}\n\n` : ""}${REPORT_PROMPT}`;
  const res = await runTurn(ctx, session, [{ type: "input_text", text: prompt }], callbacks, {
    effort: nextEffort(ctx.config.reasoningEffort),
    jsonSchema: true,
  });
  return {
    report: parseReport(res.text),
    session: { ...session, lastResponseId: res.id, responseIds: [...session.responseIds, res.id] },
  };
}

/** Downloads a file the model created in the container (chart, CSV, …). */
export async function downloadGeneratedFile(ctx: AiContext, file: GeneratedFile): Promise<Blob> {
  try {
    const res = await ctx.client.containers.files.content.retrieve(file.fileId, {
      container_id: file.containerId,
    });
    return await res.blob();
  } catch (e) {
    throw toAzureOpenAiError(e);
  }
}

/**
 * Deletes everything the session left in Azure OpenAI: uploaded files and stored responses (they
 * contain tenant data). The container expires on its own after 20 idle minutes. Best effort.
 */
export async function endSession(ctx: AiContext, session: AiChatSession): Promise<void> {
  await Promise.allSettled([
    ...session.files.map((f) => ctx.client.files.delete(f.id)),
    ...session.responseIds.map((id) => ctx.client.responses.delete(id)),
  ]);
}

export function parseReport(raw: string): AiReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(extractJson(raw));
  } catch {
    return { summary: raw, findings: [], recommendations: [] };
  }
  if (typeof parsed !== "object" || parsed === null)
    return { summary: raw, findings: [], recommendations: [] };
  const p = parsed as Record<string, unknown>;
  return {
    summary: typeof p.summary === "string" ? p.summary : "",
    findings: Array.isArray(p.findings)
      ? p.findings
          .filter(isFinding)
          .map((f) => ({ ...f, affected: f.affected.filter((a) => typeof a === "string") }))
      : [],
    recommendations: Array.isArray(p.recommendations)
      ? p.recommendations.filter((r): r is string => typeof r === "string")
      : [],
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

/** Models sometimes wrap JSON in a ```json fence; strip it if present. */
function extractJson(text: string): string {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  return (fenced ? fenced[1] : text)!.trim();
}
