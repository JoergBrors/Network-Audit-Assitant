import type { AiChatSession, ChatMessage } from "../../ai/analyze.js";
import type { FileSearchDocument } from "../../ai/azureOpenAi.js";

/**
 * Session directory: a browser-local (localStorage) history of KI-Analyse chat sessions.
 *
 * A session is either **minimized** (the user closed the window but chose to keep it running —
 * its temporary Azure OpenAI file/vector store is still alive, so the full chat state is persisted
 * here and the session can be resumed, even after a page reload) or **ended** (the user explicitly
 * ended it — its Azure OpenAI file/vector store has been deleted, so only a small metadata record
 * is kept for history; it can never be resumed since the data it would resume from no longer
 * exists). The Azure OpenAI API key is never persisted here — `config` is rebuilt from the
 * `VITE_AZURE_OPENAI_*` env vars on resume, not stored.
 */
export interface AiSessionRecord {
  id: string;
  startedAt: string;
  /** First user-visible line (e.g. the model's readiness message), truncated, for a recognizable label. */
  title: string;
  messageCount: number;
  status: "minimized" | "ended";
  endedAt?: string;
  /** Present only while `status === "minimized"` — everything needed to resume the session, except
   * the API key (see above). A minimized session keeps its Azure OpenAI vector store alive and
   * therefore keeps incurring file_search storage/indexing cost until it is resumed and ended. */
  resumable?: {
    doc: FileSearchDocument;
    lastResponseId: string;
    messages: ChatMessage[];
    sanitizationStats: { pseudonymizedTokens: number; publicIpsReplaced: number };
  };
}

const STORAGE_KEY = "ai-session-directory";
const MAX_RECORDS = 30;

function readAll(): AiSessionRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter(isRecord) : [];
  } catch {
    return [];
  }
}

function writeAll(records: AiSessionRecord[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, MAX_RECORDS)));
  } catch {
    // best effort: private window or full storage just means no history is kept
  }
}

function isRecord(value: unknown): value is AiSessionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "string" &&
    typeof v.startedAt === "string" &&
    typeof v.title === "string" &&
    typeof v.messageCount === "number" &&
    (v.status === "minimized" || v.status === "ended")
  );
}

export function listSessions(): AiSessionRecord[] {
  return [...readAll()].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}

export function recordSessionStarted(id: string, title: string): void {
  const records = readAll().filter((r) => r.id !== id);
  records.unshift({
    id,
    startedAt: new Date().toISOString(),
    title: title.slice(0, 140),
    messageCount: 1,
    status: "minimized",
  });
  writeAll(records);
}

export function recordSessionMessage(id: string, messageCount: number): void {
  const records = readAll();
  const i = records.findIndex((r) => r.id === id);
  if (i === -1) return;
  records[i] = { ...records[i]!, messageCount };
  writeAll(records);
}

/** Persists the full resumable state of a still-running session (called on "Minimieren" and kept
 * up to date on every message, so a page reload doesn't lose an in-progress minimized session). */
export function saveResumableSession(session: AiChatSession): void {
  const records = readAll();
  const i = records.findIndex((r) => r.id === session.id);
  const record: AiSessionRecord = {
    id: session.id,
    startedAt: records[i]?.startedAt ?? new Date().toISOString(),
    title: (records[i]?.title || session.messages[0]?.text) ?? "Sitzung",
    messageCount: session.messages.length,
    status: "minimized",
    resumable: {
      doc: session.doc,
      lastResponseId: session.lastResponseId,
      messages: session.messages,
      sanitizationStats: session.sanitizationStats,
    },
  };
  if (i === -1) records.unshift(record);
  else records[i] = record;
  writeAll(records);
}

/** Marks a session ended (its Azure OpenAI resources are gone) and drops the resumable payload —
 * only the small metadata record remains, for history. */
export function recordSessionEnded(id: string): void {
  const records = readAll();
  const i = records.findIndex((r) => r.id === id);
  if (i === -1) return;
  const { resumable: _resumable, ...rest } = records[i]!;
  records[i] = { ...rest, status: "ended", endedAt: new Date().toISOString() };
  writeAll(records);
}

/** The persisted state needed to resume a minimized session, or undefined if `id` isn't resumable
 * (unknown, or already ended). */
export function getResumableSession(id: string): AiSessionRecord["resumable"] | undefined {
  return readAll().find((r) => r.id === id && r.status === "minimized")?.resumable;
}

export function clearSessionDirectory(): void {
  writeAll([]);
}
