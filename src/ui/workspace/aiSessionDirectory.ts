import type { AiChatSession, ChatMessage } from "../../ai/analyze.js";

/**
 * Session directory for the KI-Analyse.
 *
 * - Metadata (time, title, message count, status) lives in `localStorage`, so past sessions stay
 *   visible as history.
 * - The resumable state of a minimized session (file/response ids and the chat without images)
 *   contains tenant data and therefore lives in `sessionStorage` only: it survives a reload of the
 *   tab, but is gone when the tab is closed. Its Azure OpenAI files then remain until they are
 *   deleted in the resource (they are not reachable from another tab).
 *
 * Credentials are never stored here.
 */
export interface AiSessionRecord {
  id: string;
  startedAt: string;
  title: string;
  messageCount: number;
  status: "minimized" | "ended";
  endedAt?: string;
  /** True while the resumable state is available in this tab. */
  resumable?: boolean;
}

export type ResumableSession = Omit<AiChatSession, "id">;

const STORAGE_KEY = "ai-session-directory";
const RESUME_PREFIX = "ai-session-resume:";
const MAX_RECORDS = 30;

function storage(kind: "local" | "session"): Storage | undefined {
  try {
    return kind === "local" ? localStorage : sessionStorage;
  } catch {
    return undefined;
  }
}

function readAll(): AiSessionRecord[] {
  try {
    const raw = storage("local")?.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter(isRecord).map(stripLegacy) : [];
  } catch {
    return [];
  }
}

function writeAll(records: AiSessionRecord[]): void {
  try {
    storage("local")?.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, MAX_RECORDS)));
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

/** Older versions kept the whole chat in `localStorage`; drop it on read. */
function stripLegacy(r: AiSessionRecord): AiSessionRecord {
  const { id, startedAt, title, messageCount, status, endedAt } = r;
  return { id, startedAt, title, messageCount, status, ...(endedAt ? { endedAt } : {}) };
}

export function listSessions(): AiSessionRecord[] {
  const s = storage("session");
  return readAll()
    .map((r) => ({ ...r, resumable: r.status === "minimized" && !!s?.getItem(RESUME_PREFIX + r.id) }))
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
}

/** Title for the directory: the first question, else a neutral label. */
function titleOf(messages: ChatMessage[]): string {
  return (messages.find((m) => m.role === "user")?.text ?? "Neue Sitzung").slice(0, 140);
}

/** Records the session and keeps its resumable state for this tab (called after every turn). */
export function saveSession(session: AiChatSession): void {
  const records = readAll();
  const i = records.findIndex((r) => r.id === session.id);
  const record: AiSessionRecord = {
    id: session.id,
    startedAt: records[i]?.startedAt ?? new Date().toISOString(),
    title: titleOf(session.messages),
    messageCount: session.messages.length,
    status: "minimized",
  };
  if (i === -1) records.unshift(record);
  else records[i] = record;
  writeAll(records);

  const { id: _id, ...state } = session;
  const withoutImages: ResumableSession = {
    ...state,
    messages: state.messages.map(({ images, ...m }) =>
      images?.length ? { ...m, text: `${m.text}\n[${images.length} Bild(er)]` } : m,
    ),
  };
  try {
    storage("session")?.setItem(RESUME_PREFIX + session.id, JSON.stringify(withoutImages));
  } catch {
    // best effort
  }
}

/** Resumable state of a minimized session in this tab, if any. */
export function loadResumableSession(id: string): AiChatSession | undefined {
  try {
    const raw = storage("session")?.getItem(RESUME_PREFIX + id);
    if (!raw) return undefined;
    const state = JSON.parse(raw) as ResumableSession;
    if (!Array.isArray(state.files) || !Array.isArray(state.messages)) return undefined;
    return { id, ...state, responseIds: state.responseIds ?? [] };
  } catch {
    return undefined;
  }
}

/** Marks a session ended (its Azure OpenAI data is deleted) and drops its resumable state. */
export function recordSessionEnded(id: string): void {
  try {
    storage("session")?.removeItem(RESUME_PREFIX + id);
  } catch {
    // best effort
  }
  const records = readAll();
  const i = records.findIndex((r) => r.id === id);
  if (i === -1) return;
  records[i] = { ...records[i]!, status: "ended", endedAt: new Date().toISOString() };
  writeAll(records);
}

export function clearSessionDirectory(): void {
  writeAll([]);
}
