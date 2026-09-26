import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearSessionDirectory,
  getResumableSession,
  listSessions,
  recordSessionEnded,
  recordSessionMessage,
  recordSessionStarted,
  saveResumableSession,
} from "../../../src/ui/workspace/aiSessionDirectory.js";
import type { AiChatSession } from "../../../src/ai/analyze.js";

/** Minimal in-memory localStorage polyfill — the test environment is plain Node, and this module
 * only needs get/set/remove, not a full DOM. */
function createMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    getItem: (key) => store.get(key) ?? null,
    setItem: (key, value) => void store.set(key, String(value)),
    removeItem: (key) => void store.delete(key),
    clear: () => store.clear(),
    key: (i) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };
}

function fakeSession(overrides: Partial<AiChatSession> = {}): AiChatSession {
  return {
    id: "s1",
    config: { endpoint: "https://example.openai.azure.com", apiKey: "should-never-be-persisted", model: "gpt-5-mini" },
    doc: { fileId: "file-abc", vectorStoreId: "vs-abc" },
    lastResponseId: "resp_1",
    messages: [{ role: "assistant", text: "Bereit." }],
    sanitizationStats: { pseudonymizedTokens: 10, publicIpsReplaced: 2 },
    ...overrides,
  };
}

describe("aiSessionDirectory", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", createMemoryStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  it("starts empty", () => {
    expect(listSessions()).toEqual([]);
  });

  it("records a started session as minimized (resumable) with the given title", () => {
    recordSessionStarted("s1", "Bereit. Ich helfe bei der Analyse.");

    const sessions = listSessions();
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      id: "s1",
      title: "Bereit. Ich helfe bei der Analyse.",
      messageCount: 1,
      status: "minimized",
    });
  });

  it("truncates a very long title", () => {
    recordSessionStarted("s1", "x".repeat(500));
    expect(listSessions()[0]!.title.length).toBe(140);
  });

  it("updates the message count as the chat progresses", () => {
    recordSessionStarted("s1", "Bereit.");
    recordSessionMessage("s1", 5);

    expect(listSessions()[0]!.messageCount).toBe(5);
  });

  it("marks a session ended, stamps endedAt, and drops its resumable payload", () => {
    recordSessionStarted("s1", "Bereit.");
    saveResumableSession(fakeSession());
    recordSessionEnded("s1");

    const session = listSessions()[0]!;
    expect(session.status).toBe("ended");
    expect(session.endedAt).toEqual(expect.any(String));
    expect(session.resumable).toBeUndefined();
    expect(getResumableSession("s1")).toBeUndefined();
  });

  it("ignores updates/end for an unknown session id instead of throwing", () => {
    expect(() => recordSessionMessage("does-not-exist", 3)).not.toThrow();
    expect(() => recordSessionEnded("does-not-exist")).not.toThrow();
    expect(listSessions()).toEqual([]);
  });

  it("lists sessions most recently started first", () => {
    recordSessionStarted("s1", "Erste Sitzung");
    // Force distinguishable timestamps.
    const realNow = Date.now;
    vi.spyOn(Date, "now").mockReturnValue(realNow() + 10_000);
    recordSessionStarted("s2", "Zweite Sitzung");

    const ids = listSessions().map((s) => s.id);
    expect(ids).toEqual(["s2", "s1"]);
  });

  it("never persists chat content, export data, or the sanitizer key for a plain (non-resumable) start record", () => {
    recordSessionStarted("s1", "Bereit.");
    const raw = localStorage.getItem("ai-session-directory")!;
    const parsed = JSON.parse(raw) as Record<string, unknown>[];
    expect(Object.keys(parsed[0]!).sort()).toEqual(
      ["id", "messageCount", "startedAt", "status", "title"].sort(),
    );
  });

  it("clears the whole directory", () => {
    recordSessionStarted("s1", "Bereit.");
    clearSessionDirectory();
    expect(listSessions()).toEqual([]);
  });

  it("degrades gracefully (no throw) when localStorage is unavailable", () => {
    vi.stubGlobal("localStorage", {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    });

    expect(() => recordSessionStarted("s1", "Bereit.")).not.toThrow();
    expect(listSessions()).toEqual([]);
  });

  describe("saveResumableSession / getResumableSession", () => {
    it("persists everything needed to resume a session, but never the Azure OpenAI API key", () => {
      const session = fakeSession();
      saveResumableSession(session);

      const resumable = getResumableSession("s1");
      expect(resumable).toEqual({
        doc: session.doc,
        lastResponseId: session.lastResponseId,
        messages: session.messages,
        sanitizationStats: session.sanitizationStats,
      });
      const raw = localStorage.getItem("ai-session-directory")!;
      expect(raw).not.toContain("should-never-be-persisted");
    });

    it("marks the session minimized and creates a directory entry if one didn't exist yet", () => {
      saveResumableSession(fakeSession());

      const record = listSessions()[0]!;
      expect(record.status).toBe("minimized");
      expect(record.messageCount).toBe(1);
    });

    it("updates message count and resumable payload on repeated saves for the same session", () => {
      saveResumableSession(fakeSession());
      saveResumableSession(
        fakeSession({
          messages: [
            { role: "assistant", text: "Bereit." },
            { role: "user", text: "Frage" },
            { role: "assistant", text: "Antwort" },
          ],
          lastResponseId: "resp_2",
        }),
      );

      expect(listSessions()).toHaveLength(1);
      const record = listSessions()[0]!;
      expect(record.messageCount).toBe(3);
      expect(record.resumable?.lastResponseId).toBe("resp_2");
    });

    it("returns undefined for an ended (non-resumable) or unknown session", () => {
      recordSessionStarted("s1", "Bereit.");
      recordSessionEnded("s1");

      expect(getResumableSession("s1")).toBeUndefined();
      expect(getResumableSession("does-not-exist")).toBeUndefined();
    });
  });
});
