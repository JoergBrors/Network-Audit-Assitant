import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearSessionDirectory,
  listSessions,
  loadResumableSession,
  recordSessionEnded,
  saveSession,
} from "../../../src/ui/workspace/aiSessionDirectory.js";
import type { AiChatSession } from "../../../src/ai/analyze.js";

/** In-memory Web Storage (the test environment is plain Node). */
function createMemoryStorage(): Storage & { dump(): string } {
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
    dump: () => [...store.values()].join("\n"),
  };
}

function fakeSession(overrides: Partial<AiChatSession> = {}): AiChatSession {
  return {
    id: "s1",
    files: [{ id: "file-1", name: "azure-network-assessment.json", kind: "export" }],
    responseIds: ["resp_1"],
    lastResponseId: "resp_1",
    overview: "[Kontext]",
    messages: [
      { role: "assistant", text: "Bereit." },
      { role: "user", text: "Welche NSG gehört zu vm-prod-01?", images: ["data:image/png;base64,AAAA"] },
      { role: "assistant", text: "nsg-prod-01" },
    ],
    ...overrides,
  };
}

describe("aiSessionDirectory", () => {
  let local: ReturnType<typeof createMemoryStorage>;
  let session: ReturnType<typeof createMemoryStorage>;
  beforeEach(() => {
    local = createMemoryStorage();
    session = createMemoryStorage();
    vi.stubGlobal("localStorage", local);
    vi.stubGlobal("sessionStorage", session);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("starts empty", () => {
    expect(listSessions()).toEqual([]);
  });

  it("keeps only metadata in localStorage and the chat in sessionStorage", () => {
    saveSession(fakeSession());
    expect(listSessions()).toEqual([
      expect.objectContaining({
        id: "s1",
        title: "Welche NSG gehört zu vm-prod-01?",
        messageCount: 3,
        status: "minimized",
        resumable: true,
      }),
    ]);
    expect(local.dump()).toContain("vm-prod-01"); // title = first question
    expect(local.dump()).not.toContain("nsg-prod-01");
    expect(local.dump()).not.toContain("file-1");
    expect(session.dump()).toContain("nsg-prod-01");
  });

  it("restores a minimized session without its images", () => {
    saveSession(fakeSession());
    const restored = loadResumableSession("s1")!;
    expect(restored.files[0]!.id).toBe("file-1");
    expect(restored.lastResponseId).toBe("resp_1");
    expect(restored.messages[1]).toEqual({
      role: "user",
      text: "Welche NSG gehört zu vm-prod-01?\n[1 Bild(er)]",
    });
    expect(session.dump()).not.toContain("base64");
  });

  it("is not resumable once the tab's sessionStorage is gone", () => {
    saveSession(fakeSession());
    session.clear();
    expect(listSessions()[0]!.resumable).toBe(false);
    expect(loadResumableSession("s1")).toBeUndefined();
  });

  it("marks a session ended and drops its resumable state", () => {
    saveSession(fakeSession());
    recordSessionEnded("s1");
    expect(listSessions()[0]).toMatchObject({ status: "ended", resumable: false });
    expect(listSessions()[0]!.endedAt).toBeDefined();
    expect(loadResumableSession("s1")).toBeUndefined();
  });

  it("drops chat content that older versions stored in localStorage", () => {
    local.setItem(
      "ai-session-directory",
      JSON.stringify([
        {
          id: "old",
          startedAt: "2026-01-01T00:00:00Z",
          title: "t",
          messageCount: 2,
          status: "minimized",
          resumable: { messages: [{ role: "user", text: "geheim" }] },
        },
      ]),
    );
    saveSession(fakeSession());
    expect(local.dump()).not.toContain("geheim");
    expect(listSessions().find((r) => r.id === "old")?.resumable).toBe(false);
  });

  it("truncates long titles, sorts newest first and can be cleared", () => {
    saveSession(fakeSession({ id: "a", messages: [{ role: "user", text: "x".repeat(500) }] }));
    saveSession(fakeSession({ id: "b" }));
    const [newest] = listSessions();
    expect(listSessions().find((r) => r.id === "a")!.title).toHaveLength(140);
    expect(newest!.startedAt >= listSessions()[1]!.startedAt).toBe(true);
    clearSessionDirectory();
    expect(listSessions()).toEqual([]);
  });

  it("survives unavailable storage", () => {
    vi.stubGlobal("localStorage", undefined);
    vi.stubGlobal("sessionStorage", undefined);
    expect(() => saveSession(fakeSession())).not.toThrow();
    expect(listSessions()).toEqual([]);
  });
});
