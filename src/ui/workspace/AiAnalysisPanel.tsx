import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AccessToken } from "@azure/core-auth";
import type { AiChatSession, AiContext, AiFinding, AiReport, GeneratedFile } from "../../ai/analyze.js";
import {
  downloadGeneratedFile,
  endSession,
  generateReport,
  sendChatMessage,
  startAnalysisSession,
} from "../../ai/analyze.js";
import { createAzureOpenAiClient, readAzureOpenAiConfigFromEnv } from "../../ai/azureOpenAi.js";
import type { AssessmentExport } from "../../export/assessmentJson.js";
import { downloadAiReportPdf } from "../../export/aiReportPdf.js";
import { ChatMarkdown } from "./ChatMarkdown.js";
import { downloadBlob, downloadJson } from "./download.js";
import { FloatingOverlay } from "./FloatingOverlay.js";
import {
  listSessions,
  loadResumableSession,
  recordSessionEnded,
  saveSession,
  type AiSessionRecord,
} from "./aiSessionDirectory.js";

const SEVERITY_ORDER: Record<AiFinding["severity"], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

/** Below this, only the spinning shield shows; above it the rainbow dots signal "still working". */
const LONG_WAIT_MS = 4000;
/** Upload limit per attachment (Azure OpenAI files: 512 MB; keep chat uploads reasonable). */
const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;

function NetworkShieldSpinner({ label }: { label: string }) {
  return (
    <div className="ai-wait-indicator">
      <svg className="ai-shield-spin" width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
        <path
          d="M12 2 L20 5.5 V11 C20 16 16.5 20 12 22 C7.5 20 4 16 4 11 V5.5 Z"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
        />
        <path
          d="M8.5 12.5 L11 15 L16 9.5"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="small muted">{label}</span>
    </div>
  );
}

const RAINBOW = ["#e11d48", "#f59e0b", "#eab308", "#22c55e", "#3b82f6"];

function RainbowDots() {
  const order = [2, 1, 3, 0, 4];
  return (
    <div className="ai-rainbow-dots" aria-hidden="true">
      {order.map((visualIndex, i) => (
        <span
          key={i}
          className="ai-rainbow-dot"
          style={{ background: RAINBOW[visualIndex], animationDelay: `${i * 0.12}s` }}
        />
      ))}
    </div>
  );
}

function readAsDataUrl(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(new Error("Datei konnte nicht gelesen werden."));
    reader.readAsDataURL(file);
  });
}

const isImage = (f: File) => /^image\/(png|jpeg|gif|webp)$/.test(f.type);

export interface AiCredential {
  getToken(scopes: string | string[]): Promise<AccessToken | null>;
}

/**
 * KI-Analyse: uploads the current export unchanged to the internal Azure OpenAI deployment and
 * opens a streamed chat in which the model queries the data with Code Interpreter. Files and
 * images can be attached; files the model creates can be downloaded. "Report erzeugen" returns a
 * typed report (Structured Outputs) that is rendered to PDF in the browser. Closing (✕) deletes
 * the uploaded files and stored responses; "Minimieren" keeps the session for this tab.
 */
export function AiAnalysisPanel({
  buildExport,
  source,
  credential,
  accountName,
  onClose,
}: {
  buildExport: () => AssessmentExport;
  /** Label of the data basis (discovery or snapshot file), for the PDF. */
  source: string;
  /** MSAL credential of the signed-in user (Entra ID); undefined when not signed in. */
  credential: AiCredential | undefined;
  accountName: string | undefined;
  onClose: () => void;
}) {
  const config = useMemo(() => readAzureOpenAiConfigFromEnv(), []);
  // An explicitly configured API key wins, so no Microsoft sign-in is needed for the AI.
  const auth: "entra" | "key" | "none" = config?.apiKey
    ? "key"
    : credential && accountName
      ? "entra"
      : "none";
  const ctx = useMemo<AiContext | undefined>(() => {
    if (!config || auth === "none") return undefined;
    const tokenProvider =
      auth === "entra"
        ? async () => {
            const token = await credential!.getToken(config.scope);
            if (!token) throw new Error("Kein Token für Azure OpenAI erhalten.");
            return token.token;
          }
        : undefined;
    return { client: createAzureOpenAiClient(config, tokenProvider), config };
  }, [config, auth, credential]);

  const [session, setSession] = useState<AiChatSession | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [pendingImages, setPendingImages] = useState<string[]>([]);
  const [pendingFiles, setPendingFiles] = useState<File[]>([]);
  const [streaming, setStreaming] = useState<{ question?: string; text: string } | null>(null);
  const [activity, setActivity] = useState<string | null>(null);
  const [showRainbow, setShowRainbow] = useState(false);
  const [report, setReport] = useState<AiReport | null>(null);
  const [showDirectory, setShowDirectory] = useState(false);
  const [directory, setDirectory] = useState<AiSessionRecord[]>(() => listSessions());
  const messagesEnd = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const sessionRef = useRef<AiChatSession | null>(null);
  const ctxRef = useRef<AiContext | undefined>(ctx);
  // Set right before "Minimieren" so the unmount cleanup keeps that session's Azure data.
  const minimizedIdRef = useRef<string | null>(null);

  useEffect(() => {
    sessionRef.current = session;
    ctxRef.current = ctx;
  }, [session, ctx]);

  useEffect(
    () => () => {
      abortRef.current?.abort();
      const s = sessionRef.current;
      if (s && ctxRef.current && minimizedIdRef.current !== s.id) {
        void endSession(ctxRef.current, s);
        recordSessionEnded(s.id);
      }
    },
    [],
  );

  useEffect(() => {
    setShowRainbow(false);
    if (!activity) return;
    const t = setTimeout(() => setShowRainbow(true), LONG_WAIT_MS);
    return () => clearTimeout(t);
  }, [activity]);

  const scrollToEnd = useCallback(() => {
    requestAnimationFrame(() => messagesEnd.current?.scrollIntoView({ block: "end" }));
  }, []);

  /** Runs one request with busy/abort/error handling. */
  const run = useCallback(async (label: string, work: (signal: AbortSignal) => Promise<void>) => {
    const controller = new AbortController();
    abortRef.current = controller;
    setBusy(true);
    setError(null);
    setActivity(label);
    try {
      await work(controller.signal);
    } catch (e) {
      if (!controller.signal.aborted) setError(e instanceof Error ? e.message : String(e));
    } finally {
      abortRef.current = null;
      setBusy(false);
      setActivity(null);
      setStreaming(null);
    }
  }, []);

  const persist = useCallback((s: AiChatSession) => {
    setSession(s);
    saveSession(s);
    setDirectory(listSessions());
  }, []);

  const start = useCallback(
    () =>
      run("Lade den Export hoch …", async (signal) => {
        if (!ctx) return;
        persist(await startAnalysisSession(ctx, buildExport(), { signal }));
        setReport(null);
      }),
    [ctx, run, buildExport, persist],
  );

  const send = useCallback(async () => {
    if (!ctx || !session || busy) return;
    if (!draft.trim() && pendingImages.length === 0 && pendingFiles.length === 0) return;
    const text =
      draft.trim() || (pendingFiles.length ? "Bitte werte die angehängte(n) Datei(en) aus." : "Siehe Bild.");
    const images = pendingImages;
    const attachments = pendingFiles;
    setDraft("");
    setPendingImages([]);
    setPendingFiles([]);
    setStreaming({ question: text, text: "" });
    scrollToEnd();
    await run("Denkt nach …", async (signal) => {
      try {
        const updated = await sendChatMessage(ctx, session, text, {
          signal,
          images,
          attachments,
          onText: (t) => {
            setActivity(null);
            setStreaming({ question: text, text: t });
            scrollToEnd();
          },
          onActivity: setActivity,
        });
        persist(updated);
        scrollToEnd();
      } catch (e) {
        // Give the question back so it can be sent again.
        setDraft(text);
        setPendingImages(images);
        setPendingFiles(attachments);
        throw e;
      }
    });
  }, [ctx, session, busy, draft, pendingImages, pendingFiles, run, persist, scrollToEnd]);

  const addFiles = useCallback(async (files: File[]) => {
    const tooBig = files.filter((f) => f.size > MAX_ATTACHMENT_BYTES);
    if (tooBig.length) setError(`Zu groß (max. 50 MB): ${tooBig.map((f) => f.name).join(", ")}`);
    const ok = files.filter((f) => f.size <= MAX_ATTACHMENT_BYTES);
    const images = await Promise.all(ok.filter(isImage).map(readAsDataUrl));
    setPendingImages((prev) => [...prev, ...images]);
    setPendingFiles((prev) => [...prev, ...ok.filter((f) => !isImage(f))]);
  }, []);

  const createReport = useCallback(
    () =>
      run("Erstelle den Abschlussbericht …", async (signal) => {
        if (!ctx || !session) return;
        const result = await generateReport(ctx, session, { signal, onActivity: setActivity });
        persist(result.session);
        setReport(result.report);
      }),
    [ctx, session, run, persist],
  );

  const download = useCallback(
    async (file: GeneratedFile) => {
      if (!ctx) return;
      try {
        downloadBlob(file.filename, await downloadGeneratedFile(ctx, file));
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [ctx],
  );

  const endAndClose = useCallback(() => {
    abortRef.current?.abort();
    if (session && ctx) {
      void endSession(ctx, session);
      recordSessionEnded(session.id);
      sessionRef.current = null;
    }
    onClose();
  }, [session, ctx, onClose]);

  const minimize = useCallback(() => {
    if (session) {
      minimizedIdRef.current = session.id;
      saveSession(session);
    }
    onClose();
  }, [session, onClose]);

  const resume = useCallback(
    (record: AiSessionRecord) => {
      const restored = loadResumableSession(record.id);
      if (!restored) return;
      setSession(restored);
      setReport(null);
      setError(null);
      setShowDirectory(false);
      scrollToEnd();
    },
    [scrollToEnd],
  );

  const sortedFindings = useMemo(
    () =>
      [...(report?.findings ?? [])].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    [report],
  );
  const hasPending = pendingImages.length > 0 || pendingFiles.length > 0;

  return (
    <FloatingOverlay
      title="KI-Analyse (Azure OpenAI)"
      onClose={endAndClose}
      headerExtra={
        <>
          {session && (
            <button
              className="secondary small"
              onClick={minimize}
              title="Fenster schließen, Sitzung in diesem Tab fortsetzbar halten"
            >
              Minimieren
            </button>
          )}
          <button className="secondary small" onClick={() => setShowDirectory((v) => !v)}>
            Sitzungsverzeichnis
          </button>
        </>
      }
    >
      <div className="ai-panel-body">
        {showDirectory && (
          <div className="ai-session-directory">
            <div className="row">
              <strong className="small">Frühere Sitzungen</strong>
              <button className="secondary small" onClick={() => setShowDirectory(false)}>
                Schließen
              </button>
            </div>
            {directory.length === 0 && <p className="muted small">Noch keine Sitzungen.</p>}
            <ul>
              {directory.map((s) => (
                <li
                  key={s.id}
                  className={`small${s.resumable ? " clickable" : ""}`}
                  onClick={() => s.resumable && resume(s)}
                  title={s.resumable ? "Klicken zum Fortsetzen" : undefined}
                >
                  <span
                    className={`ai-session-status ai-session-status-${s.resumable ? "minimized" : "ended"}`}
                  />
                  {new Date(s.startedAt).toLocaleString("de-DE")} · {s.messageCount} Nachrichten
                  {s.resumable
                    ? " · fortsetzbar"
                    : s.status === "ended"
                      ? " · beendet"
                      : " · nicht mehr verfügbar"}
                  <div className="muted ai-session-title">{s.title}</div>
                </li>
              ))}
            </ul>
            <p className="muted small">
              Im Browser bleiben nur Zeitpunkt, erste Frage und Anzahl der Nachrichten. Der Chat einer
              minimierten Sitzung liegt nur in diesem Tab (sessionStorage) und ist nach dem Schließen des Tabs
              weg.
            </p>
          </div>
        )}

        {!config && (
          <p className="status-warn small">
            Azure OpenAI ist nicht konfiguriert. Bitte <code>VITE_AZURE_OPENAI_ENDPOINT</code> und{" "}
            <code>VITE_AZURE_OPENAI_MODEL</code> in <code>.env.local</code> setzen (siehe{" "}
            <code>.env.example</code>) und die Anwendung neu starten.
          </p>
        )}
        {config && auth === "none" && (
          <p className="status-warn small">
            Bitte mit Microsoft Entra ID anmelden – die KI-Analyse nutzt Ihr Konto (Rolle „Cognitive Services
            OpenAI User“ auf der Azure-OpenAI-Ressource).
          </p>
        )}

        {config && auth !== "none" && !session && (
          <>
            <p className="muted small">
              Der aktuelle Export wird unverändert an das interne Azure-OpenAI-Deployment{" "}
              <code>{config.model}</code> übertragen (
              {auth === "entra" ? `Anmeldung als ${accountName}` : "API-Schlüssel"}). Das Modell wertet ihn
              per Code Interpreter aus. Schließen (✕) löscht die hochgeladenen Dateien und gespeicherten
              Antworten.
            </p>
            <button onClick={() => void start()} disabled={busy}>
              Sitzung starten
            </button>
          </>
        )}

        {activity && !session && (
          <div className="ai-wait">
            <NetworkShieldSpinner label={activity} />
            {showRainbow && <RainbowDots />}
          </div>
        )}

        {error && <p className="status-error small mono">{error}</p>}

        {session && (
          <div className="ai-chat">
            <div className="ai-chat-messages">
              {session.messages.map((m, i) => (
                <div key={i} className={`ai-chat-bubble ai-chat-bubble-${m.role}`}>
                  <div className="ai-chat-bubble-text">
                    {m.role === "assistant" ? <ChatMarkdown text={m.text} /> : m.text}
                  </div>
                  {m.images && m.images.length > 0 && (
                    <div className="ai-chat-bubble-images">
                      {m.images.map((src, j) => (
                        <img key={j} src={src} alt="Angehängtes Bild" className="ai-chat-image" />
                      ))}
                    </div>
                  )}
                  {m.attachments && m.attachments.length > 0 && (
                    <div className="ai-chat-files small">📎 {m.attachments.join(", ")}</div>
                  )}
                  {m.generated && m.generated.length > 0 && (
                    <div className="ai-chat-files">
                      {m.generated.map((f) => (
                        <button key={f.fileId} className="secondary small" onClick={() => void download(f)}>
                          ⬇ {f.filename}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {streaming?.question && (
                <div className="ai-chat-bubble ai-chat-bubble-user">
                  <div className="ai-chat-bubble-text">{streaming.question}</div>
                </div>
              )}
              {streaming?.text && (
                <div className="ai-chat-bubble ai-chat-bubble-assistant">
                  <div className="ai-chat-bubble-text">
                    <ChatMarkdown text={streaming.text} />
                  </div>
                </div>
              )}
              {activity && (
                <div className="ai-wait ai-wait-inline">
                  <NetworkShieldSpinner label={activity} />
                  {showRainbow && <RainbowDots />}
                </div>
              )}
              <div ref={messagesEnd} />
            </div>

            {hasPending && (
              <div className="ai-pending-images">
                {pendingImages.map((src, i) => (
                  <div key={`i${i}`} className="ai-pending-image">
                    <img src={src} alt="Zum Senden bereites Bild" />
                    <button
                      className="ai-pending-image-remove"
                      aria-label="Bild entfernen"
                      onClick={() => setPendingImages((prev) => prev.filter((_, j) => j !== i))}
                    >
                      ✕
                    </button>
                  </div>
                ))}
                {pendingFiles.map((f, i) => (
                  <span key={`f${i}`} className="ai-pending-file small">
                    📎 {f.name}
                    <button
                      className="ai-pending-image-remove"
                      aria-label="Datei entfernen"
                      onClick={() => setPendingFiles((prev) => prev.filter((_, j) => j !== i))}
                    >
                      ✕
                    </button>
                  </span>
                ))}
              </div>
            )}

            <div className="ai-composer">
              <textarea
                placeholder="Frage stellen, z. B. „Welche Subnets haben IPv6 ohne Firewall?“ – Bilder einfügen oder Dateien anhängen möglich."
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onPaste={(e) => {
                  const files = [...e.clipboardData.files];
                  if (files.length) {
                    e.preventDefault();
                    void addFiles(files);
                  }
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  void addFiles([...e.dataTransfer.files]);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void send();
                  }
                }}
                disabled={busy}
                rows={2}
              />
              <input
                ref={fileInput}
                type="file"
                multiple
                hidden
                onChange={(e) => {
                  void addFiles([...(e.target.files ?? [])]);
                  e.target.value = "";
                }}
              />
              <div className="row">
                {busy ? (
                  <button className="secondary" onClick={() => abortRef.current?.abort()}>
                    Abbrechen
                  </button>
                ) : (
                  <button onClick={() => void send()} disabled={!draft.trim() && !hasPending}>
                    Senden
                  </button>
                )}
                <button className="secondary" onClick={() => fileInput.current?.click()} disabled={busy}>
                  Datei anhängen
                </button>
                <button className="secondary" onClick={() => void createReport()} disabled={busy}>
                  Report erzeugen
                </button>
              </div>
            </div>
          </div>
        )}

        {report && (
          <div className="ai-analysis-result">
            <h3>Zusammenfassung</h3>
            <p className="small">{report.summary}</p>

            <h3>Findings ({sortedFindings.length})</h3>
            {sortedFindings.length === 0 && <p className="muted small">Keine Findings gemeldet.</p>}
            <ul className="ai-findings">
              {sortedFindings.map((f, i) => (
                <li key={i}>
                  <span className={`severity-badge severity-${f.severity}`}>{f.severity}</span>{" "}
                  <strong>{f.title}</strong>
                  <p className="small">{f.description}</p>
                  {f.affected.length > 0 && (
                    <p className="mono muted small">Betroffen: {f.affected.join(", ")}</p>
                  )}
                </li>
              ))}
            </ul>

            {report.recommendations.length > 0 && (
              <>
                <h3>Empfehlungen</h3>
                <ol>
                  {report.recommendations.map((r, i) => (
                    <li key={i} className="small">
                      {r}
                    </li>
                  ))}
                </ol>
              </>
            )}

            <div className="row">
              <button
                className="secondary"
                onClick={() =>
                  void downloadAiReportPdf(report, {
                    ...(config ? { model: config.model } : {}),
                    source,
                    ...(session ? { transcript: session.messages.slice(1) } : {}),
                  }).catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
                }
              >
                Als PDF herunterladen
              </button>
              <button className="secondary" onClick={() => downloadJson("ai-analysis-report.json", report)}>
                Als JSON herunterladen
              </button>
            </div>
          </div>
        )}
      </div>
    </FloatingOverlay>
  );
}
