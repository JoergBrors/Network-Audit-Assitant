import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AiChatSession, AiFinding, AiReport, StartSessionPhase } from "../../ai/analyze.js";
import {
  endSession,
  generateReport,
  resumeSession,
  sendChatMessage,
  startAnalysisSession,
} from "../../ai/analyze.js";
import { readAzureOpenAiConfigFromEnv } from "../../ai/azureOpenAi.js";
import type { AssessmentExport } from "../../export/assessmentJson.js";
import { downloadJson } from "./download.js";
import { downloadAiReportPdf } from "../../export/aiReportPdf.js";
import { FloatingOverlay } from "./FloatingOverlay.js";
import {
  listSessions,
  recordSessionEnded,
  recordSessionStarted,
  saveResumableSession,
  type AiSessionRecord,
} from "./aiSessionDirectory.js";

const SEVERITY_ORDER: Record<AiFinding["severity"], number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const PHASE_LABEL: Record<StartSessionPhase, string> = {
  sanitizing: "Anonymisiere Export (Namen/IDs/öffentliche IPs werden durch Pseudonyme ersetzt) …",
  uploading: "Lade anonymisierten Export in einen temporären Speicher hoch …",
  indexing: "Indiziere den Export für die gezielte Suche (file_search) …",
  ready: "Sitzung bereit.",
};

/** Long-wait threshold: below this, only the spinning shield shows; at/above it (typically a
 * rate-limit retry with a multi-second wait), the rainbow dots also appear so a long pause reads as
 * "still working", not "stuck". */
const LONG_WAIT_MS = 4000;

/** Spinning network-shield icon shown while a request is in flight — the short-wait indicator. */
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

/** Five dots in rainbow colors bouncing outward left/right — shown in addition to the shield once a
 * wait has gone on long enough (e.g. a rate-limit backoff) that a longer, more visible "still
 * working" signal is warranted. */
function RainbowDots() {
  const order = [2, 1, 3, 0, 4]; // center-out animation order, left/right symmetric
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

interface WaitState {
  label: string;
}

const SANITIZE_KEY_STORAGE_KEY = "ai-sanitizer-key";

/** The sanitizer key is not an Azure secret — it's a value the user picks themselves to make the
 * pseudonymization deterministic across sessions/exports (see src/export/sanitize.ts). Remembering
 * it in localStorage saves re-typing it every time; it's still never sent anywhere by itself, only
 * used locally to derive pseudonyms before anything leaves the browser. */
function loadSavedSanitizeKey(): string {
  try {
    return localStorage.getItem(SANITIZE_KEY_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

function saveSanitizeKey(key: string): void {
  try {
    if (key) localStorage.setItem(SANITIZE_KEY_STORAGE_KEY, key);
    else localStorage.removeItem(SANITIZE_KEY_STORAGE_KEY);
  } catch {
    // best effort: private window or full storage just means it isn't remembered
  }
}

/** Reads image files out of a paste event's clipboard data as data URIs. */
async function imagesFromClipboard(e: React.ClipboardEvent): Promise<string[]> {
  const files = [...e.clipboardData.items]
    .filter((item) => item.kind === "file" && item.type.startsWith("image/"))
    .map((item) => item.getAsFile())
    .filter((f): f is File => f !== null);
  return Promise.all(
    files.map(
      (file) =>
        new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.onerror = () => reject(new Error("Bild konnte nicht gelesen werden."));
          reader.readAsDataURL(file);
        }),
    ),
  );
}

/**
 * Sanitizes the current export (see src/export/sanitize.ts), uploads it once to a temporary
 * Azure OpenAI vector store, and opens a chat session backed by `file_search` against it — every
 * turn (including the first) only pulls in the chunks relevant to the current question, which is
 * what keeps token usage low regardless of tenant size (see ARCHITECTURE.md § 22). The user can ask
 * follow-up questions in a normal chat window, paste an image from the clipboard as visual context
 * for a question, and switch between past sessions via the session directory. "Report erzeugen"
 * asks for one strictly-typed JSON report (Structured Outputs) and turns it into a downloadable PDF
 * client-side. Closing the panel deletes the temporary upload/vector store.
 */
export function AiAnalysisPanel({
  buildExport,
  onClose,
}: {
  buildExport: () => AssessmentExport;
  onClose: () => void;
}) {
  const config = useMemo(() => readAzureOpenAiConfigFromEnv(), []);
  const [sanitizeKey, setSanitizeKeyState] = useState(loadSavedSanitizeKey);
  const setSanitizeKey = useCallback((key: string) => {
    setSanitizeKeyState(key);
    saveSanitizeKey(key);
  }, []);
  const [session, setSession] = useState<AiChatSession | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [pendingImages, setPendingImages] = useState<string[]>([]);
  const [report, setReport] = useState<AiReport | null>(null);
  const [wait, setWait] = useState<WaitState | null>(null);
  const [showRainbow, setShowRainbow] = useState(false);
  const [showDirectory, setShowDirectory] = useState(false);
  const [directory, setDirectory] = useState<AiSessionRecord[]>(() => listSessions());
  const messagesEnd = useRef<HTMLDivElement>(null);
  const sessionRef = useRef<AiChatSession | null>(null);
  // Set right before an intentional "Minimieren" so the unmount cleanup below skips deletion for
  // that session — everything else (closing the app tab, an error, simply not minimizing first)
  // still deletes the temporary Azure OpenAI file/vector store, which is the safe default.
  const minimizedIdRef = useRef<string | null>(null);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  // Unmount: release the temporary vector store UNLESS the session was just minimized (its data is
  // meant to survive so it can be resumed later) — best-effort cleanup, fire-and-forget.
  useEffect(
    () => () => {
      const s = sessionRef.current;
      if (s && minimizedIdRef.current !== s.id) {
        void endSession(s);
        recordSessionEnded(s.id);
      }
    },
    [],
  );

  useEffect(() => {
    if (!wait) {
      setShowRainbow(false);
      return;
    }
    setShowRainbow(false);
    const t = setTimeout(() => setShowRainbow(true), LONG_WAIT_MS);
    return () => clearTimeout(t);
  }, [wait]);

  const scrollToEnd = useCallback(() => {
    requestAnimationFrame(() => messagesEnd.current?.scrollIntoView({ behavior: "smooth" }));
  }, []);

  const withRetryIndicator = useCallback(
    (baseLabel: string) => ({
      onRetry: (info: { attempt: number; waitMs: number; status: number }) =>
        setWait({
          label: `${baseLabel}: Rate-Limit erreicht (HTTP ${info.status}) – warte ${Math.round(info.waitMs / 1000)} s, dann Versuch ${info.attempt} …`,
        }),
    }),
    [],
  );

  const start = useCallback(async () => {
    if (!config || !sanitizeKey) return;
    setBusy(true);
    setError(null);
    setReport(null);
    setWait({ label: PHASE_LABEL.sanitizing });
    try {
      const doc = buildExport();
      const newSession = await startAnalysisSession(
        doc,
        config,
        { key: sanitizeKey },
        {
          onProgress: (phase) => setWait({ label: PHASE_LABEL[phase] }),
          ...withRetryIndicator("Sitzung starten"),
        },
      );
      setSession(newSession);
      recordSessionStarted(newSession.id, newSession.messages[0]?.text ?? "Neue Sitzung");
      saveResumableSession(newSession);
      setDirectory(listSessions());
      scrollToEnd();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setWait(null);
    }
  }, [config, sanitizeKey, buildExport, scrollToEnd, withRetryIndicator]);

  const send = useCallback(async () => {
    if (!session || (!draft.trim() && pendingImages.length === 0) || busy) return;
    const text = draft.trim() || "Siehe angehängtes Bild.";
    const images = pendingImages;
    setDraft("");
    setPendingImages([]);
    setBusy(true);
    setError(null);
    // Show the user's own message immediately, before the (possibly slow) API call resolves —
    // otherwise it only appeared once the assistant's reply came back together with it, which read
    // as "my question wasn't sent" while actually just waiting on the network.
    setSession((s) =>
      s
        ? {
            ...s,
            messages: [...s.messages, { role: "user", text, ...(images.length ? { images } : {}) }],
          }
        : s,
    );
    scrollToEnd();
    setWait({ label: "Durchsuche den Export nach der Antwort …" });
    try {
      const updated = await sendChatMessage(session, text, {
        ...withRetryIndicator("Antwort"),
        ...(images.length ? { images: images.map((dataUri) => ({ dataUri })) } : {}),
      });
      setSession(updated);
      saveResumableSession(updated);
      setDirectory(listSessions());
      scrollToEnd();
    } catch (e) {
      // Roll back the optimistic message so a failed send doesn't leave a question with no answer.
      setSession((s) => (s ? { ...s, messages: s.messages.slice(0, -1) } : s));
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setWait(null);
    }
  }, [session, draft, pendingImages, busy, scrollToEnd, withRetryIndicator]);

  const onPasteInDraft = useCallback(async (e: React.ClipboardEvent) => {
    const images = await imagesFromClipboard(e);
    if (images.length > 0) setPendingImages((prev) => [...prev, ...images]);
  }, []);

  const createReport = useCallback(async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    setWait({ label: "Erzeuge strukturierten Report aus dem gesamten Export und dem Chatverlauf …" });
    try {
      setReport(await generateReport(session, withRetryIndicator("Report")));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setWait(null);
    }
  }, [session, withRetryIndicator]);

  /** Ends the session for good: deletes the Azure OpenAI file/vector store, records it as ended
   * (no longer resumable) in the directory, then closes the window. */
  const endAndClose = useCallback(() => {
    if (session) {
      void endSession(session);
      recordSessionEnded(session.id);
    }
    onClose();
  }, [session, onClose]);

  /** Keeps the session's Azure OpenAI resources alive and its full state persisted so it can be
   * resumed later (even after a page reload), then closes the window without deleting anything. */
  const minimize = useCallback(() => {
    if (session) {
      minimizedIdRef.current = session.id;
      saveResumableSession(session);
    }
    onClose();
  }, [session, onClose]);

  const resume = useCallback(
    (record: AiSessionRecord) => {
      if (!config || !record.resumable) return;
      setSession(resumeSession(record.id, config, record.resumable));
      setReport(null);
      setError(null);
      setShowDirectory(false);
      scrollToEnd();
    },
    [config, scrollToEnd],
  );

  const sortedFindings = useMemo(
    () => [...(report?.findings ?? [])].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]),
    [report],
  );

  return (
    <FloatingOverlay
      title="KI-Analyse (Azure OpenAI)"
      onClose={endAndClose}
      headerExtra={
        <>
          {session && (
            <button className="secondary small" onClick={minimize} title="Fenster schließen, Sitzung im Hintergrund weiterlaufen lassen">
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
                  className={`small${s.status === "minimized" ? " clickable" : ""}`}
                  onClick={() => s.status === "minimized" && resume(s)}
                  title={s.status === "minimized" ? "Klicken zum Fortsetzen" : undefined}
                >
                  <span className={`ai-session-status ai-session-status-${s.status}`} />
                  {new Date(s.startedAt).toLocaleString("de-DE")} · {s.messageCount} Nachrichten
                  {s.status === "minimized" ? " · fortsetzbar" : " · beendet"}
                  <div className="muted ai-session-title">{s.title}</div>
                </li>
              ))}
            </ul>
            <p className="muted small">
              Nur Metadaten (Zeitpunkt, Titel, Anzahl Nachrichten) werden lokal im Browser gemerkt – keine
              Chatinhalte und keine Exportdaten. Fortsetzbare Sitzungen laufen im Hintergrund weiter und
              verursachen bis zu ihrem Ende weiterhin Kosten in Azure OpenAI; beendete Sitzungen können nicht
              reaktiviert werden, da ihr temporärer Speicher bereits gelöscht wurde.
            </p>
          </div>
        )}

        <p className="muted small">
          Lädt den anonymisierten Export (Pseudonyme statt Namen/IDs, öffentliche IPs ersetzt) einmalig in
          einen temporären, durchsuchbaren Speicher hoch (file_search). „Minimieren“ lässt die Sitzung im
          Hintergrund weiterlaufen (später über das Sitzungsverzeichnis fortsetzbar); „Schließen“ (✕) beendet
          sie endgültig und löscht den temporären Speicher.
        </p>

        {!config && (
          <p className="status-warn small">
            Azure OpenAI ist nicht konfiguriert. Bitte <code>VITE_AZURE_OPENAI_ENDPOINT</code>,{" "}
            <code>VITE_AZURE_OPENAI_API_KEY</code> und <code>VITE_AZURE_OPENAI_MODEL</code> in{" "}
            <code>.env.local</code> setzen (siehe <code>.env.example</code>) und die Anwendung neu starten.
          </p>
        )}

        {config && !session && (
          <div className="row">
            <label className="small">
              Sanitizer-Schlüssel
              <input
                type="password"
                placeholder="Nur für diese Sitzung, wird nicht gespeichert"
                value={sanitizeKey}
                onChange={(e) => setSanitizeKey(e.target.value)}
              />
            </label>
            <button onClick={() => void start()} disabled={busy || !sanitizeKey}>
              Sitzung starten
            </button>
          </div>
        )}

        {wait && !session && (
          <div className="ai-wait">
            <NetworkShieldSpinner label={wait.label} />
            {showRainbow && <RainbowDots />}
          </div>
        )}

        {error && <p className="status-error small mono">{error}</p>}

        {session && (
          <div className="ai-chat">
            <p className="muted small">
              {session.sanitizationStats.pseudonymizedTokens} Bezeichner und{" "}
              {session.sanitizationStats.publicIpsReplaced} öffentliche IP(s) pseudonymisiert, bevor die
              Daten das Gerät verlassen haben.
            </p>
            <div className="ai-chat-messages">
              {session.messages.map((m, i) => (
                <div key={i} className={`ai-chat-bubble ai-chat-bubble-${m.role}`}>
                  <div className="ai-chat-bubble-text">{m.text}</div>
                  {m.images && m.images.length > 0 && (
                    <div className="ai-chat-bubble-images">
                      {m.images.map((src, j) => (
                        <img key={j} src={src} alt="Angehängtes Bild" className="ai-chat-image" />
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {wait && (
                <div className="ai-wait ai-wait-inline">
                  <NetworkShieldSpinner label={wait.label} />
                  {showRainbow && <RainbowDots />}
                </div>
              )}
              <div ref={messagesEnd} />
            </div>

            {pendingImages.length > 0 && (
              <>
                <p className="status-warn small">
                  Achtung: Bilder werden NICHT anonymisiert. Ein Screenshot (z. B. aus dem Azure-Portal)
                  kann reale Namen, IDs oder IP-Adressen zeigen – im Gegensatz zum Export selbst.
                </p>
                <div className="ai-pending-images">
                  {pendingImages.map((src, i) => (
                    <div key={i} className="ai-pending-image">
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
                </div>
              </>
            )}

            <div className="ai-composer">
              <textarea
                placeholder="Frage stellen, z. B. „Welche Subnets haben IPv6 ohne Firewall?“ – Bilder aus der Zwischenablage können hier eingefügt werden."
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onPaste={(e) => void onPasteInDraft(e)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    void send();
                  }
                }}
                disabled={busy}
                rows={2}
              />
              <div className="row">
                <button onClick={() => void send()} disabled={busy || (!draft.trim() && pendingImages.length === 0)}>
                  Senden
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
                <ul>
                  {report.recommendations.map((r, i) => (
                    <li key={i} className="small">
                      {r}
                    </li>
                  ))}
                </ul>
              </>
            )}

            <div className="row">
              <button className="secondary" onClick={() => void downloadAiReportPdf(report)}>
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
