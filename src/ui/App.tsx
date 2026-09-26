import { useCallback, useMemo, useRef, useState } from "react";
import type { AccountInfo } from "@azure/msal-browser";
import type { MsalSession } from "../auth/browser/session.js";
import { MemoryCache } from "../azure/cache.js";
import { consoleSink, createLogger } from "../logging/logger.js";
import { runDiscovery, type DiscoveryProgress } from "../discovery/runDiscovery.js";
import { analyzeInventory, type NetworkModel } from "../pipeline/analyze.js";
import {
  assessmentFileName,
  buildAssessmentExport,
  parseAssessmentExport,
} from "../export/assessmentJson.js";
import { DiscoverySummary } from "./components/DiscoverySummary.js";
import { Workspace, type WorkspaceComparison } from "./workspace/Workspace.js";
import { diffModels } from "../drift/diff.js";
import { downloadJson } from "./workspace/download.js";
import { AiAnalysisPanel } from "./workspace/AiAnalysisPanel.js";
import { ServiceAssessmentView } from "./components/ServiceAssessmentView.js";
import { readAzureOpenAiConfigFromEnv } from "../ai/azureOpenAi.js";

interface AppProps {
  session: MsalSession | null;
  startupError: { title: string; message: string } | null;
}

type Tab = "topology" | "overview";

export function App({ session, startupError }: AppProps) {
  const [account, setAccount] = useState<AccountInfo | null>(() => session?.account() ?? null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<DiscoveryProgress | null>(null);
  const [model, setModel] = useState<NetworkModel | null>(null);
  const [queryCounts, setQueryCounts] = useState<Record<string, number> | null>(null);
  const [source, setSource] = useState<string>("");
  const [tab, setTab] = useState<Tab>("topology");
  const fileInput = useRef<HTMLInputElement>(null);
  const compareInput = useRef<HTMLInputElement>(null);
  const [baseline, setBaseline] = useState<{ model: NetworkModel; label: string } | null>(null);
  const [showAiPanel, setShowAiPanel] = useState(false);
  // Discovery cache lives in memory for this tab only and is dropped on sign-out.
  const cache = useMemo(() => new MemoryCache(), []);
  const logger = useMemo(() => createLogger({ sink: consoleSink(), level: "info" }), []);
  const aiConfigured = useMemo(() => readAzureOpenAiConfigFromEnv() !== undefined, []);

  const signIn = useCallback(async () => {
    if (!session) return;
    setError(null);
    try {
      setAccount(await session.login());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [session]);

  const signOut = useCallback(async () => {
    if (!session) return;
    await cache.clear();
    setModel(null);
    setBaseline(null);
    setQueryCounts(null);
    await session.logout();
    setAccount(null);
  }, [session, cache]);

  const discover = useCallback(async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const raw = await runDiscovery({
        credential: session.credential,
        logger,
        cache,
        onProgress: setProgress,
      });
      setModel(analyzeInventory(raw));
      setQueryCounts(Object.fromEntries(Object.entries(raw.resources).map(([k, v]) => [k, v.length])));
      setSource(`Live-Discovery ${new Date(raw.generatedAt).toLocaleString()}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [session, logger, cache]);

  const compareWith = useCallback(async (file: File) => {
    setError(null);
    try {
      setBaseline({ model: parseAssessmentExport(await file.text()), label: file.name });
      setTab("topology");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const comparison = useMemo<WorkspaceComparison | undefined>(
    () =>
      baseline && model
        ? {
            diff: diffModels(baseline.model, model),
            baseline: baseline.model,
            baselineLabel: baseline.label,
            onClose: () => setBaseline(null),
          }
        : undefined,
    [baseline, model],
  );

  const exportJson = useCallback(() => {
    if (!model) return;
    const now = new Date();
    downloadJson(assessmentFileName(now), buildAssessmentExport(model, { now }));
  }, [model]);

  const buildExportForAi = useCallback(() => {
    if (!model) throw new Error("Kein Modell geladen.");
    return buildAssessmentExport(model, { now: new Date() });
  }, [model]);

  const importJson = useCallback(async (file: File) => {
    setError(null);
    try {
      setModel(parseAssessmentExport(await file.text()));
      setQueryCounts(null);
      setSource(`Snapshot ${file.name}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  return (
    <div className="app">
      <header className="app-header">
        <h1>Azure Network Audit</h1>
        <div className="row">
          {model && (
            <nav className="segmented" aria-label="Ansicht">
              <button className={tab === "topology" ? "active" : ""} onClick={() => setTab("topology")}>
                Topologie
              </button>
              <button className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}>
                Übersicht & Qualität
              </button>
            </nav>
          )}
          {account && (
            <button onClick={() => void discover()} disabled={busy}>
              {busy ? "Discovery läuft …" : model ? "Neu laden" : "Discovery starten"}
            </button>
          )}
          {busy && progress && (
            <span className="muted small">
              {progress.phase === "subscriptions"
                ? "Tenants und Subscriptions …"
                : `Resource Graph ${progress.completedQueries}/${progress.totalQueries}`}
            </span>
          )}
          <button
            className="secondary"
            onClick={exportJson}
            disabled={!model}
            title="Normalisiertes Inventar + Beziehungsgraph"
          >
            JSON exportieren
          </button>
          <button
            className="secondary"
            onClick={() => fileInput.current?.click()}
            title="Früheren Export offline laden"
          >
            JSON importieren
          </button>
          <button
            className="secondary"
            onClick={() => compareInput.current?.click()}
            disabled={!model}
            title="Früheren Export als Vergleichsbasis laden – Änderungen werden im Graph markiert"
          >
            Mit JSON vergleichen
          </button>
          <button
            className="secondary"
            onClick={() => setShowAiPanel((v) => !v)}
            disabled={!model}
            title={
              aiConfigured
                ? "Export mit dem internen Azure-OpenAI-Deployment analysieren (Chat, Report, PDF)"
                : "Azure OpenAI ist nicht konfiguriert (VITE_AZURE_OPENAI_* in .env.local)"
            }
          >
            KI-Analyse
          </button>
          <input
            ref={compareInput}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void compareWith(file);
              e.target.value = "";
            }}
          />
          <input
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) void importJson(file);
              e.target.value = "";
            }}
          />
          <span className="muted small">Read-only</span>
          {account ? (
            <>
              <span className="small">{account.username}</span>
              <button className="secondary" onClick={() => void signOut()}>
                Abmelden
              </button>
            </>
          ) : (
            <button onClick={() => void signIn()} disabled={!session}>
              Anmelden
            </button>
          )}
        </div>
      </header>

      {showAiPanel && model && (
        <AiAnalysisPanel
          buildExport={buildExportForAi}
          source={source || "Discovery"}
          credential={account ? session?.credential : undefined}
          accountName={account?.username}
          onClose={() => setShowAiPanel(false)}
        />
      )}

      {(startupError || error) && (
        <div className="messages">
          {startupError && (
            <section className="panel">
              <h2 className="status-warn">{startupError.title}</h2>
              <p className="mono">{startupError.message}</p>
            </section>
          )}
          {error && (
            <section className="panel">
              <h2 className="status-error">Fehler</h2>
              <p className="mono">{error}</p>
            </section>
          )}
        </div>
      )}

      {!model && (
        <main className="app-main">
          <section className="panel">
            <h2>Start</h2>
            <p>
              {account
                ? "„Discovery starten“ liest alle erreichbaren Subscriptions über Azure Resource Graph (ausschließlich lesend)."
                : "Mit Microsoft Entra ID anmelden oder einen früheren JSON-Export importieren (offline)."}
            </p>
          </section>
        </main>
      )}

      {model && tab === "topology" && <Workspace key={source} model={model} comparison={comparison} />}
      {model && tab === "overview" && (
        <main className="app-main">
          <p className="muted small">Quelle: {source}</p>
          <ServiceAssessmentView inventory={model.inventory} />
          <DiscoverySummary
            discovery={model.discovery}
            subscriptions={model.inventory.subscriptions}
            queryCounts={queryCounts}
          />
        </main>
      )}
    </div>
  );
}
