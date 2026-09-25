import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { EntraConfigurationError, resolveEntraSettings } from "../auth/browser/msalConfig.js";
import { createMsalSession, type MsalSession } from "../auth/browser/session.js";
import { App } from "./App.js";
import "./theme/tokens.css";
import "./theme/workspace.css";

const root = createRoot(document.getElementById("root")!);

async function bootstrap(): Promise<void> {
  let session: MsalSession | null = null;
  let startupError: { title: string; message: string } | null = null;
  try {
    const settings = resolveEntraSettings({
      VITE_ENTRA_CLIENT_ID: import.meta.env.VITE_ENTRA_CLIENT_ID as string | undefined,
      VITE_ENTRA_AUTHORITY: import.meta.env.VITE_ENTRA_AUTHORITY as string | undefined,
      origin: window.location.origin,
    });
    session = await createMsalSession(settings);
  } catch (error) {
    // The UI stays usable offline (snapshot import) when sign-in cannot be initialized.
    startupError = {
      title:
        error instanceof EntraConfigurationError
          ? "Anmeldung nicht konfiguriert"
          : "Anmeldung fehlgeschlagen",
      message: error instanceof Error ? error.message : String(error),
    };
  }
  root.render(
    <StrictMode>
      <App session={session} startupError={startupError} />
    </StrictMode>,
  );
}

void bootstrap();
