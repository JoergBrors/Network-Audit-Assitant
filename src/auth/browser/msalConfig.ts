import { BrowserCacheLocation, type Configuration } from "@azure/msal-browser";

export const DEFAULT_AUTHORITY = "https://login.microsoftonline.com/organizations";

/** MSAL v5 redirect bridge page (redirect.html); must be registered as SPA redirect URI. */
export const REDIRECT_BRIDGE_PATH = "/redirect.html";

export interface EntraSettings {
  clientId: string;
  /** e.g. https://login.microsoftonline.com/organizations or https://login.microsoftonline.com/<tenantId> */
  authority: string;
  /** Authority host without tenant segment, used to build per-tenant authorities. */
  authorityHost: string;
  /** Redirect bridge URL used for popup, silent and redirect flows. */
  redirectUri: string;
  /** App start page, used after sign-out. */
  appUri: string;
}

export class EntraConfigurationError extends Error {
  override readonly name = "EntraConfigurationError";
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Validates the (non-secret) Entra settings from the build environment. No IDs are hard-coded. */
export function resolveEntraSettings(env: {
  VITE_ENTRA_CLIENT_ID?: string | undefined;
  VITE_ENTRA_AUTHORITY?: string | undefined;
  origin: string;
}): EntraSettings {
  const clientId = env.VITE_ENTRA_CLIENT_ID?.trim() ?? "";
  if (!GUID.test(clientId)) {
    throw new EntraConfigurationError(
      "VITE_ENTRA_CLIENT_ID is missing or not a GUID. Register a SPA app in Entra ID (see ENTRA-ID-SETUP.md) and set it in .env.local.",
    );
  }
  const authority = (env.VITE_ENTRA_AUTHORITY?.trim() || DEFAULT_AUTHORITY).replace(/\/+$/, "");
  let url: URL;
  try {
    url = new URL(authority);
  } catch {
    throw new EntraConfigurationError(`VITE_ENTRA_AUTHORITY is not a valid URL: ${authority}`);
  }
  if (url.protocol !== "https:") throw new EntraConfigurationError("VITE_ENTRA_AUTHORITY must use https.");
  const appUri = env.origin.replace(/\/+$/, "");
  return {
    clientId,
    authority,
    authorityHost: url.origin,
    redirectUri: `${appUri}${REDIRECT_BRIDGE_PATH}`,
    appUri,
  };
}

export function createMsalConfiguration(settings: EntraSettings): Configuration {
  return {
    auth: {
      clientId: settings.clientId,
      authority: settings.authority,
      redirectUri: settings.redirectUri,
      postLogoutRedirectUri: settings.appUri,
    },
    cache: {
      // Session-scoped token cache: cleared when the tab is closed; never localStorage.
      cacheLocation: BrowserCacheLocation.SessionStorage,
    },
  };
}
