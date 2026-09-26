import OpenAI from "openai";

/**
 * Azure OpenAI (Microsoft Foundry) client on the official `openai` SDK and the Azure v1 API
 * (`<endpoint>/openai/v1/`), called directly from the browser. Authentication follows Microsoft's
 * recommendation: keyless via Microsoft Entra ID (the signed-in user's MSAL token, scope
 * `AZURE_OPENAI_DEFAULT_SCOPE`); an API key is only a fallback for offline use without sign-in.
 * Config comes from Vite env vars (see .env.example) — never from tenant data, never logged.
 */
export interface AzureOpenAiConfig {
  /** e.g. https://my-resource.openai.azure.com or https://my-resource.services.ai.azure.com */
  endpoint: string;
  /** Deployment name, e.g. "gpt-5-mini". */
  model: string;
  /** Optional fallback; without it the signed-in user's Entra ID token is used. */
  apiKey?: string | undefined;
  /** Reasoning effort for chat turns (reasoning models only); the report uses one level more. */
  reasoningEffort?: ReasoningEffort | undefined;
  /** Entra ID token scope. */
  scope: string;
}

export type ReasoningEffort = "minimal" | "low" | "medium" | "high";

/**
 * Entra ID scope for Azure OpenAI. The v1 API accepts both this and `https://ai.azure.com/.default`;
 * this one belongs to the well-known "Azure Cognitive Services" delegated permission that a SPA
 * registration can request (ENTRA-ID-SETUP.md § 8.1). Override with VITE_AZURE_OPENAI_SCOPE.
 */
export const AZURE_OPENAI_DEFAULT_SCOPE = "https://cognitiveservices.azure.com/.default";

export class AzureOpenAiError extends Error {
  override readonly name = "AzureOpenAiError";
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

const EFFORTS = new Set<string>(["minimal", "low", "medium", "high"]);
/** Reasoning models accept `reasoning.effort`; other deployments reject the parameter. */
const REASONING_MODEL = /^(gpt-5|o\d)/i;

export function readAzureOpenAiConfigFromEnv(
  env: Record<string, string | undefined> = import.meta.env,
): AzureOpenAiConfig | undefined {
  const endpoint = env["VITE_AZURE_OPENAI_ENDPOINT"]?.trim();
  const model = env["VITE_AZURE_OPENAI_MODEL"]?.trim();
  if (!endpoint || !model) return undefined;
  const effort = env["VITE_AZURE_OPENAI_REASONING_EFFORT"]?.trim().toLowerCase();
  return {
    endpoint: endpoint.replace(/\/+$/, "").replace(/\/openai(\/v1)?$/i, ""),
    model,
    apiKey: env["VITE_AZURE_OPENAI_API_KEY"]?.trim() || undefined,
    scope: env["VITE_AZURE_OPENAI_SCOPE"]?.trim() || AZURE_OPENAI_DEFAULT_SCOPE,
    reasoningEffort:
      effort && EFFORTS.has(effort)
        ? (effort as ReasoningEffort)
        : REASONING_MODEL.test(model)
          ? "low"
          : undefined,
  };
}

/** Supplies a bearer token for `AZURE_AI_SCOPE` (the MSAL credential of the signed-in user). */
export type TokenProvider = () => Promise<string>;

/**
 * Creates the SDK client. Retries on 429/5xx (honouring `Retry-After`) and timeouts are the SDK's
 * own. `dangerouslyAllowBrowser` is required for any browser use; with Entra ID no secret is in
 * the bundle, the token belongs to the signed-in user and is scoped to Azure AI only.
 */
export function createAzureOpenAiClient(
  config: AzureOpenAiConfig,
  tokenProvider: TokenProvider | undefined,
  options: { fetch?: typeof fetch; maxRetries?: number } = {},
): OpenAI {
  const apiKey = tokenProvider ?? config.apiKey;
  if (!apiKey) {
    throw new AzureOpenAiError(
      "Keine Anmeldung für Azure OpenAI: bitte mit Microsoft Entra ID anmelden (oder VITE_AZURE_OPENAI_API_KEY setzen).",
    );
  }
  return new OpenAI({
    baseURL: `${config.endpoint}/openai/v1/`,
    apiKey,
    dangerouslyAllowBrowser: true,
    maxRetries: options.maxRetries ?? 4,
    timeout: 10 * 60_000,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });
}

/** Turns SDK errors into short German messages (status + server message, no request details). */
export function toAzureOpenAiError(e: unknown): Error {
  if (e instanceof AzureOpenAiError) return e;
  if (e instanceof OpenAI.APIUserAbortError) return new AzureOpenAiError("Abgebrochen.");
  if (e instanceof OpenAI.APIError) {
    const hint =
      e.status === 401 || e.status === 403
        ? " – fehlt die Rolle „Cognitive Services OpenAI User“ auf der Azure-OpenAI-Ressource oder die API-Berechtigung der App-Registrierung (ENTRA-ID-SETUP.md § 8)?"
        : e.status === 404
          ? " – stimmt der Deployment-Name (VITE_AZURE_OPENAI_MODEL)?"
          : "";
    return new AzureOpenAiError(
      `Azure OpenAI antwortete mit ${e.status ?? "Fehler"}: ${e.message.slice(0, 400)}${hint}`,
      typeof e.status === "number" ? e.status : undefined,
    );
  }
  return e instanceof Error ? e : new Error(String(e));
}
