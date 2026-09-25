import type { AccessToken, GetTokenOptions, TokenCredential } from "@azure/core-auth";
import {
  InteractionRequiredAuthError,
  type AccountInfo,
  type AuthenticationResult,
  type IPublicClientApplication,
} from "@azure/msal-browser";
import { ARM_USER_IMPERSONATION_SCOPE } from "../tenantCredential.js";

export type MsalClient = Pick<
  IPublicClientApplication,
  "getActiveAccount" | "getAllAccounts" | "acquireTokenSilent" | "acquireTokenPopup"
>;

export class NoSignedInAccountError extends Error {
  override readonly name = "NoSignedInAccountError";
  constructor() {
    super("No signed-in account. Sign in before starting discovery.");
  }
}

/**
 * The Azure SDK requests `https://management.azure.com/.default`. For the SPA we request the
 * explicitly registered delegated permission instead (ENTRA-ID-SETUP.md): same resource, and the
 * consent prompt matches the documented app registration exactly.
 */
export function mapScopes(scopes: string | string[]): string[] {
  const list = Array.isArray(scopes) ? scopes : [scopes];
  return list.map((scope) => {
    const normalized = scope.toLowerCase().replace(/\/+\.default$/, "/.default");
    return normalized === "https://management.azure.com/.default" ||
      normalized === "https://management.core.windows.net/.default"
      ? ARM_USER_IMPERSONATION_SCOPE
      : scope;
  });
}

/**
 * TokenCredential backed by MSAL Browser (Authorization Code Flow with PKCE).
 * - silent first (cache / refresh token), popup only when interaction is required;
 * - one authority per tenant so that every tenant issues its own token;
 * - interactive prompts are serialized because MSAL allows only one interaction at a time.
 * Tokens are returned to the Azure SDK only; they are never stored or logged by this class.
 */
export class MsalTokenCredential implements TokenCredential {
  private interaction: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly msal: MsalClient,
    private readonly authorityHost: string,
  ) {}

  async getToken(scopes: string | string[], options?: GetTokenOptions): Promise<AccessToken | null> {
    const account = this.msal.getActiveAccount() ?? this.msal.getAllAccounts()[0];
    if (!account) throw new NoSignedInAccountError();

    const request = {
      scopes: mapScopes(scopes),
      account,
      ...(options?.tenantId ? { authority: `${this.authorityHost}/${options.tenantId}` } : {}),
      ...(options?.claims ? { claims: options.claims } : {}),
    };

    let result: AuthenticationResult;
    try {
      result = await this.msal.acquireTokenSilent(request);
    } catch (error) {
      if (!(error instanceof InteractionRequiredAuthError)) throw error;
      result = await this.interactive(request, account);
    }
    return toAccessToken(result);
  }

  private interactive(
    request: { scopes: string[]; authority?: string; claims?: string },
    account: AccountInfo,
  ): Promise<AuthenticationResult> {
    const run = this.interaction.then(() =>
      this.msal.acquireTokenPopup({ ...request, account, loginHint: account.username }),
    );
    this.interaction = run.catch(() => undefined);
    return run;
  }
}

function toAccessToken(result: AuthenticationResult): AccessToken {
  const expiresOnTimestamp = result.expiresOn ? result.expiresOn.getTime() : Date.now() + 5 * 60_000;
  return { token: result.accessToken, expiresOnTimestamp, tokenType: "Bearer" };
}
