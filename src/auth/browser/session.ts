import {
  BrowserAuthError,
  createStandardPublicClientApplication,
  type AccountInfo,
  type IPublicClientApplication,
} from "@azure/msal-browser";
import { ARM_USER_IMPERSONATION_SCOPE } from "../tenantCredential.js";
import { createMsalConfiguration, type EntraSettings } from "./msalConfig.js";
import { MsalTokenCredential } from "./msalTokenCredential.js";

export const LOGIN_SCOPES = [ARM_USER_IMPERSONATION_SCOPE];

export interface MsalSession {
  msal: IPublicClientApplication;
  credential: MsalTokenCredential;
  account(): AccountInfo | null;
  login(): Promise<AccountInfo | null>;
  logout(): Promise<void>;
}

const POPUP_BLOCKED_CODES = new Set(["popup_window_error", "empty_window_error"]);

/** Initializes MSAL, completes a pending redirect login and exposes a TokenCredential for the Azure SDK. */
export async function createMsalSession(settings: EntraSettings): Promise<MsalSession> {
  const msal = await createStandardPublicClientApplication(createMsalConfiguration(settings));
  const redirect = await msal.handleRedirectPromise();
  if (redirect?.account) msal.setActiveAccount(redirect.account);
  else if (!msal.getActiveAccount()) {
    const [first] = msal.getAllAccounts();
    if (first) msal.setActiveAccount(first);
  }

  return {
    msal,
    credential: new MsalTokenCredential(msal, settings.authorityHost),
    account: () => msal.getActiveAccount(),
    async login() {
      try {
        const result = await msal.loginPopup({ scopes: LOGIN_SCOPES, prompt: "select_account" });
        msal.setActiveAccount(result.account);
        return result.account;
      } catch (error) {
        if (error instanceof BrowserAuthError && POPUP_BLOCKED_CODES.has(error.errorCode)) {
          await msal.loginRedirect({ scopes: LOGIN_SCOPES, prompt: "select_account" });
          return null;
        }
        throw error;
      }
    },
    async logout() {
      const account = msal.getActiveAccount();
      await msal.logoutPopup(account ? { account } : {});
    },
  };
}
