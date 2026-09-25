import { describe, expect, it, vi } from "vitest";
import {
  InteractionRequiredAuthError,
  type AccountInfo,
  type AuthenticationResult,
} from "@azure/msal-browser";
import {
  mapScopes,
  MsalTokenCredential,
  NoSignedInAccountError,
  type MsalClient,
} from "../../src/auth/browser/msalTokenCredential.js";

const account = {
  username: "user@contoso.example",
  homeAccountId: "h",
  localAccountId: "l",
  environment: "e",
  tenantId: "t",
} as AccountInfo;
const result = (token: string): AuthenticationResult =>
  ({ accessToken: token, expiresOn: new Date("2026-09-25T11:00:00Z") }) as AuthenticationResult;

function client(overrides: Partial<MsalClient> = {}): MsalClient {
  return {
    getActiveAccount: () => account,
    getAllAccounts: () => [account],
    acquireTokenSilent: vi.fn(() => Promise.resolve(result("silent"))),
    acquireTokenPopup: vi.fn(() => Promise.resolve(result("popup"))),
    ...overrides,
  };
}

const HOST = "https://login.microsoftonline.com";

describe("mapScopes", () => {
  it("maps the ARM .default scope to user_impersonation", () => {
    expect(mapScopes("https://management.azure.com/.default")).toEqual([
      "https://management.azure.com/user_impersonation",
    ]);
    expect(mapScopes(["https://management.azure.com//.default"])).toEqual([
      "https://management.azure.com/user_impersonation",
    ]);
    expect(mapScopes(["https://management.core.windows.net//.default"])).toEqual([
      "https://management.azure.com/user_impersonation",
    ]);
    expect(mapScopes(["openid"])).toEqual(["openid"]);
  });
});

describe("MsalTokenCredential", () => {
  it("acquires tokens silently with a tenant-specific authority", async () => {
    const msal = client();
    const token = await new MsalTokenCredential(msal, HOST).getToken(
      "https://management.azure.com/.default",
      {
        tenantId: "tenant-b",
      },
    );
    expect(token).toEqual({
      token: "silent",
      expiresOnTimestamp: Date.parse("2026-09-25T11:00:00Z"),
      tokenType: "Bearer",
    });
    expect(msal.acquireTokenSilent).toHaveBeenCalledWith({
      scopes: ["https://management.azure.com/user_impersonation"],
      account,
      authority: `${HOST}/tenant-b`,
    });
    expect(msal.acquireTokenPopup).not.toHaveBeenCalled();
  });

  it("uses the configured authority when no tenant is requested", async () => {
    const msal = client();
    await new MsalTokenCredential(msal, HOST).getToken("https://management.azure.com/.default");
    expect(vi.mocked(msal.acquireTokenSilent).mock.calls[0]![0]).not.toHaveProperty("authority");
  });

  it("falls back to a popup only when interaction is required", async () => {
    const msal = client({
      acquireTokenSilent: vi.fn(() =>
        Promise.reject(new InteractionRequiredAuthError("interaction_required", "test")),
      ),
    });
    const token = await new MsalTokenCredential(msal, HOST).getToken(
      "https://management.azure.com/.default",
      {
        tenantId: "tenant-b",
        claims: '{"access_token":{}}',
      },
    );
    expect(token?.token).toBe("popup");
    expect(msal.acquireTokenPopup).toHaveBeenCalledWith(
      expect.objectContaining({
        authority: `${HOST}/tenant-b`,
        claims: '{"access_token":{}}',
        loginHint: account.username,
      }),
    );
  });

  it("does not open a popup for other errors", async () => {
    const msal = client({ acquireTokenSilent: vi.fn(() => Promise.reject(new Error("network"))) });
    await expect(new MsalTokenCredential(msal, HOST).getToken("x")).rejects.toThrow("network");
    expect(msal.acquireTokenPopup).not.toHaveBeenCalled();
  });

  it("serializes interactive prompts", async () => {
    let active = 0;
    let maxActive = 0;
    const msal = client({
      acquireTokenSilent: vi.fn(() =>
        Promise.reject(new InteractionRequiredAuthError("interaction_required", "test")),
      ),
      acquireTokenPopup: vi.fn(async () => {
        active++;
        maxActive = Math.max(maxActive, active);
        await new Promise((r) => setTimeout(r, 5));
        active--;
        return result("popup");
      }),
    });
    const credential = new MsalTokenCredential(msal, HOST);
    await Promise.all([
      credential.getToken("x", { tenantId: "a" }),
      credential.getToken("x", { tenantId: "b" }),
    ]);
    expect(maxActive).toBe(1);
  });

  it("requires a signed-in account", async () => {
    const msal = client({ getActiveAccount: () => null, getAllAccounts: () => [] });
    await expect(new MsalTokenCredential(msal, HOST).getToken("x")).rejects.toBeInstanceOf(
      NoSignedInAccountError,
    );
  });
});
