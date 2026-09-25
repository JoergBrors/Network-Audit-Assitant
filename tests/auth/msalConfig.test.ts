import { describe, expect, it } from "vitest";
import {
  createMsalConfiguration,
  DEFAULT_AUTHORITY,
  EntraConfigurationError,
  resolveEntraSettings,
} from "../../src/auth/browser/msalConfig.js";

const CLIENT = "11111111-2222-3333-4444-555555555555";

describe("resolveEntraSettings", () => {
  it("defaults to the organizations authority", () => {
    expect(resolveEntraSettings({ VITE_ENTRA_CLIENT_ID: CLIENT, origin: "http://localhost:5173" })).toEqual({
      clientId: CLIENT,
      authority: DEFAULT_AUTHORITY,
      authorityHost: "https://login.microsoftonline.com",
      redirectUri: "http://localhost:5173/redirect.html",
      appUri: "http://localhost:5173",
    });
  });

  it("accepts a tenant-specific authority", () => {
    const s = resolveEntraSettings({
      VITE_ENTRA_CLIENT_ID: CLIENT,
      VITE_ENTRA_AUTHORITY: "https://login.microsoftonline.com/tenant-x/",
      origin: "https://audit.example",
    });
    expect(s.authority).toBe("https://login.microsoftonline.com/tenant-x");
  });

  it.each([undefined, "", "not-a-guid"])("rejects client id %s", (id) => {
    expect(() => resolveEntraSettings({ VITE_ENTRA_CLIENT_ID: id, origin: "x" })).toThrow(
      EntraConfigurationError,
    );
  });

  it("rejects non-https authorities", () => {
    expect(() =>
      resolveEntraSettings({
        VITE_ENTRA_CLIENT_ID: CLIENT,
        VITE_ENTRA_AUTHORITY: "http://login.example/x",
        origin: "x",
      }),
    ).toThrow(EntraConfigurationError);
  });
});

describe("createMsalConfiguration", () => {
  it("uses a session-scoped token cache and the redirect bridge", () => {
    const config = createMsalConfiguration(
      resolveEntraSettings({ VITE_ENTRA_CLIENT_ID: CLIENT, origin: "http://localhost:5173/" }),
    );
    expect(config.cache?.cacheLocation).toBe("sessionStorage");
    expect(config.auth.redirectUri).toBe("http://localhost:5173/redirect.html");
    expect(config.auth.postLogoutRedirectUri).toBe("http://localhost:5173");
  });
});
