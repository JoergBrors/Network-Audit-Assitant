import { describe, expect, it, vi } from "vitest";
import { tenantBoundCredential } from "../../src/auth/tenantCredential.js";

describe("tenantBoundCredential", () => {
  it("injects the tenant id into every token request", async () => {
    const getToken = vi.fn(() => Promise.resolve({ token: "t", expiresOnTimestamp: 1 }));
    await tenantBoundCredential({ getToken }, "tenant-x").getToken("scope", { claims: "c" });
    expect(getToken).toHaveBeenCalledWith("scope", { claims: "c", tenantId: "tenant-x" });
  });
});
