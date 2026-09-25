import { describe, expect, it } from "vitest";
import { createLogger, redact, type LogRecord } from "../../src/logging/logger.js";

describe("redact", () => {
  it("removes credential-like keys and values", () => {
    const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
    expect(
      redact({
        authorization: `Bearer ${jwt}`,
        headers: { Cookie: "a=b", accept: "json" },
        message: `failed with ${jwt}`,
        url: "https://x.blob.core.windows.net/c?sv=1&sig=abc123",
        sharedKey: "k",
        nested: [{ clientSecret: "s", name: "ok" }],
      }),
    ).toEqual({
      authorization: "[REDACTED]",
      headers: { Cookie: "[REDACTED]", accept: "json" },
      message: "failed with [REDACTED]",
      url: "https://x.blob.core.windows.net/c?sv=1[REDACTED]",
      sharedKey: "[REDACTED]",
      nested: [{ clientSecret: "[REDACTED]", name: "ok" }],
    });
  });
});

describe("createLogger", () => {
  it("writes structured records above the level and redacts fields", () => {
    const records: LogRecord[] = [];
    const logger = createLogger({ sink: (r) => records.push(r), level: "info", now: () => new Date(0) });
    logger.debug("hidden");
    logger.child({ tenantId: "t" }).info("arg.query", { token: "secret", rows: 3 });
    expect(records).toEqual([
      {
        ts: "1970-01-01T00:00:00.000Z",
        level: "info",
        event: "arg.query",
        tenantId: "t",
        token: "[REDACTED]",
        rows: 3,
      },
    ]);
  });
});
