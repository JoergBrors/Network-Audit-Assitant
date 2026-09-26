import { describe, expect, it } from "vitest";
import {
  AzureOpenAiError,
  createAzureOpenAiClient,
  readAzureOpenAiConfigFromEnv,
  toAzureOpenAiError,
} from "../../src/ai/azureOpenAi.js";
import { createFakeAzure } from "./fakeAzure.js";

describe("readAzureOpenAiConfigFromEnv", () => {
  it("needs endpoint and model; the API key is optional (Entra ID is the default)", () => {
    expect(readAzureOpenAiConfigFromEnv({})).toBeUndefined();
    expect(
      readAzureOpenAiConfigFromEnv({ VITE_AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com" }),
    ).toBeUndefined();
    expect(
      readAzureOpenAiConfigFromEnv({
        VITE_AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com/openai/v1/",
        VITE_AZURE_OPENAI_MODEL: "gpt-5-mini",
      }),
    ).toEqual({
      endpoint: "https://x.openai.azure.com",
      model: "gpt-5-mini",
      apiKey: undefined,
      reasoningEffort: "low",
      scope: "https://cognitiveservices.azure.com/.default",
    });
    expect(
      readAzureOpenAiConfigFromEnv({
        VITE_AZURE_OPENAI_ENDPOINT: "https://x.services.ai.azure.com",
        VITE_AZURE_OPENAI_MODEL: "m",
        VITE_AZURE_OPENAI_SCOPE: "https://ai.azure.com/.default",
      })?.scope,
    ).toBe("https://ai.azure.com/.default");
  });

  it("uses low reasoning effort for reasoning models only, unless configured", () => {
    const base = { VITE_AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com" };
    expect(
      readAzureOpenAiConfigFromEnv({ ...base, VITE_AZURE_OPENAI_MODEL: "gpt-4.1" })?.reasoningEffort,
    ).toBe(undefined);
    expect(
      readAzureOpenAiConfigFromEnv({ ...base, VITE_AZURE_OPENAI_MODEL: "o4-mini" })?.reasoningEffort,
    ).toBe("low");
    expect(
      readAzureOpenAiConfigFromEnv({
        ...base,
        VITE_AZURE_OPENAI_MODEL: "gpt-5",
        VITE_AZURE_OPENAI_REASONING_EFFORT: "Medium",
      })?.reasoningEffort,
    ).toBe("medium");
  });
});

describe("createAzureOpenAiClient", () => {
  const config = { endpoint: "https://x.openai.azure.com", model: "gpt-5-mini", scope: "s" };

  it("sends the Entra ID token as bearer token against the v1 API", async () => {
    const azure = createFakeAzure();
    const client = createAzureOpenAiClient(config, async () => "entra-token", { fetch: azure.fetch });
    await client.files.delete("file-1");
    expect(azure.requests[0]).toMatchObject({ method: "DELETE", path: "/files/file-1" });
    expect(azure.requests[0]!.headers.get("authorization")).toBe("Bearer entra-token");
  });

  it("falls back to the API key and refuses to start without any credential", () => {
    expect(() => createAzureOpenAiClient(config, undefined)).toThrow(AzureOpenAiError);
    expect(() => createAzureOpenAiClient({ ...config, apiKey: "k" }, undefined)).not.toThrow();
  });

  it("turns 403 into a hint about the missing role", async () => {
    const azure = createFakeAzure();
    azure.failNext(403, "PermissionDenied");
    const client = createAzureOpenAiClient(config, async () => "t", { fetch: azure.fetch, maxRetries: 0 });
    const error = await client.responses
      .create({ model: "m", input: "x", stream: true })
      .then(() => undefined)
      .catch(toAzureOpenAiError);
    expect(error).toBeInstanceOf(AzureOpenAiError);
    expect(error?.message).toContain("403");
    expect(error?.message).toContain("Cognitive Services OpenAI User");
  });
});
