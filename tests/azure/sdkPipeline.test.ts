import { describe, expect, it } from "vitest";
import { ResourceGraphClient } from "@azure/arm-resourcegraph";
import { SubscriptionClient } from "@azure/arm-resources-subscriptions";
import type { TokenCredential } from "@azure/core-auth";
import { createHttpHeaders, type HttpClient, type PipelineRequest } from "@azure/core-rest-pipeline";
import { readOnlyClientOptions } from "../../src/azure/http/clientOptions.js";
import { ReadOnlyViolationError } from "../../src/azure/http/readOnlyGuardPolicy.js";

/** Verifies that the guard is really part of the Azure SDK pipelines (not just unit-tested in isolation). */
const credential: TokenCredential = {
  getToken: () => Promise.resolve({ token: "fake-token", expiresOnTimestamp: Date.now() + 3_600_000 }),
};

function recordingHttpClient(body: unknown) {
  const sent: PipelineRequest[] = [];
  const httpClient: HttpClient = {
    sendRequest(request) {
      sent.push(request);
      return Promise.resolve({
        request,
        status: 200,
        headers: createHttpHeaders({ "content-type": "application/json" }),
        bodyAsText: JSON.stringify(body),
      });
    },
  };
  return { httpClient, sent };
}

describe("Azure SDK clients with read-only options", () => {
  it("send the ARG query POST", async () => {
    const { httpClient, sent } = recordingHttpClient({
      totalRecords: 0,
      count: 0,
      resultTruncated: "false",
      data: [],
    });
    const client = new ResourceGraphClient(credential, { ...readOnlyClientOptions(), httpClient });
    await client.resources({ query: "resources | take 1", subscriptions: ["s1"] });
    expect(sent).toHaveLength(1);
    expect(sent[0]!.method).toBe("POST");
    expect(sent[0]!.url).toMatch(/\/providers\/Microsoft\.ResourceGraph\/resources/i);
  });

  it("block a non-query POST of a real SDK operation without sending it", async () => {
    const { httpClient, sent } = recordingHttpClient({});
    const client = new SubscriptionClient(credential, { ...readOnlyClientOptions(), httpClient });
    await expect(
      client.checkResourceName({ resourceNameDefinition: { name: "x", type: "y" } }),
    ).rejects.toBeInstanceOf(ReadOnlyViolationError);
    expect(sent).toHaveLength(0);
  });

  it("allow GET listings", async () => {
    const { httpClient, sent } = recordingHttpClient({ value: [] });
    const client = new SubscriptionClient(credential, { ...readOnlyClientOptions(), httpClient });
    for await (const _ of client.subscriptions.list()) {
      // no items
    }
    expect(sent.map((r) => r.method)).toEqual(["GET"]);
  });
});
