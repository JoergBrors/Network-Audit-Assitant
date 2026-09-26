import { describe, expect, it } from "vitest";
import {
  buildTagIndex,
  matchTag,
  nodesWithTag,
  parseTagQuery,
  tagSuggestions,
} from "../../src/graph/tags.js";

const index = buildTagIndex([
  ["vm1", { entity: { tags: { Environment: "Prod", Owner: "team-a" } } }],
  ["vm2", { entity: { tags: { environment: "Test" } } }],
  ["vnet", { entity: { tags: {} } }],
  ["nic", { entity: {} }],
]);

describe("tags", () => {
  it("indexes only entities with tags", () => {
    expect([...index.keys()]).toEqual(["vm1", "vm2"]);
  });

  it("parses key=value, key= and free text", () => {
    expect(parseTagQuery(" Env=Prod ")).toEqual({ key: "env", value: "prod" });
    expect(parseTagQuery("owner:")).toEqual({ key: "owner" });
    expect(parseTagQuery("owner=*")).toEqual({ key: "owner" });
    expect(parseTagQuery("team")).toEqual({ text: "team" });
    expect(parseTagQuery("  ")).toBeUndefined();
  });

  it("matches keys case-insensitively and values by substring", () => {
    expect(matchTag({ Environment: "Prod" }, parseTagQuery("environment=pro")!)).toBe("Environment=Prod");
    expect(matchTag({ Environment: "Prod" }, parseTagQuery("env=prod")!)).toBeUndefined();
    expect(nodesWithTag(index, "environment=")).toEqual(new Set(["vm1", "vm2"]));
    expect(nodesWithTag(index, "team-a")).toEqual(new Set(["vm1"]));
    expect(nodesWithTag(index, "")).toBeUndefined();
  });

  it("suggests key=value pairs and keys by frequency", () => {
    const s = tagSuggestions(index);
    expect(s).toContainEqual({ tag: "Environment=", count: 1 });
    expect(s.map((x) => x.tag)).toEqual(expect.arrayContaining(["Owner=team-a", "environment=Test"]));
  });
});
