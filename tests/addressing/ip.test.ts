import { describe, expect, it } from "vitest";
import {
  cidrContains,
  classifyAddressing,
  ipFamilyOf,
  isDefaultRoutePrefix,
  parseCidr,
  splitByFamily,
} from "../../src/addressing/ip.js";

describe("ipFamilyOf", () => {
  it.each([
    ["10.0.0.0/16", "ipv4"],
    ["10.1.2.3", "ipv4"],
    ["fd00:10::/48", "ipv6"],
    ["2a02:1234::1", "ipv6"],
    ["::/0", "ipv6"],
    ["::ffff:10.0.0.1", "ipv6"],
  ])("%s → %s", (value, family) => expect(ipFamilyOf(value)).toBe(family));

  it.each(["Internet", "*", "VirtualNetwork", "AzureCloud.WestEurope", "example.com", "300.1.1.1", ""])(
    "%s → undefined",
    (v) => expect(ipFamilyOf(v)).toBeUndefined(),
  );
});

describe("CIDR", () => {
  it("parses IPv4 and IPv6 incl. compression", () => {
    expect(parseCidr("10.0.0.0/8")).toMatchObject({ family: "ipv4", length: 8 });
    expect(parseCidr("fd00::/8")).toMatchObject({ family: "ipv6", length: 8 });
    expect(parseCidr("2001:db8:0:0:0:0:0:1")?.value).toBe(parseCidr("2001:db8::1")?.value);
    expect(parseCidr("10.0.0.0/33")).toBeUndefined();
    expect(parseCidr("fd00::/129")).toBeUndefined();
  });

  it("checks containment per family", () => {
    expect(cidrContains("10.176.0.0/16", "10.176.9.12")).toBe(true);
    expect(cidrContains("10.176.0.0/16", "10.177.0.1")).toBe(false);
    expect(cidrContains("10.0.0.0/16", "10.0.1.0/24")).toBe(true);
    expect(cidrContains("10.0.1.0/24", "10.0.0.0/16")).toBe(false);
    expect(cidrContains("0.0.0.0/0", "8.8.8.8")).toBe(true);
    expect(cidrContains("fd00:10::/48", "fd00:10:0:1::4")).toBe(true);
    expect(cidrContains("fd00:10::/48", "fd00:11::1")).toBe(false);
    expect(cidrContains("::/0", "2a02::1")).toBe(true);
    expect(cidrContains("10.0.0.0/8", "fd00::1")).toBe(false);
  });

  it("detects overlapping networks via containment in both directions", () => {
    const overlaps = (a: string, b: string) =>
      cidrContains(a, b.split("/")[0]!) || cidrContains(b, a.split("/")[0]!);
    expect(overlaps("10.0.0.0/16", "10.0.128.0/17")).toBe(true);
    expect(overlaps("10.0.0.0/16", "10.1.0.0/16")).toBe(false);
  });
});

describe("classification", () => {
  it("classifies address sets", () => {
    expect(classifyAddressing(splitByFamily(["10.0.0.0/16"]))).toBe("ipv4-only");
    expect(classifyAddressing(splitByFamily(["fd00::/48"]))).toBe("ipv6-only");
    expect(classifyAddressing(splitByFamily(["10.0.0.0/16", "fd00::/48"]))).toBe("dual-stack");
    expect(classifyAddressing(splitByFamily([]))).toBe("no-ip");
    expect(classifyAddressing(splitByFamily(["10.0.0.0/16"]), false)).toBe("unknown");
  });

  it("detects default routes", () => {
    expect(isDefaultRoutePrefix("0.0.0.0/0")).toBe("ipv4");
    expect(isDefaultRoutePrefix("::/0")).toBe("ipv6");
    expect(isDefaultRoutePrefix("10.0.0.0/8")).toBeUndefined();
  });
});
