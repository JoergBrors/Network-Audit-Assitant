import { describe, expect, it } from "vitest";
import { evaluateFirewall } from "../../src/security/firewall.js";
import * as F from "../fixtures/hubSpoke.js";
import { ctxFor, lc } from "../routing/helpers.js";

describe("Azure Firewall policy evaluation", () => {
  const ctx = ctxFor();
  const fw = ctx.firewalls.get(lc(F.FW))!;

  it("allows flows matching a network rule", () => {
    expect(
      evaluateFirewall(ctx, fw, {
        source: "10.1.1.4",
        destination: "8.8.8.8",
        protocol: "Tcp",
        port: 443,
        internet: true,
      }),
    ).toMatchObject({
      access: "Allow",
      rule: "rcg-net/allow-web/web",
      confidence: "CONFIRMED",
    });
  });

  it("denies unmatched flows (default deny)", () => {
    expect(
      evaluateFirewall(ctx, fw, {
        source: "10.1.1.4",
        destination: "8.8.8.8",
        protocol: "Tcp",
        port: 22,
        internet: true,
      }),
    ).toMatchObject({
      access: "Deny",
      confidence: "LIKELY",
    });
  });

  it("notes IPv6 limitations of Azure Firewall", () => {
    const d = evaluateFirewall(ctx, fw, {
      source: "fd00:11:0:1::4",
      destination: "2001:4860:4860::8888",
      protocol: "Tcp",
      port: 443,
      internet: true,
    });
    expect(d.evidence.some((e) => e.description.includes("IPv6 (Preview)"))).toBe(true);
  });

  it("reports UNKNOWN when no policy is attached", () => {
    expect(
      evaluateFirewall(
        ctx,
        { ...fw, firewallPolicyId: undefined },
        { source: "10.1.1.4", destination: "8.8.8.8", protocol: "Tcp", port: 443, internet: true },
      ),
    ).toMatchObject({
      access: "Unknown",
      confidence: "UNKNOWN",
    });
  });
});
