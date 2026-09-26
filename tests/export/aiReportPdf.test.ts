import { describe, expect, it } from "vitest";
import { generateAiReportPdf } from "../../src/export/aiReportPdf.js";
import type { AiReport } from "../../src/ai/analyze.js";

describe("generateAiReportPdf", () => {
  it("produces a well-formed PDF byte stream for a report with findings", async () => {
    const report: AiReport = {
      summary: "Ein IPv6-Leck gefunden, sonst unauffällig.",
      findings: [
        {
          severity: "HIGH",
          title: "IPv6 umgeht die Firewall",
          description: "Subnet res-1a2b3c4d hat eine öffentliche IPv6-Route ohne zentrale Kontrolle.",
          affected: ["res-1a2b3c4d", "res-deadbeef"],
        },
        {
          severity: "INFO",
          title: "Keine weiteren Auffälligkeiten",
          description: "Restliche Konfiguration entspricht der Baseline.",
          affected: [],
        },
      ],
      recommendations: ["IPv6-UDR auf die zentrale Firewall ergänzen.", "NSG-Regeln für IPv6 spiegeln."],
    };

    const bytes = await generateAiReportPdf(report);

    expect(bytes.length).toBeGreaterThan(0);
    // PDF file signature.
    expect(String.fromCharCode(...bytes.slice(0, 5))).toBe("%PDF-");
  });

  it("handles an empty report (no findings/recommendations) without throwing", async () => {
    const report: AiReport = { summary: "", findings: [], recommendations: [] };

    const bytes = await generateAiReportPdf(report);

    expect(bytes.length).toBeGreaterThan(0);
  });

  it("wraps long text across multiple pages without throwing", async () => {
    const longDescription = "Sehr lange Beschreibung. ".repeat(500);
    const report: AiReport = {
      summary: "Zusammenfassung. ".repeat(200),
      findings: Array.from({ length: 30 }, (_, i) => ({
        severity: "MEDIUM" as const,
        title: `Finding ${i}`,
        description: longDescription,
        affected: [`res-${i}`],
      })),
      recommendations: [],
    };

    const bytes = await generateAiReportPdf(report);

    expect(bytes.length).toBeGreaterThan(0);
  });
});
