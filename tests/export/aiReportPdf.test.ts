import { describe, expect, it } from "vitest";
import { PDFDocument, StandardFonts } from "pdf-lib";
import { generateAiReportPdf, stripMarkdown, toPdfSafe, wrapLine } from "../../src/export/aiReportPdf.js";
import type { AiReport } from "../../src/ai/analyze.js";

describe("generateAiReportPdf", () => {
  it("produces a well-formed PDF byte stream for a report with findings", async () => {
    const report: AiReport = {
      summary: "Ein IPv6-Leck gefunden, sonst unauffällig.",
      findings: [
        {
          severity: "HIGH",
          title: "IPv6 umgeht die Firewall",
          description: "Subnet snet-app (rg-prod) hat eine öffentliche IPv6-Route ohne zentrale Kontrolle.",
          affected: ["snet-app (rg-prod)", "vnet-spoke (rg-prod)"],
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

  it("renders characters outside WinAnsi (arrows, check marks, emoji) instead of failing", async () => {
    const report: AiReport = {
      summary: "IPv6 → Internet ✅, Port ≥ 1024 ⚠️ 🚀 – „Zitat“ … 中文",
      findings: [
        {
          severity: "CRITICAL",
          title: "**Bypass** → Internet",
          description: "- Punkt 1\n- Punkt 2 mit `code`\n\n## Überschrift",
          affected: [
            "/subscriptions/42fc73d5-9984-41a9-acc8-62c1a2cf6519/resourcegroups/rgpeuwangisp001/providers/microsoft.network/networkinterfaces/vmeuwangisp001143",
          ],
        },
      ],
      recommendations: ["NSG ✓ prüfen"],
    };
    const bytes = await generateAiReportPdf(report, {
      model: "gpt-5-mini",
      source: "Snapshot x.json",
      transcript: [
        { role: "user", text: "Frage → ?", attachments: ["a.csv"] },
        { role: "assistant", text: "Antwort ✅" },
      ],
    });
    const doc = await PDFDocument.load(bytes);
    expect(doc.getPageCount()).toBe(2); // report + transcript appendix
    expect(doc.getTitle()).toBe("Azure Network Audit – KI-Analyse");
  });

  it("maps unsupported characters and strips Markdown", async () => {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    expect(toPdfSafe("a → b ≥ c ✅ 🚀 „ok“ – ä", font)).toBe("a -> b >= c [OK] ? „ok“ – ä");
    // Line breaks are paragraph separators, never "?".
    expect(toPdfSafe("Zeile 1\r\n\nZeile 2", font)).toBe("Zeile 1\n\nZeile 2");
    expect(stripMarkdown("## Titel\n**fett** und `code`\n* Punkt\n[Link](https://x)")).toBe(
      "Titel\nfett und code\n• Punkt\nLink",
    );
  });

  it("splits words wider than the line (long resource IDs)", async () => {
    const doc = await PDFDocument.create();
    const font = await doc.embedFont(StandardFonts.Helvetica);
    const id =
      "/subscriptions/42fc73d5/resourcegroups/rg/providers/microsoft.network/networkinterfaces/nic".repeat(3);
    const lines = wrapLine(`Betroffen: ${id}`, font, 10, 300);
    expect(lines.length).toBeGreaterThan(2);
    for (const line of lines) expect(font.widthOfTextAtSize(line, 10)).toBeLessThanOrEqual(300);
    expect(lines.join("").replace(/ /g, "")).toBe(`Betroffen:${id}`);
  });
});
