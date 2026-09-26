import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import type { AiReport } from "../ai/analyze.js";

const PAGE_SIZE: [number, number] = [595.28, 841.89]; // A4 in points
const MARGIN = 50;
const SEVERITY_COLOR: Record<string, [number, number, number]> = {
  CRITICAL: [0.78, 0.16, 0.16],
  HIGH: [0.85, 0.35, 0.1],
  MEDIUM: [0.85, 0.65, 0.1],
  LOW: [0.4, 0.4, 0.4],
  INFO: [0.55, 0.55, 0.55],
};

interface Cursor {
  doc: PDFDocument;
  page: PDFPage;
  font: PDFFont;
  bold: PDFFont;
  y: number;
  pageWidth: number;
  pageHeight: number;
}

function newPage(cursor: Pick<Cursor, "doc" | "font" | "bold" | "pageWidth" | "pageHeight">): Cursor {
  const page = cursor.doc.addPage(PAGE_SIZE);
  return { ...cursor, page, y: cursor.pageHeight - MARGIN };
}

function ensureSpace(cursor: Cursor, neededHeight: number): Cursor {
  if (cursor.y - neededHeight < MARGIN) return newPage(cursor);
  return cursor;
}

/** Word-wraps `text` to fit within `maxWidth`, using `font` at `size`. */
function wrapText(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) > maxWidth && line) {
      lines.push(line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function drawParagraph(cursor: Cursor, text: string, opts: { size?: number; bold?: boolean; gapAfter?: number } = {}): Cursor {
  const size = opts.size ?? 11;
  const font = opts.bold ? cursor.bold : cursor.font;
  const maxWidth = cursor.pageWidth - MARGIN * 2;
  let c = cursor;
  for (const line of wrapText(text, font, size, maxWidth)) {
    c = ensureSpace(c, size + 4);
    c.page.drawText(line, { x: MARGIN, y: c.y, size, font, color: rgb(0.1, 0.1, 0.1) });
    c = { ...c, y: c.y - (size + 4) };
  }
  return { ...c, y: c.y - (opts.gapAfter ?? 0) };
}

function drawHeading(cursor: Cursor, text: string): Cursor {
  const c = ensureSpace(cursor, 28);
  c.page.drawText(text, { x: MARGIN, y: c.y, size: 16, font: c.bold, color: rgb(0, 0, 0) });
  return { ...c, y: c.y - 24 };
}

function drawSubheading(cursor: Cursor, text: string): Cursor {
  const c = ensureSpace(cursor, 22);
  c.page.drawText(text, { x: MARGIN, y: c.y, size: 13, font: c.bold, color: rgb(0, 0, 0) });
  return { ...c, y: c.y - 18 };
}

function drawFinding(cursor: Cursor, finding: AiReport["findings"][number]): Cursor {
  let c = ensureSpace(cursor, 16);
  const color = SEVERITY_COLOR[finding.severity] ?? SEVERITY_COLOR.INFO!;
  const badge = finding.severity;
  c.page.drawRectangle({
    x: MARGIN,
    y: c.y - 2,
    width: c.bold.widthOfTextAtSize(badge, 9) + 8,
    height: 13,
    color: rgb(...color),
  });
  c.page.drawText(badge, { x: MARGIN + 4, y: c.y, size: 9, font: c.bold, color: rgb(1, 1, 1) });
  const titleX = MARGIN + c.bold.widthOfTextAtSize(badge, 9) + 14;
  c.page.drawText(finding.title, { x: titleX, y: c.y, size: 11, font: c.bold, color: rgb(0, 0, 0) });
  c = { ...c, y: c.y - 16 };
  c = drawParagraph(c, finding.description, { size: 10 });
  if (finding.affected.length > 0) {
    c = drawParagraph(c, `Betroffen: ${finding.affected.join(", ")}`, { size: 9 });
  }
  return { ...c, y: c.y - 8 };
}

/** Renders an AiReport (structured findings/summary/recommendations from the AI chat session, see
 * src/ai/analyze.ts) to a PDF entirely in the browser — no server round-trip, so the (already
 * sanitized, but locally-produced) report never has to leave the client to become a document. */
export async function generateAiReportPdf(report: AiReport): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const [pageWidth, pageHeight] = PAGE_SIZE;

  let cursor = newPage({ doc, font, bold, pageWidth, pageHeight });
  cursor = drawHeading(cursor, "Azure Network Audit – KI-Analyse");
  cursor = drawParagraph(cursor, new Date().toLocaleString("de-DE"), { size: 9, gapAfter: 12 });

  cursor = drawSubheading(cursor, "Zusammenfassung");
  cursor = drawParagraph(cursor, report.summary || "(keine Zusammenfassung)", { gapAfter: 12 });

  cursor = drawSubheading(cursor, `Findings (${report.findings.length})`);
  if (report.findings.length === 0) cursor = drawParagraph(cursor, "Keine Findings gemeldet.");
  for (const finding of report.findings) cursor = drawFinding(cursor, finding);

  if (report.recommendations.length > 0) {
    cursor = drawSubheading(cursor, "Empfehlungen");
    for (const rec of report.recommendations) cursor = drawParagraph(cursor, `• ${rec}`, { size: 10 });
  }

  return doc.save();
}

/** Triggers a browser download of the report as a PDF (no data leaves the browser). */
export async function downloadAiReportPdf(report: AiReport, fileName = "azure-network-audit-ki-report.pdf"): Promise<void> {
  const bytes = await generateAiReportPdf(report);
  const blob = new Blob([bytes.slice().buffer], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
