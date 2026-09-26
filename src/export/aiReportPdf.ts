import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage, type RGB } from "pdf-lib";
import type { AiFinding, AiReport, ChatMessage } from "../ai/analyze.js";

const PAGE_SIZE: [number, number] = [595.28, 841.89]; // A4 in points
const MARGIN = 50;
const FOOTER_Y = 28;
const TEXT = rgb(0.1, 0.1, 0.1);
const MUTED = rgb(0.4, 0.4, 0.4);
const SEVERITY_ORDER: AiFinding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEVERITY_COLOR: Record<AiFinding["severity"], RGB> = {
  CRITICAL: rgb(0.78, 0.16, 0.16),
  HIGH: rgb(0.85, 0.35, 0.1),
  MEDIUM: rgb(0.8, 0.6, 0.05),
  LOW: rgb(0.4, 0.4, 0.4),
  INFO: rgb(0.55, 0.55, 0.55),
};

export interface AiReportPdfOptions {
  generatedAt?: Date;
  /** Deployment name of the model that wrote the report. */
  model?: string;
  /** Where the analysed data came from (e.g. "Discovery" or the snapshot file name). */
  source?: string;
  /** Chat transcript, rendered as an appendix. */
  transcript?: ChatMessage[];
}

/**
 * The standard PDF fonts only cover WinAnsi (Latin-1 plus a few typographic characters); anything
 * else makes pdf-lib throw. Common symbols in model output get ASCII stand-ins, the rest becomes "?".
 */
const REPLACEMENTS: Record<string, string> = {
  "→": "->",
  "⇒": "=>",
  "←": "<-",
  "↔": "<->",
  "≤": "<=",
  "≥": ">=",
  "≠": "!=",
  "≈": "~",
  "✓": "[OK]",
  "✔": "[OK]",
  "✅": "[OK]",
  "✗": "[X]",
  "✘": "[X]",
  "❌": "[X]",
  "⚠": "(!)",
  "⚠️": "(!)",
  " ": " ",
  " ": " ",
  " ": " ",
  "​": "",
  "️": "",
  "\t": "  ",
  "\n": "\n",
  "\r": "",
};

export function toPdfSafe(text: string, font: PDFFont): string {
  const supported = new Set(font.getCharacterSet());
  let out = "";
  for (const ch of text.normalize("NFC")) {
    const replacement = REPLACEMENTS[ch];
    if (replacement !== undefined) out += replacement;
    else if (supported.has(ch.codePointAt(0)!)) out += ch;
    else out += "?";
  }
  return out;
}

/** Removes Markdown emphasis/code/heading markers; keeps list markers and line structure. */
export function stripMarkdown(text: string): string {
  return text
    .replace(/```[a-z]*\n?/gi, "")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/__(.+?)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^\s*[*-]\s+/gm, "• ")
    .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, "$1");
}

/** Word-wraps one line; words wider than the line (resource IDs, URLs) are split. */
export function wrapLine(text: string, font: PDFFont, size: number, maxWidth: number): string[] {
  const lines: string[] = [];
  let line = "";
  const fits = (s: string) => font.widthOfTextAtSize(s, size) <= maxWidth;
  for (const word of text.split(/ +/)) {
    const candidate = line ? `${line} ${word}` : word;
    if (fits(candidate)) {
      line = candidate;
      continue;
    }
    if (line) lines.push(line);
    let rest = word;
    while (!fits(rest)) {
      let n = rest.length - 1;
      while (n > 1 && !fits(rest.slice(0, n))) n--;
      lines.push(rest.slice(0, n));
      rest = rest.slice(n);
    }
    line = rest;
  }
  if (line || lines.length === 0) lines.push(line);
  return lines;
}

class Writer {
  page!: PDFPage;
  y = 0;
  readonly width = PAGE_SIZE[0] - MARGIN * 2;

  constructor(
    readonly doc: PDFDocument,
    readonly font: PDFFont,
    readonly bold: PDFFont,
  ) {
    this.newPage();
  }

  newPage(): void {
    this.page = this.doc.addPage(PAGE_SIZE);
    this.y = PAGE_SIZE[1] - MARGIN;
  }

  ensure(height: number): void {
    if (this.y - height < MARGIN) this.newPage();
  }

  /** Text with paragraphs (\n) and wrapping; `indent` shifts the block right. */
  text(
    raw: string,
    opts: { size?: number; bold?: boolean; color?: RGB; indent?: number; gapAfter?: number } = {},
  ): void {
    const size = opts.size ?? 10.5;
    const font = opts.bold ? this.bold : this.font;
    const indent = opts.indent ?? 0;
    const lineHeight = size * 1.35;
    for (const paragraph of raw.split(/\r?\n/).map((p) => toPdfSafe(p, font))) {
      if (!paragraph.trim()) {
        this.y -= lineHeight / 2;
        continue;
      }
      for (const line of wrapLine(paragraph, font, size, this.width - indent)) {
        this.ensure(lineHeight);
        this.page.drawText(line, {
          x: MARGIN + indent,
          y: this.y - size,
          size,
          font,
          color: opts.color ?? TEXT,
        });
        this.y -= lineHeight;
      }
    }
    this.y -= opts.gapAfter ?? 0;
  }

  heading(text: string, size = 13): void {
    this.ensure(size * 3);
    this.y -= size * 0.6;
    this.text(text, { size, bold: true, color: rgb(0, 0, 0), gapAfter: 4 });
  }

  rule(): void {
    this.ensure(10);
    this.page.drawLine({
      start: { x: MARGIN, y: this.y - 4 },
      end: { x: MARGIN + this.width, y: this.y - 4 },
      thickness: 0.5,
      color: rgb(0.8, 0.8, 0.8),
    });
    this.y -= 10;
  }

  finding(f: AiFinding): void {
    const badgeSize = 8.5;
    const badgeWidth = this.bold.widthOfTextAtSize(f.severity, badgeSize) + 8;
    const titleLines = wrapLine(toPdfSafe(f.title, this.bold), this.bold, 11, this.width - badgeWidth - 8);
    this.ensure(16 + titleLines.length * 15 + 30);
    this.page.drawRectangle({
      x: MARGIN,
      y: this.y - 13,
      width: badgeWidth,
      height: 13,
      color: SEVERITY_COLOR[f.severity],
    });
    this.page.drawText(f.severity, {
      x: MARGIN + 4,
      y: this.y - 10,
      size: badgeSize,
      font: this.bold,
      color: rgb(1, 1, 1),
    });
    for (const line of titleLines) {
      this.page.drawText(line, { x: MARGIN + badgeWidth + 8, y: this.y - 11, size: 11, font: this.bold });
      this.y -= 15;
    }
    this.y -= 2;
    this.text(stripMarkdown(f.description), { size: 10, indent: 4 });
    if (f.affected.length > 0)
      this.text(`Betroffen: ${f.affected.join(", ")}`, { size: 9, color: MUTED, indent: 4 });
    this.y -= 8;
  }
}

/**
 * Renders the report (and optionally the chat transcript) to a PDF in the browser; nothing leaves
 * the client. The report contains tenant data and is marked internal.
 */
export async function generateAiReportPdf(
  report: AiReport,
  options: AiReportPdfOptions = {},
): Promise<Uint8Array> {
  const generatedAt = options.generatedAt ?? new Date();
  const doc = await PDFDocument.create();
  doc.setTitle("Azure Network Audit – KI-Analyse");
  doc.setCreator("Azure Network Audit Assistant");
  doc.setCreationDate(generatedAt);
  const font = await doc.embedFont(StandardFonts.Helvetica);
  const bold = await doc.embedFont(StandardFonts.HelveticaBold);
  const w = new Writer(doc, font, bold);

  w.text("Azure Network Audit – KI-Analyse", { size: 18, bold: true, color: rgb(0, 0, 0), gapAfter: 4 });
  const meta = [
    `Erstellt: ${generatedAt.toLocaleString("de-DE")}`,
    options.model ? `Modell: ${options.model}` : undefined,
    options.source ? `Datenbasis: ${options.source}` : undefined,
  ].filter(Boolean);
  w.text(meta.join("  ·  "), { size: 9, color: MUTED });
  w.text("Vertraulich – enthält nicht anonymisierte Daten des Azure-Tenants.", {
    size: 9,
    bold: true,
    color: SEVERITY_COLOR.CRITICAL,
    gapAfter: 6,
  });
  w.rule();

  const findings = [...report.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  w.heading("Zusammenfassung");
  w.text(stripMarkdown(report.summary) || "(keine Zusammenfassung)", { gapAfter: 4 });
  const counts = SEVERITY_ORDER.map(
    (s) => [s, findings.filter((f) => f.severity === s).length] as const,
  ).filter(([, n]) => n > 0);
  if (counts.length) w.text(counts.map(([s, n]) => `${s}: ${n}`).join("   "), { size: 9.5, bold: true });

  w.heading(`Findings (${findings.length})`);
  if (findings.length === 0) w.text("Keine Findings gemeldet.");
  for (const f of findings) w.finding(f);

  if (report.recommendations.length > 0) {
    w.heading("Empfehlungen");
    report.recommendations.forEach((r, i) =>
      w.text(`${i + 1}. ${stripMarkdown(r)}`, { size: 10, gapAfter: 3 }),
    );
  }

  const transcript = options.transcript?.filter((m) => m.text.trim()) ?? [];
  if (transcript.length > 0) {
    w.newPage();
    w.heading("Anhang: Chatverlauf");
    for (const m of transcript) {
      w.text(m.role === "user" ? "Frage" : "Antwort", { size: 9, bold: true, color: MUTED });
      const extras = [
        m.attachments?.length ? `Anhänge: ${m.attachments.join(", ")}` : "",
        m.images?.length ? `${m.images.length} Bild(er)` : "",
      ].filter(Boolean);
      w.text(stripMarkdown(m.text) + (extras.length ? `\n(${extras.join("; ")})` : ""), {
        size: 9.5,
        gapAfter: 6,
      });
    }
  }

  const pages = doc.getPages();
  pages.forEach((page, i) => {
    const label = `Seite ${i + 1} von ${pages.length}`;
    page.drawText(label, {
      x: PAGE_SIZE[0] - MARGIN - font.widthOfTextAtSize(label, 8),
      y: FOOTER_Y,
      size: 8,
      font,
      color: MUTED,
    });
    page.drawText("Vertraulich", { x: MARGIN, y: FOOTER_Y, size: 8, font, color: MUTED });
  });
  return doc.save();
}

/** Triggers a browser download of the report as a PDF (no data leaves the browser). */
export async function downloadAiReportPdf(
  report: AiReport,
  options: AiReportPdfOptions = {},
  fileName = `azure-network-audit-ki-report-${new Date().toISOString().slice(0, 10)}.pdf`,
): Promise<void> {
  const bytes = await generateAiReportPdf(report, options);
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
