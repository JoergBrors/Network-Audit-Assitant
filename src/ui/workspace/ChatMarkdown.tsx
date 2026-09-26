import { Fragment, type ReactNode } from "react";

/**
 * Minimal Markdown for chat answers: paragraphs, headings, bullet/numbered lists, pipe tables,
 * **bold** and `code`. Renders React elements only (no HTML injection), so model output can never
 * inject markup.
 */
export function ChatMarkdown({ text }: { text: string }) {
  return <>{blocks(text)}</>;
}

function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /\*\*(.+?)\*\*|`([^`]+)`/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(m[1] !== undefined ? <strong key={m.index}>{m[1]}</strong> : <code key={m.index}>{m[2]}</code>);
    last = re.lastIndex;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const cells = (line: string) =>
  line
    .trim()
    .replace(/^\||\|$/g, "")
    .split("|")
    .map((c) => c.trim());

function blocks(text: string): ReactNode[] {
  const lines = text.replace(/\r/g, "").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    const key = `b${i}`;
    if (/^```/.test(line)) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i]!)) code.push(lines[i++]!);
      i++;
      out.push(
        <pre key={key} className="ai-md-code">
          {code.join("\n")}
        </pre>,
      );
    } else if (/^\s*\|.*\|\s*$/.test(line) && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1] ?? "")) {
      const head = cells(line);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i]!)) rows.push(cells(lines[i++]!));
      out.push(
        <div key={key} className="ai-md-table">
          <table>
            <thead>
              <tr>
                {head.map((h, j) => (
                  <th key={j}>{inline(h)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, k) => (
                <tr key={k}>
                  {r.map((c, j) => (
                    <td key={j}>{inline(c)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
    } else if (/^\s*([-*•]|\d+[.)])\s+/.test(line)) {
      const ordered = /^\s*\d+[.)]\s+/.test(line);
      const items: string[] = [];
      const marker = ordered ? /^\s*\d+[.)]\s+/ : /^\s*[-*•]\s+/;
      while (i < lines.length && marker.test(lines[i]!)) {
        items.push(lines[i++]!.replace(/^\s*([-*•]|\d+[.)])\s+/, ""));
      }
      const children = items.map((it, j) => <li key={j}>{inline(it)}</li>);
      out.push(ordered ? <ol key={key}>{children}</ol> : <ul key={key}>{children}</ul>);
    } else if (/^#{1,6}\s+/.test(line)) {
      out.push(
        <p key={key} className="ai-md-heading">
          {inline(line.replace(/^#{1,6}\s+/, ""))}
        </p>,
      );
      i++;
    } else if (!line.trim()) {
      i++;
    } else {
      // The first line always belongs to the paragraph (e.g. a table row whose separator has not
      // been streamed yet), so the loop always advances.
      const para: string[] = [lines[i++]!];
      while (
        i < lines.length &&
        lines[i]!.trim() &&
        !/^(```|#{1,6}\s|\s*([-*•]|\d+[.)])\s|\s*\|)/.test(lines[i]!)
      ) {
        para.push(lines[i++]!);
      }
      out.push(
        <p key={key}>
          {para.map((l, j) => (
            <Fragment key={j}>
              {j > 0 && <br />}
              {inline(l)}
            </Fragment>
          ))}
        </p>,
      );
    }
  }
  return out;
}
