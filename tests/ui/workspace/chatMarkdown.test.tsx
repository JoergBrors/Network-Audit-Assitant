import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ChatMarkdown } from "../../../src/ui/workspace/ChatMarkdown.js";

const render = (text: string) => renderToStaticMarkup(createElement(ChatMarkdown, { text }));

describe("ChatMarkdown", () => {
  it("renders bold, code, lists and headings", () => {
    expect(render("## NSGs\n**nsg-a** an `nic-1`\n- eins\n- zwei\n1. erst")).toBe(
      '<p class="ai-md-heading">NSGs</p><p><strong>nsg-a</strong> an <code>nic-1</code></p>' +
        "<ul><li>eins</li><li>zwei</li></ul><ol><li>erst</li></ol>",
    );
  });

  it("renders pipe tables", () => {
    expect(render("| VM | Port |\n|---|---|\n| vm1 | 22 |")).toBe(
      '<div class="ai-md-table"><table><thead><tr><th>VM</th><th>Port</th></tr></thead>' +
        "<tbody><tr><td>vm1</td><td>22</td></tr></tbody></table></div>",
    );
  });

  it("renders incomplete streamed input (table header without separator yet)", () => {
    expect(render("Ergebnis:\n| VM | Port |")).toBe("<p>Ergebnis:</p><p>| VM | Port |</p>");
    expect(render("| VM | Port |")).toBe("<p>| VM | Port |</p>");
    expect(render("```\nprint(1)")).toBe('<pre class="ai-md-code">print(1)</pre>');
  });

  it("never injects HTML from model output", () => {
    const html = render('<img src=x onerror="alert(1)"> **<b>x</b>**');
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
    expect(html).toContain("<strong>&lt;b&gt;x&lt;/b&gt;</strong>");
  });
});
