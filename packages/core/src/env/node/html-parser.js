/**
 * Node HTML parser adapter (cheerio).
 *
 * Exposes a minimal HtmlDoc/HtmlElement surface that overlaps with the
 * browser DOM. Used by hidden-elements detector when wiring through env
 * abstraction. (Phase 2: hidden-elements still imports cheerio directly for
 * minimal disruption; this adapter exists for future Web-shared usage.)
 */
import * as cheerio from "cheerio";

function wrap($, el) {
  return {
    tagName: (el.tagName || el.name || "").toLowerCase(),
    getAttribute: (n) => $(el).attr(n) ?? null,
    get textContent() {
      return $(el).text();
    },
  };
}

export function createCheerioHtmlParser() {
  return {
    parse(html) {
      const $ = cheerio.load(html, { xmlMode: false, decodeEntities: false });
      return {
        querySelectorAll: (sel) =>
          $(sel)
            .toArray()
            .map((el) => wrap($, el)),
        getStyleTags: () =>
          $("style")
            .toArray()
            .map((el) => wrap($, el)),
        getComments: () => {
          const out = [];
          $("*")
            .contents()
            .each((_, n) => {
              if (n.type === "comment") out.push(n.data);
            });
          return out;
        },
      };
    },
  };
}
