/**
 * Web HTML parser adapter (DOMParser).
 *
 * Minimal surface that mirrors the cheerio adapter. Only available in
 * environments with a global DOMParser (browser or jsdom).
 */
function wrap(el) {
  return {
    tagName: el.tagName ? el.tagName.toLowerCase() : "",
    getAttribute: (n) => el.getAttribute(n),
    get textContent() {
      return el.textContent ?? "";
    },
  };
}

export function createDomHtmlParser() {
  if (typeof DOMParser === "undefined") {
    throw new Error("createDomHtmlParser: DOMParser is not available in this environment");
  }
  return {
    parse(html) {
      const doc = new DOMParser().parseFromString(html, "text/html");
      return {
        querySelectorAll: (sel) =>
          Array.from(doc.querySelectorAll(sel)).map(wrap),
        getStyleTags: () =>
          Array.from(doc.querySelectorAll("style")).map(wrap),
        getComments: () => {
          const out = [];
          const walker = doc.createTreeWalker(doc, NodeFilter.SHOW_COMMENT);
          let n;
          while ((n = walker.nextNode())) out.push(n.data);
          return out;
        },
      };
    },
  };
}
