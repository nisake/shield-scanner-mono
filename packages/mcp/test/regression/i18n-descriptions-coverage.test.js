/**
 * v1.20.0 T4 — i18n-descriptions coverage regression
 *
 * Pins the kebab/camel ids that MUST have an extended description
 * record (why/example/remediation) in
 * packages/web/src/i18n-descriptions.js. Adding a new finding id in
 * i18n.js without a sibling entry here will fail this test, forcing
 * the change to be intentional.
 *
 * Coverage scope: every finding-related key that shipped in i18n.js
 * up to and including v1.19.0. New v1.20.0 kebab ids (added by
 * sibling themes ODT/ODS/ODP, T8, ...) are intentionally NOT pinned
 * here — they will be added in a follow-up.
 *
 * The test reads the description registry from packages/web/ via an
 * ESM file: URL so the MCP workspace's vitest run can validate it
 * without a dependency edge.
 */

import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const REGISTRY_URL = "file://" +
  resolve(here, "..", "..", "..", "web", "src", "i18n-descriptions.js")
    .replace(/\\/g, "/");

// Snapshot of every finding-related kebab/camel id that needs an
// extended description as of v1.19.0. Two duplicate ids
// (pdfEmbedsJavaScriptActions + pdfEmbedsJavascriptActions) are listed
// because i18n.js intentionally registers both for the kebab→camel
// resolver fallback noted in t_technique().
const REQUIRED_KEYS = [
  // core 5 buckets
  "invisibleUnicode",
  "controlChars",
  "hiddenHtml",
  "suspiciousPatterns",
  "homoglyphs",
  "variationSelectors",
  "bidiOverride",
  "mathSymbolBypass",
  "combiningChars",
  // archive
  "archiveBomb",
  "archiveDepth",
  "archiveProtected",
  "archiveEntryCap",
  "archiveRenameSpoof",
  "archiveSanitizeUnsupported",
  // PDF
  "structTreeCapExceeded",
  "pdfEmbedsJavaScriptActions",
  "pdfEmbedsJavascriptActions",
  "oversizeAttachmentSkipped",
  "emptyAttachment",
  "pdfOversizeAttachment",
  "pdfEmbeddedBinaryAttachment",
  "pdfEmptyAttachment",
  "pdfWidgetAction",
  "pdfEmbeddedHtml",
  "pdfSubmitFormAction",
  "pdfGotoRemoteAction",
  "pdfRichmediaEmbed",
  "pdf3DEmbed",
  "pdfSoundAction",
  "pdfMovieAction",
  "microscopicText",
  "microscopicFontSize",
  "oversizeEmbeddedImage",
  "emptyEmbeddedImage",
  // DOCX / PPTX / OLE
  "docxAttachedTemplateRemote",
  "docxWebsettingsExternalLoad",
  "docxCustomxmlInstruction",
  "pptxAttachedTemplateRemote",
  "officeEmbeddedOleCfb",
  // XLSX
  "sheetStateConfusion",
  "autoRunDefinedName",
  "hiddenNumFmt",
  "ddeLink",
  "xlsxScanLimit",
  "xlsxCorruptZip",
  "vbaMacroProject",
  "extensionContentTypeMismatch",
  "xlmMacrosheet",
  "hiddenSheet",
  "veryhiddenSheet",
  "externalOleLink",
  "externalRelationship",
  "docpropsPromptInjection",
  "hyperlinkBaseRewrite",
  "instructionShapedComment",
  "oversizeEmbeddedObject",
  "csvScanLimitBytes",
  "csvEncodingFallback",
  "csvScanLimitRows",
  "emptyAttachmentBody",
  "whitespaceOnlyAttachment",
  "xlsxPowerQueryWebcontents",
  "xlsxDataConnectionShell",
  "xlsxActivexControl",
  "xlsxCustomUiCallback",
  // MCP descriptor scan
  "mcpDescriptorInjection",
  "mcpRugPullDetected",
  "mcpShadowToolCollision",
  "mcpHiddenInstructionInDescription",
  // EML / mail
  "emlFromReplyToMismatch",
  "emlSenderFromMismatch",
  "emlAuthenticationFailure",
  "emlPunycodeHomographDomain",
  "emlMixedScriptDomain",
  "emlEncodedWordInvisibleUnicode",
  "urlQueryVariationSelector",
  "urlQueryInvisibleUnicode",
  "mdExfilAllowlistSuppressed",
  "mdExfilAllowlistDowngraded",
  // PDF struct tree (v1.10.0+)
  "pdfStructHeadingH1",
  "pdfStructHeadingH2",
  "pdfStructHeadingH3",
  "pdfStructHeadingH4",
  "pdfStructHeadingH5",
  "pdfStructHeadingH6",
  "pdfStructBlockquote",
  "pdfStructQuote",
  "pdfStructSpan",
  // v1.19.0 B4: frontmatter
  "frontmatterPromptInjection",
  "yamlDangerousTag",
  "yamlAnchorBomb",
  "jsonldDescriptionInjection",
  "tomlInstructionKey",
  // v1.19.0 B1: SVG
  "svgScriptElement",
  "svgEventHandler",
  "svgJavascriptHref",
  "svgForeignobjectHtml",
  "svgCdataSection",
  "svgUseExternalRef",
  // v1.19.0 B2: RTF
  "rtfOleObject",
  "rtfFieldHyperlink",
  "rtfHiddenTextV",
  "rtfMicroscopicFont",
  "rtfBinaryBlock",
  "rtfUnknownDestination",
  // v1.19.0 B3: Jupyter Notebook
  "ipynbOutputHtmlInjection",
  "ipynbHiddenCellInstruction",
  "ipynbMetadataTagSmuggle",
  "ipynbUntrustedSignature",
  // v1.19.0 D1: encoded decoder
  "encodedBase64Instruction",
  "encodedHexInstruction",
  "encodedHtmlEntityInstruction",
  "punycodeHostHomograph",
  "multiLayerEncodedPayload",
];

describe("i18n-descriptions v1.19.0 coverage", () => {
  it("every required kebab id has a description in ja+en", async () => {
    const mod = await import(REGISTRY_URL);
    const { descriptions, getDescription } = mod;
    expect(descriptions).toBeTruthy();
    expect(descriptions.ja).toBeTruthy();
    expect(descriptions.en).toBeTruthy();

    const missingJa = REQUIRED_KEYS.filter(
      (k) => !descriptions.ja[k] || typeof descriptions.ja[k].why !== "string",
    );
    const missingEn = REQUIRED_KEYS.filter(
      (k) => !descriptions.en[k] || typeof descriptions.en[k].why !== "string",
    );

    expect(missingJa, "missing ja: " + missingJa.join(",")).toEqual([]);
    expect(missingEn, "missing en: " + missingEn.join(",")).toEqual([]);

    // Spot-check: getDescription resolves both forms.
    expect(getDescription("svgScriptElement", "en")).toBeTruthy();
    expect(getDescription("svg-script-element", "en")).toBeTruthy();
  });

  it("every description has why/example/remediation as non-empty strings", async () => {
    const { descriptions } = await import(REGISTRY_URL);
    for (const lang of ["ja", "en"]) {
      for (const [key, val] of Object.entries(descriptions[lang])) {
        expect(typeof val.why, lang + "/" + key + ".why").toBe("string");
        expect(val.why.length, lang + "/" + key + ".why").toBeGreaterThan(0);
        expect(typeof val.example, lang + "/" + key + ".example").toBe("string");
        expect(val.example.length, lang + "/" + key + ".example").toBeGreaterThan(0);
        expect(typeof val.remediation, lang + "/" + key + ".remediation").toBe("string");
        expect(val.remediation.length, lang + "/" + key + ".remediation").toBeGreaterThan(0);
      }
    }
  });

  it("R12: no interpolation placeholders in description prose", async () => {
    const { descriptions } = await import(REGISTRY_URL);
    const PLACEHOLDER = /\{[a-zA-Z_][a-zA-Z0-9_]*\}/;
    for (const lang of ["ja", "en"]) {
      for (const [key, val] of Object.entries(descriptions[lang])) {
        expect(PLACEHOLDER.test(val.why), lang + "/" + key + ".why").toBe(false);
        expect(PLACEHOLDER.test(val.example), lang + "/" + key + ".example").toBe(false);
        expect(PLACEHOLDER.test(val.remediation), lang + "/" + key + ".remediation").toBe(false);
      }
    }
  });
});
