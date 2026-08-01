/**
 * Browser entry (doc 07 §6.2): first-party webmail embed / content-script use.
 * `analyzePage(document?)` walks the live DOM into a PageDom snapshot
 * (phish-dom adapter) and runs the shared pipeline. No globals besides what
 * the caller passes; no network fetches (§6.2, §7.1).
 */

import { extractFromDocument } from "../dom/dom-adapter.js";
import { extractPageEvidence } from "../dom/page-context.js";
import type { ClientMeta } from "../core/evidence.js";
import { evidenceFromPage } from "../core/normalize.js";
import type { AnalyzeOptions } from "../core/pipeline.js";
import type { Verdict } from "../core/verdict.js";
import { PhishCatcher, createPhishCatcher } from "../index.js";

export * from "../index.js";

export interface AnalyzePageOptions extends AnalyzeOptions {
  clientMeta?: Partial<ClientMeta>;
  /**
   * Extraction self-test (doc 07 §9): when true, a page that yields 0 URLs
   * and 0 forms is flagged `extraction_degraded` — the caller should fall
   * back to raw-HTML string heuristics.
   */
  expectContent?: boolean;
  /** Restrict extraction to a subtree (e.g. the webmail message container). */
  root?: ParentNode;
}

export interface PageAnalysis {
  verdict: Verdict;
  /** §9 selector self-test outcome. */
  extractionDegraded: boolean;
}

export function analyzePageWith(
  catcher: PhishCatcher,
  doc: Document,
  opts: AnalyzePageOptions = {},
): PageAnalysis {
  const { clientMeta, expectContent, root, ...analyzeOpts } = opts;
  const dom = extractFromDocument(doc, root ?? doc);
  const { page, extractionDegraded } = extractPageEvidence(dom, {
    ...(expectContent !== undefined ? { expectContent } : {}),
  });
  const verdict = catcher.analyzePage({ ...page, clientMeta }, {
    ...analyzeOpts,
    extractionDegraded,
  });
  return { verdict, extractionDegraded };
}

/** One-shot convenience: default registry, empty intel (bundle-less). */
export function analyzePage(doc: Document = document, opts: AnalyzePageOptions = {}): PageAnalysis {
  return analyzePageWith(createPhishCatcher(), doc, opts);
}
