/**
 * MV3 content script (doc 07 §6.3): runs in the ISOLATED world on the
 * allowlisted webmail origins. Reads the rendered message DOM into a PageDom
 * snapshot, asks the service worker for the verdict (it owns the intel
 * bundle), and renders the inline risk badge next to the message.
 *
 * Selector self-test (§9): when a message view yields 0 URLs + 0 forms,
 * extraction is flagged degraded and the service worker falls back to
 * raw-HTML string heuristics — the badge reflects whatever could be scored.
 */

import { extractFromDocument } from "../dom/dom-adapter.js";
import type { ExtResponse } from "./messages.js";
import { renderBadge, removeBadge } from "./badge.js";

function send(msg: unknown): Promise<ExtResponse> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (r: ExtResponse) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message ?? "sendMessage failed" });
        return;
      }
      resolve(r);
    });
  });
}

/** A message view is heuristically "open" when the DOM carries mail markers. */
function looksLikeMessageView(doc: Document): boolean {
  if (doc.querySelector('[role="main"] [data-message-id], [role="main"] .msg, .ii.gt')) return true;
  return doc.querySelectorAll('[role="main"] a[href]').length > 3;
}

let lastSignature = "";

async function scan(): Promise<void> {
  const isMessage = looksLikeMessageView(document);
  if (!isMessage) {
    removeBadge(document);
    lastSignature = "";
    return;
  }
  const page = extractFromDocument(document);
  const signature = `${page.url}|${page.links.length}|${page.forms.length}|${page.title}`;
  if (signature === lastSignature) return;
  lastSignature = signature;

  const res = await send({
    type: "analyze-page",
    page,
    // §9 selector self-test: an open message that yields nothing → degraded.
    expectContent: true,
  });
  if (!res.ok || !("verdict" in res)) return;
  const state = await send({ type: "get-state" });
  const degraded = state.ok && "state" in state ? state.state.degraded : false;
  renderBadge(document, res.verdict, { degraded });
}

// Initial scan + re-scan on SPA navigation / message open (throttled).
void scan();
let scheduled = false;
const observer = new MutationObserver(() => {
  if (scheduled) return;
  scheduled = true;
  setTimeout(() => {
    scheduled = false;
    void scan();
  }, 750);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
