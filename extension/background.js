/* PromptSafe Browser Extension — Local Engine Only */
"use strict";

const MENU_ID = "promptsafe-scrub";
const BADGE_MS = 4000;

function installContextMenu() {
  chrome.contextMenus.removeAll(() => {
    if (chrome.runtime.lastError) return;
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Scrub selected text with PromptSafe",
      // No documentUrlPatterns: editors inside about:blank/srcdoc iframes
      // (TinyMCE, CKEditor 4) would never match. scrubTab checks the tab URL.
      contexts: ["editable"]
    });
  });
}

chrome.runtime.onInstalled.addListener(installContextMenu);
chrome.runtime.onStartup.addListener(installContextMenu);

/** Short-lived toolbar feedback; never includes any selected text. */
function showBadge(tabId, text, color, title) {
  const action = chrome.action;
  if (!action || !action.setBadgeText) return;
  try {
    action.setBadgeBackgroundColor({ tabId, color });
    action.setBadgeText({ tabId, text });
    if (title) action.setTitle({ tabId, title });
    setTimeout(() => {
      try {
        action.setBadgeText({ tabId, text: "" });
        action.setTitle({ tabId, title: "PromptSafe — Scrub Secrets" });
      } catch (_) { /* tab may be gone */ }
    }, BADGE_MS);
  } catch (_) { /* badge feedback is best-effort */ }
}

const FAILURE_TITLES = {
  "engine-unavailable": "PromptSafe could not load its engine on this page.",
  "selection-changed": "The selection changed before it could be scrubbed. Select the text and try again.",
  "editable-selection-unavailable": "Select text inside an editable field, then try again.",
  "empty-selection": "Select some text first.",
  "field-unsupported": "This kind of field does not let extensions read its selection. Copy the text into a text box or the PromptSafe page instead."
};
const RESTRICTED_TITLE = "PromptSafe cannot run on this page.";
const FRAME_HINT = " Right-click inside the editor to scrub text in embedded frames.";

/* Runs in the page. Must be self-contained: it is serialized by executeScript. */
function scrubSelectionInPage(selectedText) {
  const engine = globalThis.PromptSafeEngine;
  if (!engine) return { ok: false, reason: "engine-unavailable" };
  const enabled = new Set(engine.PS_RULES.filter(rule => rule.id !== "inject" && rule.id !== "custom").map(rule => rule.id));
  const scrub = text => {
    const ranges = engine.PS_scan(text, enabled);
    return { text: engine.PS_apply(text, ranges).plain, count: ranges.length };
  };

  let active = document.activeElement;
  // Follow focus into open shadow roots (common in chat UIs built with web components).
  while (active && active.shadowRoot && active.shadowRoot.activeElement) active = active.shadowRoot.activeElement;

  const isTextField = active && (active instanceof HTMLTextAreaElement ||
    (active instanceof HTMLInputElement && /^(?:text|search|url|email|tel|password|)$/i.test(active.type || "")));
  if (isTextField) {
    const start = active.selectionStart;
    const end = active.selectionEnd;
    // Chrome exposes no selection range for some field types (e.g. type=email).
    if (!Number.isInteger(start) || !Number.isInteger(end)) return { ok: false, reason: "field-unsupported" };
    if (end <= start) return { ok: false, reason: "empty-selection" };
    // Scrub the field's real selection; Chrome normalizes whitespace in selectionText.
    const original = active.value.slice(start, end);
    if (selectedText && original.replace(/\s+/g, " ").trim() !== selectedText.replace(/\s+/g, " ").trim()) {
      return { ok: false, reason: "selection-changed" };
    }
    const result = scrub(original);
    if (result.count === 0) return { ok: true, redactions: 0 };
    const nextValue = active.value.slice(0, start) + result.text + active.value.slice(end);
    // Use the native setter so frameworks such as React notice the change.
    const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(active), "value");
    if (descriptor && descriptor.set) descriptor.set.call(active, nextValue);
    else active.value = nextValue;
    active.setSelectionRange(start + result.text.length, start + result.text.length);
    active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: result.text }));
    active.dispatchEvent(new Event("change", { bubbles: true }));
    return { ok: true, redactions: result.count };
  }

  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0 || selection.isCollapsed) return { ok: false, reason: "empty-selection" };
  const anchor = selection.anchorNode && (selection.anchorNode.nodeType === Node.ELEMENT_NODE
    ? selection.anchorNode : selection.anchorNode.parentElement);
  if (!anchor || !anchor.isContentEditable) return { ok: false, reason: "editable-selection-unavailable" };
  // Walk up to the editing host so the input event reaches the editor's listener.
  let host = anchor;
  while (host.parentElement && host.parentElement.isContentEditable) host = host.parentElement;

  const original = selection.toString();
  const result = scrub(original);
  if (result.count === 0) return { ok: true, redactions: 0 };

  // Prefer execCommand: rich editors (ProseMirror, Lexical, Slate) keep their
  // undo history and internal model in sync with it. Fall back to Range APIs.
  let replaced = false;
  try { replaced = document.execCommand("insertText", false, result.text); } catch (_) { replaced = false; }
  if (!replaced) {
    const range = selection.getRangeAt(0);
    range.deleteContents();
    const node = document.createTextNode(result.text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    selection.removeAllRanges();
    selection.addRange(range);
    host.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: result.text }));
  }
  return { ok: true, redactions: result.count };
}

/* Runs in every accessible frame of the tab. Reports only booleans, never content. */
function probeFocusedEditable() {
  let active = document.activeElement;
  while (active && active.shadowRoot && active.shadowRoot.activeElement) active = active.shadowRoot.activeElement;
  const editable = !!active && (active instanceof HTMLTextAreaElement ||
    (active instanceof HTMLInputElement && /^(?:text|search|url|email|tel|password|)$/i.test(active.type || "")) ||
    !!active.isContentEditable);
  return { focused: document.hasFocus(), editable };
}

/**
 * The toolbar button and shortcut carry no frameId, so find the frame that holds
 * the focused editable element. Frames activeTab cannot reach (cross-origin
 * iframes) report nothing; if probing fails entirely, fall back to the top frame.
 */
async function findEditableFrame(tabId) {
  let results;
  try {
    results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: probeFocusedEditable });
  } catch (_) {
    return 0;
  }
  const frames = (results || []).filter(r => r && Number.isInteger(r.frameId) && r.result && r.result.editable);
  const focused = frames.filter(r => r.result.focused);
  if (focused.length) return (focused.find(r => r.frameId !== 0) || focused[0]).frameId;
  if (frames.some(r => r.frameId === 0)) return 0;
  return frames.length === 1 ? frames[0].frameId : 0;
}

async function scrubTab(tab, frameId, selectionText, fromMenu) {
  if (!tab || !Number.isInteger(tab.id)) return;
  if (!/^https?:\/\//i.test(tab.url || "")) {
    showBadge(tab.id, "!", "#dc2626", RESTRICTED_TITLE);
    return;
  }
  const target = { tabId: tab.id };
  if (Number.isInteger(frameId)) target.frameIds = [frameId];
  // Without a menu click we may have guessed the top frame for an iframe editor.
  const hint = !fromMenu && !frameId ? FRAME_HINT : "";

  try {
    await chrome.scripting.executeScript({ target, files: ["engine.js"] });
    const results = await chrome.scripting.executeScript({
      target,
      args: [selectionText || ""],
      func: scrubSelectionInPage
    });
    const outcome = results && results[0] && results[0].result;
    if (outcome && outcome.ok) {
      const n = outcome.redactions || 0;
      showBadge(tab.id, n ? String(Math.min(n, 999)) : "0", n ? "#059669" : "#64748b",
        n ? `PromptSafe redacted ${n} item${n === 1 ? "" : "s"}.` : "PromptSafe found nothing to redact.");
    } else {
      const reason = outcome && outcome.reason;
      showBadge(tab.id, "!", "#dc2626", (FAILURE_TITLES[reason] || "PromptSafe could not scrub the selection.") + hint);
    }
  } catch (error) {
    // Never log selected text or the injected page's contents.
    console.warn("PromptSafe could not scrub the selection.", error && error.message ? error.message : "unknown error");
    showBadge(tab.id, "!", "#dc2626", RESTRICTED_TITLE + hint);
  }
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID) return undefined;
  return scrubTab(tab, info.frameId, info.selectionText, true);
});

async function scrubFocusedFrame(tab) {
  if (!tab || !Number.isInteger(tab.id)) return;
  const frameId = /^https?:\/\//i.test(tab.url || "") ? await findEditableFrame(tab.id) : 0;
  await scrubTab(tab, frameId, "", false);
}

chrome.action.onClicked.addListener(scrubFocusedFrame);
chrome.commands.onCommand.addListener((command, tab) => {
  if (command === "scrub-selection") return scrubFocusedFrame(tab);
  return undefined;
});
