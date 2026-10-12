/* PromptSafe Browser Extension — Local Engine Only */
"use strict";

const MENU_ID = "promptsafe-scrub";

function installContextMenu() {
  chrome.contextMenus.removeAll(() => {
    if (chrome.runtime.lastError) return;
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Scrub selected text with PromptSafe",
      contexts: ["editable"],
      documentUrlPatterns: ["http://*/*", "https://*/*"]
    });
  });
}

chrome.runtime.onInstalled.addListener(installContextMenu);
chrome.runtime.onStartup.addListener(installContextMenu);

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !info.selectionText) return;
  if (!tab || !Number.isInteger(tab.id) || !/^https?:\/\//i.test(tab.url || "")) return;

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["engine.js"]
    });
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      args: [info.selectionText],
      func: function (selectedText) {
        const engine = globalThis.PromptSafeEngine;
        if (!engine) return { ok: false, reason: "engine-unavailable" };
        const activeRules = engine.PS_RULES.filter(rule => rule.id !== "inject");
        const enabled = new Set(activeRules.map(rule => rule.id));
        const ranges = engine.PS_scan(selectedText, enabled);
        const replacement = engine.PS_apply(selectedText, ranges).plain;
        const active = document.activeElement;

        if (active && (active instanceof HTMLTextAreaElement || active instanceof HTMLInputElement)) {
          const start = active.selectionStart;
          const end = active.selectionEnd;
          if (!Number.isInteger(start) || !Number.isInteger(end) || active.value.slice(start, end) !== selectedText) {
            return { ok: false, reason: "selection-changed" };
          }
          const nextValue = active.value.slice(0, start) + replacement + active.value.slice(end);
          const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(active), "value");
          if (descriptor && descriptor.set) descriptor.set.call(active, nextValue);
          else active.value = nextValue;
          active.setSelectionRange(start + replacement.length, start + replacement.length);
          active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: replacement }));
          active.dispatchEvent(new Event("change", { bubbles: true }));
          return { ok: true, redactions: ranges.length };
        }

        const selection = window.getSelection();
        const anchor = selection && selection.anchorNode
          ? (selection.anchorNode.nodeType === Node.ELEMENT_NODE ? selection.anchorNode : selection.anchorNode.parentElement)
          : null;
        const editable = anchor && anchor.closest("[contenteditable='true']");
        if (!selection || !editable || selection.toString() !== selectedText || selection.rangeCount === 0) {
          return { ok: false, reason: "editable-selection-unavailable" };
        }
        const range = selection.getRangeAt(0);
        range.deleteContents();
        const replacementNode = document.createTextNode(replacement);
        range.insertNode(replacementNode);
        range.setStartAfter(replacementNode);
        range.collapse(true);
        selection.removeAllRanges();
        selection.addRange(range);
        editable.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertReplacementText", data: replacement }));
        return { ok: true, redactions: ranges.length };
      }
    });
  } catch (error) {
    // Never log selected text or the injected page's contents.
    console.warn("PromptSafe could not scrub the selection.", error && error.message ? error.message : "unknown error");
  }
});
