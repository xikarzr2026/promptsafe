/* PromptSafe Browser Extension — Background Worker */

const PROMPTSAFE_URL = "https://xikarzr2026.github.io/promptsafe/";

// Create context menu item
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "promptsafe-scrub",
    title: "Scrub secrets with PromptSafe",
    contexts: ["selection", "editable"]
  });
});

// Handle context menu click
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== "promptsafe-scrub") return;

  const selectedText = info.selectionText;
  if (!selectedText) return;

  // Inject the scrubber into the active tab
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: async (text) => {
      // Fetch the PromptSafe engine
      const response = await fetch(PROMPTSAFE_URL);
      const html = await response.text();

      // Extract the script content
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, "text/html");
      const scripts = doc.querySelectorAll("script");
      let engineCode = "";
      for (const s of scripts) {
        if (s.textContent && s.textContent.includes("PS_RULES")) {
          engineCode = s.textContent;
          break;
        }
      }

      if (!engineCode) {
        alert("PromptSafe: Could not load the scrubbing engine. Please check your connection.");
        return;
      }

      // Execute the engine
      eval(engineCode);

      // Scrub the text
      const enabled = new Set(PS_RULES.map(r => r.id));
      const ranges = PS_scan(text, enabled);
      const result = PS_apply(text, ranges);

      // Replace the selected text
      if (document.activeElement) {
        const el = document.activeElement;
        if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
          const start = el.selectionStart;
          const end = el.selectionEnd;
          el.value = el.value.substring(0, start) + result.plain + el.value.substring(end);
          el.selectionStart = el.selectionEnd = start + result.plain.length;
        } else {
          // For contenteditable elements
          document.execCommand("insertText", false, result.plain);
        }
      }
    },
    args: [selectedText]
  });
});
