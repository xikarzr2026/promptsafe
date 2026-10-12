"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const root = path.resolve(__dirname, "..");
const extensionDir = path.join(root, "extension");
const manifest = JSON.parse(fs.readFileSync(path.join(extensionDir, "manifest.json"), "utf8"));
const backgroundSource = fs.readFileSync(path.join(extensionDir, "background.js"), "utf8");
const engineSource = fs.readFileSync(path.join(extensionDir, "engine.js"), "utf8");

test("extension uses a bundled engine and has the needed narrow permissions", () => {
  assert.ok(manifest.permissions.includes("scripting"));
  assert.ok(manifest.permissions.includes("activeTab"));
  assert.equal(manifest.host_permissions, undefined);
  assert.ok(backgroundSource.includes('contexts: ["editable"]'));
  assert.equal(backgroundSource.includes("fetch("), false);
  assert.equal(backgroundSource.includes("eval("), false);
  assert.equal(backgroundSource.includes("xikarzr2026.github.io"), false);
  assert.equal(backgroundSource.includes("cdn.tailwindcss.com"), false);
  assert.ok(engineSource.includes("PromptSafeEngine"));
  assert.equal(engineSource.includes("fetch("), false);
  assert.equal(engineSource.includes("eval("), false);
});

test("extension scrubs a selected textarea value using its packaged engine", async () => {
  let clickHandler;
  const selected = 'password="synthetic multi word value"';
  class FakeTextArea {
    constructor(value) {
      this.value = value;
      this.selectionStart = 0;
      this.selectionEnd = value.length;
      this.events = [];
    }
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
    dispatchEvent(event) { this.events.push(event.type); return true; }
  }
  class FakeInputEvent {
    constructor(type) { this.type = type; }
  }
  class FakeEvent {
    constructor(type) { this.type = type; }
  }

  const textarea = new FakeTextArea(selected);
  const context = vm.createContext({
    console: { warn() {} },
    document: { activeElement: textarea },
    window: {},
    HTMLTextAreaElement: FakeTextArea,
    HTMLInputElement: class FakeInput {},
    InputEvent: FakeInputEvent,
    Event: FakeEvent,
    chrome: {
      runtime: { lastError: null, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
      contextMenus: {
        removeAll(callback) { callback(); },
        create() {},
        onClicked: { addListener(fn) { clickHandler = fn; } }
      },
      scripting: {
        async executeScript(options) {
          if (options.files) {
            for (const file of options.files) {
              vm.runInContext(fs.readFileSync(path.join(extensionDir, file), "utf8"), context);
            }
            return [];
          }
          const injected = vm.runInContext(`(${options.func.toString()})`, context);
          return [{ result: await injected(...options.args) }];
        }
      }
    }
  });

  vm.runInContext(backgroundSource, context);
  await clickHandler({ menuItemId: "promptsafe-scrub", selectionText: selected }, { id: 5, url: "https://example.test/" });
  assert.equal(textarea.value, 'password="[REDACTED_SECRET]"');
  assert.ok(textarea.events.includes("input"));
  assert.ok(textarea.events.includes("change"));
});
