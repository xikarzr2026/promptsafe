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
      action: { onClicked: { addListener() {} } },
      commands: { onCommand: { addListener() {} } },
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

test("extension shows a failure badge, never selected text, when nothing editable is selected", async () => {
  let clickHandler;
  const badges = [];
  const context = vm.createContext({
    console: { warn() {} },
    setTimeout() {},
    document: { activeElement: null, execCommand() { return false; } },
    window: { getSelection() { return { rangeCount: 0, isCollapsed: true }; } },
    Node: { ELEMENT_NODE: 1 },
    HTMLTextAreaElement: class {},
    HTMLInputElement: class {},
    InputEvent: class {},
    Event: class {},
    chrome: {
      runtime: { lastError: null, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
      action: {
        setBadgeText(details) { badges.push(details.text); },
        setBadgeBackgroundColor() {},
        setTitle(details) { badges.push(details.title); },
        onClicked: { addListener() {} }
      },
      commands: { onCommand: { addListener() {} } },
      contextMenus: {
        removeAll(callback) { callback(); },
        create() {},
        onClicked: { addListener(fn) { clickHandler = fn; } }
      },
      scripting: {
        async executeScript(options) {
          if (options.files) {
            for (const file of options.files) vm.runInContext(fs.readFileSync(path.join(extensionDir, file), "utf8"), context);
            return [];
          }
          const injected = vm.runInContext(`(${options.func.toString()})`, context);
          return [{ result: await injected(...options.args) }];
        }
      }
    }
  });

  vm.runInContext(backgroundSource, context);
  await clickHandler({ menuItemId: "promptsafe-scrub", selectionText: "password=hunter2" }, { id: 7, url: "https://example.test/" });
  assert.ok(badges.includes("!"));
  assert.ok(badges.every(value => !String(value).includes("hunter2")));
});

test("manifest icons exist and are PNGs of the declared size", () => {
  const declared = { ...manifest.icons, ...manifest.action.default_icon };
  assert.ok(Object.keys(manifest.icons).includes("128"), "store listings need a 128px icon");
  for (const [size, file] of Object.entries(declared)) {
    const png = fs.readFileSync(path.join(extensionDir, file));
    assert.equal(png.subarray(1, 4).toString(), "PNG", `${file} is not a PNG`);
    assert.equal(png.readUInt32BE(16), Number(size), `${file} width`);
    assert.equal(png.readUInt32BE(20), Number(size), `${file} height`);
  }
});

test("manifest, package.json and engine report the same version", () => {
  const engine = require("../extension/engine.js");
  const pkg = require("../package.json");
  assert.equal(manifest.version, pkg.version, "manifest.json version must match package.json");
  assert.equal(engine.PS_VERSION, pkg.version, "PS_VERSION must match package.json");
});

/**
 * Loads background.js against a recording chrome fake. `frames` maps frameId to
 * the probe result that frame reports; `scrubResult` is what the scrub returns.
 */
function loadRecordingBackground({ frames = { 0: { focused: true, editable: false } }, probeThrows = false, scrubResult = { ok: true, redactions: 1 } } = {}) {
  const handlers = {};
  const calls = [];
  const badges = [];
  const menus = [];
  const context = vm.createContext({
    console: { warn() {} },
    setTimeout() {},
    chrome: {
      runtime: { lastError: null, onInstalled: { addListener(fn) { handlers.installed = fn; } }, onStartup: { addListener() {} } },
      action: {
        setBadgeText(details) { badges.push(details.text); },
        setBadgeBackgroundColor() {},
        setTitle(details) { badges.push(details.title); },
        onClicked: { addListener(fn) { handlers.action = fn; } }
      },
      commands: { onCommand: { addListener(fn) { handlers.command = fn; } } },
      contextMenus: {
        removeAll(callback) { callback(); },
        create(props) { menus.push(props); },
        onClicked: { addListener(fn) { handlers.menu = fn; } }
      },
      scripting: {
        async executeScript(options) {
          calls.push(options);
          if (options.target.allFrames) {
            if (probeThrows) throw new Error("Cannot access contents of the page.");
            return Object.entries(frames).map(([frameId, result]) => ({ frameId: Number(frameId), result }));
          }
          if (options.files) return [];
          return [{ frameId: 0, result: scrubResult }];
        }
      }
    }
  });
  vm.runInContext(backgroundSource, context);
  return { handlers, calls, badges, menus };
}

test("context menu is not limited by frame URL so about:blank editor iframes get it", () => {
  const bg = loadRecordingBackground();
  bg.handlers.installed();
  assert.equal(bg.menus.length, 1);
  assert.deepEqual([...bg.menus[0].contexts], ["editable"]);
  assert.equal(bg.menus[0].documentUrlPatterns, undefined);
});

test("menu click on a non-web tab shows a badge and injects nothing", async () => {
  const bg = loadRecordingBackground();
  await bg.handlers.menu({ menuItemId: "promptsafe-scrub", frameId: 0 }, { id: 3, url: "chrome://settings/" });
  assert.equal(bg.calls.length, 0);
  assert.ok(bg.badges.includes("!"));
  assert.ok(bg.badges.includes("PromptSafe cannot run on this page."));
});

test("toolbar click scrubs in the focused editable iframe, not the top frame", async () => {
  const bg = loadRecordingBackground({ frames: { 0: { focused: true, editable: false }, 4: { focused: false, editable: true }, 7: { focused: true, editable: true } } });
  await bg.handlers.action({ id: 9, url: "https://example.test/" });
  const injected = bg.calls.filter(call => !call.target.allFrames);
  assert.equal(injected.length, 2);
  for (const call of injected) assert.deepEqual([...call.target.frameIds], [7]);
  assert.ok(bg.badges.includes("1"));
});

test("keyboard command uses the same focused-frame path", async () => {
  const bg = loadRecordingBackground({ frames: { 0: { focused: true, editable: true } } });
  await bg.handlers.command("scrub-selection", { id: 9, url: "https://example.test/" });
  const injected = bg.calls.filter(call => !call.target.allFrames);
  assert.equal(injected.length, 2);
  for (const call of injected) assert.deepEqual([...call.target.frameIds], [0]);
});

test("toolbar click falls back to the top frame with an iframe hint when probing fails", async () => {
  const bg = loadRecordingBackground({ probeThrows: true, scrubResult: { ok: false, reason: "editable-selection-unavailable" } });
  await bg.handlers.action({ id: 9, url: "https://example.test/" });
  const injected = bg.calls.filter(call => !call.target.allFrames);
  for (const call of injected) assert.deepEqual([...call.target.frameIds], [0]);
  assert.ok(bg.badges.includes("!"));
  assert.ok(bg.badges.some(title => /Right-click inside the editor/.test(String(title))));
});

test("fields without a selection API (type=email) report field-unsupported, not selection-changed", async () => {
  let clickHandler;
  const badges = [];
  class FakeInput {
    constructor() { this.type = "email"; this.value = "a@example.test"; this.selectionStart = null; this.selectionEnd = null; }
  }
  const context = vm.createContext({
    console: { warn() {} },
    setTimeout() {},
    document: { activeElement: new FakeInput() },
    window: {},
    HTMLTextAreaElement: class {},
    HTMLInputElement: FakeInput,
    chrome: {
      runtime: { lastError: null, onInstalled: { addListener() {} }, onStartup: { addListener() {} } },
      action: {
        setBadgeText(details) { badges.push(details.text); },
        setBadgeBackgroundColor() {},
        setTitle(details) { badges.push(details.title); },
        onClicked: { addListener() {} }
      },
      commands: { onCommand: { addListener() {} } },
      contextMenus: { removeAll(callback) { callback(); }, create() {}, onClicked: { addListener(fn) { clickHandler = fn; } } },
      scripting: {
        async executeScript(options) {
          if (options.files) {
            for (const file of options.files) vm.runInContext(fs.readFileSync(path.join(extensionDir, file), "utf8"), context);
            return [];
          }
          const injected = vm.runInContext(`(${options.func.toString()})`, context);
          return [{ result: await injected(...options.args) }];
        }
      }
    }
  });
  vm.runInContext(backgroundSource, context);
  await clickHandler({ menuItemId: "promptsafe-scrub", frameId: 0, selectionText: "a@example.test" }, { id: 2, url: "https://example.test/" });
  assert.ok(badges.includes("!"));
  assert.ok(badges.some(title => /does not let extensions read its selection/.test(String(title))));
  assert.ok(!badges.some(title => /selection changed/.test(String(title))));
});
