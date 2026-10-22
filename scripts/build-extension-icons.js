#!/usr/bin/env node
"use strict";

// Renders extension/icons/icon.svg to the PNG sizes Chrome needs, using a local
// headless Chrome over the DevTools protocol (no npm dependencies).
// Set CHROME_PATH if Chrome is not in a standard location.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const iconsDir = path.join(root, "extension", "icons");
const svg = fs.readFileSync(path.join(iconsDir, "icon.svg"), "utf8");
const SIZES = [16, 32, 48, 128];
const PORT = 9335;

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser"
  ].filter(Boolean);
  const found = candidates.find(candidate => fs.existsSync(candidate));
  if (!found) throw new Error("Chrome not found; set CHROME_PATH.");
  return found;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  if (typeof WebSocket !== "function") {
    throw new Error("build:icons needs Node 22+ (global WebSocket); found Node " + process.versions.node + ".");
  }
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "promptsafe-icons-"));
  const chrome = spawn(findChrome(), [
    "--headless=new", "--disable-gpu", "--no-first-run", `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`, "about:blank"
  ], { stdio: "ignore" });

  try {
    let target;
    for (let i = 0; i < 50 && !target; i++) {
      try {
        const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
        target = list.find(t => t.type === "page");
      } catch (_) { await sleep(200); }
    }
    if (!target) throw new Error("Could not connect to headless Chrome.");

    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
    let id = 0;
    const pending = new Map();
    ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id && pending.has(message.id)) { pending.get(message.id)(message); pending.delete(message.id); }
    };
    const send = (method, params = {}) => new Promise((resolve, reject) => {
      const callId = ++id;
      pending.set(callId, message => message.error
        ? reject(new Error(`${method} failed: ${message.error.message || JSON.stringify(message.error)}`))
        : resolve(message));
      ws.send(JSON.stringify({ id: callId, method, params }));
    });

    await send("Page.enable");
    await send("Emulation.setDefaultBackgroundColorOverride", { color: { r: 0, g: 0, b: 0, a: 0 } });
    const html = "<!doctype html><html><head><style>html,body{margin:0;background:transparent}svg{display:block;width:100vw;height:100vh}</style></head><body>" +
      svg + "</body></html>";
    for (const size of SIZES) {
      await send("Emulation.setDeviceMetricsOverride", { width: size, height: size, deviceScaleFactor: 1, mobile: false });
      await send("Page.navigate", { url: "data:text/html;base64," + Buffer.from(html).toString("base64") });
      await sleep(400);
      const shot = await send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: size, height: size, scale: 1 } });
      fs.writeFileSync(path.join(iconsDir, `icon-${size}.png`), Buffer.from(shot.result.data, "base64"));
      console.log(`Wrote extension/icons/icon-${size}.png`);
    }
    ws.close();
  } finally {
    chrome.kill();
    await sleep(300);
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) { /* Chrome may still hold files */ }
  }
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
