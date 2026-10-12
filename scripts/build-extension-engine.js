#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const sourcePath = path.join(root, "index.html");
const outputPath = path.join(root, "extension", "engine.js");
const source = fs.readFileSync(sourcePath, "utf8");
const start = source.indexOf("const PS_RULES = [");
const end = source.indexOf("/* ══════════════════════════════════════════════════════════════════\n   UI WIRING", start);
if (start < 0 || end < 0 || end <= start) {
  console.error("Could not locate the engine block in index.html.");
  process.exit(1);
}

const engine = source.slice(start, end).trimEnd();
const bundle = [
  '"use strict";',
  "(function () {",
  "  if (globalThis.PromptSafeEngine) return;",
  engine,
  "  globalThis.PromptSafeEngine = Object.freeze({ PS_RULES, PS_scan, PS_apply });",
  "})();",
  ""
].join("\n");

if (process.argv.includes("--check")) {
  if (!fs.existsSync(outputPath) || fs.readFileSync(outputPath, "utf8") !== bundle) {
    console.error("extension/engine.js is stale; run node scripts/build-extension-engine.js");
    process.exit(1);
  }
  console.log("extension/engine.js matches the browser engine.");
} else {
  fs.writeFileSync(outputPath, bundle, "utf8");
  console.log("Built extension/engine.js from index.html.");
}
