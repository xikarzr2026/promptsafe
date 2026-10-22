#!/usr/bin/env node
"use strict";

// Builds extension/engine.js from the engine block in index.html. The same
// bundle is loaded by the CLI and REST server, so every surface runs one engine.

const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const sourcePath = path.join(root, "index.html");
const outputPath = path.join(root, "extension", "engine.js");
const source = fs.readFileSync(sourcePath, "utf8").replace(/\r\n/g, "\n");
const start = source.indexOf("const PS_VERSION = ");
const end = source.indexOf("/* ══════════════════════════════════════════════════════════════════\n   UI WIRING", start);
if (start < 0 || end < 0 || end <= start) {
  console.error("Could not locate the engine block in index.html.");
  process.exit(1);
}

const engine = source.slice(start, end).trimEnd();
const bundle = [
  "/* Generated from index.html by scripts/build-extension-engine.js. Do not edit. */",
  '"use strict";',
  "(function () {",
  "  if (!globalThis.PromptSafeEngine) {",
  engine,
  "  globalThis.PromptSafeEngine = Object.freeze({ PS_VERSION, PS_RULES, PS_scan, PS_scanRaw, PS_apply, PS_esc, PS_compress, PS_scrubCompress });",
  "  }",
  '  if (typeof module === "object" && module && module.exports) module.exports = globalThis.PromptSafeEngine;',
  "})();",
  ""
].join("\n");

if (process.argv.includes("--check")) {
  if (!fs.existsSync(outputPath) || fs.readFileSync(outputPath, "utf8").replace(/\r\n/g, "\n") !== bundle) {
    console.error("extension/engine.js is stale; run npm run build");
    process.exit(1);
  }
  console.log("extension/engine.js matches the browser engine.");
} else {
  fs.writeFileSync(outputPath, bundle, "utf8");
  console.log("Built extension/engine.js from index.html.");
}
