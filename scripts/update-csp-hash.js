#!/usr/bin/env node
"use strict";

// Recomputes the sha256 of the single inline <script> in index.html and writes
// it into the Content-Security-Policy meta tag. Run after editing the script.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const file = path.resolve(__dirname, "..", "index.html");
const html = fs.readFileSync(file, "utf8");
const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].filter(m => !/\bsrc\s*=/i.test(m[1]));
if (scripts.length !== 1) {
  console.error(`Expected exactly one inline script, found ${scripts.length}.`);
  process.exit(1);
}
const hash = "'sha256-" + crypto.createHash("sha256")
  .update(scripts[0][2].replace(/\r\n/g, "\n"))
  .digest("base64") + "'";
const HASH_SLOT = /(script-src )'sha256-[A-Za-z0-9+/=]+'/;
if (!HASH_SLOT.test(html)) {
  console.error("No script-src 'sha256-…' token found in the Content-Security-Policy; cannot update it.");
  process.exit(1);
}
const updated = html.replace(HASH_SLOT, `$1${hash}`);
if (!updated.includes(`script-src ${hash}`)) {
  console.error("CSP hash update did not apply.");
  process.exit(1);
}
if (updated === html) {
  console.log("CSP hash already up to date.");
} else {
  fs.writeFileSync(file, updated, "utf8");
  console.log(`Updated CSP script hash to ${hash}.`);
}
