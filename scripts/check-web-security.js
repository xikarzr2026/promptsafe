#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const index = fs.readFileSync(path.join(root, "index.html"), "utf8");
const privacy = fs.readFileSync(path.join(root, "privacy.html"), "utf8");
const css = fs.readFileSync(path.join(root, "assets", "promptsafe.css"), "utf8");

const scriptTags = [...index.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
const externalScripts = scriptTags.filter(match => /\bsrc\s*=/i.test(match[1]));
const inlineScripts = scriptTags.filter(match => !/\bsrc\s*=/i.test(match[1]));
assert.equal(externalScripts.length, 0, "The browser page must not load remote or extra external scripts.");
assert.equal(inlineScripts.length, 1, "Expected exactly one inline application script.");

const scriptHash = "'sha256-" + crypto.createHash("sha256")
  .update(inlineScripts[0][2].replace(/\r\n/g, "\n"))
  .digest("base64") + "'";
const cspMatch = index.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/i);
assert.ok(cspMatch, "index.html must include a Content-Security-Policy meta tag.");
const scriptPolicy = cspMatch[1].split(";").map(part => part.trim()).find(part => part.startsWith("script-src ")) || "";
assert.ok(scriptPolicy.includes(scriptHash), "CSP hash does not match the inline application script.");
assert.ok(!scriptPolicy.includes("unsafe-inline"), "CSP must not allow inline scripts without a hash.");

for (const [name, html] of [["index.html", index], ["privacy.html", privacy]]) {
  assert.doesNotMatch(html, /https:\/\/cdn\.tailwindcss\.com/i, `${name} must not use the Tailwind CDN.`);
  assert.match(html, /href="assets\/promptsafe\.css"/, `${name} must use the bundled local stylesheet.`);
}
assert.doesNotMatch(privacy, /<script\b/i, "privacy.html must not load or embed JavaScript.");
assert.doesNotMatch(css, /@import\b/i, "Bundled CSS must not import remote stylesheets.");
assert.doesNotMatch(css, /url\((?:https?:)?\/\//i, "Bundled CSS must not reference remote assets.");

console.log("Web security checks passed: CSP hash valid, no remote scripts, bundled CSS only.");
