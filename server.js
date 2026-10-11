#!/usr/bin/env node
/**
 * PromptSafe REST API Server
 *
 * A lightweight HTTP server that exposes PromptSafe as a REST API.
 * Useful for CI/CD pipelines, pre-commit hooks, and agent integrations.
 *
 * Usage:
 *   node server.js [--port 3000]
 *
 * Endpoints:
 *   POST /api/scrub          — Scrub secrets from text
 *   POST /api/compress       — Compress text (remove duplicates, collapse whitespace)
 *   POST /api/detect         — Detect prompt injection patterns
 *   GET  /api/rules          — List available redaction rules
 *   GET  /health             — Health check
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

// Load the CLI engine (it exports the rules)
const cliPath = path.join(__dirname, "cli.js");

// Inline the engine by reading cli.js and extracting what we need
let cliSource = fs.readFileSync(cliPath, "utf8");
// Strip the shebang line if present (it causes a syntax error when eval'd)
cliSource = cliSource.replace(/^#!.*\n/, "");

// Create a minimal module that exports the engine
const engineModule = { exports: {} };
const wrappedCode = `(function(module, exports, require) {\n${cliSource}\nreturn module.exports;\n})`;
const engineFactory = eval(wrappedCode);
const engine = engineFactory(engineModule, engineModule.exports, require);

const PS_RULES = engineModule.exports.PS_RULES || engine.PS_RULES;
const PS_scan = engineModule.exports.PS_scan || engine.PS_scan;
const PS_apply = engineModule.exports.PS_apply || engine.PS_apply;
const compressText = engineModule.exports.compressText || engine.compressText;

const PORT = parseInt(process.env.PORT) || 3000;

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;

  // Health check
  if (pathname === "/health" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", service: "PromptSafe API", version: "2.0.0" }));
    return;
  }

  // List rules
  if (pathname === "/api/rules" && req.method === "GET") {
    const rules = PS_RULES.map(r => ({ id: r.id, label: r.label, token: r.token }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ rules }));
    return;
  }

  // Parse body for POST endpoints
  let body = "";
  req.on("data", chunk => body += chunk);
  req.on("end", () => {
    try {
      const data = JSON.parse(body || "{}");

      // Scrub text
      if (pathname === "/api/scrub" && req.method === "POST") {
        const text = data.text || "";
        const ruleIds = data.rules ? new Set(data.rules) : new Set(PS_RULES.map(r => r.id));
        const ranges = PS_scan(text, ruleIds);
        const result = PS_apply(text, ranges);
        const counts = {};
        ranges.forEach(r => { counts[r.rule] = (counts[r.rule] || 0) + 1; });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          text: result.plain,
          total_redactions: ranges.length,
          by_rule: counts
        }));
        return;
      }

      // Compress text
      if (pathname === "/api/compress" && req.method === "POST") {
        const text = data.text || "";
        const compressed = compressText(text);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          text: compressed,
          original_length: text.length,
          compressed_length: compressed.length,
          savings_percent: text.length > 0
            ? Math.round((1 - compressed.length / text.length) * 100)
            : 0
        }));
        return;
      }

      // Detect injections
      if (pathname === "/api/detect" && req.method === "POST") {
        const text = data.text || "";
        const ranges = PS_scan(text, new Set(["inject"]));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          injections_found: ranges.length,
          injections: ranges.map(r => ({ rule: r.rule, token: r.text, position: r.start }))
        }));
        return;
      }

      // 404 for unknown routes
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    } catch (err) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
  });
});

server.listen(PORT, () => {
  console.log(`PromptSafe API running on http://localhost:${PORT}`);
  console.log(`Endpoints:`);
  console.log(`  GET  /health          — Health check`);
  console.log(`  GET  /api/rules       — List available rules`);
  console.log(`  POST /api/scrub       — Scrub secrets from text`);
  console.log(`  POST /api/compress    — Compress text`);
  console.log(`  POST /api/detect      — Detect prompt injections`);
  console.log(`\nExample:`);
  console.log(`  curl -X POST http://localhost:${PORT}/api/scrub -H "Content-Type: application/json" -d '{"text":"key: sk-abc123"}'`);
});
