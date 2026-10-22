#!/usr/bin/env node
"use strict";

/**
 * PromptSafe local REST API.
 *
 * Secure defaults: loopback-only, bearer token required for API routes, no
 * cross-origin access unless an exact origin is configured, and bounded JSON
 * request bodies. Set PROMPTSAFE_API_TOKEN before using the API.
 */

const http = require("node:http");
const crypto = require("node:crypto");
const {
  PS_VERSION,
  PS_RULES,
  PS_scan,
  PS_apply,
  PS_scrubCompress
} = require("./extension/engine.js");

const MAX_BODY_BYTES = 1024 * 1024;
const BODY_TIMEOUT_MS = 30_000;
const OVERSIZE_GRACE_MS = 1_000;
// "custom" has no server-side patterns, so it is not offered over the API.
const PUBLIC_RULES = PS_RULES.filter(rule => rule.id !== "custom");
const KNOWN_RULES = new Set(PUBLIC_RULES.map(rule => rule.id));
const DEFAULT_RULES = PUBLIC_RULES.filter(rule => rule.id !== "inject").map(rule => rule.id);

function sendJson(res, statusCode, payload) {
  if (res.writableEnded) return;
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(payload));
}

function safeBearerMatch(header, token) {
  if (!token || typeof header !== "string") return false;
  const prefix = "bearer "; // the auth scheme name is case-insensitive (RFC 7235)
  if (header.slice(0, prefix.length).toLowerCase() !== prefix) return false;
  const received = Buffer.from(header.slice(prefix.length), "utf8");
  const expected = Buffer.from(token, "utf8");
  return received.length === expected.length && crypto.timingSafeEqual(received, expected);
}

function statusError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const contentLength = Number(req.headers["content-length"] || 0);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      reject(statusError(413, "Request body too large"));
      return;
    }
    const chunks = [];
    let size = 0;
    let settled = false;
    const onData = chunk => {
      size += chunk.length;
      if (size > maxBytes) {
        // Stop reading at once; the caller replies 413 and closes the connection.
        settled = true;
        req.off("data", onData);
        req.pause();
        chunks.length = 0;
        reject(statusError(413, "Request body too large"));
        return;
      }
      chunks.push(chunk);
    };
    req.on("data", onData);
    req.on("end", () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks)); } });
    req.on("error", error => { if (!settled) { settled = true; reject(error); } });
  });
}

async function readJsonBody(req, maxBytes) {
  const raw = await readRawBody(req, maxBytes);
  let body;
  try {
    body = JSON.parse(raw.toString("utf8") || "{}");
  } catch (_) {
    throw statusError(400, "Invalid JSON body");
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw statusError(400, "JSON body must be an object");
  }
  return body;
}

function resolveRules(data) {
  if (data.rules === undefined) return new Set(DEFAULT_RULES);
  if (!Array.isArray(data.rules) || !data.rules.every(id => typeof id === "string")) {
    throw statusError(400, "rules must be an array of rule IDs");
  }
  const unknown = data.rules.filter(id => !KNOWN_RULES.has(id));
  if (unknown.length) {
    throw statusError(400, `Unknown rule ID(s): ${unknown.slice(0, 10).map(id => id.slice(0, 40)).join(", ")}`);
  }
  return new Set(data.rules);
}

function sameOrigin(origin, host) {
  if (!origin || !host) return false;
  try {
    return new URL(origin).host.toLowerCase() === String(host).toLowerCase();
  } catch (_) {
    return false;
  }
}

function createServer({
  apiToken = process.env.PROMPTSAFE_API_TOKEN || "",
  corsOrigin = process.env.PROMPTSAFE_CORS_ORIGIN || "",
  maxBodyBytes = MAX_BODY_BYTES
} = {}) {
  const server = http.createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");

    let pathname;
    try {
      pathname = new URL(req.url, "http://localhost").pathname;
    } catch (_) {
      sendJson(res, 400, { error: "Invalid request path" });
      return;
    }

    const origin = req.headers.origin;
    const isSameOrigin = sameOrigin(origin, req.headers.host);
    const isAllowedOrigin = Boolean(origin && corsOrigin && origin === corsOrigin);
    if (origin && !isSameOrigin && !isAllowedOrigin) {
      sendJson(res, 403, { error: "Origin not allowed" });
      return;
    }
    if (isAllowedOrigin) {
      res.setHeader("Access-Control-Allow-Origin", corsOrigin);
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
      res.setHeader("Vary", "Origin");
    }

    if (req.method === "OPTIONS") {
      if (!origin || (!isSameOrigin && !isAllowedOrigin)) {
        sendJson(res, 403, { error: "Preflight origin not allowed" });
        return;
      }
      res.writeHead(204, { "Cache-Control": "no-store" });
      res.end();
      return;
    }

    if (pathname === "/health" && req.method === "GET") {
      sendJson(res, 200, { status: "ok", service: "PromptSafe API", version: PS_VERSION });
      return;
    }

    const knownPath = pathname === "/api/rules" ||
      pathname === "/api/scrub" || pathname === "/api/compress" || pathname === "/api/detect";
    if (!knownPath) {
      sendJson(res, 404, { error: "Not found" });
      return;
    }
    if (typeof apiToken !== "string" || apiToken.length < 32) {
      sendJson(res, 503, { error: "API disabled: configure PROMPTSAFE_API_TOKEN with at least 32 characters" });
      return;
    }
    if (!safeBearerMatch(req.headers.authorization, apiToken)) {
      sendJson(res, 401, { error: "Unauthorized" });
      return;
    }

    if (pathname === "/api/rules") {
      if (req.method !== "GET") {
        sendJson(res, 405, { error: "Method not allowed" });
        return;
      }
      sendJson(res, 200, {
        rules: PUBLIC_RULES.map(rule => ({ id: rule.id, label: rule.label, token: rule.token })),
        default_rules: DEFAULT_RULES
      });
      return;
    }

    if (req.method !== "POST") {
      sendJson(res, 405, { error: "Method not allowed" });
      return;
    }
    const contentType = String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") {
      sendJson(res, 415, { error: "Content-Type must be application/json" });
      return;
    }

    req.setTimeout(BODY_TIMEOUT_MS, () => {
      sendJson(res, 408, { error: "Request timeout" });
      req.destroy();
    });
    try {
      const data = await readJsonBody(req, maxBodyBytes);
      if (typeof data.text !== "string") {
        sendJson(res, 400, { error: "text must be a string" });
        return;
      }

      if (pathname === "/api/scrub") {
        const ranges = PS_scan(data.text, resolveRules(data));
        const counts = {};
        ranges.forEach(range => { counts[range.rule] = (counts[range.rule] || 0) + 1; });
        sendJson(res, 200, {
          text: PS_apply(data.text, ranges).plain,
          total_redactions: ranges.length,
          by_rule: counts,
          redactions: ranges.map(range => ({ rule: range.rule, token: range.text, start: range.start, end: range.end }))
        });
        return;
      }

      if (pathname === "/api/compress") {
        // Scrub, compress, re-scrub (one engine helper shared with the CLI and web app).
        const result = PS_scrubCompress(data.text, resolveRules(data));
        sendJson(res, 200, {
          text: result.text,
          total_redactions: result.totalRedactions,
          original_length: result.originalLength,
          scrubbed_length: result.scrubbedLength,
          compressed_length: result.compressedLength,
          estimated_savings_percent: result.scrubbedLength
            ? Math.round((1 - result.compressedLength / result.scrubbedLength) * 100)
            : 0
        });
        return;
      }

      if (pathname === "/api/detect") {
        const ranges = PS_scan(data.text, new Set(["inject"]));
        sendJson(res, 200, {
          injections_found: ranges.length,
          injections: ranges.map(range => ({
            rule: range.rule,
            token: range.text,
            start: range.start,
            position: range.start, // kept for compatibility; same as start
            end: range.end,
            match: data.text.slice(range.start, range.end).slice(0, 200)
          }))
        });
        return;
      }
    } catch (error) {
      if (res.writableEnded) return;
      const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
      if (statusCode === 413) {
        // Do not keep reading an oversized body. Closing the socket while the client is
        // still sending (including via "Connection: close") resets the connection and the
        // client loses the 413, so discard the remainder for a short grace period, then close.
        res.once("finish", () => {
          req.resume();
          setTimeout(() => req.destroy(), OVERSIZE_GRACE_MS).unref();
        });
      }
      sendJson(res, statusCode, {
        error: statusCode >= 500 ? "Internal server error" : error.message
      });
    }
  });

  server.requestTimeout = BODY_TIMEOUT_MS;
  server.headersTimeout = 10_000;
  return server;
}

function cliOptions(argv) {
  let port = Number(process.env.PORT) || 3000;
  let host = process.env.PROMPTSAFE_HOST || "127.0.0.1";
  for (let i = 0; i < argv.length; i++) {
    if ((argv[i] === "--port" || argv[i] === "--host") && (argv[i + 1] === undefined || argv[i + 1].startsWith("--"))) {
      throw new Error(`${argv[i]} needs a value`);
    }
    if (argv[i] === "--port") port = Number(argv[++i]);
    else if (argv[i] === "--host") host = argv[++i];
    else if (argv[i] === "--help" || argv[i] === "-h") {
      console.log("Usage: PROMPTSAFE_API_TOKEN=<token> node server.js [--port 3000] [--host 127.0.0.1]");
      return null;
    } else {
      throw new Error(`Unknown server option: ${argv[i]}`);
    }
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Port must be between 1 and 65535");
  if (!host.trim()) throw new Error("Host must not be empty");
  return { port, host };
}

if (require.main === module) {
  try {
    const options = cliOptions(process.argv.slice(2));
    if (!options) process.exitCode = 0;
    else {
      const server = createServer();
      server.on("error", error => {
        console.error(error.code === "EADDRINUSE"
          ? `Port ${options.port} is already in use; pass --port to choose another.`
          : `Server error: ${error.message}`);
        process.exitCode = 1;
      });
      const shutdown = () => server.close(() => process.exit(0));
      process.once("SIGINT", shutdown);
      process.once("SIGTERM", shutdown);
      server.listen(options.port, options.host, () => {
        console.log(`PromptSafe API v${PS_VERSION} listening on http://${options.host}:${options.port}`);
        if (!["127.0.0.1", "::1", "localhost"].includes(options.host)) {
          console.warn("Warning: the API is bound to a non-loopback address and is reachable from the network.");
        }
        if (typeof process.env.PROMPTSAFE_API_TOKEN !== "string" || process.env.PROMPTSAFE_API_TOKEN.length < 32) {
          console.warn("API routes are disabled until PROMPTSAFE_API_TOKEN is configured with at least 32 characters.");
        }
      });
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
  }
}

module.exports = { createServer, MAX_BODY_BYTES, DEFAULT_RULES };
