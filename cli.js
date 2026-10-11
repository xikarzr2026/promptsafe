#!/usr/bin/env node
/**
 * PromptSafe CLI — Scrub secrets from stdin or files
 *
 * Usage:
 *   echo "text with sk-abc123" | node cli.js
 *   node cli.js --file app.log
 *   cat app.log | node cli.js --format json
 *
 * Options:
 *   --file <path>     Read input from a file instead of stdin
 *   --format <type>   Output format: text (default), json, csv
 *   --rules <ids>     Comma-separated rule IDs to enable (default: all)
 *   --compress        Also compress the output (remove duplicate lines, collapse whitespace)
 *   --detect-only     Only report what would be redacted, do not output scrubbed text
 *   --help            Show this help message
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");

// ─── Embedded Engine ──────────────────────────────────────────────────────
// This is a self-contained extraction of the PromptSafe scrubbing engine.
// It mirrors the rules from index.html to keep the CLI dependency-free.

const PS_RULES = [
  {
    id: "keys",
    label: "Mask API Keys & Secrets",
    token: "[REDACTED_API_KEY]",
    patterns: [
      /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g,
      /\bsk-(?:proj-|live-|test-|ant-)?[A-Za-z0-9_-]{16,}\b/g,
      /\bsk_[A-Za-z0-9]{16,}\b/g,
      /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
      /\bAIza[0-9A-Za-z_-]{35,}\b/g,
      /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
      /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
      /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
      /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}/g
    ]
  },
  {
    id: "dburl",
    label: "Mask Connection Strings",
    token: "[REDACTED_CONNECTION_STRING]",
    patterns: [
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql|smtp|ftp|sftp|jdbc:[a-z]+):\/\/[^\s"']+/gi
    ]
  },
  {
    id: "network",
    label: "Mask IPv4 / IPv6",
    token: "[REDACTED_IP]",
    patterns: [
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/\d{1,2})?(?::\d{1,5})?\b/g,
      /(?<![:.\w])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))(?![:\w])/g,
      /\b(?:localhost|[\w-]+\.(?:local|internal|lan|corp|home|intranet))(?::\d{1,5})?\b/gi
    ]
  },
  {
    id: "email",
    label: "Mask Emails",
    token: "[REDACTED_EMAIL]",
    patterns: [
      /[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}\b/g
    ]
  },
  {
    id: "phone",
    label: "Mask Phone Numbers",
    token: "[REDACTED_PHONE]",
    patterns: [
      /\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d[\d\s.-]{5,}\d/g,
      /\(\d{3}\)\s*\d{3}[-.\s]?\d{4}/g,
      /\b\d{3}[-.]\d{3}[-.]\d{4}\b/g
    ],
    filter: function (matched) {
      const digits = matched.replace(/\D/g, "").length;
      return digits >= 10 && digits <= 15;
    }
  },
  {
    id: "creds",
    label: "Mask Passwords & Tokens",
    token: "[REDACTED_SECRET]",
    patterns: [
      /((?:^|[^A-Za-z0-9])(?:aws_secret_access_key|secret_access_key|secret_key|private_key|client_secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|db[_-]?password|admin[_-]?password|password|passwd|pwd|passphrase|secret|token)\b["']?\s*(?:=|:|=>|:=)\s*)(["']?)([^\s,;"'`]+)\2/gi
    ],
    filter: function (matched, m) {
      return !/^\[REDACTED_[A-Z_]*\]$/.test(m[3]);
    },
    build: function (match) {
      return {
        start: match.index + match[1].length + match[2].length,
        end: match.index + match[1].length + match[2].length + match[3].length,
        text: "[REDACTED_SECRET]"
      };
    }
  },
  {
    id: "inject",
    label: "Detect Prompt Injections",
    token: "[INJECTION_DETECTED]",
    patterns: [
      /\b(?:ignore|disregard|forget|override|bypass|skip)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?)\b/gi,
      /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|impersonate)\s+(?:a\s+)?(?:different|new|another|evil|jailbroken|unrestricted)\b/gi,
      /\b(?:system\s+prompt|system\s+message)\s*(?:=|:\s*)/gi,
      /\b(?:do\s+not\s+follow|disobey|defy|ignore)\s+(?:your\s+)?(?:programming|training|guidelines|rules|instructions?|constraints?|restrictions?)\b/gi,
      /\b(?:jailbreak|DAN|do\s+anything\s+now)\b/gi,
      /\b(?:reveal|show|print|output|leak|expose)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+prompt|initial\s+prompt|secret\s+prompt)\b/gi,
      /\b(?:new\s+instructions?|updated\s+instructions?|new\s+rules?|updated\s+rules?|new\s+guidelines?|updated\s+guidelines?)\s*(?:=|:\s*)/gi
    ]
  },
  {
    id: "custom",
    label: "Custom Masking Regex",
    token: "[REDACTED_CUSTOM]",
    patterns: []
  }
];

function PS_scan(text, enabledIds) {
  const ranges = [];
  for (const rule of PS_RULES) {
    if (!enabledIds.has(rule.id)) continue;
    for (const re of rule.patterns) {
      if (!re || !re.source) continue;
      let scanner = re;
      if (!re.global) scanner = new RegExp(re.source, re.flags + "g");
      scanner.lastIndex = 0;
      let m;
      while ((m = scanner.exec(text)) !== null) {
        if (m[0].length === 0) { scanner.lastIndex++; continue; }
        if (rule.filter && !rule.filter(m[0], m)) continue;
        let start = m.index, end = m.index + m[0].length, text_ = rule.token;
        if (rule.build) {
          const b = rule.build(m);
          if (!b || b.end <= b.start) continue;
          start = b.start; end = b.end; text_ = b.text || rule.token;
        }
        ranges.push({ start, end, text: text_, rule: rule.id });
      }
    }
  }
  ranges.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const kept = [];
  let lastEnd = -1;
  for (const r of ranges) {
    if (r.start >= lastEnd) { kept.push(r); lastEnd = r.end; }
  }
  return kept;
}

function PS_apply(text, ranges) {
  let plain = "";
  let cursor = 0;
  for (const r of ranges) {
    plain += text.slice(cursor, r.start) + r.text;
    cursor = r.end;
  }
  plain += text.slice(cursor);
  return { plain };
}

function compressText(text) {
  const lines = text.split("\n");
  const seen = new Set();
  const unique = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !seen.has(trimmed)) { seen.add(trimmed); unique.push(line); }
    else if (!trimmed) { unique.push(line); }
  }
  let result = unique.join("\n").replace(/ {2,}/g, " ");
  result = result.replace(/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]?\d*\s*/gm, "");
  result = result.replace(/\b(DEBUG|INFO|WARN|ERROR|TRACE|FATAL)\s+/g, "");
  result = result.replace(/\x1b\[[0-9;]*m/g, "");
  return result;
}

// ─── CLI Entry Point ────────────────────────────────────────────────────────

function showHelp() {
  console.log(`
PromptSafe CLI — Scrub secrets from text

Usage:
  echo "text" | node cli.js [options]
  node cli.js --file <path> [options]

Options:
  --file <path>     Read input from a file instead of stdin
  --format <type>   Output format: text (default), json, csv
  --rules <ids>     Comma-separated rule IDs to enable (default: all)
  --compress        Also compress the output
  --detect-only     Only report what would be redacted
  --help            Show this help message

Examples:
  echo "key: sk-abc123" | node cli.js
  node cli.js --file app.log --format json
  cat debug.log | node cli.js --rules keys,creds --compress
`);
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    showHelp();
    process.exit(0);
  }

  let inputSource = null;
  let format = "text";
  let ruleIds = null;
  let doCompress = false;
  let detectOnly = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--file" && args[i + 1]) {
      inputSource = args[++i];
    } else if (args[i] === "--format" && args[i + 1]) {
      format = args[++i];
    } else if (args[i] === "--rules" && args[i + 1]) {
      ruleIds = args[++i].split(",").map(s => s.trim());
    } else if (args[i] === "--compress") {
      doCompress = true;
    } else if (args[i] === "--detect-only") {
      detectOnly = true;
    }
  }

  const enabled = ruleIds ? new Set(ruleIds) : new Set(PS_RULES.map(r => r.id));

  const processText = (text) => {
    if (doCompress) text = compressText(text);
    const ranges = PS_scan(text, enabled);

    if (format === "json") {
      const counts = {};
      ranges.forEach(r => { counts[r.rule] = (counts[r.rule] || 0) + 1; });
      const output = {
        total_redactions: ranges.length,
        by_rule: counts,
        redactions: ranges.map(r => ({ rule: r.rule, token: r.text, position: r.start })),
        text: PS_apply(text, ranges).plain
      };
      console.log(JSON.stringify(output, null, 2));
    } else if (format === "csv") {
      console.log("Rule,Token,Position");
      ranges.forEach(r => console.log(`${r.rule},${r.text},${r.start}`));
    } else {
      if (detectOnly) {
        ranges.forEach(r => console.log(`[${r.rule}] ${r.text} at position ${r.start}`));
        if (ranges.length === 0) console.log("No redactions found.");
      } else {
        console.log(PS_apply(text, ranges).plain);
      }
    }
  };

  if (inputSource) {
    const content = fs.readFileSync(inputSource, "utf8");
    processText(content);
  } else {
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => input += chunk);
    process.stdin.on("end", () => processText(input));
  }
}

main();
