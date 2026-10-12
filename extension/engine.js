"use strict";
(function () {
  if (globalThis.PromptSafeEngine) return;
const PS_RULES = [
  {
    id: "keys",
    label: "Mask API Keys & Secrets",
    token: "[REDACTED_API_KEY]",
    patterns: [
      // PEM private keys (multi-line, must run before line-oriented patterns)
      /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g,
      // OpenAI  sk-… / sk-proj-… / sk-ant-…
      /\bsk-(?:proj-|live-|test-|ant-)?[A-Za-z0-9_-]{16,}\b/g,
      /\bsk_[A-Za-z0-9]{16,}\b/g,
      // AWS access key IDs
      /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
      // Google API keys
      /\bAIza[0-9A-Za-z_-]{35,}\b/g,
      // GitHub tokens (classic + fine-grained)
      /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
      /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
      // Slack tokens
      /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
      // Stripe keys
      /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      // JSON Web Tokens
      /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
      // HTTP auth headers
      /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}/g
    ]
  },
  {
    id: "dburl",
    label: "Mask Connection Strings",
    token: "[REDACTED_CONNECTION_STRING]",
    patterns: [
      // Service URIs carry their credentials inline — user:pass@host
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql|smtp|ftp|sftp|jdbc:[a-z]+):\/\/[^\s"'`]+/gi
    ]
  },
  {
    id: "network",
    label: "Mask IPv4 / IPv6",
    token: "[REDACTED_IP]",
    patterns: [
      // IPv4, optionally with a CIDR suffix or :port
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/\d{1,2})?(?::\d{1,5})?\b/g,
      // IPv6 — canonical form, full and compressed
      /(?<![:.\w])(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))(?![:\w])/g,
      // Internal hostnames + localhost, with optional port
      /\b(?:localhost|[\w-]+\.(?:local|internal|lan|corp|home|intranet))(?::\d{1,5})?\b/gi
    ]
  },
  {
    id: "email",
    label: "Mask Emails",
    token: "[REDACTED_EMAIL]",
    patterns: [
      // Bound local/domain labels and label count to keep malformed input linear-time.
      /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,125}\.[A-Za-z]{2,24}\b/g
    ]
  },
  {
    id: "phone",
    label: "Mask Phone Numbers",
    token: "[REDACTED_PHONE]",
    patterns: [
      /\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d[\d\s.-]{5,}\d/g,   // international, leading +
      /\(\d{3}\)\s*\d{3}[-.\s]?\d{4}/g,                             // (555) 123-4567
      /\b\d{3}[-.]\d{3}[-.]\d{4}\b/g                                // 555-123-4567
    ],
    // Require 10–15 digits so IDs, years and timestamps are not swept up.
    filter: function (match) {
      const digits = match.replace(/\D/g, "").length;
      return digits >= 10 && digits <= 15;
    }
  },
  {
    id: "creds",
    label: "Mask Passwords & Tokens",
    token: "[REDACTED_SECRET]",
    patterns: [
      // Preserve quotes while covering multiword values; the worker timeout guards custom regexes.
      /((?:^|[^A-Za-z0-9])(?:aws_secret_access_key|secret_access_key|secret_key|private_key|client_secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|db[_-]?password|admin[_-]?password|password|passwd|pwd|passphrase|secret|token)\b["']?\s*(?:=|:|=>|:=)\s*)(["'])((?:\\.|(?!\2)[^\r\n])*?)\2/gi,
      /((?:^|[^A-Za-z0-9])(?:aws_secret_access_key|secret_access_key|secret_key|private_key|client_secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|db[_-]?password|admin[_-]?password|password|passwd|pwd|passphrase|secret|token)\b["']?\s*(?:=|:|=>|:=)\s*)(["']?)([^\s,;"'`]+)\2/gi
    ],
    // Never re-redact a token we already wrote: keeps repeat scrubs idempotent.
    //   OPENAI_API_KEY=[REDACTED_API_KEY]  must not become  ...=[REDACTED_SECRET]
    filter: function (matched, m) {
      return !/^\[REDACTED_[A-Z_]*\]$/.test(m[3]);
    },
    // Keep the key name and quotes readable, redact only the value:
    //   password = "sample value"   ->   password = "[REDACTED_SECRET]"
    build: function (match) {
      return {
        start: match.index + match[1].length + match[2].length,
        end:   match.index + match[1].length + match[2].length + match[3].length,
        text:  "[REDACTED_SECRET]"
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
    ],
    filter: function (matched, m) {
      return !/^\[REDACTED_[A-Z_]*\]$/.test(m[0]);
    }
  },
  {
    id: "custom",
    label: "Custom Masking Regex",
    token: "[REDACTED_CUSTOM]",
    patterns: []   // filled in live from the custom-regex input
  }
];

/* ── Find every redaction range in `text` for the enabled rule ids. ── */
function PS_scan(text, enabledIds) {
  const ranges = [];

  for (let r = 0; r < PS_RULES.length; r++) {
    const rule = PS_RULES[r];
    if (!enabledIds.has(rule.id)) continue;

    for (let p = 0; p < rule.patterns.length; p++) {
      const re = rule.patterns[p];
      if (!re || !re.source) continue;

      // Always iterate safely, even if the author forgot the g flag.
      let scanner = re;
      if (!re.global) scanner = new RegExp(re.source, re.flags + "g");
      scanner.lastIndex = 0;

      let m;
      while ((m = scanner.exec(text)) !== null) {
        if (m[0].length === 0) { scanner.lastIndex++; continue; }   // zero-width guard
        if (rule.filter && !rule.filter(m[0], m)) continue;

        let start = m.index;
        let end   = m.index + m[0].length;
        let text_ = rule.token;

        if (rule.build) {
          const b = rule.build(m);
          if (!b || b.end <= b.start) continue;
          start = b.start; end = b.end; text_ = b.text || rule.token;
        }

        ranges.push({ start: start, end: end, text: text_, rule: rule.id });
      }
    }
  }

  // Sort by position (longer match wins a tie) …
  ranges.sort(function (a, b) {
    return a.start - b.start || (b.end - b.start) - (a.end - a.start);
  });

  // … then drop anything overlapping an already-accepted range.
  const kept = [];
  let lastEnd = -1;
  for (let i = 0; i < ranges.length; i++) {
    if (ranges[i].start >= lastEnd) {
      kept.push(ranges[i]);
      lastEnd = ranges[i].end;
    }
  }
  return kept;
}

/* ── Apply ranges: returns the plain text plus highlighted HTML. ── */
function PS_apply(text, ranges) {
  let plain = "";
  const html = [];
  let cursor = 0;

  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const pre = text.slice(cursor, r.start);
    plain += pre;
    html.push(PS_esc(pre));

    plain += r.text;
    html.push('<mark class="hl hl-' + r.rule + '">' + PS_esc(r.text) + "</mark>");
    cursor = r.end;
  }

  const tail = text.slice(cursor);
  plain += tail;
  html.push(PS_esc(tail));

  return { plain: plain, html: html.join("") };
}

/* ── Minimal HTML escaping for everything we render. ── */
function PS_esc(s) {
  return s.replace(/[&<>"']/g, function (c) {
    return c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;"
         : c === '"' ? "&quot;" : "&#39;";
  });
}

/* ── Dump the LIVE engine as readable source (used by both modals). ── */
function PS_sourceDump() {
  const out = [];
  out.push("// ── PromptSafe sanitization engine ─────────────────────────────");
  out.push("// This text is generated at runtime from the function objects");
  out.push("// currently executing in your browser. It is not a copy.");
  out.push("");
  out.push("const RULES = [");

  PS_RULES.forEach(function (r) {
    out.push("  {");
    out.push("    id: " + JSON.stringify(r.id) + ",");
    out.push("    label: " + JSON.stringify(r.label) + ",");
    out.push("    token: " + JSON.stringify(r.token) + ",");
    out.push("    patterns: [");
    r.patterns.forEach(function (p) {
      out.push("      /" + p.source + "/" + p.flags + ",");
    });
    out.push("    ],");
    if (r.filter) out.push("    filter: " + r.filter.toString() + ",");
    if (r.build)  out.push("    build: " + r.build.toString() + ",");
    out.push("  },");
  });

  out.push("];");
  out.push("");
  out.push(PS_scan.toString());
  out.push("");
  out.push(PS_apply.toString());
  out.push("");
  out.push(PS_esc.toString());
  return out.join("\n");
}
  globalThis.PromptSafeEngine = Object.freeze({ PS_RULES, PS_scan, PS_apply });
})();
