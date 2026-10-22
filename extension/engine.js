/* Generated from index.html by scripts/build-extension-engine.js. Do not edit. */
"use strict";
(function () {
  if (!globalThis.PromptSafeEngine) {
const PS_VERSION = "2.2.0";

const PS_RULES = [
  {
    id: "keys",
    label: "Mask API Keys & Secrets",
    token: "[REDACTED_API_KEY]",
    patterns: [
      // PEM private keys (multi-line, must run before line-oriented patterns)
      /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g,
      // Truncated PEM (no END line): header, optional Proc-Type/DEK-Info, then base64-only lines.
      // Body lines carry no spaces, so prose pasted after the key is never swallowed.
      /-----BEGIN[^-]{0,40}PRIVATE KEY-----(?:\r?\nProc-Type:[^\r\n]*)?(?:\r?\nDEK-Info:[^\r\n]*\r?\n)?(?:\r?\n[A-Za-z0-9+\/=]{8,})+/g,
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
      // GitLab personal / deploy / runner tokens
      /\bgl(?:pat|dt|rt|ptt|cbt)-[A-Za-z0-9_-]{20,}\b/g,
      // npm, Hugging Face, PyPI, DigitalOcean, Shopify tokens
      /\bnpm_[A-Za-z0-9]{36}\b/g,
      /\bhf_[A-Za-z0-9]{30,}\b/g,
      /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g,
      /\bdo[pro]_v1_[a-f0-9]{64}\b/g,
      /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g,
      // Slack tokens and incoming webhooks
      /\bxox[abeprs]-[A-Za-z0-9-]{10,}\b/g,
      /\bxapp-\d-[A-Za-z0-9-]{10,}\b/g,
      /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g,
      // Discord webhooks
      /\bhttps:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{30,}/g,
      // SendGrid keys
      /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g,
      // Google OAuth access tokens
      /\bya29\.[A-Za-z0-9_-]{20,}/g,
      // Stripe keys
      /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
      /\bwhsec_[A-Za-z0-9]{24,}\b/g,
      // Mailgun API keys
      /\bkey-[0-9a-f]{32}\b/g,
      // JSON Web Tokens
      /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
      // HTTP auth headers (same line only, so the next log line is never swallowed).
      // The token needs a digit/symbol or a lower→upper pair, so "Basic authentication" is prose.
      /\b(?:Bearer|Basic)[ \t]+(?=[A-Za-z0-9._~+/=-]*(?:[0-9._~+/=-]|[a-z][A-Z]))[A-Za-z0-9._~+/=-]{12,}/g,
      // Azure storage / service-bus account keys inside connection strings
      /\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/]{20,}={0,2}/g,
      // Azure SAS signatures: mask only the sig value, keep the URL readable
      /(?<=[?&]sig=)[A-Za-z0-9%+/=]{16,}/g
    ]
  },
  {
    id: "dburl",
    label: "Mask Connection Strings",
    token: "[REDACTED_CONNECTION_STRING]",
    patterns: [
      // Service URIs carry their credentials inline — user:pass@host
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|smtps?|ftps?|sftp|ldaps?|jdbc:[a-z]+):\/\/[^\s"'`]+/gi,
      // Any other URL that embeds user:password@ credentials
      /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s\/:@"'`]{1,256}:[^\s\/@"'`]{1,256}@[^\s"'`]+/gi
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
      // Internal hostnames + localhost, with optional port. The lookbehind (not \b) lets a match
      // start only at the head of a hostname token, keeping long "a-b-c-…" runs linear-time.
      /(?<![\w-])(?:localhost|[\w-]+\.(?:local|internal|lan|corp|home|intranet))(?::\d{1,5})?\b/gi
    ],
    // Four-part version numbers look like IPv4. Skip a dotted quad when the
    // context says it is a version: "v1.2.3.4", "version 1.2.3.4", "1.2.3.4-beta",
    // or a longer dotted run such as "1.2.3.4.5". "root@10.0.0.5" stays masked.
    filter: function (matched, m) {
      if (!/^\d{1,3}(?:\.\d{1,3}){3}/.test(matched)) return true;
      const input = m.input;
      const before = input.slice(Math.max(0, m.index - 24), m.index);
      const after = input.slice(m.index + matched.length, m.index + matched.length + 2);
      if (/[\d.]$/.test(before) || /^\.\d/.test(after) || /^-[A-Za-z]/.test(after)) return false;
      // Only unambiguous version cues: a missed IP is worse than a masked version.
      return !/(?:\bv|\b(?:version|ver|release|rev|revision|firmware|fw)\b[ \t:=]*)$/i.test(before);
    }
  },
  {
    id: "email",
    label: "Mask Emails",
    token: "[REDACTED_EMAIL]",
    patterns: [
      // Bound local/domain labels and label count to keep malformed input linear-time.
      /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,125}\.[A-Za-z]{2,24}\b/g
    ],
    // "git@github.com:org/repo.git" is an SSH remote, not a mailbox.
    filter: function (matched, m) {
      if (!/^git@/i.test(matched)) return true;
      const end = m.index + matched.length;
      return !/^:[\w~.\/-]/.test(m.input.slice(end, end + 2));
    }
  },
  {
    id: "phone",
    label: "Mask Phone Numbers",
    token: "[REDACTED_PHONE]",
    patterns: [
      // Separators are horizontal only, so a number never runs into the next line.
      /\+\d{1,3}[ \t.-]?(?:\(\d{1,4}\)[ \t.-]?)?\d[\d \t.-]{5,}\d/g,   // international, leading +
      /\(\d{3}\)[ \t]*\d{3}[-. \t]?\d{4}/g,                            // (555) 123-4567
      /\b\d{3}[-.]\d{3}[-.]\d{4}\b/g                                // 555-123-4567
    ],
    // Require 10–15 digits so IDs, years and timestamps are not swept up.
    filter: function (match) {
      if (/^\+\d+\.\d+$/.test(match)) return false;   // a signed decimal such as +3.14159265358979
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
      // The key is any identifier that ENDS in a sensitive word (PGPASSWORD, clientSecret,
      // csrftoken, SECRET_KEY_BASE), so max_tokens / token_count / tokenizer stay untouched.
      /((?:^|[^A-Za-z0-9_.$-])[A-Za-z0-9_.$-]*?(?:secret|password|passwd|pwd|passphrase|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|account[_-]?key)(?:[_-]?(?:key|base)){0,2}["']?\s*(?:=|:|=>|:=)\s*)(["'])((?:\\.|(?!\2)[^\r\n])*?)\2/gi,
      /((?:^|[^A-Za-z0-9_.$-])[A-Za-z0-9_.$-]*?(?:secret|password|passwd|pwd|passphrase|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|account[_-]?key)(?:[_-]?(?:key|base)){0,2}["']?\s*(?:=|:|=>|:=)\s*)(["']?)([^\s,;"'`]+)\2/gi
    ],
    filter: function (matched, m) {
      // Never re-redact a token we already wrote: keeps repeat scrubs idempotent.
      //   OPENAI_API_KEY=[REDACTED_API_KEY]  must not become  ...=[REDACTED_SECRET]
      if (/^\[REDACTED_[A-Z_]*\]$/.test(m[3])) return false;
      if (m[2]) return true;   // a quoted literal is always masked
      // Unquoted code references are not secrets; masking them corrupts pasted code:
      //   password = os.environ["DB_PASSWORD"]   token = getToken();   pw: process.env.PW
      const v = m[3];
      if (/^(?:process\.env|os\.environ|import\.meta\.env|ENV|self|this|req|request|args|options|params|settings|config)(?=[.\[])(?:\.[A-Za-z_$][\w$]*)*\[?$/.test(v)) return false;
      if (/^[A-Za-z_$][\w$.]*\(\)?$/.test(v)) return false;                       // getToken() / os.getenv(
      if (/^(?:\$\{\{|\{\{|\$\{?[A-Z_][A-Z0-9_]*\}?$|%[A-Z_][A-Z0-9_]*%$)/.test(v)) return false;   // templates, env vars
      if (/^(?:None|null|nil|undefined|true|false|string|str|String|number|int|bool|boolean|bytes|any|SecretStr|\*+|x{3,}|<[^>]*>)$/.test(v)) return false;
      // Prose: "The token: is passed on" (a function word after "key: ")
      return !(/[ \t]$/.test(m[1]) && /^(?:is|are|was|were|be|the|a|an|to|of|for|and|or|not|must|should|will|can|may|has|have|here|below|above)$/i.test(v));
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
      /\b(?:jailbreak(?:ing|s)?|do\s+anything\s+now)\b/gi,
      // "DAN" is case-sensitive so the name "Dan" is never flagged.
      /\bDAN\b/g,
      /\b(?:reveal|show|print|output|leak|expose)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+prompt|initial\s+prompt|secret\s+prompt)\b/gi,
      /\b(?:new\s+instructions?|updated\s+instructions?|new\s+rules?|updated\s+rules?|new\s+guidelines?|updated\s+guidelines?)\s*(?:=|:\s*)/gi
    ]
  },
  {
    id: "custom",
    label: "Custom Masking Regex",
    token: "[REDACTED_CUSTOM]",
    patterns: []   // filled in live from the custom-regex input
  }
];

/* ── ANSI colour/control sequences; shared by PS_scan and PS_compress. ── */
const PS_ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;

/* ── `text` without ANSI codes, plus a map from its offsets back to the
      original ones; null when there is nothing to strip. ── */
function PS_ansiShadow(text) {
  if (text.indexOf("\x1b") === -1) return null;
  const map = new Int32Array(text.length + 1);
  const parts = [];
  let last = 0, n = 0, m;
  PS_ANSI_RE.lastIndex = 0;
  while ((m = PS_ANSI_RE.exec(text)) !== null) {
    parts.push(text.slice(last, m.index));
    for (let i = last; i < m.index; i++) map[n++] = i;
    last = m.index + m[0].length;
  }
  parts.push(text.slice(last));
  for (let i = last; i < text.length; i++) map[n++] = i;
  map[n] = text.length;
  return { text: parts.join(""), map: map };
}

/* ── Map ranges found in a shadow back to the original text. ANSI codes
      inside a range are swallowed by its token; all others are kept. ── */
function PS_remapRanges(ranges, map) {
  return ranges.map(function (r) {
    return { start: map[r.start], end: map[r.end - 1] + 1, text: r.text, rule: r.rule };
  });
}

/* ── Find every redaction range in `text`. ANSI codes are ignored while
      matching, so a colour code inside a key cannot hide it. ── */
function PS_scan(text, enabledIds) {
  const shadow = PS_ansiShadow(text);
  if (!shadow) return PS_scanRaw(text, enabledIds);
  return PS_remapRanges(PS_scanRaw(shadow.text, enabledIds), shadow.map);
}

/* ── Find every redaction range in `text` for the enabled rule ids. ── */
function PS_scanRaw(text, enabledIds) {
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

/* ── Lossy log cleanup: strip noise first, then drop repeated lines. ── */
function PS_compress(text) {
  const cleaned = text
    // ANSI colour codes first, so they cannot hide a leading timestamp or level.
    .replace(PS_ANSI_RE, "")
    // ISO-style timestamps with optional fraction and timezone.
    .replace(/^([ \t]*)\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\]?[ \t]*/gm, "$1")
    // Leading log levels only; prose words like "the ERROR" are kept.
    .replace(/^([ \t]*)\[?(?:DEBUG|INFO|WARN|WARNING|ERROR|TRACE|FATAL)\]?(?::[ \t]*|[ \t]+)/gm, "$1")
    // Collapse runs of spaces and tabs inside a line (indentation is kept), and trailing whitespace.
    .replace(/(\S)[ \t]{2,}/g, "$1 ")
    .replace(/[ \t]+$/gm, "");

  const seen = new Set();
  const kept = [];
  const lines = cleaned.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const key = lines[i].trim();
    if (!key) {
      // Keep paragraph breaks, but never more than one blank line in a row.
      if (kept.length && kept[kept.length - 1].trim() !== "") kept.push("");
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    kept.push(lines[i]);
  }
  while (kept.length && kept[kept.length - 1] === "") kept.pop();
  return kept.join("\n");
}

/* ── Scrub, compress, scrub again. Pass 1 runs on the raw text so multi-line
      secrets (PEM blocks) are replaced before line de-duplication can drop
      their BEGIN/END lines; pass 2 catches secrets that compression re-joined.
      Pass-2 hits overlapping a redaction token are dropped, so a custom regex
      cannot redact the tokens. scanFn defaults to PS_scan; if it returns a
      Promise (the page's worker-backed scan), so does this function. ── */
function PS_scrubCompress(text, enabledIds, scanFn) {
  const scan = scanFn || PS_scan;
  const then = function (v, f) { return v && typeof v.then === "function" ? v.then(f) : f(v); };
  return then(scan(text, enabledIds), function (first) {
    const scrubbed = PS_apply(text, first).plain;
    const compressed = PS_compress(scrubbed);
    return then(compressed ? scan(compressed, enabledIds) : [], function (raw) {
      const guarded = [];
      PS_RULES.forEach(function (rule) {
        const tok = rule.token;
        for (let i = compressed.indexOf(tok); i !== -1; i = compressed.indexOf(tok, i + tok.length)) {
          guarded.push([i, i + tok.length]);
        }
      });
      const second = raw.filter(function (r) {
        return !guarded.some(function (g) { return r.start < g[1] && g[0] < r.end; });
      });
      const out = PS_apply(compressed, second).plain;
      return {
        text: out,
        firstPass: first,     // offsets into the input text
        secondPass: second,   // offsets into the compressed text, before pass-2 replacement
        scrubbed: scrubbed,   // pass-1 output, what would be sent without compression
        totalRedactions: first.length + second.length,
        originalLength: text.length,
        scrubbedLength: scrubbed.length,   // after pass 1, before compression
        compressedLength: out.length       // final output
      };
    });
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
  out.push("const PS_ANSI_RE = /" + PS_ANSI_RE.source + "/" + PS_ANSI_RE.flags + ";");
  out.push("");
  out.push(PS_ansiShadow.toString());
  out.push("");
  out.push(PS_remapRanges.toString());
  out.push("");
  out.push(PS_scan.toString());
  out.push("");
  out.push(PS_scanRaw.toString());
  out.push("");
  out.push(PS_apply.toString());
  out.push("");
  out.push(PS_esc.toString());
  out.push("");
  out.push(PS_compress.toString());
  out.push("");
  out.push(PS_scrubCompress.toString());
  return out.join("\n");
}
  globalThis.PromptSafeEngine = Object.freeze({ PS_VERSION, PS_RULES, PS_scan, PS_scanRaw, PS_apply, PS_esc, PS_compress, PS_scrubCompress });
  }
  if (typeof module === "object" && module && module.exports) module.exports = globalThis.PromptSafeEngine;
})();
