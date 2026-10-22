#!/usr/bin/env node
"use strict";

/**
 * PromptSafe CLI — scrub secrets from stdin or files.
 *
 * The engine is the same generated bundle the browser extension uses
 * (extension/engine.js, built from index.html), so the CLI can never drift
 * from the web app's rules.
 */

const fs = require("node:fs");
const engine = require("./extension/engine.js");

const { PS_VERSION, PS_RULES, PS_scan, PS_apply, PS_compress, PS_scrubCompress } = engine;
const compressText = PS_compress;
const KNOWN_RULES = PS_RULES.map(rule => rule.id).filter(id => id !== "custom");
const DEFAULT_RULES = KNOWN_RULES.filter(id => id !== "inject");
const FORMATS = ["text", "json", "csv"];

const HELP = `
PromptSafe CLI v${PS_VERSION} — scrub secrets from text

Usage:
  echo "text" | promptsafe [options]
  promptsafe --file <path> [options]

Options:
  -f, --file <path>     Read input from a file instead of stdin
  -o, --output <path>   Write the result to a file instead of stdout
      --format <type>   Output format: text (default), json, csv
      --rules <ids>     Comma-separated rule IDs (default: all masking rules)
      --compress        Lossy log cleanup (ANSI, timestamps, levels, repeats, spaces)
      --detect-only     Report what would be redacted; never print the text
      --fail-on-find    Exit with code 1 when anything is found (for CI and hooks)
      --list-rules      Print the available rule IDs
  -v, --version         Print the version
  -h, --help            Show this help

Rule IDs: ${KNOWN_RULES.join(", ")} (inject is detection-only and off by default)

Input must be UTF-8 or UTF-16 with a byte-order mark. Report offsets (json/csv)
are UTF-16 code-unit positions in the input. With --compress, each finding has a
stage: "input", or "compressed" for secrets only visible after compression,
whose offsets refer to the compressed text; detect-only text output shows counts.

Examples:
  echo "key: sk-abc123..." | promptsafe
  promptsafe --file app.log --format json
  cat debug.log | promptsafe --rules keys,creds --compress
  git diff --cached | promptsafe --detect-only --fail-on-find
`;

class UsageError extends Error {}

function parseArgs(argv) {
  const options = {
    file: null,
    output: null,
    format: "text",
    rules: null,
    compress: false,
    detectOnly: false,
    failOnFind: false,
    help: false,
    version: false,
    listRules: false
  };
  const takeValue = (i, name) => {
    const value = argv[i + 1];
    // A separate value may not look like an option ("-o -f" must not write a file named "-f");
    // pass unusual names as --name=-value.
    if (value === undefined || value.startsWith("-")) throw new UsageError(`${name} needs a value`);
    return value;
  };

  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    let inline = null;
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    if (eq > 0) { inline = arg.slice(eq + 1); arg = arg.slice(0, eq); }
    const value = name => {
      if (inline !== null) {
        if (!inline) throw new UsageError(`${name} needs a value`);
        return inline;
      }
      return takeValue(i++, name);
    };

    switch (arg) {
      case "-f": case "--file": options.file = value("--file"); break;
      case "-o": case "--output": options.output = value("--output"); break;
      case "--format": options.format = value("--format").toLowerCase(); break;
      case "--rules": options.rules = value("--rules").split(",").map(s => s.trim()).filter(Boolean); break;
      case "--compress": options.compress = true; break;
      case "--detect-only": options.detectOnly = true; break;
      case "--fail-on-find": options.failOnFind = true; break;
      case "--list-rules": options.listRules = true; break;
      case "-v": case "--version": options.version = true; break;
      case "-h": case "--help": options.help = true; break;
      default: throw new UsageError(`Unknown option: ${argv[i]}`);
    }
  }

  if (!FORMATS.includes(options.format)) {
    throw new UsageError(`Unsupported output format: ${options.format}. Use text, json, or csv.`);
  }
  if (options.rules) {
    const unknown = options.rules.filter(id => !KNOWN_RULES.includes(id));
    if (unknown.length) {
      throw new UsageError(`Unknown rule ID(s): ${unknown.join(", ")}. Valid IDs: ${KNOWN_RULES.join(", ")}`);
    }
    if (!options.rules.length) throw new UsageError("--rules needs at least one rule ID");
  }
  return options;
}

function csvCell(value) {
  const s = String(value);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function countByRule(ranges) {
  const counts = {};
  for (const range of ranges) counts[range.rule] = (counts[range.rule] || 0) + 1;
  return counts;
}

/** Pure transform used by main() and tests: returns the output string. */
function processText(input, options) {
  const enabled = new Set(options.rules || DEFAULT_RULES);
  let ranges;
  let scrubbed;
  if (options.compress) {
    // Scrub, compress, re-scrub. Pass-1 offsets refer to the input; pass-2
    // findings only appeared after compression and refer to the compressed text.
    const result = PS_scrubCompress(input, enabled);
    ranges = result.firstPass.map(r => ({ ...r, stage: "input" }))
      .concat(result.secondPass.map(r => ({ ...r, stage: "compressed" })));
    scrubbed = () => result.text;
  } else {
    ranges = PS_scan(input, enabled);
    scrubbed = () => PS_apply(input, ranges).plain;
  }

  let output;
  if (options.format === "json") {
    const report = {
      version: PS_VERSION,
      total_redactions: ranges.length,
      by_rule: countByRule(ranges),
      redactions: ranges.map(r => {
        const item = { rule: r.rule, token: r.text, start: r.start, end: r.end, position: r.start };
        if (r.stage) item.stage = r.stage;
        return item;
      })
    };
    if (!options.detectOnly) report.text = scrubbed();
    output = JSON.stringify(report, null, 2) + "\n";
  } else if (options.format === "csv") {
    const rows = [options.compress ? ["Rule", "Token", "Start", "End", "Stage"] : ["Rule", "Token", "Start", "End"]];
    for (const r of ranges) rows.push(options.compress ? [r.rule, r.text, r.start, r.end, r.stage] : [r.rule, r.text, r.start, r.end]);
    output = rows.map(row => row.map(csvCell).join(",")).join("\n") + "\n";
  } else if (options.detectOnly) {
    if (!ranges.length) output = "No redactions found.\n";
    else if (options.compress) {
      // Positions are not meaningful across a lossy rewrite; report counts only.
      const tokens = {};
      for (const r of ranges) tokens[r.rule] = r.text;
      output = Object.entries(countByRule(ranges)).map(([rule, n]) => `[${rule}] ${tokens[rule]} x${n}`).join("\n") + "\n";
    } else {
      output = ranges.map(r => `[${r.rule}] ${r.text} at position ${r.start}`).join("\n") + "\n";
    }
  } else {
    output = scrubbed();
    if (!output.endsWith("\n")) output += "\n";
  }
  return { output, found: ranges.length };
}

/**
 * Decode input bytes. UTF-16 (common from Windows PowerShell redirection) is
 * honoured via its BOM; BOM-less input containing NUL bytes is refused rather
 * than scanned as mojibake, which would silently find nothing.
 */
function decodeInput(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.subarray(2).toString("utf16le");
  }
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const body = Buffer.from(buffer.subarray(2));
    if (body.length % 2 !== 0) throw new Error("truncated UTF-16BE input");
    return body.swap16().toString("utf16le");
  }
  const start = buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf ? 3 : 0;
  if (buffer.indexOf(0, start) !== -1) {
    throw new Error("input contains NUL bytes (binary, or UTF-16 without a BOM); re-save it as UTF-8");
  }
  return buffer.subarray(start).toString("utf8");
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on("data", chunk => { chunks.push(chunk); });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
    process.stdin.on("error", reject);
  });
}

function sameFile(a, b) {
  try {
    const x = fs.statSync(a, { bigint: true });
    const y = fs.statSync(b, { bigint: true });
    return x.ino !== 0n && x.ino === y.ino && x.dev === y.dev;
  } catch (_) {
    return false; // output does not exist yet
  }
}

async function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    console.error(`promptsafe: ${error.message}\nRun with --help for usage.`);
    return 2;
  }

  if (options.help) { process.stdout.write(HELP.trimStart()); return 0; }
  if (options.version) { console.log(PS_VERSION); return 0; }
  if (options.listRules) {
    for (const rule of PS_RULES) {
      if (rule.id === "custom") continue;
      console.log(`${rule.id.padEnd(8)} ${rule.label} -> ${rule.token}${rule.id === "inject" ? " (opt-in)" : ""}`);
    }
    return 0;
  }

  if (options.file && options.output && sameFile(options.file, options.output)) {
    console.error("promptsafe: refusing to overwrite the input file; choose a different --output path.");
    return 2;
  }

  let input;
  try {
    if (options.file) {
      input = decodeInput(fs.readFileSync(options.file));
    } else if (process.stdin.isTTY) {
      console.error("promptsafe: no input. Pipe text in or use --file <path>. Run with --help for usage.");
      return 2;
    } else {
      input = decodeInput(await readStdin());
    }
  } catch (error) {
    console.error(`promptsafe: cannot read ${options.file || "stdin"}: ${error.code || error.message}`);
    return 2;
  }

  const { output, found } = processText(input, options);
  const code = options.failOnFind && found > 0 ? 1 : 0;
  try {
    if (options.output) fs.writeFileSync(options.output, output, "utf8");
    else {
      // A closed pipe (e.g. "| head") is not a crash; keep the result-based exit code
      // so --fail-on-find stays meaningful.
      process.stdout.on("error", error => {
        if (error.code !== "EPIPE") console.error(`promptsafe: cannot write stdout: ${error.code || error.message}`);
        process.exit(error.code === "EPIPE" ? code : 2);
      });
      process.stdout.write(output);
    }
  } catch (error) {
    console.error(`promptsafe: cannot write ${options.output}: ${error.code || error.message}`);
    return 2;
  }
  return code;
}

module.exports = { PS_VERSION, PS_RULES, PS_scan, PS_apply, compressText, parseArgs, processText, decodeInput, DEFAULT_RULES };

if (require.main === module) {
  main().then(code => { process.exitCode = code; }, error => {
    console.error(`promptsafe: ${error.message}`);
    process.exitCode = 2;
  });
}
