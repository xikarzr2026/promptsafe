<img src="assets/banner.svg" alt="PromptSafe — scrub secrets before you paste" width="100%">

<p>
<a href="https://xikarzr2026.github.io/promptsafe/"><img src="https://img.shields.io/badge/%E2%96%B6%20live%20app-open%20promptsafe-6366f1?style=for-the-badge" alt="Open the live app"></a>
<img src="https://img.shields.io/badge/version-v2.2-8b5cf6?style=for-the-badge" alt="v2.2">
<img src="https://img.shields.io/badge/browser%20page-no%20backend-10b981?style=for-the-badge" alt="Browser page has no backend">
<img src="https://img.shields.io/badge/database-none-10b981?style=for-the-badge" alt="No database">
<img src="https://img.shields.io/badge/text%20processing-local-10b981?style=for-the-badge" alt="Text processing is local">
<img src="https://img.shields.io/badge/license-MIT-0f172a?style=for-the-badge" alt="MIT">
</p>

**PromptSafe** detects common API keys, JWTs, private keys, connection strings, IPs,
emails, phone numbers, and credential assignments in logs and prompts. It is a
risk-reduction tool, not a guarantee: review the output before sharing.

The browser app is a static bundle (`index.html` plus `assets/promptsafe.css`) with
no runtime package install or third-party script. Optional CLI, REST server, and
browser extension are separate tools with separate security settings.

> [!IMPORTANT]
> The browser page processes pasted text locally and makes no first-party network
> requests while scrubbing. The hosted page and local CSS/JavaScript assets are
> still requested from the static host, which may log normal access metadata such
> as IP address and request time. PromptSafe does not claim forensic erasure from
> memory or the operating-system clipboard. Regex detection can miss secrets.

---

## ▶️ Use it

**[xikarzr2026.github.io/promptsafe](https://xikarzr2026.github.io/promptsafe/)** — that's the whole install.

Or run it locally, offline:

```bash
git clone https://github.com/xikarzr2026/promptsafe.git
cd promptsafe
# there is no build step — just open the file
start index.html        # Windows
open  index.html        # macOS
xdg-open index.html     # Linux
```

The browser app uses only bundled local CSS and JavaScript. After the static files are loaded, text processing continues offline; no CDN script or remote asset is needed. The built-in sample log contains synthetic tokens, `example.com` addresses, and documentation-range IPs—not real credentials or infrastructure.

## 🧰 Optional local tools

- **CLI:** `node cli.js --file app.log` or `cat app.log | node cli.js --detect-only --format json`. It loads the same generated engine as the browser extension, so its rules cannot drift from the web app. Unknown options, rule IDs and formats fail with exit code 2. Injection detection is opt-in (`--rules inject`). `--compress` is lossy log cleanup: it can remove repeated lines, timestamps, log-level prefixes, extra spaces, and ANSI codes. Input may be UTF-8 (with or without BOM) or UTF-16 with a BOM, which is what Windows PowerShell 5.1 writes by default; input with NUL bytes and no BOM is rejected with exit code 2 rather than scanned as garbage. Offsets are UTF-16 code-unit offsets into the scanned text; with `--compress`, each JSON finding has a `stage` (`input` or `compressed`) and CSV gets a trailing `Stage` column. `-o` refuses to overwrite the `-f` input file, and a closed pipe (`| head`) exits with the normal result code.

  | Option | Effect |
  |---|---|
  | `-f, --file <path>` / `-o, --output <path>` | Read from / write to a file instead of stdin / stdout |
  | `--format text\|json\|csv` | Output format; JSON includes start and end offsets |
  | `--rules keys,creds,…` | Limit the rules (`--list-rules` prints them) |
  | `--detect-only` | Report findings without printing any text |
  | `--fail-on-find` | Exit 1 when anything is found, for CI jobs and pre-commit hooks |
  | `-v, --version` | Print the version |

  ```bash
  # Block a commit that stages a secret
  git diff --cached | node cli.js --detect-only --fail-on-find
  ```
- **REST server:** set `PROMPTSAFE_API_TOKEN` in the process environment, then run `node server.js`. It binds to `127.0.0.1` by default; `/health` is public, API routes require a `PROMPTSAFE_API_TOKEN` of at least 32 characters and an `Authorization: Bearer $PROMPTSAFE_API_TOKEN` header; request bodies are limited to 1 MiB. Cross-origin browser access is disabled unless the exact `PROMPTSAFE_CORS_ORIGIN` is configured. Do not commit or put the token in command history.
- **Browser extension:** load the `extension/` directory as an unpacked extension. Select text in an editable field and right-click **Scrub selected text with PromptSafe**, click the toolbar icon, or press <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd>. The toolbar and shortcut find the focused editor, including same-origin iframe editors such as TinyMCE; for editors on a different origin, use the right-click menu. It uses a bundled local engine and makes no remote fetch when used.

Run the regression suite with `npm test` (Node.js 20+). The API token is only needed to start a usable REST server, not to run tests.

---

## 🧼 What it catches **without guarantee**.

| Rule | Examples | Becomes |
|---|---|---|
| 🔑 **API keys & secrets** | OpenAI/Anthropic `sk-…`, AWS `AKIA…`, Google `AIza…` and `ya29.…`, GitHub `ghp_…`/`github_pat_…`, GitLab `glpat-…`, npm `npm_…`, Hugging Face `hf_…`, PyPI, DigitalOcean, Shopify, SendGrid, Slack tokens and webhooks, Discord webhooks, Stripe (incl. `whsec_` webhook secrets), Mailgun `key-…`, Azure `AccountKey=` and SAS `sig=`, JWTs, `Bearer`/`Basic` headers, PEM private keys (also truncated pastes without the END line) | `[REDACTED_API_KEY]` |
| 🔌 **Connection strings** | `postgres://user:pass@host:5432/db`, Mongo, Redis, MySQL, AMQP, LDAP, SFTP, and any URL with `user:password@` | `[REDACTED_CONNECTION_STRING]` |
| 🌐 **IPv4 / IPv6** | `192.0.2.42`, `192.0.2.0/24`, `203.0.113.7:8443`, full & compressed IPv6, `*.local` hostnames | `[REDACTED_IP]` |
| ✉️ **Emails** | `ops@example.com` | `[REDACTED_EMAIL]` |
| ☎️ **Phone numbers** | `+1 (555) 123-4567` | `[REDACTED_PHONE]` |
| 🔒 **Passwords & tokens** | `password='…'`, `api_key=…`, `clientSecret: "…"`, `PGPASSWORD=…`, `SECRET_KEY_BASE=…`, `--password=…` | `password='[REDACTED_SECRET]'` |
| ⚙️ **Your own pattern** | any JavaScript regex you supply, bare or as `/pattern/i` with flags | your token |

You can paste text, use **📂 Open file**, or drop a file onto the input panel; files are read inside the tab and never uploaded. The theme follows your OS setting. Keyboard shortcuts: <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>Enter</kbd> copies the safe text, <kbd>/</kbd> focuses the input, <kbd>T</kbd> toggles the theme, <kbd>?</kbd> lists shortcuts, and <kbd>Esc</kbd> closes dialogs. Native keys like <kbd>Ctrl</kbd>+<kbd>C</kbd> are never overridden.

Masking rules are toggles. Prompt-injection detection is **off by default** and runs only when you choose “Scan for Injections”; it does not rewrite copied text. Custom regexes run in a disposable worker with a one-second timeout; if a scan times out, safe-copy is disabled.

Quoted credential values may contain spaces. **Key names stay readable.** `password='sample value'` becomes `password='[REDACTED_SECRET]'`.

**Pasted code stays valid.** An unquoted value that is clearly a code reference is left alone: `password = os.environ["DB_PASSWORD"]`, `token = getToken()`, `password: process.env.DB_PASSWORD`, `${{ secrets.X }}`, `$DB_PASSWORD`, `null`/`None`/type names. Quoted literals are always masked. Unquoted values stop at whitespace, `,` and `;`, so `password=p@ss,word` leaks `,word`: quote such values or review the output.

**Terminal colour codes don't hide secrets.** Rules scan an ANSI-stripped view of the text, so `AKIA<ESC>[1m…` is still caught, while colour codes outside a secret are kept byte for byte.

---

## 🔍 Where "trust" usually breaks — and how to check it here

Most "privacy" tools ask you to take their word. Don't. This one is verifiable in
under a minute:

1. Press <kbd>F12</kbd> → **Network** tab → clear it.
2. Paste a secret into the left panel. Watch the right panel redact instantly.
3. **Look at Network.** No outbound HTTP(S) request fires; custom-regex scans may use a local `blob:` worker. Check the **Console** for errors.
4. Set throttling to **Offline** and keep scrubbing. It still works.
5. Click **{ } Source** — the code viewer isn't a screenshot. It's produced by calling
   `Function.prototype.toString()` on the function objects *currently running in your tab*,
   so it cannot drift from what's actually executing.
6. Rebuild or inspect the static HTML, CSS, and JavaScript assets yourself.

The browser page does not use `localStorage`, `sessionStorage`, IndexedDB or cookies, and makes no first-party network calls while processing. The optional REST server and browser extension are separate components and are documented separately.

> [!NOTE]
> PromptSafe is a **safety net, not a proof**. Regex catches patterns, not intent.
> Always eyeball the output before you paste it somewhere you can't take it back.

---

## 🛠️ How it works

The entire engine is one array of rules:

```js
{
  id: "creds",
  label: "Mask Passwords & Tokens",
  token: "[REDACTED_SECRET]",
  patterns: [ /(\b(?:password|passwd|pwd|secret|token|api[_-]?key|…)\b["']?\s*(?:=|:|=>|:=)\s*)(["']?)([^\s,;"'`]+)\2/gi ],
  build: (m) => ({                       // redact only PART of the match
    start: m.index + m[1].length + m[2].length,
    end:   m.index + m[1].length + m[2].length + m[3].length,
    text:  "[REDACTED_SECRET]"
  })
}
```

`PS_scan()` collects every match as a `{start, end, text}` range, sorts by position,
and drops overlaps — so two rules matching the same secret can't double-redact it.
`PS_apply()` then rebuilds the string once, emitting both the plain text (for the
clipboard) and highlighted HTML (for the screen).

Large pastes are coalesced before rendering. Custom regexes run in a disposable worker with a one-second timeout; if it times out, safe-copy is disabled rather than falling back to the raw input.

Adding a rule = adding one object to the array. The toggle list, the highlight colour
and the code viewer all pick it up automatically.

---

## 🧪 Verification

Run the regression suite with Node.js 20 or later:

```bash
npm test
```

After editing the script in `index.html`, run `npm run build`. It refreshes the CSP script hash and regenerates `extension/engine.js`, which the extension, CLI and REST server all load. Run `npm run build:css` after adding Tailwind classes, and `npm run build:icons` after editing `extension/icons/icon.svg` (it renders the PNGs with a local headless Chrome; set `CHROME_PATH` if needed). These are contributor tools only; using the app needs no build.

The checked-in suite exercises the engine, CLI, protected REST routes, invalid inputs,
rule validation, and extension-engine synchronization. It does not prove complete secret
detection; the scrubber is pattern-based and should be treated as a safety net.

| Check | Reproducible result |
|---|---|
| Engine regression cases | 53 cases, incl. a linear-time check on adversarial input |
| CLI/server/extension integration cases | 41 tests |
| No storage or network APIs in the page script; secret fields opt out of spellcheck and autofill | checked by `scripts/check-web-security.js` |
| Page script parses and contains no NUL bytes | checked by `scripts/check-web-security.js` |
| Extension engine in sync with the browser engine | checked by the test script |
| CSP hash and local-only assets | checked by `scripts/check-web-security.js` |
| HTML/SVG rendering | user text is escaped before entering the output DOM |
| Unknown CLI/API rules | fail closed instead of silently passing through |

I also manually exercised the browser app in headless Chrome from both `file://` and local HTTP, including CSP, HTML-injection escaping, the worker timeout/fail-closed path, compression output, reversible restoration, and Clear All. These manual browser checks are not part of `npm test`.

Hosted deployments also receive the normal page/static-asset requests; review the hosting
provider's access-log policy. The browser app makes no first-party request while scrubbing.

---

## 📋 Changelog

### Unreleased — review sweep (2026-10-21)
See [docs/review-2026-10-21.md](docs/review-2026-10-21.md) for each finding, its reproduction, and why it was accepted.
- **Security:** Compress no longer leaks secrets split by ANSI colour codes (web, CLI, API), nor the second of two PEM keys (CLI). Plain scrub catches ANSI-split secrets too. The CLI reads UTF-16 input instead of silently passing it. Restore fields opt out of spellcheck and autofill. CI now fails if the page script gains storage or network calls.
- **Detection:** fixed a quadratic-time hostname regex (100 KB froze the tab for ~12 s). Compound key names (`PGPASSWORD`, `clientSecret`, `SECRET_KEY_BASE`) and `whsec_`, Mailgun, Azure SAS and truncated PEM keys are detected. Code references, `Basic authentication` prose, signed decimals and `git@host:repo` remotes are no longer masked.
- **Web app:** Restore works from a saved key on a fresh page, survives input edits (Clear All still wipes it), and has a copy button. Screen readers announce counts and errors instead of re-reading the whole output. Focus returns correctly after cancelling a template.
- **CLI / server:** `-o` cannot overwrite the input or swallow the next flag; `| head` no longer crashes with exit 1. `/api/detect` returns `start`; `bearer` is accepted case-insensitively; oversized bodies are cut off after a 1 s grace period.
- **Extension:** toolbar click and <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd> now work; the menu appears in iframe editors; email fields get an accurate error. A test keeps the three version numbers in sync.
- **Tooling:** `update-csp-hash.js` fails when the CSP has no hash token; `build:icons` explains its Node 22+ requirement.

### v2.2
- **One engine everywhere:** the CLI and REST server now load the generated `extension/engine.js` instead of a hand-copied engine that had drifted from the web app.
- **Detection fixes:** international phone numbers no longer run into the next log line, which had left `+1` visible. `Bearer` headers no longer cross line breaks. URLs with `user:password@` credentials are fully masked. The name "Dan" is no longer flagged as a jailbreak. Four-part version numbers such as `v1.2.3.4` or `version 10.0.19041.1` are no longer masked as IPs, while `root@10.0.0.5` and similar real addresses still are.
- **New detections:** GitLab, npm, Hugging Face, PyPI, DigitalOcean, Shopify, SendGrid, Google OAuth, Slack app tokens and webhooks, Discord webhooks, and Azure account keys.
- **Compression:** strips ANSI codes before timestamps, handles ISO timezones and bracketed levels, deduplicates lines that differed only by timestamp, keeps indentation, and caps blank-line runs. Savings are measured against the scrubbed text.
- **Web app fixes:** the source viewer printed literal `\n` sequences. Exports ran custom regexes on the main thread, bypassing the worker timeout. CSV exports were not escaped. Reversible restore could re-expand placeholders inside restored values. Ctrl+C and Ctrl+T were hijacked by shortcuts.
- **Web app features:** open or drop local files, `/pattern/flags` custom regexes, a sanitized-text download, an export summary, a confirmation before the sample or a template replaces your text, and a footer link to the privacy page.
- **Design and accessibility:** complete dark theme that follows the OS setting, modal focus trapping and focus return, visible keyboard focus on rule switches, a scrollable header toolbar on phones, and reduced-motion support. Custom-regex scans wait for a 250 ms pause in typing, so one worker runs instead of one per keystroke.
- **CLI:** `--output`, `--fail-on-find`, `--list-rules`, `--version`, `--opt=value` syntax, strict option parsing, clean file errors, and escaped CSV.
- **REST server:** `/api/compress` accepts `rules`, scrub results include offsets, the version comes from the engine, and port conflicts and missing option values produce clear errors.
- **Extension:** scrubs the field's real selection even when Chrome normalizes whitespace, supports every contenteditable host and open shadow roots, keeps editor undo history through `insertText`, shows a toolbar badge with the result, and ships 16–128 px icons for the toolbar and store listing.
- **Tooling:** `npm run build` updates the CSP hash and engine bundle, and the security check now verifies the page script parses.

### v2.1
- Removed the Tailwind CDN runtime; styles are bundled locally and the browser page has a restrictive CSP.
- Fixed quoted multiword credential values, moved custom regex matching into a timeout-limited worker, and made injection detection opt-in.
- Fixed reversible restoration and Clear All cleanup; compression output is now visible and explicitly marked lossy.
- Repaired CLI/server exports and secured the REST API with a required bearer token, loopback default, origin allowlist, input validation, and body limits.
- Rebuilt the extension to use a locally bundled engine with no remote fetch/eval.
- Bounded email matching to avoid pathological backtracking; replaced sample PII and credential-like values with synthetic data.
- Added CLI/API/extension regressions, a CSP hash check, and reproducible CSS/extension build commands.

### v1.2
- **Light theme** — white surfaces, indigo/violet accents, soft gradients. Redaction
  highlights re-tuned for contrast on white.
- **Professional privacy statement** in the header, replacing the informal notice.
- **Connection strings** split into their own rule token (`[REDACTED_CONNECTION_STRING]`)
  so a DB URL is no longer mislabelled as an API key.
- **Phone numbers** get a digit-count filter (10–15) so timestamps and IDs aren't eaten.
- **Fixed false negatives:** `aws_secret_access_key`, `secret_key`, `db_password`,
  `refresh_token` and other compound credential names; fine-grained `github_pat_` tokens;
  Google keys of non-canonical length.
- **Fixed an idempotence bug:** a second pass over already-scrubbed text would rewrite
  `OPENAI_API_KEY=[REDACTED_API_KEY]` to `…=[REDACTED_SECRET]`. Credential values that are
  already a redaction token are now left alone.
- Version shown in the header and the README banner.

### v1.1
- Connection-string rule, phone-number mask, light/dark neutrality work.

### v1.0
- Initial release: single-file client-side scrubber with a live source viewer.

---

## 📄 License

MIT — see [LICENSE](LICENSE). Fork it, self-host it, ship it.
