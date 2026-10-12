<img src="assets/banner.svg" alt="PromptSafe — scrub secrets before you paste" width="100%">

<p>
<a href="https://xikarzr2026.github.io/promptsafe/"><img src="https://img.shields.io/badge/%E2%96%B6%20live%20app-open%20promptsafe-6366f1?style=for-the-badge" alt="Open the live app"></a>
<img src="https://img.shields.io/badge/version-v2.1-8b5cf6?style=for-the-badge" alt="v2.1">
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

- **CLI:** `node cli.js --file app.log` or `cat app.log | node cli.js --detect-only --format json`. Unknown rule IDs and formats fail with a non-zero exit code. Injection detection is opt-in (`--rules inject`). `--compress` is lossy log cleanup: it can remove repeated lines, timestamps, log-level prefixes, extra spaces, and ANSI codes.
- **REST server:** set `PROMPTSAFE_API_TOKEN` in the process environment, then run `node server.js`. It binds to `127.0.0.1` by default; `/health` is public, API routes require a `PROMPTSAFE_API_TOKEN` of at least 32 characters and an `Authorization: Bearer $PROMPTSAFE_API_TOKEN` header; request bodies are limited to 1 MiB. Cross-origin browser access is disabled unless the exact `PROMPTSAFE_CORS_ORIGIN` is configured. Do not commit or put the token in command history.
- **Browser extension:** load the `extension/` directory as an unpacked extension. It scrubs a selected value in an editable field using a bundled local engine; it makes no remote fetch when used.

Run the regression suite with `npm test` (Node.js 20+). The API token is only needed to start a usable REST server, not to run tests.

---

## 🧼 What it catches **without guarantee**.

| Rule | Examples | Becomes |
|---|---|---|
| 🔑 **API keys & secrets** | OpenAI `sk-…`, AWS `AKIA…`, Google `AIza…`, GitHub `ghp_…`, Slack `xoxb-…`, Stripe, JWTs, `Bearer`/`Basic` headers, PEM private keys | `[REDACTED_API_KEY]` |
| 🔌 **Connection strings** | `postgres://user:pass@host:5432/db`, Mongo, Redis, MySQL, AMQP, SFTP | `[REDACTED_CONNECTION_STRING]` |
| 🌐 **IPv4 / IPv6** | `192.0.2.42`, `192.0.2.0/24`, `203.0.113.7:8443`, full & compressed IPv6, `*.local` hostnames | `[REDACTED_IP]` |
| ✉️ **Emails** | `ops@example.com` | `[REDACTED_EMAIL]` |
| ☎️ **Phone numbers** | `+1 (555) 123-4567` | `[REDACTED_PHONE]` |
| 🔒 **Passwords & tokens** | `password='…'`, `api_key=…`, `client_secret: "…"` | `password='[REDACTED_SECRET]'` |
| ⚙️ **Your own pattern** | any JavaScript regex you supply | your token |

Masking rules are toggles. Prompt-injection detection is **off by default** and runs only when you choose “Scan for Injections”; it does not rewrite copied text. Custom regexes run in a disposable worker with a one-second timeout; if a scan times out, safe-copy is disabled.

Quoted credential values may contain spaces. **Key names stay readable.** `password='sample value'` becomes `password='[REDACTED_SECRET]'`.

---

## 🔍 Where "trust" usually breaks — and how to check it here

Most "privacy" tools ask you to take their word. Don't. This one is verifiable in
under a minute:

1. Press <kbd>F12</kbd> → **Network** tab → clear it.
2. Paste a secret into the left panel. Watch the right panel redact instantly.
3. **Look at Network.** No outbound HTTP(S) request fires; custom-regex scans may use a local `blob:` worker. Check the **Console** for errors.
4. Set throttling to **Offline** and keep scrubbing. It still works.
5. Click **GitHub Source** — the code viewer isn't a screenshot. It's produced by calling
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

Contributors can regenerate the local CSS and extension engine with `npm run build:css` and `npm run build:extension`; these are build-time tools only.

The checked-in suite exercises the engine, CLI, protected REST routes, invalid inputs,
rule validation, and extension-engine synchronization. It does not prove complete secret
detection; the scrubber is pattern-based and should be treated as a safety net.

| Check | Reproducible result |
|---|---|
| Engine regression cases | 27 cases |
| CLI/server/extension integration cases | 14 tests |
| Extension engine in sync with the browser engine | checked by the test script |
| CSP hash and local-only assets | checked by `scripts/check-web-security.js` |
| HTML/SVG rendering | user text is escaped before entering the output DOM |
| Unknown CLI/API rules | fail closed instead of silently passing through |

I also manually exercised the browser app in headless Chrome from both `file://` and local HTTP, including CSP, HTML-injection escaping, the worker timeout/fail-closed path, compression output, reversible restoration, and Clear All. These manual browser checks are not part of `npm test`.

Hosted deployments also receive the normal page/static-asset requests; review the hosting
provider's access-log policy. The browser app makes no first-party request while scrubbing.

---

## 📋 Changelog

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
