<img src="assets/banner.svg" alt="PromptSafe — scrub secrets before you paste" width="100%">

<p>
<a href="https://xikarzr2026.github.io/promptsafe/"><img src="https://img.shields.io/badge/%E2%96%B6%20live%20app-open%20promptsafe-6366f1?style=for-the-badge" alt="Open the live app"></a>
<img src="https://img.shields.io/badge/version-v1.2-8b5cf6?style=for-the-badge" alt="v1.2">
<img src="https://img.shields.io/badge/backend-none-10b981?style=for-the-badge" alt="No backend">
<img src="https://img.shields.io/badge/database-none-10b981?style=for-the-badge" alt="No database">
<img src="https://img.shields.io/badge/data%20stored-nothing%20ever-10b981?style=for-the-badge" alt="Nothing stored">
<img src="https://img.shields.io/badge/license-MIT-0f172a?style=for-the-badge" alt="MIT">
</p>

**PromptSafe** strips API keys, JWTs, private keys, connection strings, IPs, emails,
phone numbers and `password=` pairs out of logs, config dumps and crash reports —
so you can safely paste them into ChatGPT, Claude, Gemini, or anywhere else.

It is **one HTML file**. No build step, no dependencies to install, no server, no database.

> [!IMPORTANT]
> **No database. Nothing is seen. Nothing is saved.**
> Everything you paste is processed entirely inside your browser tab, on your own machine.
> Not one byte of your text is transmitted, logged, or stored — anywhere. There is no
> copy of it on any website, because there is no website behind the page to hold one.
> Close the tab and every trace of it is gone. Press <kbd>F12</kbd>, open the **Network**
> tab, and watch it stay completely empty while you scrub.

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

Once loaded it works with the network unplugged. Everything except the Tailwind
stylesheet is inline, and that's cached after first load.

---

## 🧼 What it catches

| Rule | Examples | Becomes |
|---|---|---|
| 🔑 **API keys & secrets** | OpenAI `sk-…`, AWS `AKIA…`, Google `AIza…`, GitHub `ghp_…`, Slack `xoxb-…`, Stripe, JWTs, `Bearer`/`Basic` headers, PEM private keys | `[REDACTED_API_KEY]` |
| 🔌 **Connection strings** | `postgres://user:pass@host:5432/db`, Mongo, Redis, MySQL, AMQP, SFTP | `[REDACTED_CONNECTION_STRING]` |
| 🌐 **IPv4 / IPv6** | `10.20.30.40`, `192.0.2.0/24`, `203.0.113.7:8443`, full & compressed IPv6, `*.local` hostnames | `[REDACTED_IP]` |
| ✉️ **Emails** | `ops@example.com` | `[REDACTED_EMAIL]` |
| ☎️ **Phone numbers** | `+1 (555) 123-4567` | `[REDACTED_PHONE]` |
| 🔒 **Passwords & tokens** | `password='…'`, `api_key=…`, `client_secret: "…"` | `password='[REDACTED_SECRET]'` |
| ⚙️ **Your own pattern** | any JavaScript regex you supply | your token |

Every rule is a toggle. Need more precision or less? Flip it off, or add a custom
regex — it's applied live with the `g` flag and a bad pattern can never throw.

**Key names stay readable.** `password='hunter2'` becomes `password='[REDACTED_SECRET]'`,
so the scrubbed log still makes sense to whoever reads it.

---

## 🔍 Where "trust" usually breaks — and how to check it here

Most "privacy" tools ask you to take their word. Don't. This one is verifiable in
under a minute:

1. Press <kbd>F12</kbd> → **Network** tab → clear it.
2. Paste a secret into the left panel. Watch the right panel redact instantly.
3. **Look at Network.** Nothing fires. Repeat with the **Console** open — no errors, no beacons.
4. Set throttling to **Offline** and keep scrubbing. It still works.
5. Click **GitHub Source** — the code viewer isn't a screenshot. It's produced by calling
   `Function.prototype.toString()` on the function objects *currently running in your tab*,
   so it cannot drift from what's actually executing.
6. Rebuild it from source yourself. It's one file.

The app also never touches `localStorage`, `sessionStorage`, IndexedDB or cookies, and
contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon` or tracking pixel.

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

Performance: **1.15 M characters → 45,456 redactions in ~140 ms**. Pastes over 120 KB
are coalesced behind a 40 ms timer so typing never stalls.

Adding a rule = adding one object to the array. The toggle list, the highlight colour
and the code viewer all pick it up automatically.

---

## 🧪 Verification

The engine is tested by extracting it *from the shipped `index.html`* and running it —
not from a re-typed copy. Nothing here is a claim; every number is from a real run.

| Check | Result |
|---|---|
| Engine + regression sweep | **151 / 151 pass** |
| Secret formats that must be caught | **39 / 39 redacted** |
| Benign strings that must survive | **30 / 30 untouched** |
| Headless Chrome render | pass, **0 JS errors** |
| Range invariants (sorted, non-overlapping, in-bounds) | pass |
| Idempotence — scrubbing twice == scrubbing once | pass |
| Sample log | 14 redactions, **0 leaks** |
| All rules off | output byte-identical to input |
| HTML / SVG injection attempts | escaped, no live tag |
| Malformed custom regex | reported, page survives |
| Shipped-file PII scan | clean |
| Network audit (Chrome DevTools Protocol) | **0 requests during scrubbing** |
| Throughput | 1.17 M chars → 48,000 redactions in ~140 ms |

---

## 📋 Changelog

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
