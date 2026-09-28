# Rehan Hosting — Full Hosting Bot

Multi-type Telegram bot/API/website hosting panel with mandatory admin
approval, a built-in security scanner, and a file-based database.

## Hosting types
- 🎮 Discord Bot Hosting
- 💬 WhatsApp Bot Hosting
- 🔗 API Hosting
- 🌐 Website Hosting

Users pick a hosting type first, then send their project as `.zip`,
`.py`, or `.js`. ZIP is recommended for multi-file projects. The engine
detects the entry point and installs the project's own
`requirements.txt` (Python) or `package.json` (Node) — no framework is
hard-coded, so any compatible Discord/WhatsApp library the project
brings works.

## Admin approval
Every non-admin upload is security-scanned first, then queued for
admin review. The approval card shows the uploader, hosting type,
file name, file count/size, and:
- `Approve`
- `Reject`
- `Get File` — copies the *exact* original Telegram upload into the
  admin's chat via `bot.copy_message`, and works even while the
  request is still pending.

Hosted projects are never started before approval — `start_child()`
hard-gates on `approval_status` being anything other than approved.

## File-based database & recovery
All panel metadata lives in local JSON under `storage/data/`, written
atomically (`tmp` + `os.replace`) under a lock so a crash or
simultaneous callback can't corrupt it. On restart the bot reloads
users, bots, the approval queue, and settings, and only restarts bots
whose last known status was `running` (never a pending or rejected
one). An optional GitHub backup/restore layer provides a second
recovery path.

## This fix pass
- **Removed a large duplicated code block.** `main.py` contained two
  overlapping copies of ~119 functions (routing, all command/callback
  handlers, admin screens), each independently decorated with
  `@bot.message_handler` / `@bot.callback_query_handler`. This caused
  every command and callback to fire twice. The AST-verified newer
  copy (the one with Discord/WhatsApp hosting, `/admin`, photo
  handling, 2FA, webhooks, etc.) was kept; the older duplicate
  definitions were removed. File went from 18,916 to 15,795 lines
  with zero functional loss — every unique function from both halves
  is retained.
- **Implemented a missing function.** The hosting-type buttons called
  `render_host_type(...)`, which was referenced but never defined
  anywhere in the source, so tapping Discord/WhatsApp/API/Website did
  nothing. Added it: it records the chosen hosting type on the user's
  upload state and prompts them to send their project.
- **Added Telegram Bot Hosting as a real 5th hosting type**, alongside
  Discord/WhatsApp/API/Website — same generic entry-point detection
  and dependency install path, no framework hard-coded.
- **Removed a dangerous silent default.** Uploads used to fall back to
  `hosting_type = "discord"` whenever no type had been chosen. The bot
  now refuses the upload and asks the user to pick a hosting type
  first.
- **Get File now survives Approve/Reject.** Previously the original
  upload's `chat_id`/`message_id` only lived in the pending-approval
  queue, which both `approve_bot()` and `reject_bot()` clear — so
  Admin's 📄 Get File stopped working the moment a decision was made.
  Added a durable `upload_records` store, written at upload time and
  never touched by approve/reject, so Get File keeps working before
  approval, after approval, and after rejection (as long as the
  original Telegram message itself still exists). The approval card's
  buttons are also preserved (not wiped) after a decision, so Get File
  stays clickable from the same message.
- **Enriched the admin approval card** with upload time and the
  security scan verdict/risk score (previously missing), and added
  hosting type + scan verdict to the compact Pending Uploads list.
- **Wired 10 orphaned admin screens** (Diagnostics, Process Monitor,
  API Keys, Webhook Log, Rate Stats, Broadcast Status, Payment
  Requests, Referral Detail, Subscription Expiry Report, Language
  Stats) into the Analytics and System Tools menus — the backend
  functions and routes already existed but no button anywhere linked
  to them.
- **Added a missing "🗑️ Delete Files" control** on the per-bot panel —
  `render_bot_delfiles_confirm`/`action_bot_delfiles` existed and were
  routed but had no button pointing to them.
- **Removed `railway.json` and `render.yaml`** per request; confirmed
  no Python code referenced either file.
- Verified: no duplicate handlers/decorators remain, no
  `exec`/`eval`/`marshal`/hidden payloads, no `os.system()` or
  `shell=True` anywhere in the app, no hardcoded bot tokens, no
  ASCII/Unicode box-border UI anywhere (the existing design already
  used clean divider lines), dependency installs are isolated per-bot
  under `.deps/` and never touch the host app's own files, and the
  health endpoint binds the platform-provided `PORT`.
- Full syntax compile, AST parse, and automated callback audit
  (every button ↔ every route, both directions) pass clean — zero
  dead buttons, zero unreachable routes.

## Latest audit pass — button style system
Every inline button in the project (515 `Btn()` calls) was enumerated
and checked. 32 buttons that perform a real action were found with no
style assigned and have been fixed:

- Payment **Approve** → `success`, **Reject** → `danger` (both
  locations — this was the most important gap, since Approve/Reject
  had no color distinction before)
- Ticket **Reply** → `primary`, **Close** → `danger`
- Env var **delete** → `danger`, **Add/Edit** → `primary`
- Captcha option buttons, **New captcha**, group **Verify Membership**,
  group **Join** link → `primary`/`success`
- **Buy plan**, **Send Proof**, **Top Up**, **Gift Plan**, **Redeem
  Code**, **Open Ticket**, **Claim Trial** → `primary`/`success`
- GitHub browser folder/file navigation, **Download**, **Run this
  file** → `primary`/`success`
- Bot-list and ticket-list row buttons → `primary`
- Plan price **+/-** adjusters, **Reset Defaults** → `primary`/`danger`
- Admin **Menu Photos** picker, **Admin Panel** entry button →
  `primary`

The 21 buttons still left without a style are all intentional: 19 are
pure `⬅️ Back` navigation buttons and one is a non-interactive "current
value" display — exactly what the style spec defines as Default /
Neutral (no color). The project's button system already implements
Neutral as "no style attribute sent," so leaving these unset *is* the
correct, explicit Neutral choice — adding a fake `style="neutral"`
value would have sent an unsupported field to Telegram's Bot API.

The style values themselves (`"primary"`/`"success"`/`"danger"`) are
Telegram Bot API 9.4's own native inline-button style field — verified
against `Btn`'s `to_dict()` override, which only ever emits those three
literal strings (or omits the field entirely for Neutral). Admins can
remap which semantic role uses which of the three via the existing
Button UI Editor (Admin → Sys Tools → Button UI). No unsupported or
invented Telegram fields are sent anywhere.

## Master audit pass (final)

**Code audit**
| Check | Result |
|---|---|
| Python syntax compile (`main.py`, `security_scanner_free.py`) | PASS |
| Duplicate top-level functions (AST-level) | PASS — 0 found |
| Duplicate `@bot.*` handler decorators | PASS — 0 found |
| Bare `except:` (no exception type) | PASS — 0 found |
| Hardcoded bot tokens | PASS — 0 found |
| `os.system()` / uncontrolled shell exec | PASS — 0 found |
| Box-drawing UI characters | PASS — 0 found |
| Module import / top-level execution | **PASS — see note below** |

*Note on runtime testing:* this build environment has no live Telegram
API access and its package mirror doesn't carry `pyTelegramBotAPI`,
`APScheduler`, `PyGithub`, or `curl_cffi`, so a real bot session could
not be started here — that part is **NOT LIVE TESTED — EXTERNAL
SERVICE REQUIRED**. To still get real signal rather than syntax-only
checks, a local stub of those four packages was built (no network
calls, just enough surface to satisfy imports and decorator
registration) and `main.py` was actually imported through it. The
whole module executed top to bottom — every class body, every
`@bot.message_handler`/`@bot.callback_query_handler` decorator
application, all constant tables — with zero `NameError`/
`AttributeError`. 9 message handlers and 3 top-level callback handlers
registered successfully (the rest of the ~500 callback routes live
inside the single catch-all callback handler's internal dispatch,
audited separately below).

Against that same stub, targeted functional tests were run directly
(not mocked assertions — actual calls into the real functions):
- `approve_bot()` / `reject_bot()` were called on seeded pending
  records: pending-queue entries were correctly removed and the
  **durable `upload_records` store still returned the file metadata
  afterward** — Get File confirmed to survive both outcomes.
- `reject_bot()` confirmed to delete the bot's DB record while the
  Get File metadata remains retrievable.
- The restart-recovery loop was found to filter only on
  `status == "running"`, relying on `start_child()`'s own approval
  check as the real gate — `start_child()` was confirmed to refuse a
  pending bot (`"Bot is waiting for admin approval"`) and a rejected
  bot (`"Bot was rejected by admin"`) directly. As a hardening (not a
  bug fix — the gate already held), the recovery loop itself now also
  checks `approval_status == "approved"` before ever calling
  `start_child()`, so a non-approved bot is never even attempted.
- All 20 functions that take a `bot_id` from callback data were
  checked for an ownership/admin guard (directly or via delegation to
  one) — 20/20 enforce it. `find_bot()` is a plain dict lookup keyed
  by the bot's opaque ID (never touches the filesystem with
  user-supplied text), so a crafted `bot_id` can't path-traverse.

**Button audit**
- Total buttons found: 515
- Dead buttons (button with no matching route, either direction):
  0 — fully re-verified this pass
- Styled buttons: 494 (primary/success/danger)
- Intentionally unstyled (Neutral — Back/secondary nav): 21

**Hosting audit** (static + stub-level; see network note above)
- Telegram: PASS (upload → scan → approval → generic entry-point
  detection → start/stop/restart/status/logs all present and routed)
- Discord: PASS (same generic pipeline, no framework hard-coded)
- WhatsApp: PASS (same pipeline; QR/pairing surfaces via the
  already-private per-owner Logs view)
- API: PASS (`PORT` env respected, no fixed port)
- Website: PASS (isolated serve directory, path-traversal guarded)

**Admin audit**
- Get File: PASS (works pre-approval, post-approval, and post-rejection
  — verified by direct function call, not just inspection)
- Approve: PASS
- Reject: PASS

**Recovery**
- Database persistence (atomic write + lock): PASS
- Restart recovery (approved+running only restarts): PASS, hardened
  this pass

**Security**
- Secret scan: PASS
- Cross-user access audit (20/20 bot-action functions): PASS
- Path/shell-injection audit: PASS

## Run
```
pip install -r requirements.txt
python main.py
```

Set a fresh `BOT_TOKEN` before starting. If any previous token for
this project was ever made public, rotate it in BotFather.

## Final fix + emoji identity pass

**Last-fix audit:** re-inspected the whole project end to end; the
button-style values (`"primary"/"success"/"danger"`) were already
confirmed correct in the prior pass as Telegram Bot API 9.4's real
native style field — no change needed there. Re-ran the full static
release gate (syntax, duplicate functions/handlers, dead buttons,
secrets, `os.system`, box design, bare `except`) — all PASS, zero
regressions found from the last shipped build.

**Final emoji identity update** (visual only — zero callback_data,
handler, database, or hosting-logic changes):

| Concept | Old | New |
|---|---|---|
| Telegram / Discord / WhatsApp / API / Website Hosting | 🤖 🎮 💬 🔗 🌐 | 🛸 🕹️ 🪢 🧪 🖥️ |
| Get File | 📄 | 🧲 |
| Approve / Reject (all 6 real occurrences, incl. post-decision labels) | ✅ / ❌ / ✓ / ✘ | 🏁 / 🧨 |
| Start / Stop / Restart / Refresh | ▶️ / — / 🔄 | 🔱 / 🧱 / 🌀 / 🪃 |
| Back (95 uses) / Home (Main Menu, 12 uses) | ↲ | 🪃 / 🏮 |
| Admin Panel (4 uses, one previously had no icon) | ◇ / none | 🗝️ |
| Settings | ⚙ | 🧿 |
| Warning (global) | ⚠ | 🕯️ |
| Projects ("My Bots") / Upload | none / 📤 | 🧳 / 🪂 |
| Logs (button + header) / Info | — / — | 🧷 / 🏷️ |
| Delete (all 3 real Delete buttons, standardized) | mixed (✖/✕) | 🗑️ |
| Statistics vs Analytics (disambiguated by label text) | 📊 (both) | 🧮 / 🔭 |
| Pending (nav item, Pending Uploads header, bot status, payment status) | 👁 / ⏳ | ⌛ |
| Scan Log | 👁 | 🧬 |
| Support | none | 🗣️ |
| Close (the one real Close button — ticket close) | ✘ | 🧹 |

Each change was applied at its specific button/label location (or at
a single-purpose shared icon constant only after confirming that
constant wasn't reused for something else) — never a blind find/replace
of an emoji character, since several old emoji (✅, ❌, 📊, 👁, 📄) are
reused throughout the app for unrelated generic status/UI purposes.
Those unrelated usages were deliberately left untouched.

**Not changed — no existing button to attach them to:** User Panel,
Notifications, Database, Recovery, Configuration, Review, Blocked,
Next/Previous. These appear in the requested emoji table but this
project doesn't expose them as distinct standalone buttons, so there
was nothing to relabel without inventing new UI (out of scope for a
"UI-only, no feature creep" pass).

**Verification performed (not just inspection):** recompiled, reran
the full AST/callback audit (0 dead buttons, 0 duplicate
handlers/functions, 0 regressions), and re-imported the module through
the local no-network stub harness used in the previous pass — `main`
loads cleanly, all handlers register, `_HOST_TYPE_LABELS` reflects the
new emoji, and `approve_bot()` + the durable Get File record were
re-exercised live and still work correctly after the icon changes.

**Packaging note:** two different final filenames were requested in
this pass (`REHAN-HOSTING-FINAL-PRODUCTION-FIXED.zip` from the audit
instructions, `REHAN-HOSTING-FINAL-PRODUCTION.zip` from the emoji
instructions, which came later and describe the true last step). This
build is shipped as `REHAN-HOSTING-FINAL-PRODUCTION.zip` per the
final instruction in the sequence.


## Runtime auto-detection
The hosting engine can auto-detect Python, Node.js, Telegram, Discord, WhatsApp, API, and static website projects from project files without rewriting the uploaded source. Node projects with a package.json use npm install automatically when npm is available. package.json, index.html, JSON and supported config files are accepted.
