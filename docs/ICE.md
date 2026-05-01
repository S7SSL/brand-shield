# BrandDefend — In Case of Emergency (ICE) Document

> System handover and operations runbook for `S7SSL/brand-shield`.
> Last updated: 2026-05-01.
> Purpose: anyone (you, a future you, a delegate) can understand the system,
> operate it, and fix it without prior context.

---

## 1. Quick Reference

| Item | Value / Location |
|---|---|
| Public dashboard | https://brand-shield.onrender.com |
| Default domain (planned) | branddefend.ai |
| GitHub repo | https://github.com/S7SSL/brand-shield |
| Render service | `brand-shield` (Python 3 / Starter, Oregon) — Service ID `srv-d6du6ccr85hc73c4u0a0` |
| Default admin login | username `sat`, password as set in code (see `backend/auth.py`) |
| Brand owner login | username `erim` |
| Health endpoint | `GET /health` (public, no auth) |
| Scheduler | APScheduler in-process, runs every 6 hours |
| Auto-deploy | enabled — push to `main` triggers Render build |
| Sender address | `legal@byerim.com` (Resend From + audit BCC) |
| Weekly report recipients | `sat@byerim.com`, `erim@byerim.com` |

---

## 2. What does BrandDefend do?

Automated brand protection for **@erim** and **@byerim**:

1. **Scans** the web every 6 hours via a search API for impersonators, counterfeit products, and content theft.
2. **Scores** each result for threat severity (critical / high / medium / low) and threat type (impersonation / counterfeit / content_theft / text_theft).
3. **Generates DMCA takedown notices** from per-platform templates (Meta, Amazon, Shopify, Twitter, generic).
4. **Sends notices** via Resend (with audit BCC to `legal@byerim.com`) to platform IP teams.
5. **Sends weekly digest** every Monday 8am UTC to the report recipients.
6. **Auto-resolves** stale `new` threats older than 24h every midnight UTC.

The dashboard surfaces active threats, suspicious accounts, the DMCA workflow (file → send → confirm-removal), and the most recent scan status.

---

## 3. Architecture

```
                           ┌──────────────────────┐
                           │   Render web service  │
                           │   (Gunicorn + Flask)  │
                           └──────────┬───────────┘
                                      │
   ┌──────────────────────────────────┼────────────────────────────────────┐
   │                                  │                                     │
   ▼                                  ▼                                     ▼
APScheduler                    Flask routes                          SQLite (WAL)
─ scan every 6h               ─ /login                               /opt/render/project/
─ weekly report Mon 8am        ─ /  (dashboard, auth required)          src/data/brand_shield.db
─ auto-resolve midnight        ─ /api/...                             ⚠ EPHEMERAL on Starter
                               ─ /health (public)                       — wiped on every deploy
                               ─ /favicon.svg (public)
                                      │
                       ┌──────────────┼─────────────────┐
                       ▼              ▼                 ▼
                 Brave Search    Google CSE        DDG html / lite
                  (primary,      (fallback,         (last-resort,
                   2000/mo)       blocked by         no key needed)
                                  byerim.com org
                                  policy)
                                      │
                                      ▼
                                 Detector
                                ─ score_result()
                                ─ confidence threshold 0.35
                                      │
                                      ▼
                                 threats / suspicious_accounts
                                      │
                                      ▼
                                 DMCA workflow
                                ─ template selection per platform
                                ─ send via Resend (preferred) or SMTP
                                ─ BCC legal@byerim.com (LEGAL_BCC)
```

### Key directories

```
brand-shield/
├── backend/
│   ├── app.py              # Flask routes, seed data, email senders, /health
│   ├── auth.py             # session auth, default users
│   ├── config.py           # BRANDS dict, weights, paths, env-var reads
│   ├── database.py         # SQLite init + query helpers
│   ├── scrapers/
│   │   ├── brave_search.py     # primary search backend (Brave API)
│   │   ├── google_search.py    # fallback (currently blocked; kept for future)
│   │   ├── duckduckgo_search.py # last-resort (html → lite endpoint fallback)
│   │   └── web_scraper.py      # profile data extraction
│   ├── services/
│   │   ├── scanner.py      # orchestrator: picks backend, runs queries, creates threats
│   │   ├── detector.py     # confidence scoring
│   │   ├── scheduler.py    # APScheduler jobs (scan, report, auto-resolve)
│   │   └── reporter.py     # weekly email digest
│   ├── templates/          # DMCA notice templates (.txt)
│   └── static/
│       ├── dashboard.html  # main UI
│       ├── login.html      # auth page
│       └── favicon.svg     # BD logo
├── docs/
│   └── ICE.md              # this file
├── render.yaml             # Render service config
├── Procfile                # web: gunicorn backend.app:app --bind 0.0.0.0:$PORT
└── requirements.txt        # Python deps (Flask 3.0.0, APScheduler 3.10.4, etc.)
```

---

## 4. Deployment

### Hosting

- **Render.com**, plan **Starter** ($7/mo). Free tier was abandoned because it sleeps after 15 min, killing the in-process scheduler.
- **Region**: Oregon.
- **Auto-deploy**: ON. Every push to `main` triggers a build → deploy.
- **Runtime**: Python 3.11.
- **Build command**: `pip install -r requirements.txt`
- **Start command**: `gunicorn backend.app:app --bind 0.0.0.0:$PORT`

### ⚠ Critical limitation: ephemeral disk

Starter tier does **not include a persistent disk** by default. Every redeploy wipes `/opt/render/project/src/data/`, so:

- `brand_shield.db` is reset on every deploy.
- The `seed_demo_data()` function in `backend/app.py` re-seeds 8 demo threats / 3 suspects / 2 DMCA notices on every fresh DB.
- Real threat detections discovered between deploys are LOST on the next deploy.

**To fix permanently:** attach a Render Disk add-on (~$1/GB/month, 1GB plenty) and mount it at `/opt/render/project/src/data/`. Or migrate the DB to a managed Postgres (Render offers a free tier — 90-day expiry which can be renewed).

### How to deploy a code change

```bash
cd ~/code/brand-shield
# … make changes
git add -A
git commit -m "describe change"
git push origin main
# Render auto-deploys; takes 2–3 minutes
# Verify: curl https://brand-shield.onrender.com/health
```

### How to roll back

In Render dashboard → brand-shield → **Events** → find the last green deploy → **Rollback to this deploy**.

---

## 5. Environment variables (Render)

Set under: Render dashboard → brand-shield → **Environment** → Edit.

| Var | Purpose | Required? |
|---|---|---|
| `SECRET_KEY` | Flask session signing secret | ✅ yes |
| `BRAVE_API_KEY` | Primary search backend (Brave Search API) | ✅ yes (current) |
| `GOOGLE_CSE_API_KEY` | Fallback search (Google Custom Search) — currently blocked by org policy, can be removed | optional |
| `GOOGLE_CSE_CX` | Search engine ID for Google CSE | optional, paired with above |
| `RESEND_API_KEY` | Email sending via Resend | ✅ yes (or SMTP_*) |
| `RESEND_FROM` | Default `BrandDefend <legal@byerim.com>` | optional |
| `LEGAL_BCC` | BCC every outgoing DMCA + report. Default `legal@byerim.com`. Set to `""` to disable | optional |
| `REPORT_RECIPIENTS` | Comma-separated emails for weekly digest. Default `sat@byerim.com,erim@byerim.com` | optional |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT`, `SMTP_FROM` | SMTP fallback if Resend unset | optional |

**Always saving env vars triggers a redeploy** (Render: "Save, rebuild, and deploy" is the only option).

---

## 6. Search backends — priority, gotchas, and how to switch

Order of preference is hard-coded in `backend/services/scanner.py::run_brand_scan()`:

1. **Brave Search API** — used when `BRAVE_API_KEY` is set. Free tier 2000/mo. Endpoint: `https://api.search.brave.com/res/v1/web/search`. Auth header: `X-Subscription-Token`.
2. **Google Custom Search API** — used when `GOOGLE_CSE_API_KEY` + `GOOGLE_CSE_CX` are set. Free tier 100/day. Currently returning 403 PERMISSION_DENIED because the `inventory-management-493814` Cloud project is structurally blocked at the byerim.com Workspace org level.
3. **DuckDuckGo** — last-resort fallback, no key. Tries `html.duckduckgo.com` first, falls back to `lite.duckduckgo.com`. Often blocked from cloud-host IPs.

### Quota math

7 queries per brand × 2 brands × 4 scans/day = **56 queries/day ≈ 1700/month**, comfortably under Brave's 2000/mo free tier.

### Adding a new backend

Create `backend/scrapers/<name>_search.py` mirroring the `brave_search.py` interface (`build_search_queries`, `search_brand`, an exception class). Add a branch in `scanner.py::run_brand_scan()` and a `backend_in_use` case in `app.py::health_check()`.

---

## 7. DMCA workflow

1. **Threat detected** → seeded with `status='new'` in `threats` table.
2. **User opens dashboard** → clicks DMCA button on a threat card → backend selects template based on platform (`backend/templates/dmca_*.txt`).
3. **Notice rendered** → user reviews → clicks Send.
4. **Email sent** via Resend (preferred) or SMTP fallback. Audit BCC to `LEGAL_BCC` (default `legal@byerim.com`) so you have a record of every outgoing notice.
5. **`dmca_notices` row** created with `status='sent'`.
6. **Removal confirmation** is manual — operator marks the notice as `resolved` after the platform takes action.

### ⚠ "Simulated" mode

If neither `RESEND_API_KEY` nor `SMTP_HOST`+`SMTP_USER` is set, `send_email()` returns `(True, "simulated", ...)` without actually sending. The dashboard will show "DMCA sent" but no email leaves the building. Always verify `RESEND_API_KEY` is set on Render after any major env-var change.

---

## 8. Operations

### Trigger a manual scan

```bash
# Authenticated via cookie:
# 1. Log into https://brand-shield.onrender.com/login
# 2. From the same browser session:
curl -X POST https://brand-shield.onrender.com/api/scan/run \
  -H "Content-Type: application/json" \
  -b "bs_session=<your-cookie>" \
  -d '{}'
```

Response: `{"message":"Scan started in background", "brand":"all"}`. Watch `/health` afterwards to see `last_scan` move forward.

### Check system health

```bash
curl https://brand-shield.onrender.com/health
```

Healthy:    `"status":"ok"`, `"search_backend":"brave_search"`, `"last_scan.status":"completed"`, `items_scanned > 0`.

Degraded:   `"status":"degraded"` — last 3 scans failed or returned 0 items. Check Render logs.

### View Render logs

Render dashboard → brand-shield → **Logs**. Filter for `[Brave]`, `[Scanner]`, or specific brand keys to trace a scan run.

### Rotate Brave API key

1. Go to https://api.search.brave.com → API Keys → revoke old key → create new one.
2. Render → Environment → edit `BRAVE_API_KEY` → Save, rebuild, deploy.

### Rotate Resend API key

1. Go to https://resend.com → API Keys → revoke old → create new (full access).
2. Render → Environment → edit `RESEND_API_KEY` → Save, rebuild, deploy.

### Add a new brand to monitor

Edit `backend/config.py` → `BRANDS` dict → add a new entry with `display_name`, `platform_handles`, `verified_urls`, `keywords`, `product_names`, `bio_phrases`. Push to `main`.

---

## 9. Common issues and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard shows "0 active threats" | Demo data is `status='reported'` and the threats list filters those out by default | Use the Status filter dropdown → "Reported" to see them |
| `/health` shows `degraded` | Last 3 scans failed or scanned 0 items | Check Render logs for `[Brave] Query N failed:` lines |
| Brave returns 403 / 401 | Key revoked or invalid | Rotate key, update env var |
| Brave returns 429 | Quota hit (>2000/mo) | Either upgrade Brave plan, or reduce `SCAN_INTERVAL_HOURS` in `config.py` to 12h |
| Google CSE returns 403 | Workspace org policy block | Don't fix — Brave is primary now. Remove `GOOGLE_CSE_*` env vars to silence |
| Buttons don't respond on dashboard | Session cookie cleared (Render redeploy invalidates in-memory sessions) | Refresh page, log in again |
| `recent_scans` shows seed data only after deploy | Ephemeral disk wiped DB | See section 4 — attach a persistent disk or migrate to Postgres |
| Dashboard images don't load | `/static/<path>` requires auth | Already public for `login*` paths and `/favicon.*` — others need user logged in |
| DMCA "sent" but recipient never gets it | `RESEND_API_KEY` not set, in simulated mode | Set the env var |

---

## 10. Open issues / known limitations

1. **Ephemeral disk on Render Starter** — see section 4. Highest-impact fix: attach a Render Disk or move to Postgres.
2. **Render Free tier sleep killed scheduler** — already fixed by Starter tier upgrade. Don't downgrade.
3. **GitHub Dependabot** flagged 13 vulnerabilities (4 high, 8 moderate, 1 low) on the dependency tree as of 2026-05-01. Worth a separate cleanup pass: review at https://github.com/S7SSL/brand-shield/security/dependabot and `pip install --upgrade` the flagged packages, retest, push.
4. **No persistent CSE alternative** — Google CSE is structurally blocked. If Brave breaks, you'd fall through to DDG which is unreliable. Worth signing up for SerpAPI or Bing as a third backup.
5. **Image search not used** — Brave returns image results in a separate field; we only consume `web.results`. Image-based counterfeit detection (matching ByErim product photos) would need a separate scraper.
6. **No persistent threat history across deploys** — same root cause as #1.
7. **DMCA confirm-removal is manual** — no scraper checks whether a flagged URL has actually gone offline. Could be added as a periodic job.

---

## 11. Accounts and credentials

> Where to find credentials. Do **not** paste actual key values into this doc.

| Service | Account | Where the key lives |
|---|---|---|
| Render | `sat@kaizengold.com` (workspace owner: Sat) — login via GitHub OAuth | Login at dashboard.render.com via GitHub |
| GitHub | `S7SSL` org — Sat as owner | n/a |
| Brave Search API | `sat@byerim.com` — register at api.search.brave.com | Account dashboard → API Keys |
| Google Cloud / CSE | `marge@byerim.com` (project: `inventory-management-493814`) — currently blocked, kept as fallback | Cloud Console → APIs & Services → Credentials |
| Resend | (whichever email you registered with) | resend.com → API Keys |
| Programmable Search Engine (CSE) | `marge@byerim.com` | programmablesearchengine.google.com — engine ID `c427abcdaafb34c58` |

API keys are stored only in Render's encrypted env-var store. Never commit them to git.

---

## 12. Future work (nice-to-haves)

- Persistent storage (disk or Postgres) → real threat history across deploys.
- Image-hash matching for counterfeit product detection.
- Slack / Telegram webhook for critical-severity threats (so you don't have to wait for the weekly digest).
- Rate-limit-aware search rotation (Brave → Google → Bing → SerpAPI in cascading fallback).
- Threat scoring tuning — adjust `IMPERSONATION_WEIGHTS` in `config.py` and `MIN_THREAT_CONFIDENCE` based on false-positive rate after a few months of real data.
- Custom domain `branddefend.ai` → CNAME to Render.
- Two-factor auth on the dashboard login.
- Audit log table — every login, every DMCA send, every threat status change.

---

## 13. Glossary

- **CSE** — Custom Search Engine (Google's term).
- **CX** — the Search engine ID for a Programmable Search Engine.
- **DMCA** — Digital Millennium Copyright Act takedown notice.
- **APScheduler** — Python in-process job scheduler used here.
- **Render Starter tier** — paid tier that doesn't sleep, no persistent disk.
- **PERMISSION_DENIED (403)** — Google API error code; here, caused by Workspace org policy.
- **DDG lite** — `lite.duckduckgo.com/lite/`, the simpler-HTML DuckDuckGo endpoint we fall back to when `html.duckduckgo.com` is blocked.

---

*If you're reading this because something broke and Sat isn't around: the system is designed to fail loudly. Hit `/health`, check `status`, follow the table in section 9. If `status: ok` but counts look wrong, it's almost always one of the items in section 9.*
